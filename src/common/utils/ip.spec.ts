import {
  normalizeIp,
  ipMatches,
  resolveClientIp,
  normalizeCfMode,
  cfConnectingIpTrusted,
  type RequestLike,
} from './ip';

describe('normalizeIp', () => {
  it('strips an IPv4-mapped IPv6 prefix', () => {
    expect(normalizeIp('::ffff:172.18.0.1')).toBe('172.18.0.1');
  });

  it('leaves a plain IPv4 address untouched', () => {
    expect(normalizeIp('10.0.0.1')).toBe('10.0.0.1');
  });

  it('leaves a real IPv6 address untouched', () => {
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1');
  });
});

describe('ipMatches', () => {
  it('matches an exact IP', () => {
    expect(ipMatches('10.0.0.5', '10.0.0.5')).toBe(true);
    expect(ipMatches('10.0.0.6', '10.0.0.5')).toBe(false);
  });

  it('matches within an IPv4 CIDR range', () => {
    expect(ipMatches('172.18.3.4', '172.18.0.0/16')).toBe(true);
    expect(ipMatches('172.19.0.1', '172.18.0.0/16')).toBe(false);
  });

  it('normalizes an IPv4-mapped IPv6 address before matching a CIDR', () => {
    expect(ipMatches('::ffff:172.18.0.9', '172.18.0.0/16')).toBe(true);
  });

  it('handles /32 and /0 boundaries', () => {
    expect(ipMatches('1.2.3.4', '1.2.3.4/32')).toBe(true);
    expect(ipMatches('1.2.3.5', '1.2.3.4/32')).toBe(false);
    expect(ipMatches('9.9.9.9', '0.0.0.0/0')).toBe(true);
  });

  it('returns false for malformed input rather than throwing', () => {
    expect(ipMatches('not-an-ip', '10.0.0.0/8')).toBe(false);
    expect(ipMatches('10.0.0.1', 'garbage/99')).toBe(false);
  });
});

describe('normalizeCfMode / cfConnectingIpTrusted', () => {
  it('accepts the two exposure modes and defaults everything else to off', () => {
    expect(normalizeCfMode('tunnel')).toBe('tunnel');
    expect(normalizeCfMode('proxy')).toBe('proxy');
    expect(normalizeCfMode('off')).toBe('off');
    expect(normalizeCfMode(undefined)).toBe('off');
    expect(normalizeCfMode('TUNNEL')).toBe('off'); // exact match only — a typo must not enable trust
    expect(normalizeCfMode('yes')).toBe('off');
  });

  it('trusts CF-Connecting-IP only in an exposure mode', () => {
    expect(cfConnectingIpTrusted('tunnel')).toBe(true);
    expect(cfConnectingIpTrusted('proxy')).toBe(true);
    expect(cfConnectingIpTrusted('off')).toBe(false);
    expect(cfConnectingIpTrusted(undefined)).toBe(false);
  });
});

describe('resolveClientIp — CF-Connecting-IP handling', () => {
  const req = (peer: string, headers: Record<string, string | string[] | undefined>): RequestLike => ({
    socket: { remoteAddress: peer },
    headers,
  });
  const PROXIES = ['172.18.0.0/16'];

  it('honors CF-Connecting-IP when the peer is trusted and the option is on', () => {
    const ip = resolveClientIp(req('172.18.0.5', { 'cf-connecting-ip': '203.0.113.9' }), PROXIES, {
      trustCfConnectingIp: true,
    });
    expect(ip).toBe('203.0.113.9');
  });

  it('prefers CF-Connecting-IP over the X-Forwarded-For chain from a trusted peer', () => {
    const ip = resolveClientIp(
      req('172.18.0.5', { 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.7, 172.18.0.5' }),
      PROXIES,
      { trustCfConnectingIp: true },
    );
    expect(ip).toBe('203.0.113.9');
  });

  it('IGNORES CF-Connecting-IP when the peer is NOT trusted (anti-spoof, even with the option on)', () => {
    const ip = resolveClientIp(req('8.8.8.8', { 'cf-connecting-ip': '203.0.113.9' }), PROXIES, {
      trustCfConnectingIp: true,
    });
    expect(ip).toBe('8.8.8.8'); // the direct socket IP, header not read
  });

  it('IGNORES CF-Connecting-IP when the option is off, even from a trusted peer', () => {
    const ip = resolveClientIp(req('172.18.0.5', { 'cf-connecting-ip': '203.0.113.9' }), PROXIES, {
      trustCfConnectingIp: false,
    });
    // No XFF either → falls back to the socket IP; the CF header is never consulted.
    expect(ip).toBe('172.18.0.5');
  });

  it('falls through to the X-Forwarded-For walk when CF-Connecting-IP is malformed', () => {
    const ip = resolveClientIp(
      req('172.18.0.5', { 'cf-connecting-ip': 'not-an-ip', 'x-forwarded-for': '198.51.100.7, 172.18.0.5' }),
      PROXIES,
      { trustCfConnectingIp: true },
    );
    expect(ip).toBe('198.51.100.7');
  });

  it('falls through to the socket IP when CF-Connecting-IP is absent and no XFF is present', () => {
    const ip = resolveClientIp(req('172.18.0.5', {}), PROXIES, { trustCfConnectingIp: true });
    expect(ip).toBe('172.18.0.5');
  });

  it('normalizes an IPv4-mapped CF-Connecting-IP value', () => {
    const ip = resolveClientIp(req('172.18.0.5', { 'cf-connecting-ip': '::ffff:203.0.113.9' }), PROXIES, {
      trustCfConnectingIp: true,
    });
    expect(ip).toBe('203.0.113.9');
  });

  it('accepts an IPv6 CF-Connecting-IP value', () => {
    const ip = resolveClientIp(req('172.18.0.5', { 'cf-connecting-ip': '2001:db8::1' }), PROXIES, {
      trustCfConnectingIp: true,
    });
    expect(ip).toBe('2001:db8::1');
  });

  it('behaves identically to before when no options are passed (default off)', () => {
    // Trusted peer + XFF → the existing right-to-left walk; CF header (present) must be ignored.
    const ip = resolveClientIp(
      req('172.18.0.5', { 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.7, 172.18.0.5' }),
      PROXIES,
    );
    expect(ip).toBe('198.51.100.7');
  });
});
