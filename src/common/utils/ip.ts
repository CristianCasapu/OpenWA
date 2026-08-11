/**
 * Strip an IPv4-mapped IPv6 prefix so comparisons work consistently.
 * Node often reports socket addresses as `::ffff:1.2.3.4` behind dual-stack
 * listeners; this returns the bare `1.2.3.4`.
 */
export function normalizeIp(ip: string): string {
  if (!ip) return ip;
  const match = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  return match ? match[1] : ip;
}

/** Cloudflare exposure modes. `off` = no CF header handling; `tunnel`/`proxy` = behind Cloudflare. */
export const CF_MODES = ['off', 'tunnel', 'proxy'] as const;
export type CfMode = (typeof CF_MODES)[number];

/** Normalize a raw CF_MODE value to a known mode, defaulting to `off` (fail-safe: no CF trust). */
export function normalizeCfMode(raw: string | undefined): CfMode {
  return raw === 'tunnel' || raw === 'proxy' ? raw : 'off';
}

/**
 * Whether CF-Connecting-IP should be honored (from a trusted peer) for the given mode. Both exposure
 * modes trust it; `off` never does. Shared so the config-based and env-direct call sites agree.
 */
export function cfConnectingIpTrusted(cfMode: string | undefined): boolean {
  return normalizeCfMode(cfMode) !== 'off';
}

/** Minimal request shape needed for client-IP resolution (framework-agnostic). */
export interface RequestLike {
  ip?: string;
  socket?: { remoteAddress?: string };
  headers: Record<string, string | string[] | undefined>;
}

/** Options that tune which forwarded headers `resolveClientIp` may trust. */
export interface ResolveClientIpOptions {
  /**
   * When true AND the immediate socket peer is a trusted proxy, honor Cloudflare's
   * `CF-Connecting-IP` as the client IP, ahead of the X-Forwarded-For walk. Off by default so
   * behavior is byte-for-byte unchanged unless a deployment opts in (CF_MODE=tunnel|proxy).
   *
   * `CF-Connecting-IP` is a SINGLE-value header Cloudflare overwrites on every proxied request and
   * strips from client-supplied input, so when the trusted peer is Cloudflare (or the cloudflared
   * tunnel / local proxy that fronts it) it is the authoritative original visitor address. It must
   * still only be read once the peer is trusted — the peer-trust gate is what keeps a client from
   * spoofing it when talking to the app directly.
   */
  trustCfConnectingIp?: boolean;
}

/**
 * Resolve the real client IP. X-Forwarded-For (and, when opted in, CF-Connecting-IP) is
 * client-controllable, so it is only honored when the request actually arrives from a configured
 * trusted proxy. With no trusted proxies, the direct socket address is used (prevents spoofing).
 * Shared by ApiKeyGuard (allowedIps whitelist), the throttler (per-client rate-limit bucket), the
 * WS gateway, and the MCP mount.
 */
export function resolveClientIp(req: RequestLike, trustedProxies: string[], opts: ResolveClientIpOptions = {}): string {
  const socketIp = normalizeIp(req.socket?.remoteAddress || req.ip || '');

  if (!trustedProxies || trustedProxies.length === 0) {
    return socketIp;
  }

  const isTrusted = (ip: string): boolean => trustedProxies.some(proxy => ipMatches(ip, proxy));

  // Only trust ANY forwarded header if the immediate peer is a trusted proxy.
  if (!isTrusted(socketIp)) {
    return socketIp;
  }

  // Cloudflare's authoritative single-value header wins over the XFF chain when the trusted peer is
  // the Cloudflare edge / tunnel / fronting proxy. A malformed value falls through to the XFF walk
  // rather than returning garbage.
  if (opts.trustCfConnectingIp) {
    const cf = req.headers['cf-connecting-ip'];
    const cfIp = normalizeIp((Array.isArray(cf) ? cf[0] : cf || '').trim());
    if (cfIp && isProbablyIp(cfIp)) {
      return cfIp;
    }
  }

  const forwarded = req.headers['x-forwarded-for'];
  if (!forwarded) {
    return socketIp;
  }

  const hops = (Array.isArray(forwarded) ? forwarded.join(',') : forwarded)
    .split(',')
    .map(hop => normalizeIp(hop.trim()))
    .filter(Boolean);

  // Walk right-to-left and return the first hop that is not a trusted proxy:
  // the closest address the trusted infrastructure actually observed.
  for (let i = hops.length - 1; i >= 0; i--) {
    if (!isTrusted(hops[i])) {
      return hops[i];
    }
  }

  return socketIp;
}

/**
 * A minimal sanity check that a string looks like an IPv4 or IPv6 address — enough to reject an
 * obviously-malformed CF-Connecting-IP (an empty/garbage value from a misconfigured origin) without
 * pulling in a full IP parser. IPv4 is validated exactly; IPv6 is accepted on the hex-colon shape
 * the header can carry (Cloudflare emits real addresses, so a loose IPv6 gate is sufficient).
 */
function isProbablyIp(value: string): boolean {
  if (ipv4ToInt(value) !== null) return true;
  return value.includes(':') && /^[0-9a-f:.]+$/i.test(value);
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = result * 256 + octet;
  }
  return result >>> 0;
}

/**
 * True if `ip` equals or falls within `target`, where `target` is either an
 * exact IP or an IPv4 CIDR (e.g. `172.18.0.0/16`). IPv4-mapped IPv6 inputs are
 * normalized first. Malformed input yields `false` rather than throwing.
 */
export function ipMatches(ip: string, target: string): boolean {
  const candidate = normalizeIp((ip || '').trim());
  const ref = (target || '').trim();

  if (!ref.includes('/')) {
    return normalizeIp(ref) === candidate;
  }

  const [range, bitsRaw] = ref.split('/');
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;

  const ipInt = ipv4ToInt(candidate);
  const rangeInt = ipv4ToInt(normalizeIp(range));
  if (ipInt === null || rangeInt === null) return false;

  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}
