import * as fs from 'fs';
import {
  Fail2banConfigService,
  FAILREGEX_WRONG_API_KEY,
  FAILREGEX_INVALID_REQUEST,
  buildFilterFile,
  buildJailFile,
  resolveFail2banSettings,
} from './fail2ban-config.service';
import { formatSecurityLine, securityLogPath } from '../../common/security/security-event-log.service';

// fs exports are non-configurable; replace the module wholesale (same idiom as the security service spec).
jest.mock('fs');
const mockedFs = fs as jest.Mocked<typeof fs>;

/**
 * Translate a fail2ban `failregex` string into a JS RegExp that captures the IP the same way fail2ban
 * would: `<HOST>` is fail2ban's IP token, so substitute a named group covering IPv4/IPv6. This is the
 * heart of the anti-drift test — the pattern the generator ships is matched against a line the app
 * ACTUALLY emits, so any format/regex divergence that would silently stop bans fails here.
 */
function failregexToJs(failregex: string): RegExp {
  return new RegExp(failregex.replace('<HOST>', '(?<host>[0-9a-fA-F:.]+)'));
}

describe('fail2ban failregex ↔ formatSecurityLine (anti-drift: a divergence here silently stops bans)', () => {
  const at = new Date('2026-08-10T12:34:56.789Z');

  it('matches a real wrong_api_key line and captures the exact IP', () => {
    const line = formatSecurityLine({ reason: 'wrong_api_key', surface: 'rest', ip: '203.0.113.9', at });
    const m = failregexToJs(FAILREGEX_WRONG_API_KEY).exec(line);
    expect(m).not.toBeNull();
    expect(m?.groups?.host).toBe('203.0.113.9');
  });

  it('matches a real invalid_request line and captures the exact IP', () => {
    const line = formatSecurityLine({ reason: 'invalid_request', surface: 'mcp', ip: '198.51.100.7', at });
    const m = failregexToJs(FAILREGEX_INVALID_REQUEST).exec(line);
    expect(m).not.toBeNull();
    expect(m?.groups?.host).toBe('198.51.100.7');
  });

  it('captures an IPv6 address too', () => {
    const line = formatSecurityLine({ reason: 'wrong_api_key', surface: 'ws', ip: '2001:db8::1', at });
    expect(failregexToJs(FAILREGEX_WRONG_API_KEY).exec(line)?.groups?.host).toBe('2001:db8::1');
  });

  it('does not cross-match: a wrong_api_key line must not satisfy the invalid_request pattern', () => {
    const line = formatSecurityLine({ reason: 'wrong_api_key', surface: 'rest', ip: '203.0.113.9', at });
    expect(failregexToJs(FAILREGEX_INVALID_REQUEST).test(line)).toBe(false);
  });

  it('does not match an unrelated log line', () => {
    expect(failregexToJs(FAILREGEX_WRONG_API_KEY).test('2026-08-10 some other log line ip=203.0.113.9')).toBe(false);
  });
});

describe('resolveFail2banSettings', () => {
  const OLD_ENV = process.env;
  beforeEach(() => {
    process.env = { ...OLD_ENV };
    delete process.env.FAIL2BAN_ENABLED;
    delete process.env.FAIL2BAN_MAXRETRY;
    delete process.env.FAIL2BAN_FINDTIME;
    delete process.env.FAIL2BAN_BANTIME;
  });
  afterEach(() => {
    process.env = OLD_ENV;
  });

  it('defaults to disabled with the standard thresholds (bantime 24h) when nothing is set', () => {
    expect(resolveFail2banSettings()).toEqual({ enabled: false, maxretry: 5, findtime: 600, bantime: 86400 });
  });

  it('reads a provided source map in preference to process.env (the just-saved values)', () => {
    process.env.FAIL2BAN_ENABLED = 'false';
    const settings = resolveFail2banSettings({
      FAIL2BAN_ENABLED: 'true',
      FAIL2BAN_MAXRETRY: '3',
      FAIL2BAN_FINDTIME: '900',
      FAIL2BAN_BANTIME: '43200',
    });
    expect(settings).toEqual({ enabled: true, maxretry: 3, findtime: 900, bantime: 43200 });
  });

  it('clamps a 0/garbage value back to the default rather than a broken window', () => {
    const settings = resolveFail2banSettings({
      FAIL2BAN_MAXRETRY: '0',
      FAIL2BAN_FINDTIME: 'abc',
      FAIL2BAN_BANTIME: '',
    });
    expect(settings).toMatchObject({ maxretry: 5, findtime: 600, bantime: 86400 });
  });
});

describe('buildJailFile', () => {
  it('contains the configured values, the DROP banaction, and the absolute security-log path', () => {
    const jail = buildJailFile({ enabled: true, maxretry: 4, findtime: 300, bantime: 86400 }, securityLogPath());
    expect(jail).toContain('[openwa]');
    expect(jail).toContain('enabled  = true');
    expect(jail).toContain('filter   = openwa');
    expect(jail).toContain(`logpath  = ${securityLogPath()}`);
    expect(jail).toContain('maxretry = 4');
    expect(jail).toContain('findtime = 300');
    expect(jail).toContain('bantime  = 86400');
    expect(jail).toContain('banaction = iptables-allports[blocktype=DROP]');
  });

  it('renders enabled=false when disabled', () => {
    const jail = buildJailFile({ enabled: false, maxretry: 5, findtime: 600, bantime: 86400 }, '/x/log');
    expect(jail).toContain('enabled  = false');
  });
});

describe('buildFilterFile', () => {
  it('is a fail2ban [Definition] carrying both failregex and no ignoreregex', () => {
    const filter = buildFilterFile();
    expect(filter).toContain('[Definition]');
    expect(filter).toContain(FAILREGEX_WRONG_API_KEY);
    expect(filter).toContain(FAILREGEX_INVALID_REQUEST);
    expect(filter).toMatch(/ignoreregex =\s*$/m);
  });
});

describe('Fail2banConfigService.regenerate', () => {
  let service: Fail2banConfigService;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new Fail2banConfigService();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => warnSpy.mockRestore());

  it('writes both the filter and the jail under data/fail2ban at mode 0644', () => {
    service.regenerate({ FAIL2BAN_ENABLED: 'true', FAIL2BAN_BANTIME: '86400' });
    const written = mockedFs.writeFileSync.mock.calls.map(c => c[0]);
    expect(written).toContain(Fail2banConfigService.filterPath());
    expect(written).toContain(Fail2banConfigService.jailPath());
    for (const call of mockedFs.writeFileSync.mock.calls) {
      expect(call[2]).toEqual({ mode: 0o644 });
    }
  });

  it('a save reflects the new values in the generated jail (regenerate(source))', () => {
    service.regenerate({
      FAIL2BAN_ENABLED: 'true',
      FAIL2BAN_MAXRETRY: '2',
      FAIL2BAN_FINDTIME: '120',
      FAIL2BAN_BANTIME: '3600',
    });
    const jailWrite = mockedFs.writeFileSync.mock.calls.find(c => c[0] === Fail2banConfigService.jailPath());
    const body = (jailWrite?.[1] as string | undefined) ?? '';
    expect(body).toContain('enabled  = true');
    expect(body).toContain('maxretry = 2');
    expect(body).toContain('findtime = 120');
    expect(body).toContain('bantime  = 3600');
  });

  it('regenerates at boot (onModuleInit) without a save', () => {
    service.onModuleInit();
    expect(mockedFs.writeFileSync).toHaveBeenCalledWith(Fail2banConfigService.jailPath(), expect.any(String), {
      mode: 0o644,
    });
  });

  it('is best-effort: a write failure warns and never throws', () => {
    mockedFs.writeFileSync.mockImplementation(() => {
      throw new Error('EROFS');
    });
    expect(() => service.regenerate()).not.toThrow();
  });
});
