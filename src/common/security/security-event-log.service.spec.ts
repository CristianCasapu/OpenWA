import * as fs from 'fs';
import {
  SecurityEventLogService,
  formatSecurityLine,
  securityLogPath,
  securityLogDir,
  claimSecurityEvent,
  isSecurityEventClaimed,
  SECURITY_LINE_TAG,
  SECURITY_LINE_VERSION,
} from './security-event-log.service';
import type { Request } from 'express';

// fs exports are non-configurable (so jest.spyOn can't redefine them); replace the module wholesale.
jest.mock('fs');

const mockedFs = fs as jest.Mocked<typeof fs>;

describe('formatSecurityLine (the single source of truth for the fail2ban line)', () => {
  const at = new Date('2026-08-10T12:34:56.789Z');

  it('renders a byte-stable single line: ISO ts, tag, version, event, reason, surface, ip', () => {
    const line = formatSecurityLine({ reason: 'wrong_api_key', surface: 'rest', ip: '203.0.113.9', at });
    expect(line).toBe(
      '2026-08-10T12:34:56.789Z OPENWA-SECURITY v=1 event=block reason=wrong_api_key surface=rest ip=203.0.113.9',
    );
  });

  it('carries the exported tag + version verbatim (so the fail2ban failregex can anchor on them)', () => {
    const line = formatSecurityLine({ reason: 'invalid_request', surface: 'ws', ip: '::1', at });
    expect(line).toContain(`${SECURITY_LINE_TAG} v=${SECURITY_LINE_VERSION} `);
    expect(line).toBe(
      '2026-08-10T12:34:56.789Z OPENWA-SECURITY v=1 event=block reason=invalid_request surface=ws ip=::1',
    );
  });

  it('never leaks a key, secret, path, or free-form message — only the five fixed fields', () => {
    const line = formatSecurityLine({ reason: 'wrong_api_key', surface: 'mcp', ip: '10.0.0.1', at });
    // Exactly one space-separated token per field beyond the timestamp.
    expect(line.split(' ')).toEqual([
      '2026-08-10T12:34:56.789Z',
      'OPENWA-SECURITY',
      'v=1',
      'event=block',
      'reason=wrong_api_key',
      'surface=mcp',
      'ip=10.0.0.1',
    ]);
  });
});

describe('securityLogPath / securityLogDir', () => {
  it('points at the shared data volume under data/logs', () => {
    expect(securityLogDir().endsWith('/data/logs')).toBe(true);
    expect(securityLogPath().endsWith('/data/logs/openwa-security.log')).toBe(true);
  });
});

describe('claim helpers', () => {
  it('are unset by default and settable per request', () => {
    const req = {} as Request;
    expect(isSecurityEventClaimed(req)).toBe(false);
    claimSecurityEvent(req);
    expect(isSecurityEventClaimed(req)).toBe(true);
  });
});

describe('SecurityEventLogService.append', () => {
  let service: SecurityEventLogService;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new SecurityEventLogService();
    // Default: file smaller than the cap → no rotation.
    mockedFs.statSync.mockReturnValue({ size: 1 } as fs.Stats);
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    warnSpy.mockRestore();
    delete process.env.FAIL2BAN_LOG_MAX_BYTES;
  });

  it('appends the formatted line (with a trailing newline) at mode 0644 to the security log', () => {
    service.logWrongApiKey('rest', '203.0.113.9');
    expect(mockedFs.mkdirSync).toHaveBeenCalledWith(securityLogDir(), { recursive: true });
    expect(mockedFs.appendFileSync).toHaveBeenCalledTimes(1);
    const [file, data, opts] = mockedFs.appendFileSync.mock.calls[0];
    expect(file).toBe(securityLogPath());
    expect(String(data)).toMatch(
      /^\d{4}-\d{2}-\d{2}T[\d:.]+Z OPENWA-SECURITY v=1 event=block reason=wrong_api_key surface=rest ip=203\.0\.113\.9\n$/,
    );
    expect(opts).toEqual({ mode: 0o644 });
  });

  it('maps logInvalidRequest to reason=invalid_request', () => {
    service.logInvalidRequest('mcp', '10.0.0.5');
    expect(String(mockedFs.appendFileSync.mock.calls[0][1])).toContain(
      'reason=invalid_request surface=mcp ip=10.0.0.5',
    );
  });

  it('never writes an unactionable line when the IP is empty or whitespace', () => {
    service.logWrongApiKey('rest', undefined);
    service.logWrongApiKey('rest', '');
    service.logInvalidRequest('ws', '   ');
    expect(mockedFs.appendFileSync).not.toHaveBeenCalled();
  });

  it('trims the IP before writing it', () => {
    service.logWrongApiKey('rest', '  203.0.113.9  ');
    expect(String(mockedFs.appendFileSync.mock.calls[0][1])).toContain('ip=203.0.113.9\n');
  });

  it('rotates depth-1 (rm .1, rename current → .1) once the file reaches the cap, then appends fresh', () => {
    process.env.FAIL2BAN_LOG_MAX_BYTES = '100';
    mockedFs.statSync.mockReturnValue({ size: 100 } as fs.Stats); // at the cap
    service.logWrongApiKey('rest', '203.0.113.9');
    expect(mockedFs.rmSync).toHaveBeenCalledWith(`${securityLogPath()}.1`, { force: true });
    expect(mockedFs.renameSync).toHaveBeenCalledWith(securityLogPath(), `${securityLogPath()}.1`);
    expect(mockedFs.appendFileSync).toHaveBeenCalledTimes(1); // the new line still lands after rotation
  });

  it('does not rotate a file below the cap', () => {
    process.env.FAIL2BAN_LOG_MAX_BYTES = '100';
    mockedFs.statSync.mockReturnValue({ size: 99 } as fs.Stats);
    service.logWrongApiKey('rest', '203.0.113.9');
    expect(mockedFs.renameSync).not.toHaveBeenCalled();
  });

  it('is best-effort: a sink write error never throws and warns at most once', () => {
    mockedFs.appendFileSync.mockImplementation(() => {
      throw new Error('EROFS: read-only file system');
    });
    expect(() => service.logWrongApiKey('rest', '203.0.113.9')).not.toThrow();
    expect(() => service.logInvalidRequest('rest', '203.0.113.9')).not.toThrow();
    expect(warnSpy).toHaveBeenCalledTimes(1); // warnedOnce latch
  });
});
