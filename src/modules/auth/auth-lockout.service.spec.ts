import { HttpException, HttpStatus } from '@nestjs/common';
import { AuthLockoutService, readAuthLockoutConfig } from './auth-lockout.service';
import { AuditAction } from '../audit/entities/audit-log.entity';

describe('readAuthLockoutConfig', () => {
  it('defaults to enabled with sane thresholds', () => {
    const cfg = readAuthLockoutConfig({});
    expect(cfg).toEqual({ enabled: true, threshold: 10, windowMs: 300_000, blockMs: 900_000, maxKeys: 50_000 });
  });

  it('reads overrides and treats AUTH_LOCKOUT_ENABLED=false as the only disable', () => {
    const cfg = readAuthLockoutConfig({
      AUTH_LOCKOUT_ENABLED: 'false',
      AUTH_LOCKOUT_THRESHOLD: '3',
      AUTH_LOCKOUT_WINDOW_MS: '1000',
      AUTH_LOCKOUT_BLOCK_MS: '2000',
    });
    expect(cfg).toMatchObject({ enabled: false, threshold: 3, windowMs: 1000, blockMs: 2000 });
  });

  it('falls back to the default for a blank, zero, or non-numeric value', () => {
    expect(readAuthLockoutConfig({ AUTH_LOCKOUT_THRESHOLD: '' }).threshold).toBe(10);
    expect(readAuthLockoutConfig({ AUTH_LOCKOUT_THRESHOLD: '0' }).threshold).toBe(10);
    expect(readAuthLockoutConfig({ AUTH_LOCKOUT_WINDOW_MS: 'abc' }).windowMs).toBe(300_000);
    // A blank AUTH_LOCKOUT_ENABLED keeps the default (enabled), not a spurious disable.
    expect(readAuthLockoutConfig({ AUTH_LOCKOUT_ENABLED: '' }).enabled).toBe(true);
  });
});

describe('AuthLockoutService', () => {
  const IP = '203.0.113.7';
  let savedEnv: Record<string, string | undefined>;
  const ENV_KEYS = [
    'AUTH_LOCKOUT_ENABLED',
    'AUTH_LOCKOUT_THRESHOLD',
    'AUTH_LOCKOUT_WINDOW_MS',
    'AUTH_LOCKOUT_BLOCK_MS',
  ];

  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(0);
    savedEnv = {};
    for (const k of ENV_KEYS) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
    // Tight thresholds so the tests are fast and explicit.
    process.env.AUTH_LOCKOUT_THRESHOLD = '3';
    process.env.AUTH_LOCKOUT_WINDOW_MS = '10000';
    process.env.AUTH_LOCKOUT_BLOCK_MS = '60000';
  });
  afterEach(() => {
    jest.useRealTimers();
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
  });

  const expect429 = (fn: () => void): void => {
    let caught: unknown;
    try {
      fn();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(HttpException);
    expect((caught as HttpException).getStatus()).toBe(HttpStatus.TOO_MANY_REQUESTS);
  };

  it('does not block below the threshold', () => {
    const svc = new AuthLockoutService();
    svc.recordFailure(IP);
    svc.recordFailure(IP);
    expect(() => svc.assertNotBlocked(IP)).not.toThrow(); // 2 < 3
  });

  it('blocks with 429 once the threshold is reached, and audits exactly once', () => {
    const audit = { logWarn: jest.fn().mockResolvedValue(null) };
    const svc = new AuthLockoutService(audit as never);

    svc.recordFailure(IP);
    svc.recordFailure(IP);
    svc.recordFailure(IP); // 3rd → blocked
    expect429(() => svc.assertNotBlocked(IP));

    expect(audit.logWarn).toHaveBeenCalledTimes(1);
    expect(audit.logWarn).toHaveBeenCalledWith(AuditAction.API_KEY_LOCKOUT, expect.objectContaining({ ipAddress: IP }));

    // Further failures while blocked do not write another audit row (no flood).
    svc.recordFailure(IP);
    expect(audit.logWarn).toHaveBeenCalledTimes(1);
  });

  it('lifts the block after blockMs elapses', () => {
    const svc = new AuthLockoutService();
    svc.recordFailure(IP);
    svc.recordFailure(IP);
    svc.recordFailure(IP);
    expect429(() => svc.assertNotBlocked(IP));

    jest.setSystemTime(60_001); // past the 60s block
    expect(() => svc.assertNotBlocked(IP)).not.toThrow();
  });

  it('ages out failures older than the window so slow probes never accumulate a block', () => {
    const svc = new AuthLockoutService();
    svc.recordFailure(IP); // t=0
    jest.setSystemTime(6000);
    svc.recordFailure(IP); // t=6s
    jest.setSystemTime(11000); // first failure now outside the 10s window
    svc.recordFailure(IP); // only 2 within the window → still below threshold
    expect(() => svc.assertNotBlocked(IP)).not.toThrow();
  });

  it('a successful auth clears the failure counter', () => {
    const svc = new AuthLockoutService();
    svc.recordFailure(IP);
    svc.recordFailure(IP);
    svc.recordSuccess(IP);
    svc.recordFailure(IP); // counter reset → 1 failure
    expect(() => svc.assertNotBlocked(IP)).not.toThrow();
  });

  it('is a no-op when disabled', () => {
    process.env.AUTH_LOCKOUT_ENABLED = 'false';
    const svc = new AuthLockoutService();
    for (let i = 0; i < 10; i++) svc.recordFailure(IP);
    expect(() => svc.assertNotBlocked(IP)).not.toThrow();
  });

  it('ignores an undefined IP (never throws, never tracks)', () => {
    const svc = new AuthLockoutService();
    expect(() => svc.assertNotBlocked(undefined)).not.toThrow();
    svc.recordFailure(undefined);
    svc.recordSuccess(undefined);
  });

  it('tracks each IP independently', () => {
    const svc = new AuthLockoutService();
    for (let i = 0; i < 3; i++) svc.recordFailure(IP);
    expect429(() => svc.assertNotBlocked(IP));
    expect(() => svc.assertNotBlocked('198.51.100.1')).not.toThrow(); // a different IP is unaffected
  });
});
