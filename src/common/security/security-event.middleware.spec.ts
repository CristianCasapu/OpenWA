import type { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { SecurityEventBoundaryMiddleware } from './security-event.middleware';
import { claimSecurityEvent, isSecurityEventClaimed, type SecurityEventLogService } from './security-event-log.service';

interface Harness {
  req: Record<string, unknown>;
  listeners: { finish?: () => void; close?: () => void };
  next: jest.Mock;
  logInvalidRequest: jest.Mock;
}

function run(opts: { statusCode?: number; path?: string; ip?: string; preClaim?: boolean }): Harness {
  const logInvalidRequest = jest.fn();
  const securityLog = { logInvalidRequest, logWrongApiKey: jest.fn() } as unknown as SecurityEventLogService;
  const configService = { get: jest.fn().mockReturnValue([]) } as unknown as ConfigService;
  const middleware = new SecurityEventBoundaryMiddleware(securityLog, configService);

  const ip = opts.ip ?? '203.0.113.9';
  const req: Record<string, unknown> = {
    path: opts.path ?? '/api/sessions',
    ip,
    socket: { remoteAddress: ip },
    headers: {},
  };
  if (opts.preClaim) claimSecurityEvent(req as unknown as Request);

  const listeners: { finish?: () => void; close?: () => void } = {};
  const res = {
    statusCode: opts.statusCode ?? 200,
    on: (event: string, cb: () => void): void => {
      listeners[event as 'finish' | 'close'] = cb;
    },
  } as unknown as Response;

  const next = jest.fn();
  middleware.use(req as unknown as Request, res, next);
  return { req, listeners, next, logInvalidRequest };
}

describe('SecurityEventBoundaryMiddleware', () => {
  it('calls next() immediately (never blocks the chain)', () => {
    const { next } = run({});
    expect(next).toHaveBeenCalledTimes(1);
  });

  it.each([400, 401, 403, 404])('emits one invalid_request line on a %i with the resolved IP', status => {
    const { listeners, logInvalidRequest } = run({ statusCode: status, ip: '198.51.100.7' });
    listeners.finish?.();
    expect(logInvalidRequest).toHaveBeenCalledTimes(1);
    expect(logInvalidRequest).toHaveBeenCalledWith('rest', '198.51.100.7');
  });

  it.each([200, 201, 301, 429, 500])('does not emit on a %i (only 400/401/403/404 are triggers)', status => {
    const { listeners, logInvalidRequest } = run({ statusCode: status });
    listeners.finish?.();
    expect(logInvalidRequest).not.toHaveBeenCalled();
  });

  it('skips a request already claimed by a more specific site (no double-count of a bad-key 401)', () => {
    const { listeners, logInvalidRequest } = run({ statusCode: 401, preClaim: true });
    listeners.finish?.();
    expect(logInvalidRequest).not.toHaveBeenCalled();
  });

  it('claims the request after firing so a finish+close pair emits only once', () => {
    const { req, listeners, logInvalidRequest } = run({ statusCode: 404 });
    listeners.finish?.();
    listeners.close?.();
    expect(logInvalidRequest).toHaveBeenCalledTimes(1);
    expect(isSecurityEventClaimed(req as unknown as Request)).toBe(true);
  });

  it.each(['/api/health', '/api/health/live', '/api/metrics'])(
    'never bans on a probe path (%s) even with a 4xx',
    path => {
      const { listeners, logInvalidRequest } = run({ statusCode: 404, path });
      listeners.finish?.();
      expect(logInvalidRequest).not.toHaveBeenCalled();
    },
  );
});
