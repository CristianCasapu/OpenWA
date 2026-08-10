import { ExecutionContext, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ApiKeyGuard } from './api-key.guard';
import { AuthService } from '../auth.service';
import { ApiKey, ApiKeyRole } from '../entities/api-key.entity';
import { AuditService } from '../../audit/audit.service';
import { AuditAction } from '../../audit/entities/audit-log.entity';
import { SecurityEventLogService } from '../../../common/security/security-event-log.service';
import { MfaService } from '../mfa.service';

function createMockApiKey(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 'uuid-1',
    name: 'Test Key',
    keyHash: 'hash',
    keyPrefix: 'owa_k1_xxxx',
    role: ApiKeyRole.OPERATOR,
    allowedIps: null,
    allowedSessions: null,
    isActive: true,
    expiresAt: null,
    lastUsedAt: null,
    usageCount: 0,
    mfaEnabled: false,
    mfaSecret: null,
    mfaEnrolledAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

function createMockContext(
  headers: Record<string, string> = {},
  params: Record<string, string> = {},
  socketIp = '127.0.0.1',
): ExecutionContext {
  const request = {
    headers,
    params,
    ip: socketIp,
    socket: { remoteAddress: socketIp },
  };

  return {
    switchToHttp: () => ({
      getRequest: () => request,
    }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as unknown as ExecutionContext;
}

describe('ApiKeyGuard', () => {
  let guard: ApiKeyGuard;
  let authService: jest.Mocked<Partial<AuthService>>;
  let reflector: jest.Mocked<Reflector>;
  let configService: jest.Mocked<Partial<ConfigService>>;
  let auditService: jest.Mocked<Partial<AuditService>>;
  let securityLog: jest.Mocked<Pick<SecurityEventLogService, 'logWrongApiKey' | 'logInvalidRequest'>>;
  let mfaService: jest.Mocked<Pick<MfaService, 'verifySessionToken'>>;

  function buildGuard(trustedProxies: string[] = []): ApiKeyGuard {
    configService = {
      get: jest.fn().mockReturnValue(trustedProxies),
    };
    return new ApiKeyGuard(
      authService as AuthService,
      reflector,
      configService as ConfigService,
      auditService as AuditService,
      securityLog as unknown as SecurityEventLogService,
      mfaService as unknown as MfaService,
    );
  }

  beforeEach(() => {
    authService = {
      validateApiKey: jest.fn(),
      hasPermission: jest.fn(),
    };

    reflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    auditService = {
      logWarn: jest.fn().mockResolvedValue(null),
    };

    securityLog = {
      logWrongApiKey: jest.fn(),
      logInvalidRequest: jest.fn(),
    };

    mfaService = {
      verifySessionToken: jest.fn().mockReturnValue(null),
    };

    guard = buildGuard();
  });

  it('should allow access to @Public() routes without API key', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(true); // isPublic = true

    const context = createMockContext();
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).not.toHaveBeenCalled();
  });

  it('should reject requests without X-API-Key header', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false); // not public

    const context = createMockContext({});

    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    await expect(guard.canActivate(context)).rejects.toThrow('API key is required');
  });

  it('should accept X-API-Key header', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(undefined); // no required role

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'my-key' });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).toHaveBeenCalledWith('my-key', '127.0.0.1', undefined);
  });

  it('should accept Authorization Bearer header', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ authorization: 'Bearer my-bearer-key' });
    const result = await guard.canActivate(context);

    expect(result).toBe(true);
    expect(authService.validateApiKey).toHaveBeenCalledWith('my-bearer-key', '127.0.0.1', undefined);
  });

  describe('two-factor (MFA) enforcement', () => {
    const mfaReq = async (headers: Record<string, string>): Promise<unknown> => {
      const context = createMockContext(headers);
      return guard.canActivate(context).catch((e: unknown) => e);
    };

    it('rejects an MFA-enabled key presented as a plain bearer (401 MFA_REQUIRED)', async () => {
      reflector.getAllAndOverride.mockReturnValue(undefined); // not public/role/scoped/exempt
      (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey({ id: 'kid', mfaEnabled: true }));

      const err = await mfaReq({ 'x-api-key': 'k' });
      expect(err).toBeInstanceOf(UnauthorizedException);
      expect((err as UnauthorizedException).getResponse()).toMatchObject({ code: 'MFA_REQUIRED' });
      expect(mfaService.verifySessionToken).toHaveBeenCalled();
    });

    it('accepts an MFA-enabled key with a valid session token for that key', async () => {
      reflector.getAllAndOverride.mockReturnValue(undefined);
      (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey({ id: 'kid', mfaEnabled: true }));
      mfaService.verifySessionToken.mockReturnValue({ keyId: 'kid' });

      const result = await guard.canActivate(createMockContext({ 'x-api-key': 'k', 'x-dashboard-session': 'tok' }));
      expect(result).toBe(true);
    });

    it('rejects when the session token belongs to a DIFFERENT key', async () => {
      reflector.getAllAndOverride.mockReturnValue(undefined);
      (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey({ id: 'kid', mfaEnabled: true }));
      mfaService.verifySessionToken.mockReturnValue({ keyId: 'someone-else' });

      const err = await mfaReq({ 'x-api-key': 'k', 'x-dashboard-session': 'tok' });
      expect((err as UnauthorizedException).getResponse()).toMatchObject({ code: 'MFA_REQUIRED' });
    });

    it('bypasses the session check on an @MfaExempt() route (so an enrolled key can obtain a session)', async () => {
      reflector.getAllAndOverride.mockImplementation((key: unknown) => (key === 'mfaExempt' ? true : undefined));
      (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey({ mfaEnabled: true }));

      const result = await guard.canActivate(createMockContext({ 'x-api-key': 'k' })); // no session header
      expect(result).toBe(true);
      expect(mfaService.verifySessionToken).not.toHaveBeenCalled();
    });

    it('never requires a session for a key without MFA', async () => {
      reflector.getAllAndOverride.mockReturnValue(undefined);
      (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey({ mfaEnabled: false }));

      const result = await guard.canActivate(createMockContext({ 'x-api-key': 'k' }));
      expect(result).toBe(true);
      expect(mfaService.verifySessionToken).not.toHaveBeenCalled();
    });
  });

  it('should reject when API key validation fails', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false);

    (authService.validateApiKey as jest.Mock).mockRejectedValue(new UnauthorizedException('Invalid API key'));

    const context = createMockContext({ 'x-api-key': 'bad-key' });

    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API key');
  });

  it('records an API_KEY_AUTH_FAILED audit event when a key is rejected (with ip + reason)', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false); // not public
    (authService.validateApiKey as jest.Mock).mockRejectedValue(new UnauthorizedException('Invalid API key'));

    const context = createMockContext({ 'x-api-key': 'bad-key' }, {}, '203.0.113.9');
    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API key');
    await new Promise(resolve => setImmediate(resolve)); // let the fire-and-forget audit write settle

    expect(auditService.logWarn).toHaveBeenCalledWith(
      AuditAction.API_KEY_AUTH_FAILED,
      expect.objectContaining({ ipAddress: '203.0.113.9', errorMessage: 'Invalid API key' }),
    );
  });

  it('emits a wrong_api_key security line (for fail2ban) with the resolved IP when a key is rejected', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false); // not public
    (authService.validateApiKey as jest.Mock).mockRejectedValue(new UnauthorizedException('Invalid API key'));

    const context = createMockContext({ 'x-api-key': 'bad-key' }, {}, '203.0.113.9');
    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API key');

    expect(securityLog.logWrongApiKey).toHaveBeenCalledWith('rest', '203.0.113.9');
    // The specific line is emitted; the generic invalid_request one is left to the boundary observer,
    // which the per-request claim then suppresses.
    expect(securityLog.logInvalidRequest).not.toHaveBeenCalled();
  });

  it('records an audit event when a missing key is rejected', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false);

    const context = createMockContext({}); // no key
    await expect(guard.canActivate(context)).rejects.toThrow(UnauthorizedException);
    await new Promise(resolve => setImmediate(resolve));

    expect(auditService.logWarn).toHaveBeenCalledWith(AuditAction.API_KEY_AUTH_FAILED, expect.any(Object));
  });

  it('does not record an audit event or a security line on a successful authorization', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);
    (authService.validateApiKey as jest.Mock).mockResolvedValue(createMockApiKey());

    const context = createMockContext({ 'x-api-key': 'good-key' });
    await guard.canActivate(context);
    await new Promise(resolve => setImmediate(resolve));

    expect(auditService.logWarn).not.toHaveBeenCalled();
    expect(securityLog.logWrongApiKey).not.toHaveBeenCalled();
  });

  it('should reject when role permission is insufficient', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(ApiKeyRole.ADMIN); // required role = ADMIN

    const apiKey = createMockApiKey({ role: ApiKeyRole.VIEWER });
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);
    (authService.hasPermission as jest.Mock).mockReturnValue(false);

    const context = createMockContext({ 'x-api-key': 'viewer-key' });

    await expect(guard.canActivate(context)).rejects.toThrow(ForbiddenException);
  });

  it('rejects a session-scoped key on a @RequireUnscopedKey route, whatever its role', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(ApiKeyRole.ADMIN) // required role = ADMIN
      .mockReturnValueOnce(undefined) // not @SessionScoped
      .mockReturnValueOnce(true); // @RequireUnscopedKey

    const apiKey = createMockApiKey({ role: ApiKeyRole.ADMIN, allowedSessions: ['sess-A'] });
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);
    (authService.hasPermission as jest.Mock).mockReturnValue(true);

    const context = createMockContext({ 'x-api-key': 'scoped-admin-key' }, {}, '203.0.113.44');

    await expect(guard.canActivate(context)).rejects.toThrow('Session-scoped API keys are not permitted on this route');
    await new Promise(resolve => setImmediate(resolve)); // let the fire-and-forget audit write settle
    expect(auditService.logWarn).toHaveBeenCalledWith(
      AuditAction.API_KEY_AUTH_FAILED,
      expect.objectContaining({ ipAddress: '203.0.113.44' }),
    );
  });

  it('admits an unrestricted key on a @RequireUnscopedKey route', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(ApiKeyRole.ADMIN) // required role = ADMIN
      .mockReturnValueOnce(undefined) // not @SessionScoped
      .mockReturnValueOnce(true); // @RequireUnscopedKey

    const apiKey = createMockApiKey({ role: ApiKeyRole.ADMIN, allowedSessions: null });
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);
    (authService.hasPermission as jest.Mock).mockReturnValue(true);

    const context = createMockContext({ 'x-api-key': 'admin-key' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('admits a session-scoped key on routes WITHOUT the @RequireUnscopedKey marker', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(undefined) // no required role
      .mockReturnValueOnce(undefined) // not @SessionScoped
      .mockReturnValueOnce(undefined); // not @RequireUnscopedKey

    const apiKey = createMockApiKey({ allowedSessions: ['sess-A'] });
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'scoped-key' });

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('should pass session ID from route params to validateApiKey', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'key' }, { sessionId: 'sess-123' });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', 'sess-123');
  });

  it('does not treat a non-session route :id as a session id (no @SessionScoped)', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(undefined) // no required role
      .mockReturnValueOnce(undefined); // controller is NOT @SessionScoped

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    // e.g. GET /plugins/:id or /auth/api-keys/:id — :id is a plugin/key id, not a session.
    const context = createMockContext({ 'x-api-key': 'key' }, { id: 'plugin-x' });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', undefined);
  });

  it('treats :id as the session id on a @SessionScoped controller (session scoping preserved)', async () => {
    reflector.getAllAndOverride
      .mockReturnValueOnce(false) // not public
      .mockReturnValueOnce(undefined) // no required role
      .mockReturnValueOnce(true); // controller IS @SessionScoped (SessionController)

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    // GET /sessions/:id/... — :id IS the session, so allowedSessions must still be enforced.
    const context = createMockContext({ 'x-api-key': 'key' }, { id: 'sess-B' });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', 'sess-B');
  });

  it('ignores X-Forwarded-For by default (no trusted proxies) to prevent IP spoofing', async () => {
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    // Attacker forges X-Forwarded-For; the direct socket IP must win.
    const context = createMockContext({
      'x-api-key': 'key',
      'x-forwarded-for': '203.0.113.50, 70.41.3.18',
    });
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '127.0.0.1', undefined);
  });

  it('uses the rightmost untrusted hop when the request comes from a trusted proxy', async () => {
    guard = buildGuard(['10.0.0.0/8']);
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    // Direct peer 10.0.0.1 is a trusted proxy; XFF = [real client, inner proxy].
    const context = createMockContext(
      { 'x-api-key': 'key', 'x-forwarded-for': '203.0.113.50, 10.0.0.5' },
      {},
      '10.0.0.1',
    );
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '203.0.113.50', undefined);
  });

  it('ignores X-Forwarded-For when the direct peer is not a trusted proxy', async () => {
    guard = buildGuard(['10.0.0.0/8']);
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    // Attacker connects directly (203.0.113.99) and forges a trusted-looking XFF.
    const context = createMockContext({ 'x-api-key': 'key', 'x-forwarded-for': '10.0.0.5' }, {}, '203.0.113.99');
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '203.0.113.99', undefined);
  });

  it('normalizes an IPv4-mapped IPv6 proxy address (e.g. ::ffff:10.0.0.1)', async () => {
    guard = buildGuard(['10.0.0.0/8']);
    reflector.getAllAndOverride.mockReturnValueOnce(false).mockReturnValueOnce(undefined);

    const apiKey = createMockApiKey();
    (authService.validateApiKey as jest.Mock).mockResolvedValue(apiKey);

    const context = createMockContext({ 'x-api-key': 'key', 'x-forwarded-for': '203.0.113.50' }, {}, '::ffff:10.0.0.1');
    await guard.canActivate(context);

    expect(authService.validateApiKey).toHaveBeenCalledWith('key', '203.0.113.50', undefined);
  });
});
