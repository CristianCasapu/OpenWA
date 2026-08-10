import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { TOTP, Secret } from 'otpauth';
import { AuthMfaController } from './auth-mfa.controller';
import { MfaService } from './mfa.service';
import { AuthService } from './auth.service';
import { AuditService } from '../audit/audit.service';
import { AuditAction } from '../audit/entities/audit-log.entity';
import { ApiKey, ApiKeyRole } from './entities/api-key.entity';
import type { Request } from 'express';

function mockKey(overrides: Partial<ApiKey> = {}): ApiKey {
  return {
    id: 'key-1',
    name: 'Admin',
    keyHash: 'h',
    keyPrefix: 'p',
    role: ApiKeyRole.ADMIN,
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

const req = { clientIp: '203.0.113.5' } as unknown as Request;

describe('AuthMfaController', () => {
  let controller: AuthMfaController;
  let mfa: MfaService;
  let authService: jest.Mocked<Pick<AuthService, 'findKeyById' | 'setMfaSecret' | 'enableMfa' | 'disableMfa'>>;
  let audit: jest.Mocked<Pick<AuditService, 'logInfo' | 'logWarn'>>;
  let dir: string;
  const saved = { key: process.env.MFA_KEY, file: process.env.MFA_KEY_FILE };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'owa-mfa-c-'));
    process.env.MFA_KEY = Buffer.alloc(32, 3).toString('base64');
    process.env.MFA_KEY_FILE = join(dir, '.mfa-key');
    mfa = new MfaService();
    authService = {
      findKeyById: jest.fn(),
      setMfaSecret: jest.fn().mockResolvedValue(undefined),
      enableMfa: jest.fn().mockResolvedValue(undefined),
      disableMfa: jest.fn().mockResolvedValue(undefined),
    };
    audit = { logInfo: jest.fn().mockResolvedValue(null), logWarn: jest.fn().mockResolvedValue(null) };
    controller = new AuthMfaController(authService as unknown as AuthService, mfa, audit as unknown as AuditService);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (saved.key === undefined) delete process.env.MFA_KEY;
    else process.env.MFA_KEY = saved.key;
    if (saved.file === undefined) delete process.env.MFA_KEY_FILE;
    else process.env.MFA_KEY_FILE = saved.file;
  });

  /** A base32 secret + its current valid code, and the encrypted column value the guard would attach. */
  function enrolledSecret() {
    const secret = new Secret({ size: 20 });
    return {
      base32: secret.base32,
      code: new TOTP({ issuer: 'OpenWA', secret }).generate(),
      encrypted: mfa.encryptSecret(secret.base32),
    };
  }

  describe('status', () => {
    it('reflects the key mfaEnabled flag', () => {
      expect(controller.getStatus(mockKey({ mfaEnabled: false })).enabled).toBe(false);
      expect(controller.getStatus(mockKey({ mfaEnabled: true })).enabled).toBe(true);
    });
  });

  describe('setup', () => {
    it('generates + stores an (un-confirmed) secret and returns the QR', async () => {
      const out = await controller.setup(mockKey());
      expect(out.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
      expect(out.qrDataUrl).toMatch(/^data:image\/png/);
      expect(out.secret).toMatch(/^[A-Z2-7]+$/);
      expect(authService.setMfaSecret).toHaveBeenCalledWith('key-1', expect.stringMatching(/^v1:/));
    });

    it('refuses (409) when 2FA is already enabled', async () => {
      await expect(controller.setup(mockKey({ mfaEnabled: true }))).rejects.toBeInstanceOf(ConflictException);
      expect(authService.setMfaSecret).not.toHaveBeenCalled();
    });
  });

  describe('enable', () => {
    it('confirms a valid code, enables 2FA, audits MFA_ENROLLED, and returns a session token', async () => {
      const s = enrolledSecret();
      authService.findKeyById.mockResolvedValue(mockKey({ mfaSecret: s.encrypted }));
      const out = await controller.enable(mockKey(), { code: s.code }, req);
      expect(authService.enableMfa).toHaveBeenCalledWith('key-1');
      expect(audit.logInfo).toHaveBeenCalledWith(AuditAction.MFA_ENROLLED, expect.any(Object));
      expect(mfa.verifySessionToken(out.sessionToken)?.keyId).toBe('key-1');
    });

    it('rejects a wrong code (401) and audits MFA_FAILED, without enabling', async () => {
      const s = enrolledSecret();
      authService.findKeyById.mockResolvedValue(mockKey({ mfaSecret: s.encrypted }));
      await expect(controller.enable(mockKey(), { code: '000000' }, req)).rejects.toBeInstanceOf(UnauthorizedException);
      expect(authService.enableMfa).not.toHaveBeenCalled();
      expect(audit.logWarn).toHaveBeenCalledWith(AuditAction.MFA_FAILED, expect.any(Object));
    });
  });

  describe('disable', () => {
    it('disables with a valid current code and audits MFA_DISABLED', async () => {
      const s = enrolledSecret();
      await controller.disable(mockKey({ mfaEnabled: true, mfaSecret: s.encrypted }), { code: s.code }, req);
      expect(authService.disableMfa).toHaveBeenCalledWith('key-1');
      expect(audit.logInfo).toHaveBeenCalledWith(AuditAction.MFA_DISABLED, expect.any(Object));
    });

    it('rejects a wrong code (401), leaving 2FA on', async () => {
      const s = enrolledSecret();
      await expect(
        controller.disable(mockKey({ mfaEnabled: true, mfaSecret: s.encrypted }), { code: '111111' }, req),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      expect(authService.disableMfa).not.toHaveBeenCalled();
    });
  });

  describe('session', () => {
    it('mints a session token for a valid code and audits MFA_VERIFIED', () => {
      const s = enrolledSecret();
      const out = controller.session(mockKey({ mfaEnabled: true, mfaSecret: s.encrypted }), { code: s.code }, req);
      expect(mfa.verifySessionToken(out.sessionToken)?.keyId).toBe('key-1');
      expect(audit.logInfo).toHaveBeenCalledWith(AuditAction.MFA_VERIFIED, expect.any(Object));
    });

    it('rejects a wrong code (401) and audits MFA_FAILED', () => {
      const s = enrolledSecret();
      expect(() =>
        controller.session(mockKey({ mfaEnabled: true, mfaSecret: s.encrypted }), { code: '222222' }, req),
      ).toThrow(UnauthorizedException);
      expect(audit.logWarn).toHaveBeenCalledWith(AuditAction.MFA_FAILED, expect.any(Object));
    });
  });
});
