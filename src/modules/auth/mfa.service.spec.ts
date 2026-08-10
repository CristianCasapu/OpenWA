import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { TOTP, Secret } from 'otpauth';
import { MfaService } from './mfa.service';

// Give the service a throwaway data dir for the auto-generated master key file, and pin a known
// MFA_KEY so encryption/signing are deterministic within a test run.
const TEST_MFA_KEY = Buffer.alloc(32, 7).toString('base64');

describe('MfaService', () => {
  let service: MfaService;
  let dir: string;
  const savedEnv = { key: process.env.MFA_KEY, file: process.env.MFA_KEY_FILE, ttl: process.env.MFA_SESSION_TTL_MS };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'owa-mfa-'));
    process.env.MFA_KEY = TEST_MFA_KEY;
    process.env.MFA_KEY_FILE = join(dir, '.mfa-key');
    delete process.env.MFA_SESSION_TTL_MS;
    service = new MfaService();
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    if (savedEnv.key === undefined) delete process.env.MFA_KEY;
    else process.env.MFA_KEY = savedEnv.key;
    if (savedEnv.file === undefined) delete process.env.MFA_KEY_FILE;
    else process.env.MFA_KEY_FILE = savedEnv.file;
    if (savedEnv.ttl === undefined) delete process.env.MFA_SESSION_TTL_MS;
    else process.env.MFA_SESSION_TTL_MS = savedEnv.ttl;
  });

  describe('enrollment', () => {
    it('generates a base32 secret, an otpauth URI, and a PNG data-URL QR', async () => {
      const e = await service.generateEnrollment('My Admin Key');
      expect(e.secret).toMatch(/^[A-Z2-7]+$/); // base32
      expect(e.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
      expect(e.otpauthUri).toContain('issuer=OpenWA');
      expect(e.qrDataUrl).toMatch(/^data:image\/png;base64,/);
    });
  });

  describe('code verification', () => {
    it('accepts the current code for the secret and rejects a wrong one', () => {
      const secret = new Secret({ size: 20 });
      const totp = new TOTP({ issuer: 'OpenWA', secret });
      const good = totp.generate();
      expect(service.verifyCodeAgainstSecret(secret.base32, good)).toBe(true);
      expect(service.verifyCodeAgainstSecret(secret.base32, '000000')).toBe(false);
    });

    it('rejects non-6-digit input without throwing', () => {
      const secret = new Secret({ size: 20 }).base32;
      expect(service.verifyCodeAgainstSecret(secret, 'abcdef')).toBe(false);
      expect(service.verifyCodeAgainstSecret(secret, '12345')).toBe(false);
      expect(service.verifyCodeAgainstSecret(secret, '')).toBe(false);
    });
  });

  describe('secret encryption at rest', () => {
    it('round-trips a secret through encrypt/decrypt', () => {
      const secret = new Secret({ size: 20 }).base32;
      const enc = service.encryptSecret(secret);
      expect(enc.startsWith('v1:')).toBe(true);
      expect(enc).not.toContain(secret); // ciphertext, not plaintext
      expect(service.decryptSecret(enc)).toBe(secret);
    });

    it('fails closed (null) on a tampered ciphertext or a null input', () => {
      const enc = service.encryptSecret(new Secret({ size: 20 }).base32);
      const tampered = enc.slice(0, -4) + 'AAAA';
      expect(service.decryptSecret(tampered)).toBeNull();
      expect(service.decryptSecret(null)).toBeNull();
      expect(service.decryptSecret('not-a-valid-blob')).toBeNull();
    });

    it('verifyCode works end-to-end against the encrypted form', () => {
      const secret = new Secret({ size: 20 });
      const enc = service.encryptSecret(secret.base32);
      const code = new TOTP({ issuer: 'OpenWA', secret }).generate();
      expect(service.verifyCode(enc, code)).toBe(true);
      expect(service.verifyCode(enc, '000000')).toBe(false);
    });
  });

  describe('session tokens', () => {
    it('issues a token that verifies back to the same keyId', () => {
      const { token, expiresAt } = service.issueSessionToken('key-123');
      expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());
      expect(service.verifySessionToken(token)?.keyId).toBe('key-123');
    });

    it('rejects an expired token', () => {
      const now = 1_000_000;
      process.env.MFA_SESSION_TTL_MS = '1000';
      const { token } = service.issueSessionToken('key-123', now);
      expect(service.verifySessionToken(token, now + 500)?.keyId).toBe('key-123');
      expect(service.verifySessionToken(token, now + 2000)).toBeNull();
    });

    it('rejects a tampered signature or payload', () => {
      const { token } = service.issueSessionToken('key-123');
      const [body, sig] = token.split('.');
      expect(service.verifySessionToken(`${body}.${sig.slice(0, -2)}xx`)).toBeNull();
      // Swap the keyId in the payload but keep the old signature → must fail.
      const forged = Buffer.from(JSON.stringify({ k: 'attacker', iat: Date.now(), exp: Date.now() + 10000 }))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      expect(service.verifySessionToken(`${forged}.${sig}`)).toBeNull();
    });

    it('rejects malformed tokens without throwing', () => {
      expect(service.verifySessionToken(undefined)).toBeNull();
      expect(service.verifySessionToken('')).toBeNull();
      expect(service.verifySessionToken('nodot')).toBeNull();
      expect(service.verifySessionToken('.onlysig')).toBeNull();
    });

    it('a token signed under a different MFA_KEY does not verify', () => {
      const { token } = service.issueSessionToken('key-123');
      process.env.MFA_KEY = Buffer.alloc(32, 9).toString('base64'); // different master
      const other = new MfaService();
      expect(other.verifySessionToken(token)).toBeNull();
    });
  });
});
