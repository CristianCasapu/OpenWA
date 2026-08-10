import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'crypto';
import * as QRCode from 'qrcode';
import { Secret, TOTP } from 'otpauth';
import { deriveMfaSubkey } from './mfa-key';
import { createLogger } from '../../common/services/logger.service';

const TOTP_ISSUER = 'OpenWA';
const DEFAULT_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h

/** What the enrollment step hands back to the dashboard once, so it can render the QR + manual key. */
export interface MfaEnrollment {
  /** The raw base32 secret — shown ONCE for manual entry; never returned again after this. */
  secret: string;
  /** `otpauth://totp/...` provisioning URI (what the QR encodes). */
  otpauthUri: string;
  /** A `data:image/png;base64,...` QR of the URI, rendered server-side (no dashboard QR lib needed). */
  qrDataUrl: string;
}

interface SessionPayload {
  k: string; // keyId
  iat: number;
  exp: number;
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

/**
 * TOTP (Google Authenticator) two-factor for the dashboard. Attaches to an API key (the principal):
 * generates + encrypts the shared secret, verifies 6-digit codes, and mints/verifies the short-lived
 * post-TOTP dashboard SESSION TOKEN that the guard requires for an MFA-enabled key. Every verify path
 * is fail-safe — a decryption/parse error resolves to "invalid", never a thrown 500 that could take
 * down auth for other keys.
 */
@Injectable()
export class MfaService {
  private readonly logger = createLogger('MfaService');

  private sessionTtlMs(): number {
    const raw = process.env.MFA_SESSION_TTL_MS?.trim();
    if (!raw || !/^\d+$/.test(raw)) return DEFAULT_SESSION_TTL_MS;
    const n = Number(raw);
    return n >= 1 ? n : DEFAULT_SESSION_TTL_MS;
  }

  /** Fresh random TOTP secret + provisioning URI + QR, for the enrollment step. */
  async generateEnrollment(keyName: string): Promise<MfaEnrollment> {
    const secret = new Secret({ size: 20 }); // 160-bit, the RFC 4226 recommendation
    const totp = new TOTP({ issuer: TOTP_ISSUER, label: keyName || 'API key', secret });
    const otpauthUri = totp.toString();
    const qrDataUrl = await QRCode.toDataURL(otpauthUri);
    return { secret: secret.base32, otpauthUri, qrDataUrl };
  }

  /** Verify a 6-digit code against a base32 secret, tolerating ±1 time step for clock skew. */
  verifyCodeAgainstSecret(base32Secret: string, code: string): boolean {
    const cleaned = (code ?? '').replace(/\s+/g, '');
    if (!/^\d{6}$/.test(cleaned)) return false;
    try {
      const totp = new TOTP({ issuer: TOTP_ISSUER, secret: Secret.fromBase32(base32Secret) });
      return totp.validate({ token: cleaned, window: 1 }) !== null;
    } catch {
      return false;
    }
  }

  /** Verify a code against the key's ENCRYPTED stored secret. Returns false on any decrypt/parse error. */
  verifyCode(encryptedSecret: string | null | undefined, code: string): boolean {
    const base32 = this.decryptSecret(encryptedSecret);
    if (!base32) return false;
    return this.verifyCodeAgainstSecret(base32, code);
  }

  // ── secret encryption at rest (AES-256-GCM) ───────────────────────────────
  // Stored form: `v1:<ivB64>:<tagB64>:<ciphertextB64>`. Recoverable (unlike the API-key HMAC) because
  // the raw base32 must be re-read to recompute the current OTP.

  encryptSecret(base32Secret: string): string {
    const key = deriveMfaSubkey('enc');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(base32Secret, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
  }

  decryptSecret(stored: string | null | undefined): string | null {
    if (!stored) return null;
    try {
      const [version, ivB64, tagB64, dataB64] = stored.split(':');
      if (version !== 'v1' || !ivB64 || !tagB64 || !dataB64) return null;
      const key = deriveMfaSubkey('enc');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
      decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
      return plaintext.toString('utf8');
    } catch (err) {
      // A wrong/rotated MFA_KEY, or tampered ciphertext, lands here. Treat as "no usable secret" so the
      // user is prompted to re-enroll rather than the process 500ing.
      this.logger.warn('Could not decrypt a stored MFA secret (wrong MFA_KEY or corrupted value?)', {
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    }
  }

  // ── post-TOTP dashboard session token (HMAC-signed, stateless) ────────────

  /** Mint a short-lived session token binding this key id, signed with the `sess` subkey. */
  issueSessionToken(keyId: string, now: number = Date.now()): { token: string; expiresAt: string } {
    const exp = now + this.sessionTtlMs();
    const payload: SessionPayload = { k: keyId, iat: now, exp };
    const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
    const sig = b64url(this.sign(body));
    return { token: `${body}.${sig}`, expiresAt: new Date(exp).toISOString() };
  }

  /** Verify a session token: signature + not-expired. Returns the bound keyId, or null. */
  verifySessionToken(token: string | undefined | null, now: number = Date.now()): { keyId: string } | null {
    if (!token || typeof token !== 'string') return null;
    const dot = token.indexOf('.');
    if (dot <= 0) return null;
    const body = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    try {
      const expected = this.sign(body);
      const provided = fromB64url(sig);
      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
      const payload = JSON.parse(fromB64url(body).toString('utf8')) as SessionPayload;
      if (typeof payload.k !== 'string' || typeof payload.exp !== 'number') return null;
      if (payload.exp <= now) return null;
      return { keyId: payload.k };
    } catch {
      return null;
    }
  }

  private sign(body: string): Buffer {
    return createHmac('sha256', deriveMfaSubkey('sess')).update(body).digest();
  }
}
