import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { hkdfSync, randomBytes } from 'crypto';
import { writeSecretFile } from '../../common/utils/secret-file';

/**
 * The server-side master secret behind the 2FA feature. It does TWO jobs, via two derived subkeys:
 *   - `enc`  — AES-256-GCM encryption of each key's stored TOTP secret (`ApiKey.mfaSecret`).
 *   - `sess` — HMAC-SHA256 signing of the short-lived post-TOTP dashboard session tokens.
 *
 * Resolution (mirrors `bootstrap-key-file.ts` / `API_KEY_PEPPER` conventions):
 *   1. `MFA_KEY` env — 32 bytes as base64 or hex. Set this on MULTI-NODE deployments so every node
 *      derives the same subkeys (a per-node file would make one node's session tokens unverifiable on
 *      another). A malformed value is rejected loudly rather than silently downgraded.
 *   2. Otherwise `data/.mfa-key` (honouring `MFA_KEY_FILE`) — auto-created 0600 with 32 random bytes
 *      on first use. Zero-config for the single-machine deployment this project targets.
 *
 * Resolved per call (not cached at import) so tests and an e2e boot that redirect the data dir get a
 * throwaway key, exactly like `bootstrapKeyFilePath()`.
 */
export function mfaKeyFilePath(): string {
  return process.env.MFA_KEY_FILE || join(process.cwd(), 'data', '.mfa-key');
}

function parseEnvKey(raw: string): Buffer {
  const trimmed = raw.trim();
  // Accept base64 (default) or hex; both must decode to exactly 32 bytes.
  const asHex = /^[0-9a-fA-F]{64}$/.test(trimmed) ? Buffer.from(trimmed, 'hex') : null;
  const buf = asHex ?? Buffer.from(trimmed, 'base64');
  if (buf.length !== 32) {
    throw new Error(
      `MFA_KEY must decode to exactly 32 bytes (got ${buf.length}); provide 32 random bytes as base64 or hex`,
    );
  }
  return buf;
}

/** The raw 32-byte master secret (env override, else the auto-created data-volume file). */
export function resolveMfaMasterKey(): Buffer {
  const fromEnv = process.env.MFA_KEY?.trim();
  if (fromEnv) return parseEnvKey(fromEnv);

  const file = mfaKeyFilePath();
  if (existsSync(file)) {
    const contents = readFileSync(file, 'utf-8').trim();
    if (contents) return parseEnvKey(contents);
  }
  // First use on this host: generate + persist a random key, owner-only.
  const key = randomBytes(32);
  writeSecretFile(file, key.toString('base64'));
  return key;
}

/** Domain-separated 32-byte subkeys derived from the master via HKDF-SHA256. */
export function deriveMfaSubkey(purpose: 'enc' | 'sess'): Buffer {
  const master = resolveMfaMasterKey();
  // Empty salt is fine: the master is already a high-entropy random key, and the `info` label is what
  // separates the two purposes so the enc key and the signing key can never coincide.
  return Buffer.from(hkdfSync('sha256', master, Buffer.alloc(0), `openwa-mfa-${purpose}`, 32));
}
