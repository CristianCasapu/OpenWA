import * as fs from 'fs';
import { randomBytes } from 'crypto';
import { writeSecretFile } from '../common/utils/secret-file';

export interface EnsurePepperResult {
  /** True when a fresh pepper was generated, persisted, and applied to the environment. */
  generated: boolean;
  /** Set when generation was attempted but the file could not be written (see below). */
  persistError?: unknown;
}

/**
 * Ensure a server-side API-key pepper exists, generating and persisting one on first boot.
 *
 * Without a pepper, stored API-key hashes are plain SHA-256, so a database leak alone lets an
 * attacker precompute candidate hashes. Rather than leave the pepper as an advisory the operator
 * must remember to set (and then re-issue every key), we generate a strong one automatically and
 * write it into data/.env.generated (0600), where the next boot reads it back. Existing SHA-256
 * keys are NOT invalidated: validateApiKey verifies against both the peppered and the legacy hash
 * and upgrades a legacy row in place on first use (see hashApiKeyCandidates).
 *
 * Precedence-safe: called AFTER load-env has merged process env / .env / .env.generated, so a
 * pepper supplied by any of those layers is honored and generation is skipped — an operator who
 * manages secrets externally keeps full control.
 *
 * Fail-safe on a read-only data dir: if the pepper cannot be PERSISTED, it is deliberately NOT
 * applied to this process. Starting to hash under a pepper we cannot write back would mean the next
 * boot generates a DIFFERENT one, and every key hashed under the first would then be unreadable —
 * strictly worse than staying on SHA-256 (which the legacy candidate still matches). So a persist
 * failure degrades cleanly to the pre-pepper behavior for that boot.
 */
export function ensureApiKeyPepper(generatedEnvPath: string, env: NodeJS.ProcessEnv = process.env): EnsurePepperResult {
  // Already supplied by a higher layer (host / .env / .env.generated) — nothing to do. A blank value
  // is treated as unset for hashing, but a blank LINE in the file (below) is still respected so a
  // deliberately-blanked pepper is never silently re-armed.
  if (env.API_KEY_PEPPER && env.API_KEY_PEPPER.trim() !== '') {
    return { generated: false };
  }

  const existing = fs.existsSync(generatedEnvPath) ? fs.readFileSync(generatedEnvPath, 'utf8') : '';
  // A present (even blank) key line means the operator chose it — leave it and stay on the SHA-256
  // path for this boot rather than append a second line or override their choice.
  if (/^\s*API_KEY_PEPPER=/m.test(existing)) {
    return { generated: false };
  }

  const pepper = randomBytes(32).toString('hex');
  try {
    const needsNewline = existing.length > 0 && !existing.endsWith('\n');
    const block =
      `${needsNewline ? '\n' : ''}` +
      '# Auto-generated server-side pepper for API-key HMAC hashing. Keep this secret and back it up:\n' +
      '# losing it invalidates every API key. Managed by the app; do not edit by hand.\n' +
      `API_KEY_PEPPER=${pepper}\n`;
    writeSecretFile(generatedEnvPath, existing + block);
  } catch (persistError) {
    // Read-only data dir etc.: do NOT apply an unpersisted pepper (see the doc comment above).
    return { generated: false, persistError };
  }
  env.API_KEY_PEPPER = pepper;
  return { generated: true };
}
