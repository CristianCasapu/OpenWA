import { createHash, createHmac } from 'crypto';

/**
 * Hash an API key for storage/lookup. With a server-side pepper (`API_KEY_PEPPER`) set, uses HMAC so
 * a database leak alone can't precompute candidate hashes against a guessed/user-chosen key. Without
 * a pepper it falls back to plain SHA-256 — unchanged behaviour, so existing stored hashes still
 * validate. NOTE: enabling (or changing) the pepper invalidates keys hashed before it was set, so it
 * is a deploy-time choice; rotate/re-issue keys when turning it on.
 */
export function hashApiKey(rawKey: string, pepper?: string): string {
  return pepper
    ? createHmac('sha256', pepper).update(rawKey).digest('hex')
    : createHash('sha256').update(rawKey).digest('hex');
}

/**
 * The hashes a raw key may currently be STORED under, in priority order, for a lookup.
 *
 * With a pepper set, the current format is the HMAC (index 0), but rows created before the pepper
 * existed are still stored as plain SHA-256 (index 1). Returning both lets validateApiKey find a
 * legacy row and transparently upgrade it in place (rehash-on-use), so enabling a pepper never
 * invalidates existing keys. Without a pepper there is only the SHA-256 form. `hashApiKey` remains
 * the single source of truth for how a key is WRITTEN (candidate 0).
 */
export function hashApiKeyCandidates(rawKey: string, pepper?: string): string[] {
  const primary = hashApiKey(rawKey, pepper);
  if (!pepper) return [primary];
  const legacy = hashApiKey(rawKey); // unpeppered SHA-256, how pre-pepper rows were stored
  return legacy === primary ? [primary] : [primary, legacy];
}
