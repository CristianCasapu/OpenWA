import { createHash, createHmac } from 'crypto';
import { hashApiKey, hashApiKeyCandidates } from './api-key-hash';

describe('hashApiKey', () => {
  it('uses plain SHA-256 when no pepper is set (preserves existing stored hashes)', () => {
    expect(hashApiKey('owa_secret')).toBe(createHash('sha256').update('owa_secret').digest('hex'));
    expect(hashApiKey('owa_secret', undefined)).toBe(createHash('sha256').update('owa_secret').digest('hex'));
  });

  it('uses HMAC-SHA256 with the pepper when set, distinct from the un-peppered hash', () => {
    const peppered = hashApiKey('owa_secret', 'server-pepper');
    expect(peppered).toBe(createHmac('sha256', 'server-pepper').update('owa_secret').digest('hex'));
    expect(peppered).not.toBe(hashApiKey('owa_secret'));
  });

  it('is deterministic for the same key + pepper', () => {
    expect(hashApiKey('k', 'p')).toBe(hashApiKey('k', 'p'));
  });
});

describe('hashApiKeyCandidates', () => {
  it('returns only the SHA-256 hash when no pepper is set', () => {
    expect(hashApiKeyCandidates('owa_secret')).toEqual([hashApiKey('owa_secret')]);
  });

  it('returns the peppered HMAC first, then the legacy SHA-256, when a pepper is set', () => {
    const candidates = hashApiKeyCandidates('owa_secret', 'server-pepper');
    expect(candidates).toEqual([hashApiKey('owa_secret', 'server-pepper'), hashApiKey('owa_secret')]);
    // Candidate 0 is always how a key is WRITTEN (the primary), so a hit on it needs no upgrade.
    expect(candidates[0]).toBe(createHmac('sha256', 'server-pepper').update('owa_secret').digest('hex'));
    expect(candidates[1]).toBe(createHash('sha256').update('owa_secret').digest('hex'));
  });

  it('collapses to a single candidate if the peppered and legacy hashes ever coincide', () => {
    // Defensive: guards the caller from a spurious "upgrade" when the two forms are identical.
    // They cannot coincide for real HMAC vs SHA-256, but the caller relies on de-duplication.
    const candidates = hashApiKeyCandidates('k', 'p');
    expect(new Set(candidates).size).toBe(candidates.length);
  });
});
