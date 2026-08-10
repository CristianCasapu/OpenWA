import { HttpException, HttpStatus, Injectable, Optional } from '@nestjs/common';
import { AuditService } from '../audit/audit.service';
import { AuditAction } from '../audit/entities/audit-log.entity';
import { createLogger } from '../../common/services/logger.service';

const DEFAULT_ENABLED = true;
const DEFAULT_THRESHOLD = 10;
const DEFAULT_WINDOW_MS = 300_000; // 5 minutes
const DEFAULT_BLOCK_MS = 900_000; // 15 minutes
const DEFAULT_MAX_KEYS = 50_000;

export interface AuthLockoutConfig {
  enabled: boolean;
  /** Failed attempts within `windowMs` from one IP that trigger a block. */
  threshold: number;
  windowMs: number;
  /** How long an IP stays blocked once the threshold is crossed. */
  blockMs: number;
  /** LRU cap on tracked IPs so a spoofed-source flood cannot grow memory without bound. */
  maxKeys: number;
}

const parsePositiveInt = (raw: string | undefined, fallback: number): number => {
  if (!raw || raw.trim() === '') return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  const i = Math.floor(n);
  return i >= 1 ? i : fallback;
};

/**
 * Read the lockout configuration from the environment. Falls back to the default for any missing,
 * blank, non-positive, or non-numeric value (same rule as the WS/MCP limiters). Enabled by default:
 * API keys are 256-bit random and never typed, so a legitimate client essentially never presents a
 * wrong key — a burst of unknown keys from one IP is abuse, and the threshold is generous enough
 * that a shared-NAT hiccup cannot trip it.
 */
export function readAuthLockoutConfig(env: NodeJS.ProcessEnv = process.env): AuthLockoutConfig {
  const enabledRaw = env['AUTH_LOCKOUT_ENABLED']?.trim();
  return {
    enabled: enabledRaw ? enabledRaw !== 'false' : DEFAULT_ENABLED,
    threshold: parsePositiveInt(env['AUTH_LOCKOUT_THRESHOLD'], DEFAULT_THRESHOLD),
    windowMs: parsePositiveInt(env['AUTH_LOCKOUT_WINDOW_MS'], DEFAULT_WINDOW_MS),
    blockMs: parsePositiveInt(env['AUTH_LOCKOUT_BLOCK_MS'], DEFAULT_BLOCK_MS),
    maxKeys: parsePositiveInt(env['AUTH_LOCKOUT_MAX_KEYS'], DEFAULT_MAX_KEYS),
  };
}

interface Entry {
  /** Timestamps of failed attempts still inside the sliding window. */
  fails: number[];
  /** Epoch ms until which the IP is blocked, or 0 when not blocked. */
  blockedUntil: number;
}

/**
 * Per-client-IP brute-force lockout for API-key validation.
 *
 * The global throttler bounds request RATE per IP, but a distributed guesser staying under that
 * limit is otherwise unbounded. This adds a failure-count lockout: after `threshold` unknown-key
 * attempts from one IP within `windowMs`, that IP is rejected with 429 for `blockMs`, before the
 * hash lookup even runs. A successful auth clears the IP's counter.
 *
 * Keyed on the resolved client IP (the same trusted-proxy/Cloudflare-aware value the throttler and
 * allowedIps use), so behind a proxy the lockout targets the real attacker, not the edge.
 *
 * In-memory per process, like the WS and MCP limiters (move to a shared store for multi-instance);
 * a single node still bounds a probe hitting it, and the LRU cap keeps a spoofed-source flood from
 * growing memory. Every path is fail-safe: only `assertNotBlocked` ever throws, and only the
 * intended 429 — a bookkeeping error can never turn into an auth outage.
 */
@Injectable()
export class AuthLockoutService {
  private readonly logger = createLogger('AuthLockout');
  private readonly config: AuthLockoutConfig;
  private readonly entries = new Map<string, Entry>();

  // Single injectable dependency so Nest can construct it; the config is read from the environment
  // at construction (like the WS limiters). Tests drive time with jest fake timers and set the
  // AUTH_LOCKOUT_* env before constructing, so no clock/config constructor seam is needed.
  constructor(@Optional() private readonly auditService?: AuditService) {
    this.config = readAuthLockoutConfig();
  }

  private now(): number {
    return Date.now();
  }

  /** Throw 429 when the IP is currently locked out. No-op when disabled or the IP is unknown. */
  assertNotBlocked(ip: string | undefined): void {
    if (!this.config.enabled || !ip) return;
    const entry = this.entries.get(ip);
    if (entry && entry.blockedUntil > this.now()) {
      const retryAfterMs = entry.blockedUntil - this.now();
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: 'Too many failed authentication attempts; try again later',
          retryAfterMs,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  /** Record one failed (unknown-key) attempt; blocks the IP once it crosses the threshold. */
  recordFailure(ip: string | undefined): void {
    if (!this.config.enabled || !ip) return;
    const t = this.now();
    const entry = this.entries.get(ip) ?? { fails: [], blockedUntil: 0 };
    entry.fails = entry.fails.filter(ts => t - ts < this.config.windowMs);
    entry.fails.push(t);

    let justBlocked = false;
    if (entry.fails.length >= this.config.threshold && entry.blockedUntil <= t) {
      entry.blockedUntil = t + this.config.blockMs;
      justBlocked = true;
    }
    this.touch(ip, entry);
    if (justBlocked) this.onBlock(ip);
  }

  /** Clear an IP's failure state after a successful authentication. */
  recordSuccess(ip: string | undefined): void {
    if (!ip) return;
    this.entries.delete(ip);
  }

  private onBlock(ip: string): void {
    this.logger.warn(`Client IP locked out after ${this.config.threshold} failed auth attempts`, {
      ipAddress: ip,
      action: 'api_key_lockout',
      blockMs: this.config.blockMs,
    });
    // Audit once per block (the subsequent 429s do not write), so a probe never floods the log.
    void this.auditService?.logWarn(AuditAction.API_KEY_LOCKOUT, {
      ipAddress: ip,
      metadata: { threshold: this.config.threshold, windowMs: this.config.windowMs, blockMs: this.config.blockMs },
    });
  }

  /** Move `ip` to the LRU tail and evict overflow so an active abuser cannot be evicted for a reset. */
  private touch(ip: string, entry: Entry): void {
    this.entries.delete(ip);
    this.entries.set(ip, entry);
    while (this.entries.size > Math.max(1, this.config.maxKeys)) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }
}
