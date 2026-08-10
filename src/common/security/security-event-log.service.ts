import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import type { Request } from 'express';

/** Which surface a security event came from. */
export type SecuritySurface = 'rest' | 'ws' | 'mcp';
/** Coarse reason code — never a raw key, secret, path, or message. */
export type SecurityReason = 'wrong_api_key' | 'invalid_request';

/** The fixed anchor token every security line carries, and the format version. */
export const SECURITY_LINE_TAG = 'OPENWA-SECURITY';
export const SECURITY_LINE_VERSION = 1;

/**
 * The dedicated security-event log file: `data/logs/openwa-security.log`. Separate from the app's
 * stdout log so fail2ban greps a clean, format-stable anchor, and readable (0644) by the host
 * fail2ban process — the file carries only an IP + a coarse reason, no secrets. Derived like
 * `generatedEnvPath()` so it lands on the shared data volume.
 */
export function securityLogDir(): string {
  return path.resolve(process.cwd(), 'data', 'logs');
}
export function securityLogPath(): string {
  return path.join(securityLogDir(), 'openwa-security.log');
}

/**
 * Render one stable, single-line security event. This is the SINGLE source of truth for the line
 * format — the fail2ban `failregex` (generated in the fail2ban config service) is written against
 * exactly this shape, and a drift test asserts the two still match. Deliberately minimal: an
 * ISO-8601 UTC timestamp (so fail2ban's date detection works), the fixed tag + version, the coarse
 * reason, the surface, and the client IP. Never the key, secret, path, or user input.
 */
export function formatSecurityLine(entry: {
  reason: SecurityReason;
  surface: SecuritySurface;
  ip: string;
  at: Date;
}): string {
  return (
    `${entry.at.toISOString()} ${SECURITY_LINE_TAG} v=${SECURITY_LINE_VERSION} ` +
    `event=block reason=${entry.reason} surface=${entry.surface} ip=${entry.ip}`
  );
}

/**
 * Per-request marker: the REST guard sets it when it emits the specific `wrong_api_key` line, so the
 * HTTP boundary observer does not ALSO emit a generic `invalid_request` line for the same rejected
 * response — exactly one security line per request, tagged with the most specific reason (otherwise
 * a single bad-key 401 would count twice toward fail2ban's maxretry).
 */
export const SECURITY_EVENT_CLAIMED = Symbol('openwa.securityEventClaimed');
type ClaimableRequest = Request & { [SECURITY_EVENT_CLAIMED]?: boolean };

export function claimSecurityEvent(req: Request): void {
  (req as ClaimableRequest)[SECURITY_EVENT_CLAIMED] = true;
}
export function isSecurityEventClaimed(req: Request): boolean {
  return Boolean((req as ClaimableRequest)[SECURITY_EVENT_CLAIMED]);
}

const DEFAULT_LOG_MAX_BYTES = 10 * 1024 * 1024; // 10 MB

function resolveLogMaxBytes(): number {
  const raw = process.env.FAIL2BAN_LOG_MAX_BYTES?.trim();
  if (!raw || !/^\d+$/.test(raw)) return DEFAULT_LOG_MAX_BYTES;
  const n = Number(raw);
  return n >= 1 ? n : DEFAULT_LOG_MAX_BYTES;
}

/**
 * Appends security events (failed auth, invalid requests) to the dedicated security log that
 * fail2ban tails. Every write is best-effort: a log-sink error (read-only volume, disk full) must
 * never break an auth rejection or a request, so failures are swallowed after a single warning.
 */
@Injectable()
export class SecurityEventLogService {
  private warnedOnce = false;

  logWrongApiKey(surface: SecuritySurface, ip: string | undefined): void {
    this.append('wrong_api_key', surface, ip);
  }

  logInvalidRequest(surface: SecuritySurface, ip: string | undefined): void {
    this.append('invalid_request', surface, ip);
  }

  private append(reason: SecurityReason, surface: SecuritySurface, ip: string | undefined): void {
    // No IP means no fail2ban anchor — never write an unactionable line.
    if (!ip || !ip.trim()) return;
    const line = formatSecurityLine({ reason, surface, ip: ip.trim(), at: new Date() });
    try {
      const dir = securityLogDir();
      const file = securityLogPath();
      fs.mkdirSync(dir, { recursive: true });
      this.rotateIfNeeded(file);
      // 0644: the host fail2ban process must read it; the content is an IP + coarse reason, no secret.
      fs.appendFileSync(file, line + '\n', { mode: 0o644 });
    } catch (err) {
      if (!this.warnedOnce) {
        this.warnedOnce = true;
        // Deliberately console.warn (not the app logger): this is the security-log sink itself, and
        // it must not depend on or recurse through the logging stack.
        console.warn(
          '[SecurityEventLog] Could not write the security log; fail2ban will not see events until this is fixed:',
          err instanceof Error ? err.message : String(err),
        );
      }
    }
  }

  /** Size-bounded rotation, depth 1: at the cap, drop `.1` and rename the current log to `.1`. */
  private rotateIfNeeded(file: string): void {
    const max = resolveLogMaxBytes();
    let size: number;
    try {
      size = fs.statSync(file).size;
    } catch {
      return; // file does not exist yet — nothing to rotate
    }
    if (size < max) return;
    const rotated = `${file}.1`;
    try {
      fs.rmSync(rotated, { force: true });
    } catch {
      /* best-effort */
    }
    fs.renameSync(file, rotated);
  }
}
