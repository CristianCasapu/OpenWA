import { Injectable, NestMiddleware } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response, NextFunction } from 'express';
import { resolveClientIp } from '../utils/ip';
import { SecurityEventLogService, claimSecurityEvent, isSecurityEventClaimed } from './security-event-log.service';

/**
 * HTTP statuses that count as an unauthorized/malformed request for fail2ban purposes. 429 is
 * deliberately EXCLUDED — rate limiting is a separate control with its own back-off, and a client
 * that trips the limiter is not necessarily an attacker probing credentials or endpoints.
 */
const INVALID_REQUEST_STATUSES = new Set([400, 401, 403, 404]);

/**
 * Health/metrics probes are not attack surface worth banning on: a monitoring 404 against a probe
 * path must never contribute to a fail2ban count. Mirrors the request-metrics middleware exclusion.
 */
const SKIPPED_PREFIXES = ['/api/health', '/api/metrics'];

/**
 * Boundary observer, sibling to `requestMetricsBoundaryMiddleware`: it runs BEFORE the guards (Nest
 * middleware precedes the guard/interceptor chain) and records on `res.on('finish'/'close')`, so it
 * sees the FINAL status the exception filter wrote — including the 401/403 the API-key guard raised.
 *
 * On a 400/401/403/404 that no more specific site already claimed, it emits ONE `invalid_request`
 * security line for fail2ban. It is an OBSERVER, never a filter: it reads `res.statusCode` and never
 * touches the response body, so the error-response contract (and `swagger.config.spec`) is untouched.
 *
 * Exactly-once is enforced through the shared per-request claim: the REST guard claims when it emits
 * the more specific `wrong_api_key` line, so a bad-key 401 is counted once (as `wrong_api_key`), not
 * twice. The observer also claims after it fires, so a finish+close pair emits a single line.
 */
@Injectable()
export class SecurityEventBoundaryMiddleware implements NestMiddleware {
  constructor(
    private readonly securityLog: SecurityEventLogService,
    private readonly configService: ConfigService,
  ) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const record = (): void => {
      // A more specific site (the REST guard's wrong_api_key) already accounted for this request,
      // or this observer already fired on a prior finish/close — emit nothing.
      if (isSecurityEventClaimed(req)) return;
      if (!INVALID_REQUEST_STATUSES.has(res.statusCode)) return;
      const reqPath = typeof req.path === 'string' ? req.path : '';
      if (SKIPPED_PREFIXES.some(prefix => reqPath.startsWith(prefix))) return;
      // Claim before writing so a finish+close pair (or a later, more specific claim) cannot double-count.
      claimSecurityEvent(req);
      const trustedProxies = this.configService.get<string[]>('security.trustedProxies') ?? [];
      this.securityLog.logInvalidRequest('rest', resolveClientIp(req, trustedProxies));
    };
    res.on('finish', record);
    res.on('close', record);
    next();
  }
}
