import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  ConflictException,
  UnauthorizedException,
  HttpCode,
  HttpStatus,
  Optional,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { Request } from 'express';
import { CurrentApiKey, MfaExempt, RequireRole, RequireUnscopedKey } from './decorators/auth.decorators';
import { ApiKey, ApiKeyRole } from './entities/api-key.entity';
import { MfaCodeDto } from './dto/mfa.dto';
import { AuthService } from './auth.service';
import { MfaService } from './mfa.service';
import { AuditService } from '../audit/audit.service';
import { AuditAction } from '../audit/entities/audit-log.entity';

/**
 * Two-factor authentication (TOTP / Google Authenticator) for the dashboard, attached to an ADMIN
 * API key. Every route is `@MfaExempt()` because these are the endpoints an enrolled key uses to
 * obtain a session in the first place — the guard still fully validates the key (admin role, unscoped,
 * IP), it just skips the extra session-token check here.
 *
 * Flow: setup (generate secret + QR) → enable (confirm a code) → the key is now interactive-only.
 * On each dashboard login the key + a fresh code mint a session token via `session`. `disable` (with a
 * current code) turns it back off. Recovery from a lost device is the host-side `mfa:reset` CLI.
 */
@ApiTags('auth')
@Controller('auth/mfa')
@RequireUnscopedKey()
@RequireRole(ApiKeyRole.ADMIN)
@MfaExempt()
export class AuthMfaController {
  constructor(
    private readonly authService: AuthService,
    private readonly mfaService: MfaService,
    @Optional() private readonly auditService?: AuditService,
  ) {}

  @Get('status')
  @ApiOperation({ summary: 'Whether 2FA is enabled on the current API key' })
  @ApiResponse({ status: 200, description: '2FA status' })
  getStatus(@CurrentApiKey() apiKey?: ApiKey): { enabled: boolean } {
    return { enabled: Boolean(apiKey?.mfaEnabled) };
  }

  @Post('setup')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Begin 2FA enrollment: generate a secret + QR (not yet active)' })
  @ApiResponse({ status: 200, description: 'Enrollment material (shown once)' })
  @ApiResponse({ status: 409, description: '2FA is already enabled' })
  async setup(@CurrentApiKey() apiKey: ApiKey): Promise<{ otpauthUri: string; qrDataUrl: string; secret: string }> {
    if (apiKey.mfaEnabled) {
      throw new ConflictException('2FA is already enabled for this key; disable it first to re-enroll');
    }
    const enrollment = await this.mfaService.generateEnrollment(apiKey.name);
    await this.authService.setMfaSecret(apiKey.id, this.mfaService.encryptSecret(enrollment.secret));
    // The raw secret is returned ONCE so the user can scan the QR or type it into the app.
    return { otpauthUri: enrollment.otpauthUri, qrDataUrl: enrollment.qrDataUrl, secret: enrollment.secret };
  }

  @Post('enable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirm enrollment with a code — the key becomes interactive-only' })
  @ApiResponse({ status: 200, description: 'Enabled; a session token is returned' })
  @ApiResponse({ status: 401, description: 'Invalid code' })
  async enable(
    @CurrentApiKey() apiKey: ApiKey,
    @Body() body: MfaCodeDto,
    @Req() req: Request,
  ): Promise<{ enabled: true; sessionToken: string; expiresAt: string }> {
    // Read the just-stored (un-confirmed) secret. It was set by /setup on a prior request.
    const key = await this.authService.findKeyById(apiKey.id);
    if (!this.mfaService.verifyCode(key?.mfaSecret, body.code)) {
      void this.auditService?.logWarn(AuditAction.MFA_FAILED, {
        ipAddress: this.ip(req),
        metadata: { phase: 'enable' },
      });
      throw new UnauthorizedException('Invalid authenticator code');
    }
    await this.authService.enableMfa(apiKey.id);
    void this.auditService?.logInfo(AuditAction.MFA_ENROLLED, { ipAddress: this.ip(req) });
    const session = this.mfaService.issueSessionToken(apiKey.id);
    return { enabled: true, sessionToken: session.token, expiresAt: session.expiresAt };
  }

  @Post('disable')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Disable 2FA (requires a current code)' })
  @ApiResponse({ status: 200, description: 'Disabled' })
  @ApiResponse({ status: 401, description: 'Invalid code' })
  async disable(
    @CurrentApiKey() apiKey: ApiKey,
    @Body() body: MfaCodeDto,
    @Req() req: Request,
  ): Promise<{ enabled: false }> {
    if (!this.mfaService.verifyCode(apiKey.mfaSecret, body.code)) {
      void this.auditService?.logWarn(AuditAction.MFA_FAILED, {
        ipAddress: this.ip(req),
        metadata: { phase: 'disable' },
      });
      throw new UnauthorizedException('Invalid authenticator code');
    }
    await this.authService.disableMfa(apiKey.id);
    void this.auditService?.logInfo(AuditAction.MFA_DISABLED, { ipAddress: this.ip(req) });
    return { enabled: false };
  }

  @Post('session')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Exchange a code for a short-lived dashboard session token' })
  @ApiResponse({ status: 200, description: 'Session token issued' })
  @ApiResponse({ status: 401, description: 'Invalid code' })
  session(
    @CurrentApiKey() apiKey: ApiKey,
    @Body() body: MfaCodeDto,
    @Req() req: Request,
  ): { sessionToken: string; expiresAt: string } {
    if (!apiKey.mfaEnabled || !this.mfaService.verifyCode(apiKey.mfaSecret, body.code)) {
      void this.auditService?.logWarn(AuditAction.MFA_FAILED, {
        ipAddress: this.ip(req),
        metadata: { phase: 'session' },
      });
      throw new UnauthorizedException('Invalid authenticator code');
    }
    void this.auditService?.logInfo(AuditAction.MFA_VERIFIED, { ipAddress: this.ip(req) });
    const session = this.mfaService.issueSessionToken(apiKey.id);
    return { sessionToken: session.token, expiresAt: session.expiresAt };
  }

  private ip(req: Request): string | undefined {
    return (req as Request & { clientIp?: string }).clientIp;
  }
}
