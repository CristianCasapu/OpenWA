// archiver v8 is ESM-only and pulled in transitively via the @Global StorageModule; stub it.
jest.mock('archiver', () => ({ TarArchive: jest.fn() }));

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { TOTP, Secret } from 'otpauth';
import { AppModule } from './../src/app.module';
import { applyGlobalValidation } from './../src/config/app-validation';
import { AuthService } from './../src/modules/auth/auth.service';
import { ApiKeyRole } from './../src/modules/auth/entities/api-key.entity';

/**
 * End-to-end 2FA: an admin key enrolls TOTP, after which it is refused as a plain bearer credential
 * (headless) and only works with a valid post-TOTP dashboard session token.
 */
describe('MFA (2FA/TOTP) enforcement (e2e)', () => {
  let app: INestApplication<App>;
  let adminKey: string;

  beforeAll(async () => {
    process.env.MFA_KEY = Buffer.alloc(32, 5).toString('base64'); // deterministic master for the run
    const moduleFixture: TestingModule = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleFixture.createNestApplication();
    applyGlobalValidation(app);
    await app.init();
    const authService = app.get(AuthService);
    adminKey = (await authService.createApiKey({ name: 'e2e-mfa-admin', role: ApiKeyRole.ADMIN })).rawKey;
  });

  afterAll(async () => {
    delete process.env.MFA_KEY;
    try {
      await app?.close();
    } catch {
      /* multi-datasource teardown quirk */
    }
  });

  const server = () => app.getHttpServer();

  it('enrolls, then enforces the session requirement on the enrolled key', async () => {
    // 1. Before enrollment, /auth/validate reports mfaRequired:false and the key works headless.
    const before = await request(server()).post('/api/auth/validate').set('X-API-Key', adminKey).expect(200);
    expect((before.body as { mfaRequired?: boolean }).mfaRequired).toBe(false);
    await request(server()).get('/api/sessions').set('X-API-Key', adminKey).expect(200);

    // 2. Setup: generate a secret + QR.
    const setup = await request(server()).post('/api/auth/mfa/setup').set('X-API-Key', adminKey).expect(200);
    const secretB32 = (setup.body as { secret: string }).secret;
    expect(secretB32).toMatch(/^[A-Z2-7]+$/);
    const totp = new TOTP({ issuer: 'OpenWA', secret: Secret.fromBase32(secretB32) });

    // 3. Enable with a valid code — the key becomes interactive-only from here.
    const enable = await request(server())
      .post('/api/auth/mfa/enable')
      .set('X-API-Key', adminKey)
      .send({ code: totp.generate() })
      .expect(200);
    expect((enable.body as { enabled: boolean }).enabled).toBe(true);

    // 4. The same key used headless (only X-API-Key) is now refused with MFA_REQUIRED.
    const blocked = await request(server()).get('/api/sessions').set('X-API-Key', adminKey).expect(401);
    expect((blocked.body as { code?: string }).code).toBe('MFA_REQUIRED');

    // 5. /auth/validate stays reachable (MfaExempt) and now advertises mfaRequired:true.
    const validate = await request(server()).post('/api/auth/validate').set('X-API-Key', adminKey).expect(200);
    expect((validate.body as { mfaRequired?: boolean }).mfaRequired).toBe(true);

    // 6. Exchange a fresh code for a session token, then the request passes with both headers.
    const session = await request(server())
      .post('/api/auth/mfa/session')
      .set('X-API-Key', adminKey)
      .send({ code: totp.generate() })
      .expect(200);
    const token = (session.body as { sessionToken: string }).sessionToken;
    expect(token).toBeTruthy();

    await request(server())
      .get('/api/sessions')
      .set('X-API-Key', adminKey)
      .set('X-Dashboard-Session', token)
      .expect(200);

    // 7. A wrong code is refused (and does not mint a session).
    await request(server())
      .post('/api/auth/mfa/session')
      .set('X-API-Key', adminKey)
      .send({ code: '000000' })
      .expect(401);
  });
});
