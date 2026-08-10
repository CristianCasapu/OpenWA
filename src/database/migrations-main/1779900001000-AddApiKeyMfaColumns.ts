import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Adds the two-factor-auth columns to `api_keys` on the **main** connection:
 *   - `mfaEnabled`   — whether TOTP 2FA is active on the key (interactive-only once true)
 *   - `mfaSecret`    — the AES-256-GCM-encrypted TOTP shared secret (nullable)
 *   - `mfaEnrolledAt`— when 2FA was confirmed (nullable)
 *
 * Runs when `MAIN_DATABASE_SYNCHRONIZE=false` (`migrationsRun: !synchronize`); under the default
 * `synchronize:true`, TypeORM adds these from the entity automatically. The main DB is always SQLite,
 * which has no `ADD COLUMN IF NOT EXISTS`, so each add is guarded by a `PRAGMA table_info` check to
 * stay idempotent (safe on a DB previously created by synchronize).
 */
export class AddApiKeyMfaColumns1779900001000 implements MigrationInterface {
  name = 'AddApiKeyMfaColumns1779900001000';

  private async columns(queryRunner: QueryRunner): Promise<Set<string>> {
    const rows = (await queryRunner.query(`PRAGMA table_info("api_keys")`)) as Array<{ name: string }>;
    return new Set(rows.map(r => r.name));
  }

  public async up(queryRunner: QueryRunner): Promise<void> {
    const existing = await this.columns(queryRunner);
    if (!existing.has('mfaEnabled')) {
      await queryRunner.query(`ALTER TABLE "api_keys" ADD COLUMN "mfaEnabled" boolean NOT NULL DEFAULT (0)`);
    }
    if (!existing.has('mfaSecret')) {
      await queryRunner.query(`ALTER TABLE "api_keys" ADD COLUMN "mfaSecret" text`);
    }
    if (!existing.has('mfaEnrolledAt')) {
      await queryRunner.query(`ALTER TABLE "api_keys" ADD COLUMN "mfaEnrolledAt" datetime`);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // SQLite gained DROP COLUMN in 3.35; guard each so the down migration is tolerant on older engines
    // and when a column is already absent.
    const existing = await this.columns(queryRunner);
    for (const col of ['mfaEnrolledAt', 'mfaSecret', 'mfaEnabled']) {
      if (existing.has(col)) {
        try {
          await queryRunner.query(`ALTER TABLE "api_keys" DROP COLUMN "${col}"`);
        } catch {
          /* older SQLite without DROP COLUMN — leaving the column is harmless */
        }
      }
    }
  }
}
