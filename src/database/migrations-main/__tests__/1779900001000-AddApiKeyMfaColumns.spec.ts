import { DataSource } from 'typeorm';
import { CreateAuthAuditTables1779900000000 } from '../1779900000000-CreateAuthAuditTables';
import { AddApiKeyMfaColumns1779900001000 } from '../1779900001000-AddApiKeyMfaColumns';

/**
 * The MFA-columns migration must add mfaEnabled/mfaSecret/mfaEnrolledAt to api_keys on the main
 * connection (for MAIN_DATABASE_SYNCHRONIZE=false deployments), and be idempotent.
 */
describe('AddApiKeyMfaColumns migration', () => {
  let ds: DataSource;

  beforeEach(async () => {
    ds = new DataSource({ type: 'better-sqlite3', database: ':memory:', entities: [], synchronize: false });
    await ds.initialize();
    await new CreateAuthAuditTables1779900000000().up(ds.createQueryRunner());
  });

  afterEach(async () => {
    await ds.destroy();
  });

  const columns = async (): Promise<Set<string>> => {
    const rows = (await ds.createQueryRunner().query(`PRAGMA table_info("api_keys")`)) as Array<{ name: string }>;
    return new Set(rows.map(r => r.name));
  };

  it('adds the three MFA columns with a working default', async () => {
    await new AddApiKeyMfaColumns1779900001000().up(ds.createQueryRunner());
    const cols = await columns();
    expect(cols.has('mfaEnabled')).toBe(true);
    expect(cols.has('mfaSecret')).toBe(true);
    expect(cols.has('mfaEnrolledAt')).toBe(true);

    const qr = ds.createQueryRunner();
    await qr.query("INSERT INTO api_keys (id, name, keyHash, keyPrefix) VALUES ('1', 'k', 'hash', 'pref')");
    const row = (await qr.query("SELECT mfaEnabled, mfaSecret, mfaEnrolledAt FROM api_keys WHERE id = '1'")) as Array<{
      mfaEnabled: number;
      mfaSecret: string | null;
      mfaEnrolledAt: string | null;
    }>;
    expect(row[0]).toEqual({ mfaEnabled: 0, mfaSecret: null, mfaEnrolledAt: null });
  });

  it('is idempotent (re-running does not throw)', async () => {
    await new AddApiKeyMfaColumns1779900001000().up(ds.createQueryRunner());
    await expect(new AddApiKeyMfaColumns1779900001000().up(ds.createQueryRunner())).resolves.not.toThrow();
  });
});
