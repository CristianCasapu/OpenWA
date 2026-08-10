/**
 * Recovery CLI: disable two-factor auth on an API key (or all keys) directly on the main SQLite DB.
 *
 * When the only admin key has 2FA enabled and its authenticator device is lost, the dashboard AND the
 * API are locked (an MFA-enabled key is refused without a valid post-TOTP session). This host-side
 * script — run by an operator with access to the data volume — clears the 2FA state so the key works
 * as a plain bearer credential again.
 *
 *   npm run mfa:reset -- --all           # disable 2FA on every key
 *   npm run mfa:reset -- <apiKeyId>      # disable 2FA on one key by id
 *   npm run mfa:reset -- --list          # show which keys currently have 2FA enabled
 *
 * Honours MAIN_DATABASE_NAME (same path the app/CLI use), so it targets the real main DB.
 */
import Database from 'better-sqlite3';
import { loadCliEnv } from '../src/database/load-cli-env';

loadCliEnv();

const dbPath = process.env.MAIN_DATABASE_NAME || './data/main.sqlite';
const arg = process.argv[2];

function usageAndExit(code: number): never {
  console.log('Usage:\n  npm run mfa:reset -- --all\n  npm run mfa:reset -- <apiKeyId>\n  npm run mfa:reset -- --list');
  process.exit(code);
}

if (!arg) usageAndExit(1);

const db = new Database(dbPath);
try {
  if (arg === '--list') {
    const rows = db
      .prepare(`SELECT id, name, role FROM api_keys WHERE mfaEnabled = 1`)
      .all() as Array<{ id: string; name: string; role: string }>;
    if (rows.length === 0) {
      console.log('No keys currently have 2FA enabled.');
    } else {
      console.log(`Keys with 2FA enabled (${rows.length}):`);
      for (const r of rows) console.log(`  ${r.id}  [${r.role}]  ${r.name}`);
    }
    process.exit(0);
  }

  const clear = `UPDATE api_keys SET mfaEnabled = 0, mfaSecret = NULL, mfaEnrolledAt = NULL`;
  const result =
    arg === '--all'
      ? db.prepare(`${clear} WHERE mfaEnabled = 1`).run()
      : db.prepare(`${clear} WHERE id = ?`).run(arg);

  if (arg !== '--all' && result.changes === 0) {
    console.error(`No key with id "${arg}" found (or it already had 2FA off).`);
    process.exit(2);
  }
  console.log(`Disabled 2FA on ${result.changes} key(s). They can now authenticate without a code.`);
  process.exit(0);
} finally {
  db.close();
}
