import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ensureApiKeyPepper } from './ensure-api-key-pepper';

describe('ensureApiKeyPepper', () => {
  let dir: string;
  let genPath: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'owa-pepper-'));
    genPath = path.join(dir, '.env.generated');
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('generates, persists (0600), and applies a pepper when none is configured', () => {
    const env: NodeJS.ProcessEnv = {};
    const result = ensureApiKeyPepper(genPath, env);

    expect(result.generated).toBe(true);
    expect(env.API_KEY_PEPPER).toMatch(/^[0-9a-f]{64}$/); // 32 random bytes hex
    const file = fs.readFileSync(genPath, 'utf8');
    expect(file).toContain(`API_KEY_PEPPER=${env.API_KEY_PEPPER}`);
    // Secret file perms: owner read/write only.
    expect(fs.statSync(genPath).mode & 0o777).toBe(0o600);
  });

  it('appends to an existing generated file without clobbering its contents', () => {
    fs.writeFileSync(genPath, 'DATABASE_TYPE=sqlite\nREDIS_ENABLED=false\n');
    const env: NodeJS.ProcessEnv = {};

    ensureApiKeyPepper(genPath, env);

    const file = fs.readFileSync(genPath, 'utf8');
    expect(file).toContain('DATABASE_TYPE=sqlite'); // preserved
    expect(file).toContain('REDIS_ENABLED=false'); // preserved
    expect(file).toContain(`API_KEY_PEPPER=${env.API_KEY_PEPPER}`);
  });

  it('is a no-op when a pepper is already supplied by the environment', () => {
    const env: NodeJS.ProcessEnv = { API_KEY_PEPPER: 'operator-set-pepper' };
    const result = ensureApiKeyPepper(genPath, env);

    expect(result.generated).toBe(false);
    expect(env.API_KEY_PEPPER).toBe('operator-set-pepper'); // untouched
    expect(fs.existsSync(genPath)).toBe(false); // nothing written
  });

  it('respects a present-but-blank pepper line in the file (does not re-arm or duplicate it)', () => {
    // An operator who deliberately blanked the pepper stays on SHA-256; we must not append a second
    // line or override their choice.
    fs.writeFileSync(genPath, 'API_KEY_PEPPER=\nDATABASE_TYPE=sqlite\n');
    const env: NodeJS.ProcessEnv = {}; // dotenv would load the blank as '' → treated as unset here

    const result = ensureApiKeyPepper(genPath, env);

    expect(result.generated).toBe(false);
    expect(env.API_KEY_PEPPER).toBeUndefined();
    const lines = fs
      .readFileSync(genPath, 'utf8')
      .split('\n')
      .filter(l => l.startsWith('API_KEY_PEPPER='));
    expect(lines).toEqual(['API_KEY_PEPPER=']); // exactly one, unchanged
  });

  it('does NOT apply a pepper it cannot persist (read-only dir) — stays on SHA-256 for the boot', () => {
    // Point at a path whose parent does not exist so writeSecretFile throws.
    const unwritable = path.join(dir, 'missing-subdir', '.env.generated');
    const env: NodeJS.ProcessEnv = {};

    const result = ensureApiKeyPepper(unwritable, env);

    expect(result.generated).toBe(false);
    expect(result.persistError).toBeDefined();
    // Critical: the env is NOT set, so this boot never hashes under a pepper it can't reproduce next boot.
    expect(env.API_KEY_PEPPER).toBeUndefined();
  });
});
