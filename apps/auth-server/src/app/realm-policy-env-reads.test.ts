import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { CONFIG_KEY_REGISTRY } from '@qauth-labs/server-config';
import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { POLICIES_READ_FROM_REALM_ROW } from './helpers/realm-policy-readers';

/**
 * No code of the auth server reads an environment key whose policy it reads
 * from the realm row (ADR-019 Decision 10, #516, #528, #534). Such a key only seeds
 * a new realm's policies (`defaultsFromEnv` and the boot step, which take the
 * whole environment and name no key); a flow that read it again would let the
 * environment overrule a realm, and every realm would get one value.
 *
 * The keys are the registry's: every `realm-seed` key whose policy path is in
 * `POLICIES_READ_FROM_REALM_ROW`, under its current name and its old ones. A
 * read is `x.KEY` or `x?.KEY`, `x['KEY']` or ``x[`KEY`]``, or a destructured
 * `{ KEY }` in a declaration or a parameter, in any source file under
 * `apps/auth-server/src` but tests and test support. A key named in a comment,
 * a message or an object literal that sets it (the OpenAPI export's
 * environment) is not a read.
 */

const SOURCE_ROOT = resolve(__dirname, '..');

/**
 * Reads that stay, by key, with the files that make them, relative to
 * `apps/auth-server/src`.
 */
const ALLOWED_READS: Readonly<Record<string, readonly string[]>> = {
  // The JWT plugin's lifespans, which app.ts registers it with: what a realm
  // with no policies yet (counter 0, created by a node of the previous
  // release during a rolling upgrade) runs on until its fill lands
  // (`tokenLifetimesOf`, #527). A realm that has its policies never reads
  // them.
  ACCESS_TOKEN_LIFESPAN: ['app/app.ts'],
  REFRESH_TOKEN_LIFESPAN: ['app/app.ts'],
};

/** The environment keys, current and old names, that seed a policy read from the realm row. */
function keysReadFromRealmRow(): ReadonlyMap<string, string> {
  const keys = new Map<string, string>();
  for (const key of CONFIG_KEY_REGISTRY) {
    if (key.seeds === undefined || !POLICIES_READ_FROM_REALM_ROW.has(key.seeds)) continue;
    keys.set(key.name, key.seeds);
    for (const alias of key.aliases) keys.set(alias.name, key.seeds);
  }
  return keys;
}

/** The names of `keys` that `source` reads, with the line of each read. */
function readsIn(source: string, keys: ReadonlySet<string>, fileName = 'sample.ts') {
  const reads: { key: string; line: number }[] = [];
  // A file that names no key cannot read one: parse only the others, which
  // keeps the walk of the whole source tree to a few files.
  if (![...keys].some((key) => source.includes(key))) return reads;
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const found = (key: string, node: ts.Node) => {
    if (keys.has(key)) {
      reads.push({ key, line: file.getLineAndCharacterOfPosition(node.getStart()).line + 1 });
    }
  };
  const visit = (node: ts.Node): void => {
    if (ts.isPropertyAccessExpression(node)) {
      found(node.name.text, node.name);
    } else if (
      ts.isElementAccessExpression(node) &&
      ts.isStringLiteralLike(node.argumentExpression)
    ) {
      found(node.argumentExpression.text, node.argumentExpression);
    } else if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
      const name = node.propertyName ?? node.name;
      if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) found(name.text, name);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return reads;
}

/** Every source file under `dir`, but tests and the test support of `src/testing`. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      return path === join(SOURCE_ROOT, 'testing') ? [] : sourceFiles(path);
    }
    return entry.name.endsWith('.ts') && !/\.(test|spec)\.ts$/.test(entry.name) ? [path] : [];
  });
}

describe('environment keys of policies read from the realm row (#528, #534)', () => {
  const keys = keysReadFromRealmRow();

  it("covers the verified-account, password and brute-force keys (#528), the old name of the gate's key included", () => {
    for (const [key, path] of [
      ['REQUIRE_VERIFIED_ACCOUNT', 'accounts.requireVerifiedAccount'],
      ['REQUIRE_EMAIL_VERIFIED', 'accounts.requireVerifiedAccount'],
      ['PASSWORD_MIN_SCORE', 'password.minScore'],
      ['FAILED_LOGIN_TRACKING_ENABLED', 'bruteForce.enabled'],
      ['FAILED_LOGIN_MAX_ATTEMPTS', 'bruteForce.maxAttempts'],
      ['FAILED_LOGIN_WINDOW', 'bruteForce.windowSeconds'],
      ['FAILED_LOGIN_LOCKOUT_DURATION', 'bruteForce.lockoutSeconds'],
    ]) {
      expect(keys.get(key), key).toBe(path);
    }
  });

  it('covers the client registration keys (#534), and not the CIMD fetch tuning, which stays a deployment setting', () => {
    for (const [key, path] of [
      ['DEFAULT_DYNAMIC_REGISTRATION_SCOPES', 'registration.dynamicRegistrationAllowedScopes'],
      ['CIMD_ENABLED', 'registration.cimd.enabled'],
      ['CIMD_TRUST_POLICY', 'registration.cimd.trustPolicy'],
      ['CIMD_TRUSTED_DOMAINS', 'registration.cimd.trustedDomains'],
    ]) {
      expect(keys.get(key), key).toBe(path);
    }
    for (const key of [
      'CIMD_CACHE_DEFAULT_TTL',
      'CIMD_CACHE_MAX_TTL',
      'CIMD_MAX_DOCUMENT_BYTES',
      'CIMD_FETCH_TIMEOUT_MS',
    ]) {
      expect(keys.has(key), key).toBe(false);
    }
  });

  it('finds a read in each form it looks for, and nothing in a comment, a message or a write', () => {
    const watched = new Set(['PASSWORD_MIN_SCORE', 'FAILED_LOGIN_WINDOW']);

    expect(
      readsIn(
        [
          'const a = env.PASSWORD_MIN_SCORE;',
          "const b = env['FAILED_LOGIN_WINDOW'];",
          'const { PASSWORD_MIN_SCORE } = env;',
          'const { FAILED_LOGIN_WINDOW: window } = process.env;',
          'const c = process.env.PASSWORD_MIN_SCORE;',
          'const d = env?.FAILED_LOGIN_WINDOW;',
          'const e = env[`PASSWORD_MIN_SCORE`];',
          'function f({ FAILED_LOGIN_WINDOW }: Env) {}',
        ].join('\n'),
        watched
      ).map((read) => read.line)
    ).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(
      readsIn(
        [
          '// env.PASSWORD_MIN_SCORE only seeds new realms',
          "const message = 'PASSWORD_MIN_SCORE is ignored';",
          'const environment = { PASSWORD_MIN_SCORE: "2" };',
          'const other = env.PASSWORD_MAX_SCORE;',
        ].join('\n'),
        watched
      )
    ).toEqual([]);
  });

  it('is read nowhere in apps/auth-server/src but where a read is allowed', () => {
    const files = sourceFiles(SOURCE_ROOT);
    // The walk found the server's code, the handlers included.
    expect(files).toContain(join(SOURCE_ROOT, 'app/routes/auth/login.ts'));
    expect(files).toContain(join(SOURCE_ROOT, 'app/helpers/failed-login.ts'));
    expect(files).toContain(join(SOURCE_ROOT, 'app/routes/oauth/register.ts'));
    expect(files).toContain(join(SOURCE_ROOT, 'app/helpers/cimd.ts'));

    const unexpected: string[] = [];
    for (const file of files) {
      const path = relative(SOURCE_ROOT, file);
      for (const { key, line } of readsIn(readFileSync(file, 'utf8'), new Set(keys.keys()), file)) {
        if (!(ALLOWED_READS[key] ?? []).includes(path)) unexpected.push(`${path}:${line} ${key}`);
      }
    }

    expect(unexpected).toEqual([]);
  }, 30_000);

  it('allows only reads that still happen, of keys it watches', () => {
    for (const [key, paths] of Object.entries(ALLOWED_READS)) {
      expect(keys.has(key), key).toBe(true);
      for (const path of paths) {
        const reads = readsIn(readFileSync(join(SOURCE_ROOT, path), 'utf8'), new Set([key]), path);
        expect(reads.length, `${path} ${key}`).toBeGreaterThan(0);
      }
    }
  });
});
