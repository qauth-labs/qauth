import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import { OID4VP_REQUEST_OBJECT_TYP } from '@qauth-labs/fastify-plugin-federation';
import { SIGNER_REQUEST_OBJECT_TYP } from '@qauth-labs/fastify-plugin-signer';
import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

/**
 * No code path outside the signer's key import reads the OID4VP verifier's
 * private key (ADR-019 Decision 9, #546).
 *
 * The key boot step imports `OID4VP_VERIFIER_SIGNING_KEY` (or its `_PATH`
 * form) once, as the realm's `oid4vp_request_signing` key, and from then on
 * only the signer signs with it. Two files touch the variable: the config
 * schema, which parses it (and reads the file the `_PATH` form names) and
 * picks one form (`resolveVerifierSigningKeyPem`), and the auth server's
 * `keyVariableSettings`, which hands it to the key boot step. Anything else
 * that read it would hold the key outside the store again.
 *
 * A read is `x.KEY`, `x['KEY']`, `{ KEY } = x`, a call that takes `'KEY'` as
 * an argument (`readConfiguredFile(raw, 'KEY')`), or a call of
 * `resolveVerifierSigningKeyPem`, in any source file under `apps/` and
 * `libs/` but tests and test support. A key named in a comment, a message, an
 * object literal that sets it or a list of variable names is not a read.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** The verifier key's variables. */
const KEYS: ReadonlySet<string> = new Set([
  'OID4VP_VERIFIER_SIGNING_KEY',
  'OID4VP_VERIFIER_SIGNING_KEY_PATH',
]);

/** The function that picks the key from the parsed environment. */
const RESOLVER = 'resolveVerifierSigningKeyPem';

/** The files that may read the key, relative to the workspace root. */
const ALLOWED_READERS: readonly string[] = [
  'libs/server/config/src/lib/schemas/federation.ts',
  'apps/auth-server/src/app/helpers/key-variables.ts',
];

/** The reads of the key in `source`, with the line of each. */
function readsIn(source: string, fileName = 'sample.ts'): { what: string; line: number }[] {
  const reads: { what: string; line: number }[] = [];
  // A file that names neither the key nor the resolver cannot read it: parse
  // only the others, which keeps the walk of the workspace to a few files.
  if (!source.includes('OID4VP_VERIFIER_SIGNING_KEY') && !source.includes(RESOLVER)) return reads;
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
  const lineOf = (node: ts.Node) => file.getLineAndCharacterOfPosition(node.getStart()).line + 1;
  const found = (what: string, node: ts.Node) => {
    if (KEYS.has(what)) reads.push({ what, line: lineOf(node) });
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
    } else if (ts.isCallExpression(node)) {
      for (const argument of node.arguments) {
        if (ts.isStringLiteralLike(argument)) found(argument.text, argument);
      }
      const callee = ts.isPropertyAccessExpression(node.expression)
        ? node.expression.name
        : node.expression;
      if (ts.isIdentifier(callee) && callee.text === RESOLVER) {
        reads.push({ what: RESOLVER, line: lineOf(callee) });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return reads;
}

/** Directories that hold no shipped source. */
const SKIPPED_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  'dist',
  'out-tsc',
  'coverage',
  'testing',
  'test',
  '__fixtures__',
]);

/** Every shipped TypeScript source file under `dir`. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      return SKIPPED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')
        ? []
        : sourceFiles(path);
    }
    return /\.tsx?$/.test(entry.name) &&
      !/\.d\.ts$/.test(entry.name) &&
      !/\.(test|spec|integration\.test)\.tsx?$/.test(entry.name)
      ? [path]
      : [];
  });
}

describe('the OID4VP verifier key is read only by its import (#546)', () => {
  it('finds a read in each form it looks for, and nothing in a comment, a message or a write', () => {
    expect(
      readsIn(
        [
          'const a = env.OID4VP_VERIFIER_SIGNING_KEY;',
          "const b = env['OID4VP_VERIFIER_SIGNING_KEY_PATH'];",
          'const { OID4VP_VERIFIER_SIGNING_KEY } = env;',
          "const c = readConfiguredFile(raw, 'OID4VP_VERIFIER_SIGNING_KEY_PATH', ctx);",
          'const d = resolveVerifierSigningKeyPem(env);',
          'const e = config.resolveVerifierSigningKeyPem(env);',
        ].join('\n')
      ).map((read) => read.line)
    ).toEqual([1, 2, 3, 4, 5, 6]);
    expect(
      readsIn(
        [
          '// env.OID4VP_VERIFIER_SIGNING_KEY is imported once',
          "const message = 'Set OID4VP_VERIFIER_SIGNING_KEY for one boot';",
          'const environment = { OID4VP_VERIFIER_SIGNING_KEY: pem };',
          "const variables = ['OID4VP_VERIFIER_SIGNING_KEY'];",
          "warn('OID4VP_VERIFIER_SIGNING_KEY is set; it is imported once');",
          'const other = env.OID4VP_VERIFIER_CERTIFICATE_CHAIN;',
        ].join('\n')
      )
    ).toEqual([]);
  });

  it('is read nowhere in apps/ and libs/ but by the config schema and the key boot step', () => {
    const files = [
      ...sourceFiles(join(WORKSPACE_ROOT, 'apps')),
      ...sourceFiles(join(WORKSPACE_ROOT, 'libs')),
    ];
    // The walk found the code that once held the key and the code that signs now.
    for (const path of [
      'apps/auth-server/src/app/helpers/verifier-identity.ts',
      'apps/auth-server/src/app/helpers/wallet-login-request.ts',
      'libs/server/federation/src/oid4vp/request-object.ts',
      'libs/server/keys/src/lib/in-process-signer.ts',
      ...ALLOWED_READERS,
    ]) {
      expect(files).toContain(join(WORKSPACE_ROOT, path));
    }

    const unexpected: string[] = [];
    for (const file of files) {
      const path = relative(WORKSPACE_ROOT, file);
      if (ALLOWED_READERS.includes(path)) continue;
      for (const { what, line } of readsIn(readFileSync(file, 'utf8'), file)) {
        unexpected.push(`${path}:${line} ${what}`);
      }
    }

    expect(unexpected).toEqual([]);
  }, 60_000);

  it('allows only readers that still read it', () => {
    for (const path of ALLOWED_READERS) {
      const reads = readsIn(readFileSync(join(WORKSPACE_ROOT, path), 'utf8'), path);
      expect(reads.length, path).toBeGreaterThan(0);
    }
  });
});

describe('the request object typ (#546)', () => {
  it('is the same string in the signer and in the federation library', () => {
    // The signer stamps it; the federation library names it for the wallet
    // side. Neither library may import the other.
    expect(SIGNER_REQUEST_OBJECT_TYP).toBe(OID4VP_REQUEST_OBJECT_TYP);
    expect(SIGNER_REQUEST_OBJECT_TYP).toBe('oauth-authz-req+jwt');
  });
});
