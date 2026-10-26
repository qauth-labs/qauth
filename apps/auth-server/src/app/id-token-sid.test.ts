import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

/**
 * ONLY THE CODE EXCHANGE PUTS `sid` IN AN ID TOKEN (issue #549, ADR-019
 * Decisions 3 and 4).
 *
 * An ID token's `sid` names the browser session back-channel logout will end.
 * One that came from anywhere else (another grant, a helper spread into the
 * claims, a future mapper) would name a session no logout reaches, or one the
 * token was never issued under. ADR-014 gives agent access tokens their own
 * identifier, `tree_id`, so `sid` has this one meaning.
 *
 * Every production source file of `apps/` and `libs/` is parsed, and every
 * call of an ID-token signer (`signIdToken`, `signHybridIdToken`,
 * `buildIdTokenClaims`) is classified:
 *
 * - a payload written in place, with or without a `sid` member anywhere in
 *   it (spreads of object literals included);
 * - a payload passed through from elsewhere, which only the signers' own
 *   delegations may do, so every real caller writes its payload in place
 *   where this test can read it.
 *
 * The claim builder is the one place that writes a `sid` claim into the
 * claims object. The integration suite (`id-token-sid.integration.test.ts`)
 * checks the tokens themselves.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** The functions that sign an ID token or build its claims. */
const ID_TOKEN_SIGNERS = new Set(['signIdToken', 'signHybridIdToken', 'buildIdTokenClaims']);

/** Where the signers live: the only files that may assign a `sid` claim. */
const SIGNER_HOMES = ['libs/server/jwt/src/', 'libs/fastify/plugins/jwt/src/'];

const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'out-tsc', 'coverage', 'tmp', 'testing']);

/** One call of an ID-token signer, or one write of a `sid` member. */
interface Site {
  /** Workspace-relative path. */
  readonly file: string;
  /** The nearest named function around it. */
  readonly within: string;
}

interface Scan {
  /** Calls whose in-place payload has a `sid` member. */
  readonly setsSid: Site[];
  /** Calls whose in-place payload has none. */
  readonly withoutSid: Site[];
  /** Calls that pass a payload built elsewhere. */
  readonly passThrough: Site[];
  /** Assignments to a `sid` member (`x.sid = …`, `x['sid'] = …`). */
  readonly sidWrites: Site[];
}

function productionSources(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || SKIPPED_DIRS.has(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...productionSources(path));
    } else if (
      /\.tsx?$/.test(entry.name) &&
      !/\.d\.ts$/.test(entry.name) &&
      !/\.(test|spec)\.tsx?$/.test(entry.name)
    ) {
      found.push(path);
    }
  }
  return found;
}

function nameOf(node: ts.Node): string | undefined {
  if (
    (ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isFunctionExpression(node)) &&
    node.name !== undefined
  ) {
    return node.name.getText();
  }
  return undefined;
}

function enclosingName(node: ts.Node): string {
  for (let at: ts.Node | undefined = node.parent; at !== undefined; at = at.parent) {
    const name = nameOf(at);
    if (name !== undefined) return name;
  }
  return '<module>';
}

function calleeName(call: ts.CallExpression): string | undefined {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  return undefined;
}

function isSidName(name: ts.PropertyName | ts.Identifier): boolean {
  return (ts.isIdentifier(name) || ts.isStringLiteral(name)) && name.text === 'sid';
}

/** Whether an in-place payload has a `sid` member, at any depth. */
function hasSidMember(node: ts.Node): boolean {
  if (
    (ts.isPropertyAssignment(node) || ts.isShorthandPropertyAssignment(node)) &&
    isSidName(node.name)
  ) {
    return true;
  }
  return ts.forEachChild(node, (child) => hasSidMember(child) || undefined) ?? false;
}

function isSidTarget(target: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(target)) return target.name.text === 'sid';
  if (ts.isElementAccessExpression(target)) {
    const key = target.argumentExpression;
    return ts.isStringLiteralLike(key) && key.text === 'sid';
  }
  return false;
}

/** Classify every signer call and `sid` write in one source text. */
function scanSource(file: string, text: string, scan: Scan): void {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      if (name !== undefined && ID_TOKEN_SIGNERS.has(name)) {
        const site = { file, within: enclosingName(node) };
        const [payload] = node.arguments;
        if (payload === undefined || !ts.isObjectLiteralExpression(payload)) {
          scan.passThrough.push(site);
        } else if (hasSidMember(payload)) {
          scan.setsSid.push(site);
        } else {
          scan.withoutSid.push(site);
        }
      }
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      isSidTarget(node.left)
    ) {
      scan.sidWrites.push({ file, within: enclosingName(node) });
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

function emptyScan(): Scan {
  return { setsSid: [], withoutSid: [], passThrough: [], sidWrites: [] };
}

function scanWorkspace(): Scan {
  const scan = emptyScan();
  for (const root of ['apps', 'libs']) {
    for (const path of productionSources(join(WORKSPACE_ROOT, root))) {
      const text = readFileSync(path, 'utf8');
      const named = [...ID_TOKEN_SIGNERS].some((signer) => text.includes(signer));
      if (!named && !text.includes('sid')) continue;
      scanSource(relative(WORKSPACE_ROOT, path), text, scan);
    }
  }
  return scan;
}

describe('the ID token’s sid comes from the code exchange alone (#549)', () => {
  const scan = scanWorkspace();

  it('is set by exactly one signer call: the authorization code exchange', () => {
    expect(scan.setsSid).toEqual([
      { file: 'apps/auth-server/src/app/routes/oauth/token.ts', within: 'handleAuthorizationCode' },
    ]);
  });

  it('reaches the signers otherwise only through their own delegations', () => {
    expect(scan.passThrough).toEqual(
      expect.arrayContaining([
        { file: 'libs/server/jwt/src/lib/jwt-service.ts', within: 'signIdToken' },
        { file: 'libs/server/jwt/src/lib/hybrid-jwt-service.ts', within: 'signHybridIdToken' },
      ])
    );
    for (const site of scan.passThrough) {
      expect(
        [
          'libs/server/jwt/src/lib/jwt-service.ts#signIdToken',
          'libs/server/jwt/src/lib/hybrid-jwt-service.ts#signHybridIdToken',
          'libs/fastify/plugins/jwt/src/lib/fastify-plugin-jwt.ts#signIdToken',
        ],
        `${site.file} passes an ID-token payload it did not write in place`
      ).toContain(`${site.file}#${site.within}`);
    }
  });

  it('is written into a claim set only by the claim builder', () => {
    const inSignerHomes = scan.sidWrites.filter((site) =>
      SIGNER_HOMES.some((home) => site.file.startsWith(home))
    );
    expect(inSignerHomes).toEqual([
      { file: 'libs/server/jwt/src/lib/jwt-service.ts', within: 'buildIdTokenClaims' },
    ]);
  });

  it('finds a sid however the payload spells it, and a payload built elsewhere', () => {
    const sample = emptyScan();
    scanSource(
      'sample.ts',
      `
        async function plain(app, s) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c', sid: s }); }
        async function shorthand(app, sid) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c', sid }); }
        async function quoted(s) { await signIdToken({ sub: 'u', audience: 'c', 'sid': s }, k, i, 1); }
        async function spread(s) { buildIdTokenClaims({ sub: 'u', audience: 'c', ...(s ? { sid: s } : {}) }); }
        async function clean(app) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c' }); }
        async function variable(app, payload) { await app.jwtUtils.signIdToken(payload); }
        function write(claims, s) { claims['sid'] = s; claims.sid = s; }
      `,
      sample
    );

    expect(sample.setsSid.map((site) => site.within)).toEqual([
      'plain',
      'shorthand',
      'quoted',
      'spread',
    ]);
    expect(sample.withoutSid.map((site) => site.within)).toEqual(['clean']);
    expect(sample.passThrough.map((site) => site.within)).toEqual(['variable']);
    expect(sample.sidWrites.map((site) => site.within)).toEqual(['write', 'write']);
  });
});
