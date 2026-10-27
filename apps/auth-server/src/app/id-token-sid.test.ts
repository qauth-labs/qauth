import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import type { resolveAcrClaims } from './helpers/acr-claims';
import type { resolveEmailClaimsForScopes } from './helpers/email-claims';
import type { resolveProfileClaimsForScopes } from './helpers/profile-claims';

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
 * Every production source file of `apps/` and `libs/` is parsed (syntax only,
 * no type checker), and every mention of an ID-token signer (`signIdToken`,
 * `signHybridIdToken`, `buildIdTokenClaims`) is classified:
 *
 * - a call whose payload is written in place, with or without a `sid` member
 *   anywhere in it (plain, shorthand, quoted or computed keys, and object
 *   literals spread into it);
 * - a call whose payload comes from elsewhere, which only the signers' own
 *   delegations may do, so every real caller writes its payload where this
 *   test reads it;
 * - a spread into an in-place payload of something other than an object
 *   literal (a variable, a helper's result), which this test cannot read: the
 *   list is pinned, and each helper's return type is checked below to have no
 *   `sid` key;
 * - any other mention of a signer (an alias, `.call`, `.bind`, a value passed
 *   along), which would let a call escape the rules above: there is none.
 *
 * The claim builder is the one place in the signers' libraries that writes a
 * `sid` claim into a claim set. The integration suite
 * (`id-token-sid.integration.test.ts`) checks the tokens themselves.
 *
 * The scan reads the whole workspace, while this project's Nx `test` target
 * hashes only its own inputs; CI's coverage job runs every unit test on each
 * pull request without the Nx cache, so a change elsewhere is still checked.
 */

const WORKSPACE_ROOT = resolve(__dirname, '../../../..');

/** The functions that sign an ID token or build its claims. */
const ID_TOKEN_SIGNERS = new Set(['signIdToken', 'signHybridIdToken', 'buildIdTokenClaims']);

/** Where the signers live: the only files that may assign a `sid` claim. */
const SIGNER_HOMES = ['libs/server/jwt/src/', 'libs/fastify/plugins/jwt/src/'];

const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'out-tsc', 'coverage', 'tmp', 'testing']);

/** One place in the source. */
interface Site {
  /** Workspace-relative path. */
  readonly file: string;
  /** The nearest named function around it. */
  readonly within: string;
}

/** A spread into an in-place payload that the scan cannot read. */
interface OpaqueSpread extends Site {
  /** The spread expression's source text. */
  readonly spread: string;
}

interface Scan {
  /** Calls whose in-place payload has a `sid` member. */
  readonly setsSid: Site[];
  /** Calls whose in-place payload has none. */
  readonly withoutSid: Site[];
  /** Calls that pass a payload built elsewhere. */
  readonly passThrough: Site[];
  /** Spreads of something other than an object literal into an in-place payload. */
  readonly opaqueSpreads: OpaqueSpread[];
  /** Mentions of a signer that are neither a call nor a declaration. */
  readonly escaped: Site[];
  /** Assignments to a `sid` member (`x.sid = …`, `x['sid'] = …`). */
  readonly sidWrites: Site[];
}

function emptyScan(): Scan {
  return {
    setsSid: [],
    withoutSid: [],
    passThrough: [],
    opaqueSpreads: [],
    escaped: [],
    sidWrites: [],
  };
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

function enclosingName(node: ts.Node): string {
  for (let at: ts.Node | undefined = node.parent; at !== undefined; at = at.parent) {
    if (
      (ts.isFunctionDeclaration(at) || ts.isMethodDeclaration(at) || ts.isFunctionExpression(at)) &&
      at.name !== undefined
    ) {
      return at.name.getText();
    }
  }
  return '<module>';
}

/** The text of a key written as a name, a string or a computed string. */
function keyText(name: ts.PropertyName | ts.Expression): string | undefined {
  if (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) return name.text;
  if (ts.isComputedPropertyName(name)) return keyText(name.expression);
  return undefined;
}

/** The signer a call's callee names: `f(…)`, `x.f(…)` or `x['f'](…)`. */
function calleeName(call: ts.CallExpression): string | undefined {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  if (ts.isElementAccessExpression(callee)) return keyText(callee.argumentExpression);
  return undefined;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let at = expression;
  while (
    ts.isParenthesizedExpression(at) ||
    ts.isAsExpression(at) ||
    ts.isSatisfiesExpression(at)
  ) {
    at = at.expression;
  }
  return at;
}

/** Whether a spread's expression is object literals the scan reads in full. */
function isReadableSpread(expression: ts.Expression): boolean {
  const at = unwrap(expression);
  if (ts.isObjectLiteralExpression(at)) return true;
  if (ts.isConditionalExpression(at)) {
    return isReadableSpread(at.whenTrue) && isReadableSpread(at.whenFalse);
  }
  return false;
}

/** Whether an in-place payload has a `sid` member, at any depth. */
function hasSidMember(node: ts.Node): boolean {
  if (
    (ts.isPropertyAssignment(node) ||
      ts.isShorthandPropertyAssignment(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isGetAccessorDeclaration(node)) &&
    keyText(node.name) === 'sid'
  ) {
    return true;
  }
  return ts.forEachChild(node, (child) => hasSidMember(child) || undefined) ?? false;
}

/** The spreads of an in-place payload, at any depth, that the scan cannot read. */
function opaqueSpreadsOf(node: ts.Node): ts.SpreadAssignment[] {
  const found: ts.SpreadAssignment[] = [];
  const visit = (at: ts.Node): void => {
    if (ts.isSpreadAssignment(at) && !isReadableSpread(at.expression)) found.push(at);
    ts.forEachChild(at, visit);
  };
  visit(node);
  return found;
}

function isSidTarget(target: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(target)) return target.name.text === 'sid';
  if (ts.isElementAccessExpression(target)) return keyText(target.argumentExpression) === 'sid';
  return false;
}

/**
 * Whether a node that names a signer is the callee of a call, through
 * `f`, `x.f` or `x['f']`.
 */
function isCallee(node: ts.Node): boolean {
  let callee: ts.Node = node;
  if (
    (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) ||
    (ts.isElementAccessExpression(node.parent) && node.parent.argumentExpression === node)
  ) {
    callee = node.parent;
  }
  return ts.isCallExpression(callee.parent) && callee.parent.expression === callee;
}

/** Whether a node that names a signer declares, imports or exports it. */
function isDeclarationName(node: ts.Node): boolean {
  const parent = node.parent;
  return (
    ((ts.isFunctionDeclaration(parent) ||
      ts.isMethodDeclaration(parent) ||
      ts.isMethodSignature(parent) ||
      ts.isPropertySignature(parent)) &&
      parent.name === node) ||
    ts.isImportSpecifier(parent) ||
    ts.isExportSpecifier(parent)
  );
}

/** Classify every signer mention and `sid` write in one source text. */
function scanSource(file: string, text: string, scan: Scan): void {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      if (name !== undefined && ID_TOKEN_SIGNERS.has(name)) {
        const site = { file, within: enclosingName(node) };
        const [first] = node.arguments;
        const payload = first === undefined ? undefined : unwrap(first);
        if (payload === undefined || !ts.isObjectLiteralExpression(payload)) {
          scan.passThrough.push(site);
        } else {
          (hasSidMember(payload) ? scan.setsSid : scan.withoutSid).push(site);
          for (const spread of opaqueSpreadsOf(payload)) {
            scan.opaqueSpreads.push({ ...site, spread: spread.expression.getText(source) });
          }
        }
      }
    }
    if (
      (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
      ID_TOKEN_SIGNERS.has(node.text) &&
      (ts.isIdentifier(node) || ts.isElementAccessExpression(node.parent)) &&
      !isCallee(node) &&
      !isDeclarationName(node)
    ) {
      scan.escaped.push({ file, within: enclosingName(node) });
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

/**
 * The type a `sid` key may hold in a claim set's type, taken over each member
 * of a union: `never` when no member can hold one. An index signature admits
 * `sid` with the signature's value type, so `Record<string, never>` (the empty
 * claim set) holds nothing while `Record<string, unknown>` holds anything.
 */
type SidValue<T> = T extends unknown
  ? 'sid' extends keyof T
    ? T[Extract<'sid', keyof T>]
    : never
  : never;

/** `true` when a claim set's type cannot carry a `sid` value. */
type HasNoSid<T> = [SidValue<T>] extends [never] ? true : false;

/**
 * The helpers spread into the code exchange's ID token cannot add `sid`: each
 * return type has no such key, and a type that admits any key (an index
 * signature) fails too. A compile-time check: `typecheck` fails when one
 * changes.
 */
const SPREAD_HELPERS_CARRY_NO_SID: [
  HasNoSid<Awaited<ReturnType<typeof resolveEmailClaimsForScopes>>>,
  HasNoSid<ReturnType<typeof resolveProfileClaimsForScopes>>,
  HasNoSid<ReturnType<typeof resolveAcrClaims>>,
] = [true, true, true];

describe('the ID token’s sid comes from the code exchange alone (#549)', () => {
  const scan = scanWorkspace();

  it('is set by exactly one signer call: the authorization code exchange', () => {
    expect(scan.setsSid).toEqual([
      { file: 'apps/auth-server/src/app/routes/oauth/token.ts', within: 'handleAuthorizationCode' },
    ]);
  });

  it('is spread in only from helpers whose results cannot carry it', () => {
    expect(SPREAD_HELPERS_CARRY_NO_SID).toEqual([true, true, true]);
    expect(scan.opaqueSpreads).toEqual([
      {
        file: 'apps/auth-server/src/app/routes/oauth/token.ts',
        within: 'handleAuthorizationCode',
        spread: 'emailClaims',
      },
      {
        file: 'apps/auth-server/src/app/routes/oauth/token.ts',
        within: 'handleAuthorizationCode',
        spread: 'resolveProfileClaimsForScopes(user, authCode.scopes)',
      },
      {
        file: 'apps/auth-server/src/app/routes/oauth/token.ts',
        within: 'handleAuthorizationCode',
        spread: 'resolveAcrClaims(authCode.assuranceLevel)',
      },
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

  it('is never reached through an alias, `.call` or a signer passed as a value', () => {
    expect(scan.escaped).toEqual([]);
  });

  it('is written into a claim set only by the claim builder', () => {
    const inSignerHomes = scan.sidWrites.filter((site) =>
      SIGNER_HOMES.some((home) => site.file.startsWith(home))
    );
    expect(inSignerHomes).toEqual([
      { file: 'libs/server/jwt/src/lib/jwt-service.ts', within: 'buildIdTokenClaims' },
    ]);
  });

  it('finds a sid however the payload spells it, and every way around the rules', () => {
    const sample = emptyScan();
    scanSource(
      'sample.ts',
      `
        async function plain(app, s) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c', sid: s }); }
        async function shorthand(app, sid) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c', sid }); }
        async function quoted(s) { await signIdToken({ sub: 'u', audience: 'c', 'sid': s }, k, i, 1); }
        async function computed(s) { await signIdToken({ sub: 'u', audience: 'c', ['sid']: s }, k, i, 1); }
        async function spread(s) { buildIdTokenClaims({ sub: 'u', audience: 'c', ...(s ? { sid: s } : {}) }); }
        async function bracket(app, s) { await app.jwtUtils['signIdToken']({ sub: 'u', audience: 'c', sid: s }); }
        async function clean(app) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c' }); }
        async function helper(app, s) { await app.jwtUtils.signIdToken({ sub: 'u', audience: 'c', ...claimsOf(s) }); }
        async function variable(app, payload) { await app.jwtUtils.signIdToken(payload); }
        async function aliased(app, s) { const sign = app.jwtUtils.signIdToken; await sign({ sid: s }); }
        async function called(app, p) { await app.jwtUtils.signIdToken.call(app.jwtUtils, p); }
        async function bound(app) { return [signIdToken].map((f) => f); }
        function write(claims, s) { claims['sid'] = s; claims.sid = s; }
      `,
      sample
    );

    expect(sample.setsSid.map((site) => site.within)).toEqual([
      'plain',
      'shorthand',
      'quoted',
      'computed',
      'spread',
      'bracket',
    ]);
    expect(sample.withoutSid.map((site) => site.within)).toEqual(['clean', 'helper']);
    expect(sample.opaqueSpreads.map((site) => [site.within, site.spread])).toEqual([
      ['helper', 'claimsOf(s)'],
    ]);
    expect(sample.passThrough.map((site) => site.within)).toEqual(['variable']);
    expect(sample.escaped.map((site) => site.within)).toEqual(['aliased', 'called', 'bound']);
    expect(sample.sidWrites.map((site) => site.within)).toEqual(['write', 'write']);
  });
});
