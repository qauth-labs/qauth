import { readdirSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

import {
  AUTH_METHOD_DISPLAY_NAME_PATTERN,
  RESERVED_AUTH_METHOD_TYPES,
  UPSTREAM_STEP_URN,
} from '@qauth-labs/plugin-sdk';
import { DISPLAY_TEXT_PATTERN, stepUrn } from '@qauth-labs/shared-interaction-contract';
import * as ts from 'typescript';
import { describe, expect, it } from 'vitest';

import { PASSWORD_PROVIDER_TYPE, SELF_REPORTED_SOURCE } from '../providers/password.provider';
import { WALLET_PROVIDER_TYPE } from '../providers/wallet.provider';
import { WEBAUTHN_PROVIDER_TYPE } from '../providers/webauthn.provider';

/**
 * ONE COPY OF THE CONTRACT (#1009). The AuthMethod contract (its types, its
 * constants, its errors, its checks and the test kit) is declared in
 * `@qauth-labs/plugin-sdk`, the package a plugin is written against in its own
 * repository. This library re-exports it and must declare none of it again: a
 * second copy could drift, and a plugin would be held by the server to a
 * contract other than the one it was built and tested against.
 *
 * So every name an entry point of the SDK exports is, in this library, either
 * a re-export that resolves to the SDK's own declaration or absent; and no
 * module of this library declares a top-level name the SDK exports, exported
 * or not.
 */

const FEDERATION_SOURCE = resolve(__dirname, '..');
const SDK_SOURCE = resolve(__dirname, '../../../../sdk/plugin-sdk/src');
const SDK_ENTRIES = ['index.ts', 'host.ts', 'testing/index.ts'].map((entry) =>
  join(SDK_SOURCE, entry)
);
const FEDERATION_ENTRY = join(FEDERATION_SOURCE, 'index.ts');

/** Every `.ts` module of this library's source, tests left out. */
function federationModules(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return federationModules(path);
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : [];
  });
}

/** The names a declaration statement declares at the top level of a module. */
function declaredNames(statement: ts.Statement): string[] {
  if (ts.isVariableStatement(statement)) {
    return statement.declarationList.declarations.flatMap((declaration) =>
      ts.isIdentifier(declaration.name) ? [declaration.name.text] : []
    );
  }
  if (
    (ts.isFunctionDeclaration(statement) ||
      ts.isClassDeclaration(statement) ||
      ts.isInterfaceDeclaration(statement) ||
      ts.isTypeAliasDeclaration(statement) ||
      ts.isEnumDeclaration(statement)) &&
    statement.name !== undefined
  ) {
    return [statement.name.text];
  }
  return [];
}

const inSdk = (file: string) => resolve(file).startsWith(SDK_SOURCE + sep);

// Building one TypeScript program over both libraries takes a few seconds,
// more while CI runs every project's suite at once.
describe(
  'the AuthMethod contract has one copy, in @qauth-labs/plugin-sdk',
  { timeout: 60_000 },
  () => {
    const program = ts.createProgram([...SDK_ENTRIES, FEDERATION_ENTRY], {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      strict: true,
      noEmit: true,
      skipLibCheck: true,
      types: ['node'],
    });
    const checker = program.getTypeChecker();

    const exportsOf = (file: string): ts.Symbol[] => {
      const source = program.getSourceFile(file);
      if (source === undefined) throw new Error(`${file} is not part of the program`);
      const module = checker.getSymbolAtLocation(source);
      if (module === undefined) throw new Error(`${file} is not a module`);
      return checker.getExportsOfModule(module);
    };
    const target = (symbol: ts.Symbol): ts.Symbol =>
      symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;

    const sdkNames = new Set(SDK_ENTRIES.flatMap(exportsOf).map((symbol) => symbol.name));

    it('finds the names it is asserting about', () => {
      expect(sdkNames.size).toBeGreaterThan(80);
      for (const name of ['AuthMethod', 'AUTH_METHOD_CONTRACT', 'checkAuthMethod']) {
        expect(sdkNames.has(name)).toBe(true);
      }
    });

    it('re-exports every contract name it exports from the SDK, never from a copy', () => {
      const copies: string[] = [];
      let reExported = 0;
      for (const symbol of exportsOf(FEDERATION_ENTRY)) {
        if (!sdkNames.has(symbol.name)) continue;
        reExported += 1;
        const declarations = target(symbol).declarations ?? [];
        const elsewhere = declarations
          .map((declaration) => declaration.getSourceFile().fileName)
          .filter((file) => !inSdk(file));
        if (declarations.length === 0 || elsewhere.length > 0) {
          copies.push(
            `${symbol.name}: ${elsewhere.map((file) => relative(FEDERATION_SOURCE, file)).join(', ')}`
          );
        }
      }
      expect(reExported).toBeGreaterThan(80);
      expect(copies).toEqual([]);
    });

    it('declares no name the SDK exports in any of its modules', () => {
      const copies: string[] = [];
      for (const file of federationModules(FEDERATION_SOURCE)) {
        const source = program.getSourceFile(file);
        if (source === undefined) continue;
        for (const statement of source.statements) {
          for (const name of declaredNames(statement)) {
            if (sdkNames.has(name)) copies.push(`${relative(FEDERATION_SOURCE, file)}: ${name}`);
          }
        }
      }
      expect(copies).toEqual([]);
    });
  }
);

describe('the values the SDK writes out still equal their sources', () => {
  it('names the upstream step by the Interaction API step name rule', () => {
    expect(UPSTREAM_STEP_URN).toBe(stepUrn('upstream'));
  });

  it("holds a method's default name to the Interaction API's display rule", () => {
    expect(AUTH_METHOD_DISPLAY_NAME_PATTERN.source).toBe(DISPLAY_TEXT_PATTERN);
    expect(AUTH_METHOD_DISPLAY_NAME_PATTERN.flags).toBe('u');
  });

  it('reserves every credential type QAuth writes itself', () => {
    expect(RESERVED_AUTH_METHOD_TYPES).toEqual(
      expect.arrayContaining([
        PASSWORD_PROVIDER_TYPE,
        WALLET_PROVIDER_TYPE,
        WEBAUTHN_PROVIDER_TYPE,
        SELF_REPORTED_SOURCE,
      ])
    );
  });
});
