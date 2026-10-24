import { globSync } from 'node:fs';
import { dirname, join } from 'node:path';

import nx from '@nx/eslint-plugin';
import prettierPlugin from 'eslint-plugin-prettier';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import * as jsoncParser from 'jsonc-eslint-parser';
import ts from 'typescript';

/**
 * Files inside a project that are NOT part of what it ships: build tooling and
 * test code. Imports made only from these belong in devDependencies, so
 * `@nx/dependency-checks` must not read them. Without this the rule would take
 * the whole typecheck input set (`default`, so every file in the project since
 * Nx 24) at face value and demand vitest, testcontainers and friends in
 * `dependencies`.
 */
const NON_SHIPPED_FILES = [
  '{projectRoot}/vite.config.ts',
  '{projectRoot}/vite.config.mts',
  '{projectRoot}/vitest.config.ts',
  // Tooling beside src/ that Nx 23's typecheck inputs (the tsconfig includes)
  // left out and Nx 24's `default` input takes in: wire-suite's runner config,
  // infra-db's drizzle-kit config, crypto-native's packaging script and
  // mcp-guard's runnable example. None of them ships with the package.
  '{projectRoot}/vitest.*.config.ts',
  '{projectRoot}/drizzle.config.ts',
  '{projectRoot}/scripts/**',
  '{projectRoot}/examples/**',
  '{projectRoot}/**/*.test.ts',
  '{projectRoot}/**/*.test.tsx',
  '{projectRoot}/**/*.spec.ts',
  '{projectRoot}/**/*.spec.tsx',
  // Vitest harness for infra-db's `*.integration.test.ts` suites. It sits under
  // src/ (so the typecheck input set picks it up) but is deliberately not
  // re-exported from the library's entry point, so its imports are test-scope.
  '{projectRoot}/**/integration-setup.ts',
  // #240's E2E harness and reference mock wallet. Same shape as
  // integration-setup.ts above: under src/ so the typecheck input set picks it
  // up, but imported only by `*.integration.test.ts` and never reachable from
  // main.ts, so its imports (jose) are test-scope.
  '{projectRoot}/src/testing/**',
  // docs-site's drift guards. Same shape as src/testing/** above: under src/
  // (so the typecheck input set picks it up) but imported only from the
  // sibling `*.test.ts` files — astro.config.mjs, content.config.ts and the
  // .astro pages reach src/lib/ and src/plugins/ only, never src/invariants/.
  // Its imports (github-slugger) are test-scope.
  '{projectRoot}/src/invariants/**',
];

/**
 * The package.json of every project whose tsconfig.json turns on
 * `importHelpers`, so tsc's output imports its helpers from tslib and tslib is
 * a real dependency. `@nx/dependency-checks` finds that setting only in a
 * `tsc --build <config>` command, the typecheck shape Nx 23 inferred; Nx 24
 * infers `tsc -p <config> --noEmit`, the rule falls back to
 * tsconfig.base.json, and it would call tslib unused in every one of them.
 * Naming tslib as a runtime helper for exactly these projects restores the
 * Nx 23 verdicts: still required here, still obsolete everywhere else.
 */
function importHelpersManifests() {
  const root = import.meta.dirname;
  const host = {
    ...ts.sys,
    onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
      throw new Error(ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'));
    },
  };
  return globSync(['apps/*/package.json', 'libs/**/package.json'], {
    cwd: root,
    exclude: ['**/node_modules/**'],
  }).filter((manifest) => {
    const tsconfig = join(root, dirname(manifest), 'tsconfig.json');
    return (
      ts.sys.fileExists(tsconfig) &&
      ts.getParsedCommandLineOfConfigFile(tsconfig, {}, host)?.options.importHelpers === true
    );
  });
}

/**
 * Builds the `@nx/dependency-checks` config blocks.
 *
 * `buildTargets: ['typecheck', ...]` is deliberate and load-bearing. The rule
 * skips any project that has none of these targets, and only accepts a
 * workspace package as a legitimate dependency when that package itself has
 * one. Only four projects here have a `build` target; every project has
 * `typecheck`. Under the default `['build']` the rule would skip most libs
 * outright AND flag the genuinely-required `@qauth-labs/core-crypto` as
 * obsolete on auth-server, because core-crypto is typecheck-only. Listing
 * `typecheck` first makes the rule reason over the whole workspace.
 *
 * The per-project entries below are genuine false positives: real dependencies
 * that reach the project through a channel the rule cannot see. They are scoped
 * to a single package.json each rather than folded into a workspace-wide
 * `ignoredDependencies`, so the guard stays sharp everywhere else.
 */
function dependencyChecksConfigs() {
  const tslibManifests = importHelpersManifests();

  /** @type {Array<{ files: string[]; ignoredDependencies?: string[] }>} */
  const scopes = [
    { files: ['**/package.json'] },
    { files: tslibManifests },
    {
      files: ['libs/ui/package.json'],
      // Both are peerDependencies: requirements this component library places
      // on its host, not packages it imports. `react-dom` renders the exported
      // components (only the .test.tsx files import it directly); `tailwindcss`
      // is the styling contract behind every utility class the components emit.
      // Neither has an import site in shipped source, by design.
      ignoredDependencies: ['react-dom', 'tailwindcss'],
    },
    {
      files: ['apps/docs-site/package.json'],
      // Astro loads it at config time, when `markdown.remarkPlugins` is set:
      // since 7.4 the unified Markdown pipeline is an optional peer that astro
      // resolves itself, so nothing in the site imports it.
      ignoredDependencies: ['@astrojs/markdown-remark'],
    },
  ];

  // A later block replaces an earlier one's rule options for the files they
  // share, so each block carries the tslib helper itself when it covers only
  // importHelpers projects (libs/ui does).
  return scopes.map(({ files, ignoredDependencies }) => ({
    files,
    languageOptions: { parser: jsoncParser },
    rules: {
      '@nx/dependency-checks': [
        'error',
        {
          buildTargets: ['typecheck', 'build'],
          ignoredFiles: NON_SHIPPED_FILES,
          ...(ignoredDependencies ? { ignoredDependencies } : {}),
          ...(files.every((file) => tslibManifests.includes(file))
            ? { runtimeHelpers: ['tslib'] }
            : {}),
        },
      ],
    },
  }));
}

/**
 * The projects that may import `@qauth-labs/server-keys/custody` (see the key
 * custody guard below): the library itself and the signer's wiring.
 */
const KEY_CUSTODY_WIRING = ['libs/server/keys/**', 'libs/fastify/plugins/signer/**'];

/**
 * Any import below `@qauth-labs/server-keys/`: the `/custody` entry point or a
 * deep path into the package. Written without `/` so it reads the same as an
 * esquery regex inside a selector and as a `no-restricted-imports` pattern.
 */
const KEY_CUSTODY_IMPORT = /^@qauth-labs.server-keys./;

const KEY_CUSTODY_MESSAGE =
  "Only the signer's wiring imports the KEK provider and envelope API (ADR-019 Decision 9). " +
  "Sign, encrypt and read keys through the Signer interface of '@qauth-labs/server-keys'.";

export default [
  ...nx.configs['flat/base'],
  ...nx.configs['flat/typescript'],
  ...nx.configs['flat/javascript'],
  {
    ignores: [
      '**/.astro/**',
      '**/.expo/**',
      '**/.nitro/**',
      '**/.nx/**',
      '**/.cache/**',
      '**/coverage/**',
      '**/dist/**',
      '**/node_modules/**',
      '**/out-tsc/**',
      '**/web-build/**',
      '**/vitest.config.ts',
      '**/vitest.workspace.ts',
      '**/vite.config.*.timestamp*',
      '**/vitest.config.*.timestamp*',
      '**/routeTree.gen.ts',
    ],
  },
  {
    files: ['**/*.ts', '**/*.tsx', '**/*.js', '**/*.jsx'],
    rules: {
      '@nx/enforce-module-boundaries': [
        'error',
        {
          enforceBuildableLibDependency: true,
          allow: [],
          depConstraints: [
            // Shared layer (bottom layer - no internal dependencies)
            // Shared libraries contain pure utilities, errors, and common types
            // They can only depend on external npm packages, not other workspace libs
            {
              sourceTag: 'scope:shared',
              onlyDependOnLibsWithTags: [],
            },
            // Core layer (foundational primitives - the true bottom layer)
            // Core libraries provide low-level, framework-agnostic primitives
            // (crypto, encoding). Like the shared layer, they depend on nothing
            // internal (leaf) and are consumable by every layer above (infra,
            // server, fastify, app). Kept a strict leaf on purpose: a crypto
            // primitive must not reach up into domain/error libs.
            {
              sourceTag: 'scope:core',
              onlyDependOnLibsWithTags: [],
            },
            // UI layer
            // UI libraries contain React components and utilities
            // They can only depend on external npm packages, not other workspace libs
            {
              sourceTag: 'scope:ui',
              onlyDependOnLibsWithTags: [],
            },
            // Wire suite (#450, ADR-018 §5): the black-box HTTP suite in
            // apps/wire-suite. It may use `fetch`, `jose` and its own helpers,
            // and NO workspace project: a helper shared with the server could
            // carry the same encoding bug on both sides and hide it. Its
            // `type:testing` tag does not widen this, because Nx requires
            // every matching constraint to pass.
            {
              sourceTag: 'scope:wire-suite',
              onlyDependOnLibsWithTags: [],
            },
            // ...and nothing imports the wire suite.
            {
              sourceTag: '*',
              notDependOnLibsWithTags: ['scope:wire-suite'],
            },
            {
              sourceTag: 'type:testing',
              onlyDependOnLibsWithTags: [
                'scope:core',
                'scope:shared',
                'scope:ui',
                'scope:infra',
                'scope:server',
                'scope:fastify',
              ],
            },
            // Infrastructure layer
            // Infrastructure libraries handle external services (DB, Cache, etc.)
            // Can depend on: other infra libs, shared libs
            // Cannot depend on: server, fastify, app layers
            {
              sourceTag: 'scope:infra',
              onlyDependOnLibsWithTags: ['scope:core', 'scope:infra', 'scope:shared'],
            },
            // Server utilities layer
            // Server libraries contain business logic utilities (password, config, etc.)
            // Can depend on: other server libs, shared libs
            // Cannot depend on: infra, fastify, app layers
            {
              sourceTag: 'scope:server',
              onlyDependOnLibsWithTags: ['scope:core', 'scope:server', 'scope:shared'],
            },
            // Fastify plugins layer
            // Fastify plugins wrap infrastructure and server utilities for Fastify
            // Can depend on: other fastify plugins, server libs, infra libs, shared libs
            // Cannot depend on: app layer
            {
              sourceTag: 'scope:fastify',
              onlyDependOnLibsWithTags: [
                'scope:core',
                'scope:fastify',
                'scope:server',
                'scope:infra',
                'scope:shared',
              ],
            },
            // Application layer (top layer)
            // Applications are the entry points and can use all layers
            // Can depend on: fastify plugins, shared libs, ui
            {
              sourceTag: 'scope:app',
              onlyDependOnLibsWithTags: [
                'scope:core',
                'scope:fastify',
                'scope:shared',
                'scope:server-config',
                'scope:ui',
              ],
            },
            // The delivery role (ADR-019 Decisions 8 and 9, #460) holds no
            // private key and must not be able to load one. It is also
            // `scope:server`, and this narrows it: it reaches only the
            // shared layer (the event contract), never core-crypto, the
            // config library, server-jwt or server-keys. It signs through
            // the handle the signer role gives it.
            {
              sourceTag: 'type:event-delivery',
              onlyDependOnLibsWithTags: ['scope:shared'],
            },
            // Key custody (ADR-019 Decision 9)
            // `@qauth-labs/server-keys` is also `scope:server`, and Nx applies
            // every constraint whose tag a project carries, so this one narrows
            // it: the library that opens stored keys reaches only the core and
            // shared layers, never another server library such as config.
            {
              sourceTag: 'type:key-custody',
              onlyDependOnLibsWithTags: ['scope:core', 'scope:shared'],
            },
          ],
        },
      ],
    },
  },
  {
    files: [
      '**/*.ts',
      '**/*.tsx',
      '**/*.cts',
      '**/*.mts',
      '**/*.js',
      '**/*.jsx',
      '**/*.cjs',
      '**/*.mjs',
    ],
    // Override or add rules here
    rules: {},
  },

  // The experimental-feature registry (#476). `scripts/experimental-status.mjs`
  // loads libs/shared/stability through Node's own type stripping, which keeps
  // an import of a type that is not marked `type` and then finds no such
  // export at run time. So an import used only as a type says so. The
  // library's tsconfig sets `erasableSyntaxOnly` for the other half: no enum,
  // namespace or parameter property, which type stripping cannot remove.
  {
    files: ['libs/shared/stability/src/**/*.ts'],
    rules: {
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
    },
  },

  // Key custody guard (#464, ADR-019 Decision 9).
  //
  // ADR-019 provisions the KEK to the signer role alone. `@qauth-labs/server-keys`
  // therefore has two entry points: the package itself, with the `Signer`
  // interface and public facts that any project may import, and `/custody`, with
  // the KEK provider, the envelope API, the key factory and the in-process
  // signer. Only the signer's wiring may import `/custody`; every other project
  // signs, encrypts and reads keys through `Signer` (`fastify.signer`).
  //
  // `@nx/enforce-module-boundaries` works per project and cannot tell one entry
  // point of a package from another, so this is a path rule. It also refuses a
  // deep import such as `@qauth-labs/server-keys/src/lib/envelope`, which would
  // otherwise reach the same code past the entry point, and any string that
  // names either path, which covers `import()`, `require()` and the forms
  // `no-restricted-imports` does not see. A path assembled at run time still
  // passes: this keeps honest code honest, the signer role's own process and
  // database user are what hold the line (ADR-019 Decision 9). A KEK adapter package (#577-#579) joins KEY_CUSTODY_WIRING when it lands.
  {
    files: [
      '**/*.ts',
      '**/*.tsx',
      '**/*.cts',
      '**/*.mts',
      '**/*.js',
      '**/*.jsx',
      '**/*.cjs',
      '**/*.mjs',
    ],
    ignores: KEY_CUSTODY_WIRING,
    rules: {
      'no-restricted-imports': [
        'error',
        { patterns: [{ regex: KEY_CUSTODY_IMPORT.source, message: KEY_CUSTODY_MESSAGE }] },
      ],
      // Any other string naming the path: a dynamic import(), require(),
      // createRequire(...)(...), a type-level import('...'), or a template
      // literal. Import and export declarations are left to the rule above, so
      // each import is reported once.
      'no-restricted-syntax': [
        'error',
        {
          selector: `:not(ImportDeclaration, ExportNamedDeclaration, ExportAllDeclaration, TSExternalModuleReference) > Literal[value=${KEY_CUSTODY_IMPORT}]`,
          message: KEY_CUSTODY_MESSAGE,
        },
        {
          selector: `TemplateElement[value.raw=${KEY_CUSTODY_IMPORT}]`,
          message: KEY_CUSTODY_MESSAGE,
        },
      ],
    },
  },

  // Phantom-dependency guard (#370).
  //
  // Every project's package.json must declare, in a *production* section, every
  // package its shipped source actually imports. The auth-server image is built
  // with `pnpm --filter @qauth-labs/auth-server deploy --prod` and then runs the
  // TypeScript sources under tsx, so every import has to resolve at runtime from
  // a tree that has had devDependencies stripped. In the dev workspace the root
  // hoists everything and an undeclared import resolves anyway; in the image
  // pnpm's isolated layout does not, and the container crash-loops on boot.
  // This rule turns that runtime failure into a lint failure.
  ...dependencyChecksConfigs(),

  {
    plugins: {
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',
    },
  },
  {
    plugins: {
      prettier: prettierPlugin,
    },
    rules: {
      'prettier/prettier': 'error',
    },
  },
];
