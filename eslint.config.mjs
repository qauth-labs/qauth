import nx from '@nx/eslint-plugin';
import prettierPlugin from 'eslint-plugin-prettier';
import simpleImportSort from 'eslint-plugin-simple-import-sort';
import jsoncParser from 'jsonc-eslint-parser';

/**
 * Files inside a project that are NOT part of what it ships: build tooling and
 * test code. Imports made only from these belong in devDependencies, so
 * `@nx/dependency-checks` must not read them. Without this the rule would take
 * the whole `{projectRoot}/src/**\/*.ts` typecheck input set at face value and
 * demand vitest, testcontainers and friends in `dependencies`.
 */
const NON_SHIPPED_FILES = [
  '{projectRoot}/vite.config.ts',
  '{projectRoot}/vite.config.mts',
  '{projectRoot}/vitest.config.ts',
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
  /** @type {Array<{ files: string[]; ignoredDependencies?: string[] }>} */
  const scopes = [
    { files: ['**/package.json'] },
    {
      files: ['libs/ui/package.json'],
      // Both are peerDependencies: requirements this component library places
      // on its host, not packages it imports. `react-dom` renders the exported
      // components (only the .test.tsx files import it directly); `tailwindcss`
      // is the styling contract behind every utility class the components emit.
      // Neither has an import site in shipped source, by design.
      ignoredDependencies: ['react-dom', 'tailwindcss'],
    },
  ];

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
        },
      ],
    },
  }));
}

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
