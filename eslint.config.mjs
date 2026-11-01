import { globSync } from 'node:fs';
import { dirname, join } from 'node:path';

import nx from '@nx/eslint-plugin';
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
  '{projectRoot}/vitest.config.mts',
  // Tooling beside src/ that Nx 23's typecheck inputs (the tsconfig includes)
  // left out and Nx 24's `default` input takes in: wire-suite's runner config,
  // infra-db's drizzle-kit config, crypto-native's packaging script and
  // resource-guard's runnable example. None of them ships with the package.
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
 * infers `tsgo -p <config> --noEmit` here (`tsc` by default), the rule falls
 * back to tsconfig.base.json, and it would call tslib unused in every one of
 * them.
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
 * ESLint runs one rule here: `@nx/dependency-checks`, on package.json files.
 * Everything else, the Nx module boundaries and the key custody guard
 * included, is Oxlint's (.oxlintrc.json), and formatting is Oxfmt's
 * (.oxfmtrc.json). Oxlint does not lint JSON, so this rule stays on ESLint,
 * as the `dependency-checks` target that @nx/eslint/plugin infers for every
 * project with a package.json (nx.json). CI runs it in the `affected (lint)`
 * leg, beside Oxlint's `lint`.
 */
export default [
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
      // ESLint lints .js, .cjs and .mjs files unless told not to, and every
      // file a block below names. Only package.json is ESLint's now, and a
      // project with no package.json (test-vectors) then has nothing to lint,
      // so @nx/eslint/plugin infers no target for it.
      '**/*.js',
      '**/*.cjs',
      '**/*.mjs',
      '**/*.json',
      '!**/package.json',
    ],
  },
  {
    plugins: { '@nx': nx },
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
];
