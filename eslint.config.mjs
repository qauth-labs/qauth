import nx from '@nx/eslint-plugin';
import prettierPlugin from 'eslint-plugin-prettier';
import simpleImportSort from 'eslint-plugin-simple-import-sort';

export default [
  ...nx.configs['flat/base'],
  ...nx.configs['flat/typescript'],
  ...nx.configs['flat/javascript'],
  {
    ignores: [
      '**/.expo/**',
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
              onlyDependOnLibsWithTags: ['scope:infra', 'scope:shared'],
            },
            // Server utilities layer
            // Server libraries contain business logic utilities (password, config, etc.)
            // Can depend on: other server libs, shared libs
            // Cannot depend on: infra, fastify, app layers
            {
              sourceTag: 'scope:server',
              onlyDependOnLibsWithTags: ['scope:server', 'scope:shared'],
            },
            // Fastify plugins layer
            // Fastify plugins wrap infrastructure and server utilities for Fastify
            // Can depend on: other fastify plugins, server libs, infra libs, shared libs
            // Cannot depend on: app layer
            {
              sourceTag: 'scope:fastify',
              onlyDependOnLibsWithTags: [
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
