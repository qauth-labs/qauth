import path from 'node:path';
import { fileURLToPath } from 'node:url';

import tailwindcss from '@tailwindcss/vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, type PluginOption } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Nx dist dir, for cache + Docker consistency: `server/index.mjs` (the Node
// server) and `public/` (client assets), the layout the Dockerfile copies.
const outDir = path.join(__dirname, '../../dist/apps/developer-portal');

export default defineConfig(({ command }) => ({
  cacheDir: '../../node_modules/.vite/apps/developer-portal',
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
    },
  },
  root: __dirname,
  server: {
    port: 3000,
  },
  // No Nitro: TanStack Start's plugin alone builds a client and an SSR
  // environment. The SSR build's entry is `index` (src/node-entry.ts, a small
  // srvx server) instead of Start's server entry, which `index` imports.
  // `noExternal: true` bundles every dependency, srvx included, so `server/`
  // runs with no node_modules. Build only: in `vite dev` it pushes CommonJS
  // deps through Vite's module runner, and every request 500s with
  // `module is not defined`.
  // `.mjs` names because nothing marks the copied output `"type": "module"`.
  environments: {
    client: {
      build: { outDir: path.join(outDir, 'public') },
    },
    ssr: {
      ...(command === 'build' && { resolve: { noExternal: true } }),
      build: {
        outDir: path.join(outDir, 'server'),
        rolldownOptions: {
          input: { index: path.join(__dirname, 'src/node-entry.ts') },
          output: {
            entryFileNames: '[name].mjs',
            chunkFileNames: '_chunks/[name]-[hash].mjs',
          },
        },
      },
    },
  },
  plugins: [
    ...(tailwindcss() as PluginOption[]),
    tanstackStart({
      // Tests are colocated with routes; exclude them from the route generator
      // so it doesn't warn that *.test.tsx files don't export a Route.
      router: {
        routeFileIgnorePattern: '\\.(test|spec)\\.[jt]sx?$',
      },
    }),
    react(),
  ],
}));
