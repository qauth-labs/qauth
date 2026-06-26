import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { nxCopyAssetsPlugin } from '@nx/vite/plugins/nx-copy-assets.plugin';
import { nxViteTsPaths } from '@nx/vite/plugins/nx-tsconfig-paths.plugin';
import tailwindcss from '@tailwindcss/vite';
import { nitroV2Plugin } from '@tanstack/nitro-v2-vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import react from '@vitejs/plugin-react';
import { defineConfig, type PluginOption } from 'vite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
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
  plugins: [
    ...(tailwindcss() as PluginOption[]),
    tanstackStart(),
    // Nitro emits a self-listening Node server (`server/index.mjs`) plus static
    // assets (`public/`), so the portal needs no custom adapter. Output goes to
    // the Nx dist dir for cache + Docker consistency. compatibilityDate pins
    // Nitro's preset behaviour (bump deliberately, not implicitly).
    nitroV2Plugin({
      compatibilityDate: '2026-06-26',
      output: {
        dir: path.join(__dirname, '../../dist/apps/developer-portal'),
      },
    }),
    react(),
    nxViteTsPaths(),
    nxCopyAssetsPlugin(['*.md']),
  ],
});
