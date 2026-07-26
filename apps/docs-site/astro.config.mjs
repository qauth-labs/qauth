import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

// QAuth documentation site (docs.qauth.dev), #347. Task 2 owns the sidebar
// and information architecture — this config intentionally stops at the
// integration + build wiring.
export default defineConfig({
  site: 'https://docs.qauth.dev',
  output: 'static',
  // Astro's default `outDir` is `./dist` relative to this project. Nx's
  // `build` target (project.json) declares its output as the
  // workspace-level `dist/apps/docs-site`, so `outDir` is redirected here to
  // match — a declared Nx output that does not match reality breaks caching
  // silently.
  outDir: '../../dist/apps/docs-site',
  integrations: [
    starlight({
      title: 'QAuth',
    }),
  ],
});
