/**
 * Production Node server for the developer portal.
 *
 * `vite build` builds this file as the SSR environment's entry, in place of
 * Start's own server entry, which it imports (see `vite.config.mts`). srvx and
 * every runtime dependency are bundled into `server/`, so the image needs no
 * `node_modules`.
 * It serves the built client assets from `public/` and hands every other
 * request to Start's fetch handler: pages, server functions, redirects, 404s.
 *
 * Listens on PORT (default 3000) and HOST (default: all interfaces), the same
 * variables the Nitro build honoured.
 */
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { serve } from 'srvx';
import { staticMiddleware } from 'srvx/static';
import serverEntry from 'virtual:tanstack-start-server-entry';

const publicDir = fileURLToPath(new URL('../public', import.meta.url));

// Vite gives everything under /assets a content hash in its name, so a hit can
// be cached for good. Anything else in public/ keeps revalidating. A miss falls
// through to Start, which renders the 404 page without any of these headers.
const hashedAssets = staticMiddleware({ dir: publicDir, maxAge: 31_536_000, immutable: true });
const otherFiles = staticMiddleware({ dir: publicDir });

// public/'s other top-level entries (none today; Vite copies an app public/ dir
// here if one is added), read once. Every other path goes straight to Start, so
// rendering a page costs no filesystem lookups: probing public/ for `/login`
// (login, login.html, login/index.html) cut SSR throughput under concurrency.
const otherEntries = new Set(readdirSync(publicDir).filter((name) => name !== 'assets'));

serve({
  middleware: [
    (request, next) => {
      const { pathname } = new URL(request.url);
      if (pathname.startsWith('/assets/')) return hashedAssets(request, next);
      if (otherEntries.has(pathname.split('/')[1] ?? '')) return otherFiles(request, next);
      return next();
    },
  ],
  fetch: (request) => serverEntry.fetch(request),
});
