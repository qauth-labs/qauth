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
 * variables the Nitro build honoured. Request bodies are capped at 1 MiB.
 * PORTAL_TRUST_PROXY lists the proxies in front of the portal (default: none).
 */
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { serve } from 'srvx';
import { staticMiddleware } from 'srvx/static';
import serverEntry from 'virtual:tanstack-start-server-entry';

import { parsePortalTrustProxy } from './server/trust-proxy';

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

// The largest request body the portal reads. Server functions take small JSON
// payloads (the largest, a client create or update, is a few KB), so 1 MiB
// leaves ample room.
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;

// The proxies whose X-Forwarded-For, X-Forwarded-Proto and X-Forwarded-Host
// srvx believes (see server/trust-proxy.ts). With none listed, the client
// address is the TCP peer and the request URL is the one received. An invalid
// value stops the server here, before it listens.
let trustProxy: false | string[];
try {
  trustProxy = parsePortalTrustProxy(process.env['PORTAL_TRUST_PROXY']);
} catch (error) {
  console.error(`[developer-portal] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

serve({
  trustProxy,
  // srvx counts the bytes as the body streams in, with or without a
  // Content-Length, and stops reading at the limit: `request.json()` and the
  // other body readers then reject instead of buffering the rest.
  maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
  // A request must arrive in full within 30 s, its headers within 15 s
  // (Node's defaults: 300 s and 60 s), so a slow upload does not hold a
  // connection and its buffered body for long.
  node: { requestTimeout: 30_000, headersTimeout: 15_000 },
  middleware: [
    // A body declared larger than the limit is refused before any handler
    // runs. `Connection: close` ends the connection after the response, so
    // the server does not go on reading the body it refused.
    (request, next) => {
      const declaredLength = Number(request.headers.get('content-length'));
      if (declaredLength > MAX_REQUEST_BODY_BYTES) {
        return new Response(null, { status: 413, headers: { Connection: 'close' } });
      }
      return next();
    },
    (request, next) => {
      const { pathname } = new URL(request.url);
      if (pathname.startsWith('/assets/')) return hashedAssets(request, next);
      if (otherEntries.has(pathname.split('/')[1] ?? '')) return otherFiles(request, next);
      return next();
    },
  ],
  fetch: (request) => serverEntry.fetch(request),
});
