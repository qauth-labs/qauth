/**
 * Production Node.js server for the QAuth developer portal.
 *
 * TanStack Start's Vite build emits a framework-agnostic fetch handler at
 * `server/server.js` (default export `{ fetch }`) plus static client assets
 * under `client/`. It does not ship a self-listening server, so this thin
 * adapter wires the fetch handler into `node:http` and serves the prebuilt
 * client assets. It depends only on Node built-ins.
 *
 * Layout expected at runtime (see Dockerfile):
 *   /app/server/server.js   <- TanStack Start fetch handler (default export)
 *   /app/client/...         <- hashed client assets + index html shell
 *   /app/server.mjs         <- this file (the container entrypoint)
 *
 * Env:
 *   PORT  (default 3001) — port to listen on
 *   HOST  (default 0.0.0.0) — interface to bind
 */
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLIENT_DIR = join(__dirname, 'client');

const PORT = Number(process.env.PORT ?? 3001);
const HOST = process.env.HOST ?? '0.0.0.0';

// The TanStack Start server entry resolves its dependencies (react, @tanstack/*)
// from node_modules. Importing it lazily keeps any resolution error visible.
const { default: handler } = await import('./server/server.js');

const MIME = {
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

/** Resolve a request path to a real file under CLIENT_DIR, or null. */
async function resolveStaticFile(pathname) {
  // Block path traversal: normalize and ensure the result stays in CLIENT_DIR.
  const safe = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  const filePath = join(CLIENT_DIR, safe);
  if (!filePath.startsWith(CLIENT_DIR)) return null;
  try {
    const s = await stat(filePath);
    if (s.isFile()) return filePath;
  } catch {
    /* not a static file */
  }
  return null;
}

/** Convert a Node IncomingMessage into a WHATWG Request. */
function toWebRequest(req) {
  const proto = (req.headers['x-forwarded-proto'] || 'http').toString().split(',')[0];
  const host = req.headers.host ?? `${HOST}:${PORT}`;
  const url = new URL(req.url ?? '/', `${proto}://${host}`);
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(key, v);
    else headers.set(key, value);
  }
  const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
  return new Request(url, {
    method: req.method,
    headers,
    body: hasBody ? Readable.toWeb(req) : undefined,
    duplex: hasBody ? 'half' : undefined,
  });
}

/** Pipe a WHATWG Response back onto the Node ServerResponse. */
async function writeWebResponse(webRes, res) {
  res.statusCode = webRes.status;
  webRes.headers.forEach((value, key) => res.setHeader(key, value));
  if (!webRes.body) {
    res.end();
    return;
  }
  await new Promise((resolve, reject) => {
    const nodeStream = Readable.fromWeb(webRes.body);
    nodeStream.on('error', reject);
    res.on('close', resolve);
    nodeStream.pipe(res);
  });
}

const server = createServer(async (req, res) => {
  try {
    // Liveness probe: answered by the adapter itself so a HEALTHCHECK never
    // depends on the upstream auth-server being reachable. It only confirms
    // the Node process is up and accepting connections.
    if (req.url === '/healthz') {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.end('ok');
      return;
    }

    // Static assets first (cheap, avoids running the SSR handler for files).
    if (req.method === 'GET' || req.method === 'HEAD') {
      const filePath = await resolveStaticFile(new URL(req.url ?? '/', 'http://x').pathname);
      if (filePath) {
        res.statusCode = 200;
        res.setHeader('Content-Type', MIME[extname(filePath)] ?? 'application/octet-stream');
        // Hashed assets are immutable; the HTML shell is handled by the SSR path.
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        if (req.method === 'HEAD') {
          res.end();
          return;
        }
        createReadStream(filePath).pipe(res);
        return;
      }
    }

    const webRes = await handler.fetch(toWebRequest(req));
    await writeWebResponse(webRes, res);
  } catch (err) {
    console.error('Request failed:', err);
    if (!res.headersSent) res.statusCode = 500;
    res.end('Internal Server Error');
  }
});

server.listen(PORT, HOST, () => {
  console.log(`developer-portal listening on http://${HOST}:${PORT}`);
});

// Graceful shutdown for container orchestration.
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
