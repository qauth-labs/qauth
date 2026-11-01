#!/usr/bin/env node
// A local proxy between Nx and a self-hosted Nx remote cache, so that losing the
// cache makes a run slower and never red.
//
// Nx 24's HTTP remote cache (NX_SELF_HOSTED_REMOTE_CACHE_SERVER) fails the whole
// `nx` command when the server cannot be reached, times out, or answers anything
// but 200/404 to a read or 200/403/409 to a write. This proxy listens on
// 127.0.0.1, holds the token, and answers Nx only with what Nx carries on from:
//
//   read  (GET /v1/cache/:hash): the server's 200 with the whole body, else 404
//   write (PUT /v1/cache/:hash): the server's 200 or 409, else 403
//
// A read is buffered whole before Nx sees a 200, so a connection that drops
// mid-body is a miss, not a broken tarball. After three failures in a row (no
// connection, a timeout, a 5xx, a 401), the proxy stops calling the server for
// the rest of the run and answers every read with a miss at once.
//
// Node's standard library only, no install step.
//
//   NX_REMOTE_CACHE_TOKEN=… node proxy.mjs serve --upstream https://cache.example \
//       --ready-file ready.json --stats-file stats.json [--port 0]
//   node proxy.mjs summary --stats-file stats.json
//
// `serve` first asks the server who the token is (GET /v1/stats). If that fails it
// exits 3 with one line saying why, and the caller runs Nx without a remote cache.
// Otherwise it writes {"port", "namespace", "access"} to the ready file and serves
// until killed. The token is never printed.

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';

const HASH = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const CACHE_PATH = /^\/v1\/cache\/([^/?#]+)$/;

export const DEFAULTS = Object.freeze({
  // No byte for this long on an open request: give up on it.
  idleMs: 20_000,
  // A whole read, or a whole write, may take at most this long.
  readDeadlineMs: 90_000,
  writeDeadlineMs: 120_000,
  // Failures in a row before the proxy stops calling the server.
  maxFailures: 3,
  // The largest read buffered; anything bigger is a miss.
  maxReadBytes: 512 * 1024 * 1024,
});

/** True for an upstream the token may be sent to: https, or http on loopback. */
export function safeUpstream(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
}

/**
 * One call to the server. Resolves {status, body} (body only for a 200 read), or
 * {status: 0, error} when there was no answer in time. Never rejects.
 */
function call(base, token, method, path, body, opts) {
  return new Promise((resolve) => {
    const url = new URL(base.pathname.replace(/\/$/, '') + path, base);
    const lib = url.protocol === 'https:' ? https : http;
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/octet-stream' };
    if (body) {
      headers['Content-Type'] = 'application/octet-stream';
      headers['Content-Length'] = String(body.length);
    }
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(result);
    };
    const req = lib.request(url, { method, headers, agent: opts.agent });
    const deadline = setTimeout(
      () => {
        req.destroy(new Error('deadline'));
      },
      method === 'PUT' ? opts.writeDeadlineMs : opts.readDeadlineMs
    );
    req.setTimeout(opts.idleMs, () => req.destroy(new Error('idle timeout')));
    req.on('error', (err) => done({ status: 0, error: err.message }));
    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      if (method !== 'GET' || status !== 200) {
        res.resume();
        res.on('end', () => done({ status }));
        res.on('error', (err) => done({ status: 0, error: err.message }));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > opts.maxReadBytes) {
          req.destroy(new Error('entry larger than the read limit'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (!res.complete) return done({ status: 0, error: 'connection closed mid-body' });
        done({ status, body: Buffer.concat(chunks, size) });
      });
      res.on('close', () => {
        if (!res.complete) done({ status: 0, error: 'connection closed mid-body' });
      });
      res.on('error', (err) => done({ status: 0, error: err.message }));
    });
    if (body) req.end(body);
    else req.end();
  });
}

function readAll(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** A failure that counts toward giving up: no answer, a server error, or a refused token. */
function isFailure(status) {
  return status === 0 || status === 401 || status >= 500;
}

/**
 * The proxy server (not yet listening). `stats` is live; `onStats` is called after
 * each request with it.
 */
export function createProxy({
  upstream,
  token,
  warn = () => undefined,
  onStats = () => undefined,
  ...overrides
}) {
  if (!safeUpstream(upstream)) throw new Error('the upstream must be https (or http on loopback)');
  if (!token) throw new Error('no token');
  const opts = { ...DEFAULTS, ...overrides };
  const base = new URL(upstream);
  opts.agent = new (base.protocol === 'https:' ? https : http).Agent({
    keepAlive: true,
    maxSockets: 16,
  });
  const stats = {
    hits: 0,
    misses: 0,
    stored: 0,
    existing: 0,
    refused: 0,
    errors: 0,
    bytesDown: 0,
    bytesUp: 0,
    gaveUp: false,
    lastError: null,
  };
  let failuresInARow = 0;

  const note = (result) => {
    if (isFailure(result.status)) {
      stats.errors += 1;
      stats.lastError = result.error ?? `HTTP ${result.status}`;
      failuresInARow += 1;
      if (!stats.gaveUp && (failuresInARow >= opts.maxFailures || result.status === 401)) {
        stats.gaveUp = true;
        warn(
          `the cache server failed ${failuresInARow} time(s) in a row (last: ${stats.lastError}); the rest of this run uses the local cache only`
        );
      }
    } else {
      failuresInARow = 0;
    }
  };

  const server = http.createServer(async (req, res) => {
    const reply = (status, body) => {
      res.writeHead(status, { 'Content-Type': body ? 'application/octet-stream' : 'text/plain' });
      res.end(body ?? '');
      onStats(stats);
    };
    const match = CACHE_PATH.exec(req.url ?? '');
    const hash = match?.[1];
    if (req.method === 'GET') {
      if (!hash || !HASH.test(hash) || stats.gaveUp) {
        if (hash) stats.misses += 1;
        return reply(404);
      }
      const result = await call(base, token, 'GET', `/v1/cache/${hash}`, null, opts);
      note(result);
      if (result.status === 200) {
        stats.hits += 1;
        stats.bytesDown += result.body.length;
        return reply(200, result.body);
      }
      stats.misses += 1;
      return reply(404);
    }
    if (req.method === 'PUT') {
      let body;
      try {
        body = await readAll(req);
      } catch {
        return reply(403);
      }
      if (!hash || !HASH.test(hash) || stats.gaveUp) {
        stats.refused += 1;
        return reply(403);
      }
      const result = await call(base, token, 'PUT', `/v1/cache/${hash}`, body, opts);
      note(result);
      if (result.status === 200) {
        stats.stored += 1;
        stats.bytesUp += body.length;
        return reply(200);
      }
      if (result.status === 409) {
        stats.existing += 1;
        return reply(409);
      }
      stats.refused += 1;
      return reply(403);
    }
    return reply(404);
  });
  server.on('close', () => opts.agent.destroy());
  return { server, stats };
}

/** Who the token is: {namespace, access}, or {error}. */
export async function probe(upstream, token, overrides = {}) {
  if (!safeUpstream(upstream)) return { error: 'the upstream must be https (or http on loopback)' };
  const opts = { ...DEFAULTS, readDeadlineMs: 10_000, idleMs: 10_000, ...overrides };
  const base = new URL(upstream);
  const result = await call(base, token, 'GET', '/v1/stats', null, opts);
  if (result.status !== 200) {
    return {
      error:
        result.status === 0
          ? `cannot reach the cache server (${result.error})`
          : `the cache server answered HTTP ${result.status}`,
    };
  }
  try {
    const body = JSON.parse(result.body.toString('utf8'));
    return { namespace: String(body.namespace), access: String(body.access) };
  } catch {
    return { error: 'the cache server answered something that is not its stats' };
  }
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(value));
  renameSync(tmp, path);
}

const MB = 1024 * 1024;

/** The job-summary table for one run's stats. */
export function summary(stats, ready) {
  const reads = stats.hits + stats.misses;
  const rate = reads ? `${Math.round((100 * stats.hits) / reads)}%` : '–';
  const who = ready
    ? `\`${ready.namespace}\` (${ready.access === 'write' ? 'read and write' : 'read only'})`
    : '–';
  const rows = [
    ['Namespace', who],
    ['Reads', `${reads}: ${stats.hits} hit, ${stats.misses} miss (hit rate ${rate})`],
    ['Writes', `${stats.stored} stored, ${stats.existing} already there, ${stats.refused} refused`],
    [
      'Transferred',
      `${(stats.bytesDown / MB).toFixed(1)} MB down, ${(stats.bytesUp / MB).toFixed(1)} MB up`,
    ],
    [
      'Server errors',
      stats.errors
        ? `${stats.errors}${stats.gaveUp ? ', then local cache only' : ''} (last: ${stats.lastError})`
        : '0',
    ],
  ];
  return [
    '### Nx remote cache',
    '',
    '| | |',
    '|---|---|',
    ...rows.map(([k, v]) => `| ${k} | ${v} |`),
    '',
  ].join('\n');
}

function flag(args, name, fallback) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return fallback;
  return args[i + 1];
}

async function main(argv) {
  const [command, ...args] = argv;
  if (command === 'summary') {
    const statsFile = flag(args, 'stats-file');
    let stats;
    try {
      stats = JSON.parse(readFileSync(statsFile, 'utf8'));
    } catch {
      return 0; // no proxy ran in this job: nothing to report
    }
    let ready = null;
    try {
      ready = JSON.parse(readFileSync(flag(args, 'ready-file', ''), 'utf8'));
    } catch {
      // the summary works without it
    }
    process.stdout.write(summary(stats, ready) + '\n');
    return 0;
  }
  if (command !== 'serve') {
    process.stderr.write('usage: proxy.mjs serve|summary …\n');
    return 2;
  }
  const upstream = flag(args, 'upstream');
  const readyFile = flag(args, 'ready-file');
  const statsFile = flag(args, 'stats-file');
  const port = Number(flag(args, 'port', '0'));
  const token = process.env.NX_REMOTE_CACHE_TOKEN ?? '';
  if (!upstream || !readyFile || !statsFile) {
    process.stderr.write('serve needs --upstream, --ready-file and --stats-file\n');
    return 2;
  }
  if (!token) {
    console.log('no token in NX_REMOTE_CACHE_TOKEN');
    return 3;
  }
  const who = await probe(upstream, token);
  if (who.error) {
    console.log(who.error);
    return 3;
  }
  const warn = (message) => {
    const prefix =
      process.env.GITHUB_ACTIONS === 'true' ? '::warning title=Nx remote cache::' : 'warning: ';
    console.log(prefix + message);
  };
  const { server, stats } = createProxy({
    upstream,
    token,
    warn,
    onStats: (s) => writeJson(statsFile, s),
  });
  writeJson(statsFile, stats);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  writeJson(readyFile, {
    port: server.address().port,
    namespace: who.namespace,
    access: who.access,
  });
  console.log(`serving ${who.namespace} (${who.access}) on 127.0.0.1:${server.address().port}`);
  return new Promise(() => undefined); // until killed
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.log(`proxy failed: ${err.message}`);
      process.exit(3);
    }
  );
}
