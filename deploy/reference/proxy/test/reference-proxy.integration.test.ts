/**
 * The reference reverse proxy (#482, ADR-019 Decisions 1, 5 and 8), end to end.
 *
 * Runs the shipped configuration, unchanged, in the nginx image: `nginx.conf`,
 * `qauth/` and the example `site/` files, which name the upstreams
 * `auth-server:3000` and `ceremony-app:3000` and the realm hosts
 * `auth.example.com` and `login.example.org`. Two stub upstreams stand behind
 * it under those names (`stub-upstream.mjs`): each echoes the request it
 * received and logs a line per request, so a test can prove what reached
 * which side, and that a refused request reached neither. The certificate is
 * a throwaway one, made with `openssl` for this run and mounted as files.
 *
 * Needs Docker and `openssl`. Locally the suite skips without them; on CI it
 * fails instead, as the other container suites do.
 */
import { execFile } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import type { IncomingHttpHeaders } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const run = promisify(execFile);

/** The nginx stable branch, tagged like the repository's other images. */
const NGINX_IMAGE = 'nginx:1.30-alpine';
/** The image the stubs run in: the Node major the repository builds with. */
const NODE_IMAGE = 'node:26-alpine';

/** The realm hosts `site/realms.conf` names. */
const REALM_HOSTS = ['auth.example.com', 'login.example.org'] as const;
const [REALM_HOST] = REALM_HOSTS;
const UNKNOWN_HOST = 'unknown.example.net';

/** The policy `qauth/realm.conf` puts on every /ui/* answer. */
const REFERENCE_CSP =
  "default-src 'self'; base-uri 'self'; script-src 'self'; style-src 'self'; " +
  "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; " +
  "object-src 'none'; frame-ancestors 'none'";
const IMMUTABLE = 'public, max-age=31536000, immutable';

/** A QAuth session cookie and the wallet flow's binder cookie. */
const QAUTH_COOKIES = '__Host-qauth_session=s3ss10n; __Host-qauth_wallet_flow=fl0w';

const PROXY_ROOT = join(import.meta.dirname, '..');

function isCiLane(): boolean {
  const ci = process.env['CI'];
  if (ci === undefined || ci === '') return false;
  return ci !== '0' && ci.toLowerCase() !== 'false';
}

/** True when Docker and openssl are here; on CI, their absence is an error. */
async function prerequisitesOrSkip(): Promise<boolean> {
  const missing: string[] = [];
  await run('docker', ['version', '--format', '{{.Server.Version}}']).catch(() =>
    missing.push('a reachable Docker daemon')
  );
  await run('openssl', ['version']).catch(() => missing.push('openssl'));
  if (missing.length === 0) return true;
  if (isCiLane()) {
    throw new Error(
      `The reference proxy suite needs ${missing.join(' and ')}, and must never skip on CI.`
    );
  }
  return false;
}

async function docker(...args: string[]): Promise<string> {
  const { stdout } = await run('docker', args, { maxBuffer: 16 * 1024 * 1024 });
  return stdout.trim();
}

/** stdout and stderr of a container, for a log check or a failure message. */
async function logsOf(container: string): Promise<string> {
  const { stdout, stderr } = await run('docker', ['logs', container], {
    maxBuffer: 16 * 1024 * 1024,
  });
  return stdout + stderr;
}

async function until(what: string, check: () => Promise<boolean>, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check().catch(() => false)) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

interface ProxyResponse {
  status: number;
  headers: IncomingHttpHeaders;
  rawHeaders: string[];
  body: string;
  /** The `X-Test-Marker` the request carried, to look for in the stub logs. */
  marker: string;
}

/** What a stub received, from its echo. */
interface Echo {
  upstream: 'auth-server' | 'ceremony-app';
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
}

interface Stack {
  port: number;
  ca: string;
  containers: { proxy: string; authServer: string; ceremonyApp: string };
}

let stack: Stack | undefined;
let prerequisites = false;
let workDir: string | undefined;
let network: string | undefined;
const started: string[] = [];

/**
 * Send one request through the proxy over TLS. The client sends the request
 * target exactly as given: Node does not normalise it.
 */
function send(
  path: string,
  options: { host?: string; method?: string; headers?: Record<string, string> } = {}
): Promise<ProxyResponse> {
  if (stack === undefined) throw new Error('the stack is not running');
  const { port, ca } = stack;
  const host = options.host ?? REALM_HOST;
  const hostname = host.replace(/:\d+$/, '').toLowerCase();
  const knownHost = (REALM_HOSTS as readonly string[]).includes(hostname);
  const marker = randomUUID();
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      {
        host: '127.0.0.1',
        port,
        method: options.method ?? 'GET',
        path,
        // SNI names the host, as a browser would; an IP address gets none.
        ...(isIP(hostname) === 0 ? { servername: hostname } : {}),
        ca,
        // The throwaway certificate names the realm hosts only.
        ...(knownHost ? {} : { checkServerIdentity: () => undefined }),
        agent: false,
        headers: { host, 'x-test-marker': marker, ...options.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks).toString('utf8'),
            marker,
          })
        );
        res.on('error', reject);
      }
    );
    req.on('error', reject);
    req.end();
  });
}

/** The stub's echo; fails when the answer did not come from a stub. */
function echoOf(response: ProxyResponse): Echo {
  expect(response.headers['x-stub-upstream'], response.body).toBeDefined();
  return JSON.parse(response.body) as Echo;
}

/** Every value of one response header, in order, as sent. */
function headerValues(response: ProxyResponse, name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < response.rawHeaders.length; i += 2) {
    if (response.rawHeaders[i].toLowerCase() === name) values.push(response.rawHeaders[i + 1]);
  }
  return values;
}

/** Asserts the proxy answered by itself: no stub answered or logged the request. */
async function expectReachedNeitherStub(response: ProxyResponse): Promise<void> {
  if (stack === undefined) throw new Error('the stack is not running');
  expect(response.headers['x-stub-upstream']).toBeUndefined();
  const { authServer, ceremonyApp } = stack.containers;
  expect(await logsOf(authServer)).not.toContain(response.marker);
  expect(await logsOf(ceremonyApp)).not.toContain(response.marker);
}

async function startStub(name: 'auth-server' | 'ceremony-app'): Promise<string> {
  if (network === undefined) throw new Error('no network');
  const container = await docker(
    'run',
    '--detach',
    '--label',
    'qauth-test=reference-proxy',
    '--network',
    network,
    '--network-alias',
    name,
    '--env',
    `STUB_NAME=${name}`,
    // Both send weak headers: the ceremony app's must be replaced, and the
    // auth server's must pass untouched.
    '--env',
    'STUB_WEAK=1',
    '--volume',
    `${join(PROXY_ROOT, 'test', 'stub-upstream.mjs')}:/stub/stub-upstream.mjs:ro`,
    NODE_IMAGE,
    'node',
    '/stub/stub-upstream.mjs'
  );
  started.push(container);
  await until(`the ${name} stub`, async () => (await logsOf(container)).includes('"listening"'));
  return container;
}

beforeAll(async () => {
  prerequisites = await prerequisitesOrSkip();
  if (!prerequisites) return;

  workDir = await mkdtemp(join(tmpdir(), 'qauth-reference-proxy-'));
  const certs = join(workDir, 'certs');
  await mkdir(certs);
  await run('openssl', [
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-days',
    '1',
    '-subj',
    `/CN=${REALM_HOST}`,
    '-addext',
    `subjectAltName=${REALM_HOSTS.map((host) => `DNS:${host}`).join(',')}`,
    '-keyout',
    join(certs, 'privkey.pem'),
    '-out',
    join(certs, 'fullchain.pem'),
  ]);

  network = `qauth-reference-proxy-${randomBytes(4).toString('hex')}`;
  await docker('network', 'create', '--label', 'qauth-test=reference-proxy', network);

  // nginx resolves the upstream names once, at start, so the stubs come first.
  const [authServer, ceremonyApp] = await Promise.all([
    startStub('auth-server'),
    startStub('ceremony-app'),
  ]);

  const proxy = await docker(
    'run',
    '--detach',
    '--label',
    'qauth-test=reference-proxy',
    '--network',
    network,
    '--publish',
    '127.0.0.1::443',
    '--volume',
    `${join(PROXY_ROOT, 'nginx.conf')}:/etc/nginx/nginx.conf:ro`,
    '--volume',
    `${join(PROXY_ROOT, 'qauth')}:/etc/nginx/qauth:ro`,
    '--volume',
    `${join(PROXY_ROOT, 'site')}:/etc/nginx/site:ro`,
    '--volume',
    `${certs}:/etc/nginx/certs:ro`,
    NGINX_IMAGE
  );
  started.push(proxy);

  const published = await docker('port', proxy, '443/tcp');
  const port = Number(published.split('\n')[0].split(':').pop());
  stack = {
    port,
    ca: await readFile(join(certs, 'fullchain.pem'), 'utf8'),
    containers: { proxy, authServer, ceremonyApp },
  };

  try {
    await until('the proxy', async () => {
      const response = await send('/health');
      return response.status === 200 && response.headers['x-stub-upstream'] === 'auth-server';
    });
  } catch (error) {
    const state = await docker('inspect', '--format', '{{json .State}}', proxy).catch(() => '');
    throw new Error(
      `${String(error)}\n--- proxy state ---\n${state}\n--- proxy log ---\n${await logsOf(proxy)}`,
      { cause: error }
    );
  }
}, 300_000);

afterAll(async () => {
  if (started.length > 0) await docker('rm', '--force', ...started).catch(() => undefined);
  if (network !== undefined) await docker('network', 'rm', network).catch(() => undefined);
  if (workDir !== undefined) await rm(workDir, { recursive: true, force: true });
});

describe('the reference proxy (#482)', () => {
  describe('routing', () => {
    it.each(REALM_HOSTS)('sends %s to the auth server with its cookies', async (host) => {
      if (!prerequisites) return;
      const response = await send('/oauth/token', {
        host,
        method: 'POST',
        headers: { cookie: QAUTH_COOKIES },
      });

      const echo = echoOf(response);
      expect(echo.upstream).toBe('auth-server');
      expect(echo.method).toBe('POST');
      expect(echo.url).toBe('/oauth/token');
      expect(echo.headers.host).toBe(host);
      expect(echo.headers.cookie).toBe(QAUTH_COOKIES);
    });

    it.each(REALM_HOSTS)(
      'sends /ui/* on %s to the ceremony app with no Cookie header',
      async (host) => {
        if (!prerequisites) return;
        const response = await send('/ui/login?interaction=abc', {
          host,
          headers: { cookie: QAUTH_COOKIES },
        });

        const echo = echoOf(response);
        expect(echo.upstream).toBe('ceremony-app');
        expect(echo.url).toBe('/ui/login?interaction=abc');
        expect(echo.headers.host).toBe(host);
        expect(echo.headers).not.toHaveProperty('cookie');
      }
    );

    it('matches a realm host case-insensitively and without its port', async () => {
      if (!prerequisites) return;
      const echo = echoOf(await send('/oauth/token', { host: 'AUTH.Example.com:443' }));

      expect(echo.upstream).toBe('auth-server');
      expect(echo.headers.host).toBe(REALM_HOST);
    });

    it.each([
      '//ui/login',
      '/ui/../ui/login',
      '/%75i/login',
      '/ui//login',
      '/ui/./login',
      '/oauth/../ui/login',
      '/%2E/ui/login',
    ])(
      'routes %s on its normalised path to the ceremony app, with no Cookie header',
      async (path) => {
        if (!prerequisites) return;
        const echo = echoOf(await send(path, { headers: { cookie: QAUTH_COOKIES } }));

        expect(echo.upstream).toBe('ceremony-app');
        expect(echo.url).toBe('/ui/login');
        expect(echo.headers).not.toHaveProperty('cookie');
      }
    );

    it.each(['/ui/%2E%2E/oauth/token', '//oauth//token', '/%6Fauth/token'])(
      'routes %s on its normalised path to the auth server',
      async (path) => {
        if (!prerequisites) return;
        const echo = echoOf(await send(path));

        expect(echo.upstream).toBe('auth-server');
        expect(echo.url).toBe('/oauth/token');
      }
    );

    it.each([
      '/ui%2Flogin',
      '/ui%2flogin',
      '/UI/login',
      '/Ui/login',
      '/%55I/login',
      '/ui;x/login',
      '/ui%3Bx/login',
      '/ui',
      '/UI',
      '/x/..%2Fui/login',
      '/ui/..%2Foauth/token',
      '/oauth%2Ftoken',
    ])('answers %s with 404 from the proxy, reaching neither stub', async (path) => {
      if (!prerequisites) return;
      const response = await send(path, { headers: { cookie: QAUTH_COOKIES } });

      expect(response.status).toBe(404);
      await expectReachedNeitherStub(response);
    });
  });

  describe('the /ui/* response headers', () => {
    it.each(['200', '302', '404', '500'])(
      'replaces a weak CSP, Cache-Control: public and the Referrer-Policy on a %s answer',
      async (status) => {
        if (!prerequisites) return;
        const response = await send('/ui/login', { headers: { 'x-stub-status': status } });

        expect(response.status).toBe(Number(status));
        expect(response.headers['x-stub-upstream']).toBe('ceremony-app');
        expect(headerValues(response, 'content-security-policy')).toEqual([REFERENCE_CSP]);
        expect(headerValues(response, 'referrer-policy')).toEqual(['no-referrer']);
        expect(headerValues(response, 'cache-control')).toEqual(['no-store']);
      }
    );

    it('allows scripts from the realm origin only and no framing', async () => {
      if (!prerequisites) return;
      const [policy] = headerValues(await send('/ui/login'), 'content-security-policy');
      const directives = new Map(
        policy.split(';').map((directive) => {
          const [name, ...sources] = directive.trim().split(/\s+/);
          return [name, sources] as const;
        })
      );

      expect(directives.get('script-src')).toEqual(["'self'"]);
      expect(directives.get('default-src')).toEqual(["'self'"]);
      expect(directives.get('frame-ancestors')).toEqual(["'none'"]);
    });

    it('sets the same headers on an answer the proxy makes itself', async () => {
      if (!prerequisites) return;
      // The stub closes the connection, so nginx answers 502 on its own.
      const response = await send('/ui/login', { headers: { 'x-stub-hang-up': '1' } });

      expect(response.status).toBe(502);
      expect(response.headers['x-stub-upstream']).toBeUndefined();
      expect(headerValues(response, 'content-security-policy')).toEqual([REFERENCE_CSP]);
      expect(headerValues(response, 'referrer-policy')).toEqual(['no-referrer']);
      expect(headerValues(response, 'cache-control')).toEqual(['no-store']);
    });

    it('leaves the auth server answers alone', async () => {
      if (!prerequisites) return;
      const response = await send('/oauth/token', { method: 'POST' });

      expect(response.headers['x-stub-upstream']).toBe('auth-server');
      expect(headerValues(response, 'content-security-policy')).toEqual([
        "script-src * 'unsafe-inline' 'unsafe-eval'",
      ]);
      expect(headerValues(response, 'cache-control')).toEqual(['public, max-age=3600']);
    });

    it.each(['GET', 'HEAD'])(
      'lets a cache keep a content-hashed asset answered to a %s',
      async (method) => {
        if (!prerequisites) return;
        const response = await send('/ui/assets/index-BxY2abcd.js', { method });

        expect(response.headers['x-stub-upstream']).toBe('ceremony-app');
        expect(headerValues(response, 'cache-control')).toEqual([IMMUTABLE]);
        expect(headerValues(response, 'content-security-policy')).toEqual([REFERENCE_CSP]);
      }
    );

    it.each([
      ['a POST', '/ui/assets/index-BxY2abcd.js', { method: 'POST' }],
      ['a 404', '/ui/assets/index-BxY2abcd.js', { headers: { 'x-stub-status': '404' } }],
      [
        'an answer that sets a cookie',
        '/ui/assets/index-BxY2abcd.js',
        {
          headers: { 'x-stub-set-cookie': 'theme=dark; Path=/' },
        },
      ],
      ['a name with no hash', '/ui/assets/logo.svg', {}],
      ['a source map', '/ui/assets/index-BxY2abcd.js.map', {}],
      ['a path outside the asset prefix', '/ui/index-BxY2abcd.js', {}],
      ['a path below the asset prefix', '/ui/assets/sub/index-BxY2abcd.js', {}],
    ] as const)('keeps no-store on %s', async (_case, path, options) => {
      if (!prerequisites) return;
      const response = await send(path, options);

      expect(response.headers['x-stub-upstream']).toBe('ceremony-app');
      expect(headerValues(response, 'cache-control')).toEqual(['no-store']);
    });
  });

  describe('forwarded headers', () => {
    it.each([
      ['the auth server', '/oauth/token', 'auth-server'],
      ['the ceremony app', '/ui/login', 'ceremony-app'],
    ] as const)(
      'replaces what the client sent, on the way to %s',
      async (_side, path, upstream) => {
        if (!prerequisites) return;
        const echo = echoOf(
          await send(path, {
            headers: {
              'x-forwarded-for': '203.0.113.9',
              'x-forwarded-host': 'evil.example.net',
              'x-forwarded-proto': 'http',
              forwarded: 'for=203.0.113.9;host=evil.example.net;proto=http',
            },
          })
        );

        expect(echo.upstream).toBe(upstream);
        // One address: the one the proxy accepted the connection from.
        const forwardedFor = String(echo.headers['x-forwarded-for']);
        expect(isIP(forwardedFor)).not.toBe(0);
        expect(forwardedFor).not.toBe('203.0.113.9');
        expect(echo.headers['x-forwarded-host']).toBe(REALM_HOST);
        expect(echo.headers['x-forwarded-proto']).toBe('https');
        expect(echo.headers).not.toHaveProperty('forwarded');
        expect(echo.headers.host).toBe(REALM_HOST);
      }
    );
  });

  describe('hosts and public paths', () => {
    it.each([UNKNOWN_HOST, '127.0.0.1'])(
      'answers 421 for %s, reaching neither stub',
      async (host) => {
        if (!prerequisites) return;
        for (const path of [
          '/oauth/token',
          '/ui/login',
          '/',
          '/.well-known/openid-configuration',
        ]) {
          const response = await send(path, { host, headers: { cookie: QAUTH_COOKIES } });

          expect(response.status, path).toBe(421);
          await expectReachedNeitherStub(response);
        }
      }
    );

    it.each(['/health', '/ready'])('passes %s through on an unknown host', async (path) => {
      if (!prerequisites) return;
      for (const host of [UNKNOWN_HOST, '127.0.0.1']) {
        const echo = echoOf(await send(path, { host }));

        expect(echo.upstream).toBe('auth-server');
        expect(echo.url).toBe(path);
      }
    });

    it.each([
      '/metrics',
      '/internal/signer/v1/sign',
      '/METRICS',
      '/metrics/',
      '/metrics;x',
      '/%6Detrics',
      '/internal',
      '/Internal/signer/v1/sign',
    ])('answers %s with 404 on a realm host, reaching neither stub', async (path) => {
      if (!prerequisites) return;
      const response = await send(path, { method: 'POST' });

      expect(response.status).toBe(404);
      await expectReachedNeitherStub(response);
    });
  });
});
