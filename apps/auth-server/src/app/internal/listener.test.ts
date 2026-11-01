import type { AddressInfo } from 'node:net';
import { Readable } from 'node:stream';
import type { ConnectionOptions } from 'node:tls';

import { internalListenerEnvSchema } from '@qauth-labs/server-config';
import Fastify, { type FastifyInstance, type FastifyPluginAsync } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    REQUEST_TIMEOUT_MS: 60_000,
    REQUEST_ID_HEADER: 'x-request-id',
  },
}));

import {
  createInternalPki,
  eventually,
  fingerprintOf,
  type InternalPki,
  type IssuedCredentials,
  servedFingerprint,
  tlsExchange,
  type TlsFileDirectory,
  writeTlsFiles,
} from '../../testing/internal-pki';
import { createInternalClient, type InternalClient, InternalClientError } from './client';
import {
  createInternalServer,
  installInternalApi,
  INTERNAL_MAX_CONNECTIONS,
  requestPeerRole,
} from './listener';
import type { InternalRouteModule } from './route-manifest';
import { readInternalTlsFiles } from './tls-files';

/**
 * THE INTERNAL LISTENER AND ITS CLIENT, over real TLS on loopback (#496).
 *
 * The listener is the one `main.ts` builds, with a fixture route module in
 * place of the manifest's (empty until #497); the client is the one other
 * roles use. No database: the fixture routes read none, and the decorators
 * the listener shares are stand-ins. `internal-listener.integration.test.ts`
 * runs the same listener inside the real app, on a real database.
 */

const SIGNER_URI = 'spiffe://qauth.test/signer';
const SIGNER_DNS = 'signer.qauth.internal';
const FIXTURE_PREFIX = '/internal/fixture/v1-rc.0';

const PEER_ROLES = internalListenerEnvSchema.parse({
  INTERNAL_PEER_ROLES: JSON.stringify({
    'spiffe://qauth.test/web': 'web',
    'api.qauth.internal': 'api',
    'spiffe://qauth.test/delivery': 'delivery',
    'admin.qauth.internal': 'admin',
    'two-roles.qauth.internal': 'web',
    'spiffe://qauth.test/two-roles': 'api',
  }),
}).INTERNAL_PEER_ROLES;

/** What the fixture routes saw. */
const seen = { requests: 0, adminOnly: 0 };

/** Ends the request `/hold` keeps open, once it is. */
const hold: { release?: () => void } = {};

const fixtureRoutes: FastifyPluginAsync = async (scope) => {
  scope.get('/peer', async (request) => ({ peerRole: requestPeerRole(request) }));
  scope.post('/echo', async (request) => ({ body: request.body }));
  scope.get('/large', async (_request, reply) => reply.send(Buffer.alloc(64 * 1024, 0x61)));
  scope.get('/stream', async (_request, reply) =>
    reply.send(Readable.from([Buffer.alloc(32 * 1024, 0x61), Buffer.alloc(32 * 1024, 0x62)]))
  );
  scope.get('/slow', async () => {
    await new Promise((resolve) => setTimeout(resolve, 1_000));
    return { slow: true };
  });
  scope.get('/hold', async () => {
    await new Promise<void>((resolve) => {
      hold.release = resolve;
    });
    hold.release = undefined;
    return { held: true };
  });
};

const FIXTURE_MODULE: InternalRouteModule = {
  module: 'fixture',
  prefix: FIXTURE_PREFIX,
  roles: ['signer'],
  peerRoles: ['web', 'api', 'delivery', 'admin'],
  load: async () => ({ default: fixtureRoutes }),
};

const ADMIN_ONLY_PREFIX = '/internal/admin-only/v1-rc.0';

/** A module only the admin role's peers may call. */
const ADMIN_ONLY_MODULE: InternalRouteModule = {
  module: 'admin-only',
  prefix: ADMIN_ONLY_PREFIX,
  roles: ['signer'],
  peerRoles: ['admin'],
  load: async () => ({
    default: async (scope) => {
      scope.get('/peer', async (request) => {
        seen.adminOnly += 1;
        return { peerRole: requestPeerRole(request) };
      });
    },
  }),
};

/** A module of a role the process does not hold: it must not register. */
const OTHER_ROLE_MODULE: InternalRouteModule = {
  module: 'other-role',
  prefix: '/internal/other/v1-rc.0',
  roles: ['web'],
  peerRoles: ['api'],
  load: async () => ({ default: async (scope) => void scope.get('/x', async () => ({})) }),
};

let pki: InternalPki;
let otherPki: InternalPki;
let signer: IssuedCredentials;
let peers: Record<
  'web' | 'api' | 'delivery' | 'admin' | 'stranger' | 'twoRoles',
  IssuedCredentials
>;
let tlsDirectory: TlsFileDirectory;
let source: FastifyInstance;
let internal: FastifyInstance;
let port: number;
let url: string;
const clients: InternalClient[] = [];
const warnings: string[] = [];

/** A client of the listener, closed after the file. */
function client(
  credentials: IssuedCredentials,
  overrides: Partial<Parameters<typeof createInternalClient>[0]> = {}
): InternalClient {
  const made = createInternalClient({
    url,
    cert: credentials.cert,
    key: credentials.key,
    ca: pki.caPem,
    expectedServerSan: SIGNER_URI,
    ...overrides,
  });
  clients.push(made);
  return made;
}

/** A source scope with stand-ins for the decorators the listener shares. */
function sourceScope(): FastifyInstance {
  const scope = Fastify({ logger: false });
  for (const name of ['db', 'dbPool', 'repositories', 'redis', 'signer'] as const) {
    scope.decorate(name, { standIn: name } as never);
  }
  return scope;
}

/** A logger that keeps the warnings, for the assertions about what the listener logs. */
function recordingLogger() {
  const logger = {
    level: 'warn',
    fatal: () => undefined,
    error: () => undefined,
    warn: (...args: unknown[]) => {
      warnings.push(
        args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' ')
      );
    },
    info: () => undefined,
    debug: () => undefined,
    trace: () => undefined,
    silent: () => undefined,
    child: () => logger,
  };
  return logger;
}

/** {@link tlsExchange} to the listener, for the fixture route. */
function rawExchange(options: ConnectionOptions) {
  return tlsExchange({ host: '127.0.0.1', port }, options, `${FIXTURE_PREFIX}/peer`);
}

/**
 * {@link rawExchange}, and the handshake errors the listener reported for it
 * (`tlsClientError`): under TLS 1.3 the client learns of a refused
 * certificate only after its side of the handshake, so the listener's side
 * is where the refusal shows.
 */
async function refusedHandshake(
  options: ConnectionOptions
): Promise<{ readonly received: string; readonly refusals: readonly string[] }> {
  const refusals: string[] = [];
  const onRefusal = (error: NodeJS.ErrnoException, socket: { authorizationError?: unknown }) =>
    refusals.push(
      `${error.code ?? ''} ${error.message} ${String(socket.authorizationError ?? '')}`
    );
  internal.server.on('tlsClientError', onRefusal);
  try {
    const { received } = await rawExchange(options);
    await eventually(async () => refusals.length > 0);
    return { received, refusals };
  } finally {
    internal.server.off('tlsClientError', onRefusal);
  }
}

/** The fingerprint of the certificate the listener serves to a new connection. */
function served(): Promise<string> {
  return servedFingerprint({ host: '127.0.0.1', port }, peers.web, [pki.caPem, otherPki.caPem]);
}

beforeAll(async () => {
  pki = createInternalPki();
  otherPki = createInternalPki('Another CA');
  signer = pki.issue({ dnsNames: [SIGNER_DNS], uris: [SIGNER_URI] });
  peers = {
    web: pki.issue({ uris: ['spiffe://qauth.test/web'] }),
    api: pki.issue({ dnsNames: ['API.qauth.internal'] }),
    delivery: pki.issue({ uris: ['spiffe://qauth.test/delivery'] }),
    admin: pki.issue({ dnsNames: ['admin.qauth.internal'] }),
    stranger: pki.issue({ dnsNames: ['stranger.qauth.internal'], uris: ['spiffe://qauth.test/x'] }),
    twoRoles: pki.issue({
      dnsNames: ['two-roles.qauth.internal'],
      uris: ['spiffe://qauth.test/two-roles'],
    }),
  };
  tlsDirectory = writeTlsFiles(signer, pki.caPem);

  internal = createInternalServer({
    loggerInstance: recordingLogger() as never,
    peerRoles: PEER_ROLES,
    tls: {
      files: tlsDirectory.files,
      material: readInternalTlsFiles(tlsDirectory.files),
      reloadIntervalMs: 50,
    },
  });
  internal.addHook('onRequest', async () => {
    seen.requests += 1;
  });
  source = sourceScope();
  await installInternalApi(internal, source, {
    roles: ['api', 'signer'],
    modules: [FIXTURE_MODULE, ADMIN_ONLY_MODULE, OTHER_ROLE_MODULE],
  });
  await internal.listen({ host: '127.0.0.1', port: 0 });
  port = (internal.server.address() as AddressInfo).port;
  url = `https://127.0.0.1:${port}`;
});

afterAll(async () => {
  for (const made of clients) made.close();
  await source.close();
  await internal.close();
  tlsDirectory.remove();
});

beforeEach(() => {
  seen.requests = 0;
  seen.adminOnly = 0;
});

describe('mutual TLS on the internal listener', () => {
  it('lets a client with a certificate from the right CA reach an internal route', async () => {
    const response = await client(peers.web).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });
  });

  it('gives each request the role its certificate maps to, by a URI or a DNS SAN', async () => {
    for (const role of ['web', 'api', 'delivery', 'admin'] as const) {
      const response = await client(peers[role]).request({
        method: 'GET',
        path: `${FIXTURE_PREFIX}/peer`,
      });
      expect(JSON.parse(response.body.toString()), role).toEqual({ peerRole: role });
    }
  });

  it('fails the handshake of a client that presents no certificate', async () => {
    const { received, refusals } = await refusedHandshake({ ca: pki.caPem });
    expect(received).toBe('');
    expect(refusals.join(' ')).toMatch(/CERTIFICATE|certificate/);
    expect(seen.requests).toBe(0);
  });

  it('fails the handshake of a client whose certificate another CA issued, whatever its SAN', async () => {
    const forged = otherPki.issue({ uris: ['spiffe://qauth.test/web'] });
    const { received, refusals } = await refusedHandshake({
      ca: pki.caPem,
      cert: forged.cert,
      key: forged.key,
    });
    expect(received).toBe('');
    expect(refusals.join(' ')).toMatch(/UNABLE_TO|ISSUER|CERT/);
    expect(
      warnings.some((line) => line.includes('Refused an internal TLS connection at the handshake'))
    ).toBe(true);

    const refused = await client(forged)
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })
      .catch((caught: unknown) => caught);
    expect(refused).toBeInstanceOf(InternalClientError);
    expect((refused as InternalClientError).code).toBe('unreachable');
    expect(seen.requests).toBe(0);
  });

  it('serves TLS 1.3 only', async () => {
    const { received, refusals } = await refusedHandshake({
      ca: pki.caPem,
      cert: peers.web.cert,
      key: peers.web.key,
      maxVersion: 'TLSv1.2',
    });
    expect(received).toBe('');
    expect(refusals.join(' ')).toMatch(/VERSION|version|PROTOCOL/);
  });
});

describe('peer roles', () => {
  it('answers 403 to a certificate from the right CA whose SAN INTERNAL_PEER_ROLES does not map', async () => {
    const response = await client(peers.stranger).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(response.status).toBe(403);
    expect(response.headers['content-type']).toContain('application/problem+json');
    expect(JSON.parse(response.body.toString())).toMatchObject({ status: 403, code: 'forbidden' });
    expect(response.headers['x-request-id']).toEqual(expect.any(String));
    expect(warnings.some((line) => line.includes('stranger.qauth.internal'))).toBe(true);
  });

  it('answers 403 to such a peer before it learns which paths exist', async () => {
    const stranger = client(peers.stranger);
    for (const path of ['/internal/none', '/oauth/token', `${FIXTURE_PREFIX}/peer`]) {
      expect((await stranger.request({ method: 'GET', path })).status, path).toBe(403);
    }
  });

  it('answers 403 to a certificate whose SANs map to two roles', async () => {
    const response = await client(peers.twoRoles).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(response.status).toBe(403);
  });

  it('answers 404 to a known peer on a path no internal route serves', async () => {
    const response = await client(peers.web).request({ method: 'GET', path: '/oauth/token' });
    expect(response.status).toBe(404);
    expect(JSON.parse(response.body.toString())).toMatchObject({ code: 'not_found' });
  });

  it("answers 403 to a peer whose role the route's module does not admit, before the route runs", async () => {
    for (const role of ['web', 'api', 'delivery'] as const) {
      const response = await client(peers[role]).request({
        method: 'GET',
        path: `${ADMIN_ONLY_PREFIX}/peer`,
      });
      expect(response.status, role).toBe(403);
      expect(response.headers['connection'], role).toBe('close');
      expect(JSON.parse(response.body.toString()), role).toMatchObject({ code: 'forbidden' });
    }
    expect(seen.adminOnly).toBe(0);
    expect(warnings.some((line) => line.includes("does not admit the peer's role"))).toBe(true);

    const admitted = await client(peers.admin).request({
      method: 'GET',
      path: `${ADMIN_ONLY_PREFIX}/peer`,
    });
    expect(admitted.status).toBe(200);
    expect(JSON.parse(admitted.body.toString())).toEqual({ peerRole: 'admin' });
    expect(seen.adminOnly).toBe(1);
  });

  it('closes the connection of every refused request', async () => {
    const response = await client(peers.stranger).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(response.status).toBe(403);
    expect(response.headers['connection']).toBe('close');
  });

  it('refuses a request on a kept-alive connection once the peer certificate has expired, and closes it', async () => {
    const notAfter = new Date(Math.floor(Date.now() / 1_000) * 1_000 + 60 * 60 * 1_000);
    const expiring = pki.issue({ uris: ['spiffe://qauth.test/web'], notAfter });
    const connections = vi.fn();
    internal.server.on('secureConnection', connections);
    try {
      const pooled = client(expiring, { maxSockets: 1 });
      const path = `${FIXTURE_PREFIX}/peer`;
      expect((await pooled.request({ method: 'GET', path })).status).toBe(200);

      // The same connection, past the certificate's notAfter.
      const clock = vi.spyOn(Date, 'now').mockReturnValue(notAfter.getTime() + 1_000);
      let refused: Awaited<ReturnType<InternalClient['request']>>;
      try {
        refused = await pooled.request({ method: 'GET', path });
      } finally {
        clock.mockRestore();
      }
      expect(refused.status).toBe(403);
      expect(refused.headers['connection']).toBe('close');
      expect(connections).toHaveBeenCalledTimes(1);
      expect(warnings.some((line) => line.includes('the peer certificate has expired'))).toBe(true);

      // The refusal closed it: the next request makes a new connection.
      expect((await pooled.request({ method: 'GET', path })).status).toBe(200);
      expect(connections).toHaveBeenCalledTimes(2);
    } finally {
      internal.server.off('secureConnection', connections);
    }
  });

  it('caps the connections it holds open at once', () => {
    expect(internal.server.maxConnections).toBe(INTERNAL_MAX_CONNECTIONS);
  });

  it('registers the modules of the roles the process holds, and no other', () => {
    expect(internal.hasRoute({ method: 'GET', url: `${FIXTURE_PREFIX}/peer` })).toBe(true);
    expect(internal.hasRoute({ method: 'GET', url: '/internal/other/v1-rc.0/x' })).toBe(false);
  });
});

describe('the internal client', () => {
  it('refuses a server whose certificate does not hold expectedServerSan, before sending the request', async () => {
    for (const expectedServerSan of ['spiffe://qauth.test/other', 'other.qauth.internal']) {
      const refused = await client(peers.web, { expectedServerSan })
        .request({ method: 'POST', path: `${FIXTURE_PREFIX}/echo`, body: '{"secret":"x"}' })
        .catch((caught: unknown) => caught);
      expect(refused, expectedServerSan).toBeInstanceOf(InternalClientError);
      expect((refused as InternalClientError).code).toBe('server_identity');
      expect((refused as Error).message).not.toContain('secret');
    }
    expect(seen.requests).toBe(0);
  });

  it('knows the server by a DNS SAN too, without regard to case', async () => {
    const response = await client(peers.api, {
      expectedServerSan: 'SIGNER.qauth.internal',
    }).request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'api' });
  });

  it('refuses a server whose certificate another CA issued', async () => {
    const refused = await client(peers.web, { ca: otherPki.caPem })
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })
      .catch((caught: unknown) => caught);
    expect((refused as InternalClientError).code).toBe('unreachable');
    expect(seen.requests).toBe(0);
  });

  it('sends a body and reads the answer', async () => {
    const response = await client(peers.api).request({
      method: 'POST',
      path: `${FIXTURE_PREFIX}/echo`,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'signer' }),
    });
    expect(JSON.parse(response.body.toString())).toEqual({ body: { hello: 'signer' } });
  });

  it('keeps its connection open between requests', async () => {
    const connections = vi.fn();
    internal.server.on('secureConnection', connections);
    try {
      const pooled = client(peers.web);
      for (let index = 0; index < 3; index += 1) {
        await pooled.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
      }
      expect(connections).toHaveBeenCalledTimes(1);
    } finally {
      internal.server.off('secureConnection', connections);
    }
  });

  it('caps the size of an answer, declared or streamed', async () => {
    const capped = client(peers.web, { maxResponseBytes: 1024 });
    for (const path of [`${FIXTURE_PREFIX}/large`, `${FIXTURE_PREFIX}/stream`]) {
      const refused = await capped
        .request({ method: 'GET', path })
        .catch((caught: unknown) => caught);
      expect((refused as InternalClientError).code, path).toBe('response_too_large');
    }
    const roomy = await client(peers.web).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/stream`,
    });
    expect(roomy.body.length).toBe(64 * 1024);
  });

  it('gives up on an answer that does not come within its deadline', async () => {
    const started = Date.now();
    const refused = await client(peers.web, { timeoutMs: 100 })
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/slow` })
      .catch((caught: unknown) => caught);
    expect((refused as InternalClientError).code).toBe('timeout');
    expect(Date.now() - started).toBeLessThan(900);
  });

  it('aborts on its caller signal', async () => {
    const controller = new AbortController();
    const pending = client(peers.web)
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/slow`, signal: controller.signal })
      .catch((caught: unknown) => caught);
    controller.abort();
    expect(((await pending) as InternalClientError).code).toBe('aborted');
  });

  it('presents new credentials once they are reloaded', async () => {
    const reloaded = client(peers.web);
    const before = await reloaded.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
    expect(JSON.parse(before.body.toString())).toEqual({ peerRole: 'web' });
    reloaded.reloadCredentials({
      cert: peers.delivery.cert,
      key: peers.delivery.key,
      ca: pki.caPem,
    });
    const after = await reloaded.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
    expect(JSON.parse(after.body.toString())).toEqual({ peerRole: 'delivery' });
  });

  it("refuses credentials whose key is not the certificate's own, and keeps the ones in use", async () => {
    const mismatched = { cert: peers.web.cert, key: peers.api.key, ca: pki.caPem };
    expect(() =>
      createInternalClient({ url, ...mismatched, expectedServerSan: SIGNER_URI })
    ).toThrow('do not make a TLS identity');
    const kept = client(peers.web);
    expect(() => kept.reloadCredentials(mismatched)).toThrow('do not make a TLS identity');
    const response = await kept.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });
  });

  it('fails the requests in flight and those queued for a connection when closed', async () => {
    const closing = client(peers.web, { maxSockets: 1 });
    const outcomes = [0, 1, 2].map(() =>
      closing
        .request({ method: 'GET', path: `${FIXTURE_PREFIX}/slow` })
        .then(() => 'answered')
        .catch((caught: unknown) => (caught as InternalClientError).code)
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    closing.close();
    expect(await Promise.all(outcomes)).toEqual(['closed', 'closed', 'closed']);
    // Nothing was sent once the client closed.
    await new Promise((resolve) => setTimeout(resolve, 1_200));
    expect(seen.requests).toBeLessThanOrEqual(1);
  });

  it('refuses requests once closed', async () => {
    const closed = client(peers.web);
    closed.close();
    const refused = await closed
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })
      .catch((caught: unknown) => caught);
    expect((refused as InternalClientError).code).toBe('closed');
  });

  it('refuses a base URL that is not https, or carries credentials, and a bad SAN', () => {
    const base = { cert: peers.web.cert, key: peers.web.key, ca: pki.caPem };
    expect(() =>
      createInternalClient({
        ...base,
        url: `http://127.0.0.1:${port}`,
        expectedServerSan: SIGNER_URI,
      })
    ).toThrow('must be https');
    expect(() =>
      createInternalClient({
        ...base,
        url: `https://user:pass@127.0.0.1:${port}`,
        expectedServerSan: SIGNER_URI,
      })
    ).toThrow('credentials');
    expect(() =>
      createInternalClient({ ...base, url, expectedServerSan: '*.qauth.internal' })
    ).toThrow('expectedServerSan');
  });

  it('keeps every request on the base URL', async () => {
    const pinned = client(peers.web);
    for (const path of ['//evil.example/x', 'https://evil.example/x', 'internal/x', '/a b']) {
      await expect(pinned.request({ method: 'GET', path })).rejects.toThrow(TypeError);
    }
  });
});

describe('certificate reload', () => {
  it('serves new certificate files with no restart, and still asks every client for one', async () => {
    expect(await served()).toBe(fingerprintOf(signer.cert));

    const rotated = pki.issue({ dnsNames: [SIGNER_DNS], uris: [SIGNER_URI] });
    tlsDirectory.replace(rotated, pki.caPem);
    const rotatedFingerprint = fingerprintOf(rotated.cert);
    await eventually(async () => (await served()) === rotatedFingerprint);

    const response = await client(peers.web).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });

    const noCertificate = await refusedHandshake({ ca: pki.caPem });
    expect(noCertificate.received).toBe('');
    expect(noCertificate.refusals.join(' ')).toMatch(/CERTIFICATE|certificate/);
    const legacy = await refusedHandshake({
      ca: pki.caPem,
      cert: peers.web.cert,
      key: peers.web.key,
      maxVersion: 'TLSv1.2',
    });
    expect(legacy.received).toBe('');
    expect(legacy.refusals.join(' ')).toMatch(/VERSION|version|PROTOCOL/);
  });

  it('keeps the files it serves while a rotation is half-way, and applies it once complete', async () => {
    const before = await served();
    const next = pki.issue({ dnsNames: [SIGNER_DNS], uris: [SIGNER_URI] });
    const warningsBefore = warnings.length;

    // The certificate first: it does not match the key still on disk.
    tlsDirectory.writeOne('certPath', next.cert);
    await eventually(async () =>
      warnings.slice(warningsBefore).some((line) => line.includes('cannot be used yet'))
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(await served()).toBe(before);
    expect(
      warnings.slice(warningsBefore).filter((line) => line.includes('cannot be used yet'))
    ).toHaveLength(1);

    tlsDirectory.writeOne('keyPath', next.key);
    const nextFingerprint = fingerprintOf(next.cert);
    await eventually(async () => (await served()) === nextFingerprint);
  });

  it("trusts a new CA file once it is replaced, and the old CA's peers no longer, on a connection made before as on a new one", async () => {
    // A connection of a peer of the old CA, busy with a request while the
    // files are replaced, so the reload does not close it as idle.
    const busy = client(peers.web, { maxSockets: 1 });
    expect((await busy.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })).status).toBe(
      200
    );
    const held = busy.request({ method: 'GET', path: `${FIXTURE_PREFIX}/hold` });
    await eventually(() => hold.release !== undefined);

    const newSigner = otherPki.issue({ dnsNames: [SIGNER_DNS], uris: [SIGNER_URI] });
    tlsDirectory.replace(newSigner, otherPki.caPem);
    const fingerprint = fingerprintOf(newSigner.cert);
    await eventually(async () => (await served()) === fingerprint);

    // The request in flight finishes; the next one on that connection, which
    // the old CA's certificate opened, is refused, and the connection closes.
    hold.release?.();
    expect((await held).status).toBe(200);
    const stale = await busy.request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` });
    expect(stale.status).toBe(403);
    expect(stale.headers['connection']).toBe('close');
    const reconnected = await busy
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })
      .catch((caught: unknown) => caught);
    expect((reconnected as InternalClientError).code).toBe('unreachable');

    const newPeer = otherPki.issue({ uris: ['spiffe://qauth.test/web'] });
    const response = await client(newPeer, { ca: otherPki.caPem }).request({
      method: 'GET',
      path: `${FIXTURE_PREFIX}/peer`,
    });
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });

    const refused = await client(peers.web, { ca: otherPki.caPem })
      .request({ method: 'GET', path: `${FIXTURE_PREFIX}/peer` })
      .catch((caught: unknown) => caught);
    expect((refused as InternalClientError).code).toBe('unreachable');
  });
});

describe('installInternalApi', () => {
  it('refuses a route outside /internal/', async () => {
    const server = createInternalServer({ peerRoles: PEER_ROLES });
    const scope = sourceScope();
    try {
      await expect(
        installInternalApi(server, scope, {
          roles: ['signer'],
          modules: [
            {
              module: 'misplaced',
              prefix: '/oauth',
              roles: ['signer'],
              peerRoles: ['web'],
              load: async () => ({
                default: async (routes) => void routes.get('/x', async () => ({})),
              }),
            },
          ],
        })
      ).rejects.toThrow('GET /oauth/x: every route of the internal listener sits under /internal/');
    } finally {
      await scope.close();
      await server.close();
    }
  });
});

describe('installInternalApi and peer roles', () => {
  it('refuses a module that names no peer role, before it loads any module', async () => {
    const server = createInternalServer({ peerRoles: PEER_ROLES });
    const scope = sourceScope();
    const load = vi.fn(async () => ({ default: fixtureRoutes }));
    try {
      await expect(
        installInternalApi(server, scope, {
          roles: ['signer'],
          modules: [FIXTURE_MODULE, { ...FIXTURE_MODULE, module: 'open', peerRoles: [], load }],
        })
      ).rejects.toThrow('The internal route module open names no peer role');
      expect(load).not.toHaveBeenCalled();
    } finally {
      await scope.close();
      await server.close();
    }
  });
});

describe('plain HTTP', () => {
  it('gives no request a peer role, so it refuses every one', async () => {
    const server = createInternalServer({ peerRoles: PEER_ROLES });
    const scope = sourceScope();
    try {
      await installInternalApi(server, scope, { roles: ['signer'], modules: [FIXTURE_MODULE] });
      await server.listen({ host: '127.0.0.1', port: 0 });
      const plainPort = (server.server.address() as AddressInfo).port;
      const response = await fetch(`http://127.0.0.1:${plainPort}${FIXTURE_PREFIX}/peer`);
      expect(response.status).toBe(403);
    } finally {
      await scope.close();
      await server.close();
    }
  });
});
