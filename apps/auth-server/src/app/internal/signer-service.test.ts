import type { AddressInfo } from 'node:net';

import {
  SIGNER_SERVICE_PATH,
  SIGNER_SERVICE_ROUTES,
  type SignerOperation,
} from '@qauth-labs/fastify-plugin-signer';
import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import { internalListenerEnvSchema } from '@qauth-labs/server-config';
import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance } from 'fastify';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    REQUEST_TIMEOUT_MS: 60_000,
    REQUEST_ID_HEADER: 'x-request-id',
  },
}));

import {
  createInternalPki,
  type InternalPki,
  type IssuedCredentials,
  tlsExchange,
  type TlsFileDirectory,
  writeTlsFiles,
} from '../../testing/internal-pki';
import { metricsPlugin } from '../plugins/metrics';
import { createInternalClient, type InternalClient } from './client';
import { createInternalServer, installInternalApi } from './listener';
import { type AppRemoteSigner, createAppRemoteSigner } from './remote-signer';
import { INTERNAL_ROUTE_MODULES } from './route-manifest';
import { readInternalTlsFiles } from './tls-files';

/**
 * THE SIGNER SERVICE OVER MUTUAL TLS (ADR-019 Decision 9, #497), Docker-free.
 *
 * The signer's side is the internal listener `main.ts` builds, with the
 * manifest's signer module and an in-memory signer; each caller's side is the
 * remote signer the app builds on a process without the signer, presenting
 * its role's certificate. Every call crosses a real TLS 1.3 connection on
 * loopback. `signer-service.integration.test.ts` runs the same two sides as
 * two booted servers on a database.
 */

const SIGNER_SAN = 'signer.qauth.internal';
const ISSUER = 'https://auth.signer-service.test';
const MARKER = 'claim-value-5e1f0b';

const PEERS = {
  web: 'spiffe://qauth.test/web',
  api: 'spiffe://qauth.test/api',
  delivery: 'spiffe://qauth.test/delivery',
  admin: 'spiffe://qauth.test/admin',
  metrics: 'spiffe://qauth.test/prometheus',
} as const;
type PeerName = keyof typeof PEERS;

const PEER_ROLES = internalListenerEnvSchema.parse({
  INTERNAL_PEER_ROLES: JSON.stringify(
    Object.fromEntries(Object.entries(PEERS).map(([role, san]) => [san, role]))
  ),
}).INTERNAL_PEER_ROLES;

const SIGNER_MODULE = INTERNAL_ROUTE_MODULES.find((entry) => entry.module === 'signer');

/** Every line both sides logged, as JSON. */
const logged: string[] = [];

/**
 * A log line's fields as the server's logger writes them: Fastify's request
 * and reply objects reduced to what its serializers keep, and the rest as
 * JSON, so every field a line carries is searched.
 */
function loggable(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value !== 'object' || value === null) return String(value);
  const { req, res, ...rest } = value as Record<string, unknown>;
  const request = req as { method?: string; url?: string } | undefined;
  const reply = res as { statusCode?: number } | undefined;
  return JSON.stringify({
    ...rest,
    ...(request === undefined ? {} : { req: { method: request.method, url: request.url } }),
    ...(reply === undefined ? {} : { res: { statusCode: reply.statusCode } }),
  });
}

function recordingLogger() {
  const record =
    (level: string) =>
    (...args: unknown[]) => {
      logged.push(`${level} ${args.map(loggable).join(' ')}`);
    };
  const logger = {
    level: 'debug',
    fatal: record('fatal'),
    error: record('error'),
    warn: record('warn'),
    info: record('info'),
    debug: record('debug'),
    trace: () => undefined,
    silent: () => undefined,
    child: () => logger,
  };
  return logger as never;
}

let pki: InternalPki;
let otherPki: InternalPki;
let test: TestSigner;
let realmId: string;
let signerFiles: TlsFileDirectory;
let port: number | undefined;
/** The app scope whose decorators the listener shares: one per start of the signer. */
let source: FastifyInstance;
const sources: FastifyInstance[] = [];
let signer: FastifyInstance['signer'];
const credentials = new Map<PeerName, IssuedCredentials>();
const peerFiles: TlsFileDirectory[] = [];
const remotes: AppRemoteSigner[] = [];
const clients: InternalClient[] = [];
/** The webhook calls the signer got, by caller. */
const webhookCallers: string[] = [];

/** Start the signer's internal listener, on `port` once it has one. */
async function startSigner(): Promise<void> {
  if (SIGNER_MODULE === undefined) throw new Error('the manifest has no signer module');
  // As the app scope `main.ts` registers: the listener shares its signer and
  // its metrics, and closes when it closes.
  source = Fastify({ logger: false });
  sources.push(source);
  for (const name of ['db', 'dbPool', 'repositories', 'redis'] as const) {
    source.decorate(name, { standIn: name } as never);
  }
  source.decorate('signer', signer);
  await source.register(metricsPlugin);
  const server = createInternalServer({
    loggerInstance: recordingLogger(),
    peerRoles: PEER_ROLES,
    tls: { files: signerFiles.files, material: readInternalTlsFiles(signerFiles.files) },
  });
  await installInternalApi(server, source, { roles: ['signer'], modules: [SIGNER_MODULE] });
  await server.listen({ host: '127.0.0.1', port: port ?? 0 });
  port = (server.server.address() as AddressInfo).port;
}

/** Stop the signer: its scope closes the listener with it. */
async function stopSigner(): Promise<void> {
  await source.close();
  sources.splice(sources.indexOf(source), 1);
}

/** The remote signer of a process whose certificate is `peer`'s. */
function remoteOf(
  peer: PeerName,
  limits: Parameters<typeof createAppRemoteSigner>[0]['limits'] = {}
): FastifyInstance['signer'] {
  const issued = credentials.get(peer);
  if (issued === undefined) throw new Error(`no credentials for ${peer}`);
  return remoteWith(issued, limits);
}

function remoteWith(
  issued: IssuedCredentials,
  limits: Parameters<typeof createAppRemoteSigner>[0]['limits'] = {}
): FastifyInstance['signer'] {
  const directory = writeTlsFiles(issued, pki.caPem);
  peerFiles.push(directory);
  const remote = createAppRemoteSigner(
    {
      url: `https://127.0.0.1:${port}`,
      serverSan: SIGNER_SAN,
      tls: { files: directory.files, material: readInternalTlsFiles(directory.files) },
      limits: { retryDelayMs: 0, ...limits },
    },
    { publishedKeys: test.signer, log: recordingLogger() }
  );
  remotes.push(remote);
  return remote.signer;
}

/** A raw client of the signer service, as `peer`. */
function rawClient(peer: PeerName): InternalClient {
  const issued = credentials.get(peer) as IssuedCredentials;
  const client = createInternalClient({
    url: `https://127.0.0.1:${port}`,
    cert: issued.cert,
    key: issued.key,
    ca: pki.caPem,
    expectedServerSan: SIGNER_SAN,
  });
  clients.push(client);
  return client;
}

function post(client: InternalClient, operation: SignerOperation, body: string | Buffer) {
  return client.request({
    method: 'POST',
    path: `${SIGNER_SERVICE_PATH}${SIGNER_SERVICE_ROUTES[operation]}`,
    headers: { 'content-type': 'application/json' },
    body,
  });
}

async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('expected the call to fail');
}

/** The refusals the signer service counted, by `role/operation/reason`. */
async function refusals(): Promise<Record<string, number>> {
  const metric = await source.metrics.signerRefusals.get();
  return Object.fromEntries(
    metric.values.map((value) => [
      `${value.labels['role']}/${value.labels['operation']}/${value.labels['reason']}`,
      value.value,
    ])
  );
}

function accessToken(claims: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    realmId,
    purpose: 'token_signing',
    typ: 'at+jwt',
    claims: { sub: 'user-1', aud: 'client-1', iat: now, exp: now + 300, ...claims },
  } as const;
}

beforeAll(async () => {
  pki = createInternalPki();
  otherPki = createInternalPki('Another internal CA');
  signerFiles = writeTlsFiles(pki.issue({ dnsNames: [SIGNER_SAN] }), pki.caPem);
  for (const [peer, san] of Object.entries(PEERS) as [PeerName, string][]) {
    credentials.set(peer, pki.issue({ uris: [san] }));
  }

  test = createTestSigner({ refreshIntervalMs: 0 });
  realmId = await test.addRealm({ issuer: ISSUER });
  // The in-memory signer keeps no webhook keys: this one signs for the
  // `delivery` caller alone, as the in-process signer's grant does.
  signer = Object.freeze({
    ...test.signer,
    signWebhook: async (caller: string) => {
      webhookCallers.push(caller);
      if (caller !== 'delivery') throw new Error(`signWebhook called as ${caller}`);
      return 'v1,c2lnbmF0dXJl';
    },
  }) as FastifyInstance['signer'];

  await startSigner();
}, 60_000);

afterAll(async () => {
  for (const remote of remotes) remote.close();
  for (const client of clients) client.close();
  for (const scope of sources) await scope.close();
  signerFiles?.remove();
  for (const directory of peerFiles) directory.remove();
});

describe('the signer service over mutual TLS (#497)', () => {
  it('signs an access token for the api role, which verifies against the realm JWKS', async () => {
    const api = remoteOf('api');
    const token = await api.signJws('api', accessToken());
    const jwks = await api.getJwks('api', realmId);
    const { payload } = await jwtVerify(
      token,
      createLocalJWKSet(jwks as unknown as JSONWebKeySet),
      {
        issuer: ISSUER,
        typ: 'at+jwt',
      }
    );
    expect(payload['sub']).toBe('user-1');
    expect(jwks.keys.map((key) => key['kid'])).toContain(decodeProtectedHeader(token).kid);
  });

  it('hands the cookie secrets to the web role, and refuses the api and delivery roles', async () => {
    const before = await refusals();
    const secrets = await remoteOf('web').getCookieSecrets('web', realmId);
    expect(secrets.current.secret.length).toBeGreaterThanOrEqual(32);

    // The call's own role passes the table; the certificate's does not.
    for (const peer of ['api', 'delivery'] as const) {
      const refused = await caught(remoteOf(peer).getCookieSecrets('web', realmId));
      expect(refused, peer).toBeInstanceOf(TemporarilyUnavailableError);
      expect(refused).toMatchObject({ details: { reason: 'signer_role_refused' } });
    }
    const after = await refusals();
    for (const role of ['api', 'delivery']) {
      const key = `${role}/getCookieSecrets/not_allowed`;
      expect(after[key] ?? 0, key).toBe((before[key] ?? 0) + 1);
    }
    expect(
      logged.filter((line) => line.includes("Refused a signer call the peer's role may not make"))
        .length
    ).toBeGreaterThanOrEqual(2);
  });

  it('signs a webhook for the delivery role, and refuses the web role', async () => {
    const request = { realmId, subscriptionId: 'sub-1', id: 'evt_1', timestamp: 1, body: '{}' };
    expect(await remoteOf('delivery').signWebhook('delivery', request)).toBe('v1,c2lnbmF0dXJl');
    const before = await refusals();
    expect(await caught(remoteOf('web').signWebhook('delivery', request))).toMatchObject({
      details: { reason: 'signer_role_refused' },
    });
    expect((await refusals())['web/signWebhook/not_allowed']).toBe(
      (before['web/signWebhook/not_allowed'] ?? 0) + 1
    );
    // The web role's call never reached the signer.
    expect(webhookCallers).toEqual(['delivery']);
  });

  it('refuses a caller without a valid client certificate at the handshake', async () => {
    const target = { host: '127.0.0.1', port: port ?? 0 };
    const path = `${SIGNER_SERVICE_PATH}${SIGNER_SERVICE_ROUTES.getJwks}`;
    const none = await tlsExchange(target, { ca: pki.caPem }, path);
    expect(none.received).toBe('');
    const forged = otherPki.issue({ uris: [PEERS.api] });
    const stranger = await tlsExchange(
      target,
      { ca: pki.caPem, cert: forged.cert, key: forged.key },
      path
    );
    expect(stranger.received).toBe('');

    // The remote signer of such a process gets no answer: 503, nothing signed.
    expect(await caught(remoteWith(forged).signJws('api', accessToken()))).toMatchObject({
      statusCode: 503,
      details: { reason: 'signer_unreachable' },
    });
  });

  it('refuses a peer whose role the module does not admit, before the service reads its call', async () => {
    const response = await post(rawClient('metrics'), 'getJwks', JSON.stringify({ realmId }));
    expect(response.status).toBe(403);
    expect(await caught(remoteOf('metrics').signJws('api', accessToken()))).toMatchObject({
      details: { reason: 'signer_peer_refused' },
    });
  });

  it('answers 503 while the signer is stopped, keeps the JWKS and verification, and recovers when it is back', async () => {
    const api = remoteOf('api', { failureThreshold: 2, openMs: 200 });
    const token = await api.signJws('api', accessToken());
    await stopSigner();
    try {
      for (let index = 0; index < 3; index += 1) {
        const refused = await caught(api.signJws('api', accessToken()));
        expect(refused).toBeInstanceOf(TemporarilyUnavailableError);
        expect((refused as TemporarilyUnavailableError).statusCode).toBe(503);
      }
      // The public reads come from the published keys, not the signer.
      const jwks = await api.getJwks('api', realmId);
      await expect(
        jwtVerify(token, createLocalJWKSet(jwks as unknown as JSONWebKeySet), { issuer: ISSUER })
      ).resolves.toBeDefined();
      expect((await api.getVerificationKeys('api', realmId, 'token_signing')).length).toBe(
        jwks.keys.length
      );
    } finally {
      await startSigner();
    }
    // The circuit opened after two failures; once its time is out, the next
    // call probes the signer and closes it, with no restart of the caller.
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(await api.signJws('api', accessToken())).toMatch(/^ey/);
    expect(logged.some((line) => line.includes('The signer service answers again'))).toBe(true);
  });

  it('answers with no claim value, plaintext or key bytes, and logs none', async () => {
    const api = rawClient('api');
    const web = rawClient('web');
    const secrets = await remoteOf('web').getCookieSecrets('web', realmId);
    const secretTexts = [secrets.current.secret, secrets.previous?.secret]
      .filter((secret) => secret !== undefined)
      .flatMap((secret) => [secret.toString('base64url'), secret.toString('hex')]);

    const answers = await Promise.all([
      // A claim the signer sets.
      post(api, 'signJws', JSON.stringify(accessToken({ iss: MARKER }))),
      // A field the operation does not take, named and valued with the marker.
      post(api, 'signJws', JSON.stringify({ ...accessToken(), [MARKER]: MARKER })),
      // A body that is not JSON, holding the marker.
      post(api, 'signJws', `{"claims":"${MARKER}`),
      // A realm with no issuer.
      post(
        api,
        'signJws',
        JSON.stringify({ ...accessToken({ secret: MARKER }), realmId: crypto.randomUUID() })
      ),
      // A ciphertext that does not open.
      post(
        api,
        'decrypt',
        JSON.stringify({ realmId, ciphertext: MARKER, context: 'oid4vp-response-key:x' })
      ),
      // A role the grant refuses, with the marker in its request.
      post(web, 'signJws', JSON.stringify(accessToken({ secret: MARKER }))),
      // An unknown named argument.
      post(web, 'getCookieSecrets', JSON.stringify({ realmId, [MARKER]: 1 })),
    ]);
    for (const answer of answers) {
      const body = answer.body.toString();
      expect(answer.status, body).toBeGreaterThanOrEqual(400);
      expect(answer.headers['cache-control']).toBe('no-store');
      expect(body).not.toContain(MARKER);
    }
    expect(answers.map((answer) => answer.status)).toEqual([400, 400, 400, 422, 422, 403, 400]);

    const all = logged.join('\n');
    expect(all).not.toContain(MARKER);
    for (const text of secretTexts) expect(all).not.toContain(text);
  });

  it('refuses a role with no grant for the operation before it reads the body', async () => {
    const web = rawClient('web');
    const path = `${SIGNER_SERVICE_PATH}${SIGNER_SERVICE_ROUTES.signJws}`;
    const answers = await Promise.all([
      // Not JSON: a role with the grant gets 400 for it.
      post(web, 'signJws', '{"claims":'),
      // Not even JSON's media type: 415 for a role with the grant.
      web.request({ method: 'POST', path, headers: { 'content-type': 'text/plain' }, body: 'x' }),
    ]);
    for (const answer of answers) {
      expect(answer.status, answer.body.toString()).toBe(403);
      expect(JSON.parse(answer.body.toString())).toMatchObject({
        error: { code: 'SIGNER_ACCESS_DENIED', caller: 'web', operation: 'signJws' },
      });
    }
    expect((await post(rawClient('api'), 'signJws', '{"claims":')).status).toBe(400);
  });

  it('answers a body larger than the operation takes with 413, before the service reads it', async () => {
    const response = await post(
      rawClient('web'),
      'getCookieSecrets',
      JSON.stringify({ realmId, padding: 'x'.repeat(70 * 1024) })
    );
    expect(response.status).toBe(413);
  });
});
