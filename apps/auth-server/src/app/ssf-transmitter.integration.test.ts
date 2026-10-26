import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-ssf/src/testing/egress-network';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE SHARED SIGNALS FRAMEWORK TRANSMITTER, END TO END (issue #410).
 *
 * The real app boots with Postgres, Redis, the in-process signer and the
 * delivery role; receivers are local HTTPS servers. The egress client
 * refuses loopback, so this suite replaces only its two network edges, as
 * the egress library's own tests do: a DNS table and a dialler that routes
 * the public addresses below to the local servers. Every check between,
 * the address checks included, is the production code.
 *
 * Covers the acceptance criteria of #410: metadata when enabled, none when
 * not; a receiver creates a push stream, adds a subject, asks for
 * verification and receives a SET that verifies with a key from the
 * metadata's `jwks_uri`, the transmitter's own JWKS, which the realm JWKS of
 * the token keys does not share (d-1026-09); the SET `jti` is the event id on every retry; a receiver answering 5xx is
 * retried and the status shows it; a private endpoint is refused at
 * registration and at delivery; with the switch off there is no route, no
 * metadata and no delivery row; a stream in one realm never gets another
 * realm's events. And the review fixes of #865: a paused stream's events are
 * held without spending attempts; a realm switched off answers as if the
 * routes did not exist; a token of another realm, or of a client whose scope
 * was taken away, manages no stream; the verification interval outlives a
 * recreated stream; and a stream deleted while a request on it runs is a 404.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const current = (): EgressTransport => {
    if (network.current === undefined) throw new Error('no fixture network');
    return network.current;
  };
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

const ISSUER = 'https://auth.example.com';
const HOST_B = 'beta.example.com';
const ISSUER_B = `https://${HOST_B}`;
const HOST_C = 'gamma.example.com';
const ISSUER_C = `https://${HOST_C}`;
const PUSH = 'urn:ietf:rfc:8935';
const VERIFICATION = 'https://schemas.openid.net/secevent/ssf/event-type/verification';
const VERIFICATION_EVENT_TYPE = 'urn:qauth:event:ssf.stream.verification_requested:v1-rc.0';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };

/** Public addresses the fixture DNS hands out; each is served by a local server. */
const RECEIVER_ADDRESS = '93.184.215.14';
const OTHER_RECEIVER_ADDRESS = '151.101.1.140';
/** A private address; the server behind it must never be reached. */
const PRIVATE_ADDRESS = '10.0.0.7';

type Handler = (req: IncomingMessage, body: Buffer, res: ServerResponse) => void;

const accept: Handler = (_req, _body, res) => {
  res.writeHead(202);
  res.end();
};

interface Receiver {
  readonly clientId: string;
  readonly id: string;
  readonly token: string;
}

describe('the SSF transmitter (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let net: FixtureNetwork | undefined;
  let receiver: FixtureServer;
  let otherReceiver: FixtureServer;
  let internal: FixtureServer;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    net = await createFixtureNetwork();
    receiver = await net.serve(RECEIVER_ADDRESS, accept);
    otherReceiver = await net.serve(OTHER_RECEIVER_ADDRESS, accept);
    internal = await net.serve(PRIVATE_ADDRESS, accept);
  }, 240_000);

  afterAll(async () => {
    await net?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp || !net) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set('receiver.egress.test', [RECEIVER_ADDRESS]);
    net.dns.set('other.egress.test', [OTHER_RECEIVER_ADDRESS]);
    net.dns.set('internal.egress.test', [PRIVATE_ADDRESS]);
    for (const server of [receiver, otherReceiver, internal]) {
      server.requests.length = 0;
      server.handler = accept;
    }
    network.current = net.transport;
  });

  afterEach(async () => {
    await Promise.all(booted.splice(0).map((server) => server.close()));
  });

  /** Boot the server; the database keeps what earlier tests wrote, so every id here is new. */
  async function boot(environment: Record<string, string> = {}): Promise<FastifyInstance> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer({
      ...baseEnvironment(infra, jwt),
      // A retry one second after a failure, two after the next.
      EVENT_DELIVERY_RETRY_INITIAL_DELAY: '1',
      EVENT_DELIVERY_RETRY_MAX_DELAY: '2',
      ...environment,
    });
    booted.push(server);
    return server.app;
  }

  async function setRealmSwitch(app: FastifyInstance, name: string, on: boolean): Promise<string> {
    const { rows } = await app.dbPool.query<{ id: string }>(
      'UPDATE realms SET ssf_transmitter_enabled = $2 WHERE name = $1 RETURNING id::text AS id',
      [name, on]
    );
    // The resolver caches realm rows; a test must not wait out its cache.
    app.realmHostCache.clear();
    return rows[0].id;
  }

  /** A receiver client of the realm, and an access token it got with its own credentials. */
  async function newReceiver(
    app: FastifyInstance,
    realmId: string,
    options: {
      audience?: string | string[];
      host?: string;
      scopes?: string[];
      clientId?: string;
    } = {}
  ): Promise<Receiver> {
    const clientId = options.clientId ?? `receiver-${randomUUID()}`;
    const secret = `secret-${randomUUID()}`;
    const scopes = options.scopes ?? ['ssf:stream'];
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(secret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'SSF receiver',
      redirectUris: [],
      scopes,
      grantTypes: ['client_credentials'],
      audience: [options.audience ?? ISSUER].flat(),
      enabled: true,
      requirePkce: false,
    });
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, ...(options.host === undefined ? {} : { host: options.host }) },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: secret,
        scope: scopes.join(' '),
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return {
      clientId,
      id: client.id,
      token: response.json<{ access_token: string }>().access_token,
    };
  }

  function call(
    app: FastifyInstance,
    who: Receiver,
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    url: string,
    payload?: unknown,
    host?: string
  ) {
    return app.inject({
      method,
      url,
      headers: {
        authorization: `Bearer ${who.token}`,
        ...(host === undefined ? {} : { host }),
      },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  async function createStream(
    app: FastifyInstance,
    who: Receiver,
    endpoint = 'https://receiver.egress.test/events',
    options: { host?: string; authorizationHeader?: string | null } = {}
  ): Promise<string> {
    const header =
      options.authorizationHeader === undefined ? 'Bearer push-me' : options.authorizationHeader;
    const response = await call(
      app,
      who,
      'POST',
      '/ssf/stream',
      {
        events_requested: [VERIFICATION],
        delivery: {
          method: PUSH,
          endpoint_url: endpoint,
          ...(header === null ? {} : { authorization_header: header }),
        },
        description: 'an E2E receiver',
      },
      options.host
    );
    expect(response.statusCode, response.body).toBe(201);
    return response.json<{ stream_id: string }>().stream_id;
  }

  /** The id of the verification event the realm recorded for the stream, once there is one. */
  async function verificationEventIds(app: FastifyInstance, streamId: string): Promise<string[]> {
    const { rows } = await app.dbPool.query<{ id: string }>(
      `SELECT id::text AS id FROM events WHERE type = $1 AND subject_type = 'ssf_stream'
         AND subject_id = $2 ORDER BY seq`,
      [VERIFICATION_EVENT_TYPE, streamId]
    );
    return rows.map((row) => row.id);
  }

  async function ssfRows(app: FastifyInstance): Promise<number> {
    const { rows } = await app.dbPool.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM event_deliveries WHERE destination_kind = 'ssf'`
    );
    return rows[0].count;
  }

  describe('with SSF_TRANSMITTER_ENABLED off (the default deployment)', () => {
    it('registers no route, publishes no metadata, adds no key and writes no delivery row', async () => {
      const app = await boot();
      // Even a realm whose own switch is on, with a stream stored, gets nothing.
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const client = await app.repositories.oauthClients.create({
        realmId,
        clientId: `receiver-${randomUUID()}`,
        clientSecretHash: 'unused',
        name: 'stored receiver',
        redirectUris: [],
        scopes: ['ssf:stream'],
        grantTypes: ['client_credentials'],
        enabled: true,
        requirePkce: false,
      });
      const stream = await app.repositories.ssfStreams.create({
        realmId,
        receiverClientId: client.id,
        audience: client.clientId,
        eventsRequested: [VERIFICATION],
        deliveryMethod: PUSH,
        endpointUrl: 'https://receiver.egress.test/events',
        authorizationHeader: null,
        description: null,
      });
      expect(stream).not.toBeNull();

      const missing = await app.inject({ method: 'GET', url: `/no-such-route-${randomUUID()}` });
      expect(missing.statusCode).toBe(404);
      const metadata = await app.inject({ method: 'GET', url: '/.well-known/ssf-configuration' });
      expect(metadata.statusCode).toBe(404);
      expect(metadata.json()).toMatchObject({ error: 'Not Found', statusCode: 404 });
      expect(metadata.json<{ message: string }>().message).toMatch(/^Route GET:/);
      for (const [method, url] of [
        ['POST', '/ssf/stream'],
        ['GET', '/ssf/status'],
        ['POST', '/ssf/verify'],
        ['GET', '/ssf/jwks.json'],
      ] as const) {
        const response = await app.inject({ method, url, payload: {} });
        expect(response.statusCode, url).toBe(404);
        expect(response.json<{ message: string }>().message, url).toMatch(/^Route /);
      }

      const jwks = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
      expect(jwks.json()).toEqual(await app.jwtUtils.getJwks());

      // Events go on being written; none is fanned out to an SSF stream.
      await app.repositories.events.emitInOwnTransaction({
        type: VERIFICATION_EVENT_TYPE,
        realm: realmId,
        subject: { type: 'ssf_stream', id: stream?.id ?? '' },
        data: {},
      });
      await new Promise((resolve) => setTimeout(resolve, 2500));
      expect(await ssfRows(app)).toBe(0);
      const { rows: positions } = await app.dbPool.query(
        `SELECT 1 FROM event_delivery_positions WHERE destination_kind = 'ssf'`
      );
      expect(positions).toEqual([]);
      expect(receiver.requests).toEqual([]);
      await app.repositories.ssfStreams.remove({
        realmId,
        receiverClientId: client.id,
        streamId: stream?.id ?? '',
      });
    });
  });

  describe('with SSF_TRANSMITTER_ENABLED on', () => {
    const on = { SSF_TRANSMITTER_ENABLED: 'true' };

    it('publishes valid metadata for a realm that runs the transmitter, and 404 for one that does not', async () => {
      const app = await boot(on);
      await setRealmSwitch(app, E2E_REALM_NAME, false);
      const off = await app.inject({ method: 'GET', url: '/.well-known/ssf-configuration' });
      expect(off.statusCode).toBe(404);

      await setRealmSwitch(app, E2E_REALM_NAME, true);
      const response = await app.inject({ method: 'GET', url: '/.well-known/ssf-configuration' });
      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toMatch(/^application\/json/);
      expect(response.json()).toEqual({
        spec_version: '1_0',
        issuer: ISSUER,
        jwks_uri: `${ISSUER}/ssf/jwks.json`,
        delivery_methods_supported: [PUSH],
        configuration_endpoint: `${ISSUER}/ssf/stream`,
        status_endpoint: `${ISSUER}/ssf/status`,
        add_subject_endpoint: `${ISSUER}/ssf/subjects/add`,
        remove_subject_endpoint: `${ISSUER}/ssf/subjects/remove`,
        verification_endpoint: `${ISSUER}/ssf/verify`,
        authorization_schemes: [{ spec_urn: 'urn:ietf:rfc:6749' }],
        default_subjects: 'NONE',
      });
    });

    it('lets a receiver create a push stream, add a subject, verify it, and receive a SET that verifies with the metadata’s jwks_uri', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const streamId = await createStream(app, who);

      const read = await call(app, who, 'GET', `/ssf/stream?stream_id=${streamId}`);
      expect(read.statusCode, read.body).toBe(200);
      expect(read.json()).toEqual({
        stream_id: streamId,
        iss: ISSUER,
        aud: who.clientId,
        events_supported: [],
        events_requested: [VERIFICATION],
        events_delivered: [],
        delivery: { method: PUSH, endpoint_url: 'https://receiver.egress.test/events' },
        min_verification_interval: 10,
        description: 'an E2E receiver',
      });
      expect(read.body).not.toContain('push-me');
      const stored = await app.dbPool.query<{ authorization_header: string }>(
        'SELECT authorization_header FROM ssf_streams WHERE id = $1',
        [streamId]
      );
      expect(stored.rows[0].authorization_header).toMatch(/^v1\./);

      const added = await call(app, who, 'POST', '/ssf/subjects/add', {
        stream_id: streamId,
        subject: { format: 'iss_sub', iss: ISSUER, sub: randomUUID() },
      });
      expect(added.statusCode, added.body).toBe(200);
      expect(added.body).toBe('');

      const verify = await call(app, who, 'POST', '/ssf/verify', {
        stream_id: streamId,
        state: 'VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=',
      });
      expect(verify.statusCode, verify.body).toBe(204);
      const again = await call(app, who, 'POST', '/ssf/verify', { stream_id: streamId });
      expect(again.statusCode).toBe(429);

      await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
        timeout: 15_000,
        interval: 100,
      });
      const [push] = receiver.requests;
      expect(push.method).toBe('POST');
      expect(push.url).toBe('/events');
      expect(push.headers['content-type']).toBe('application/secevent+jwt');
      expect(push.headers['authorization']).toBe('Bearer push-me');

      const token = push.body.toString('utf8');
      expect(decodeProtectedHeader(token)).toMatchObject({ alg: 'EdDSA', typ: 'secevent+jwt' });
      // A receiver finds the SET keys as SSF 1.0 §7.1 says: the metadata's
      // jwks_uri, the transmitter's own JWKS.
      const metadata = await app.inject({ method: 'GET', url: '/.well-known/ssf-configuration' });
      const jwksUri = new URL(metadata.json<{ jwks_uri: string }>().jwks_uri);
      expect(jwksUri.origin).toBe(ISSUER);
      const setKeys = await app.inject({ method: 'GET', url: jwksUri.pathname });
      expect(setKeys.statusCode, setKeys.body).toBe(200);
      const { payload } = await jwtVerify(token, createLocalJWKSet(setKeys.json<JSONWebKeySet>()), {
        issuer: ISSUER,
        audience: who.clientId,
        typ: 'secevent+jwt',
      });
      // The realm JWKS of the token keys holds no SET key, so a SET never
      // verifies as a token (d-1026-09).
      const tokenKeys = (
        await app.inject({ method: 'GET', url: '/.well-known/jwks.json' })
      ).json<JSONWebKeySet>();
      expect(tokenKeys.keys.map((key) => key.kid)).not.toContain(decodeProtectedHeader(token).kid);
      await expect(jwtVerify(token, createLocalJWKSet(tokenKeys))).rejects.toThrow();
      const [eventId] = await verificationEventIds(app, streamId);
      expect(payload).toEqual({
        iss: ISSUER,
        jti: eventId,
        iat: expect.any(Number),
        aud: who.clientId,
        sub_id: { format: 'opaque', id: streamId },
        events: { [VERIFICATION]: { state: 'VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=' } },
      });

      await vi.waitFor(
        async () => {
          const status = await call(app, who, 'GET', `/ssf/status?stream_id=${streamId}`);
          expect(status.json()).toEqual({
            stream_id: streamId,
            status: 'enabled',
            delivery_status: { pending: 0 },
          });
        },
        { timeout: 5000, interval: 100 }
      );
    });

    it('retries a receiver that answers 5xx with the same jti, the event id, and shows the failure on the status', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const streamId = await createStream(app, who);
      let answered = 0;
      receiver.handler = (_req, _body, res) => {
        answered += 1;
        res.writeHead(answered <= 2 ? 503 : 202);
        res.end();
      };

      const verify = await call(app, who, 'POST', '/ssf/verify', { stream_id: streamId });
      expect(verify.statusCode, verify.body).toBe(204);
      const [eventId] = await verificationEventIds(app, streamId);

      await vi.waitFor(
        async () => {
          const status = await call(app, who, 'GET', `/ssf/status?stream_id=${streamId}`);
          expect(status.json()).toMatchObject({
            delivery_status: {
              pending: 1,
              last_failure: {
                event_id: eventId,
                status_code: 503,
                error: 'http_status',
                state: 'retrying',
              },
            },
          });
        },
        { timeout: 15_000, interval: 100 }
      );

      await vi.waitFor(() => expect(receiver.requests).toHaveLength(3), {
        timeout: 20_000,
        interval: 100,
      });
      const tokens = receiver.requests.map((request) => request.body.toString('utf8'));
      const jtis = tokens.map(
        (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).jti
      );
      expect(jtis).toEqual([eventId, eventId, eventId]);
      // The same claims on every attempt, and EdDSA signs them the same way.
      expect(new Set(tokens).size).toBe(1);

      const rows = await app.repositories.eventDeliveries.listForEvent(eventId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        status: 'delivered',
        attemptCount: 3,
        destinationId: streamId,
      });
    });

    it('refuses a private endpoint at registration and at delivery', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);

      for (const endpoint of [
        `https://${PRIVATE_ADDRESS}/events`,
        'https://internal.egress.test/events',
        'https://127.0.0.1/events',
      ]) {
        const response = await call(app, who, 'POST', '/ssf/stream', {
          delivery: { method: PUSH, endpoint_url: endpoint },
        });
        expect(response.statusCode, endpoint).toBe(400);
        expect(response.json<{ error: string }>().error).toBe('endpoint_url is refused');
      }
      expect(await app.repositories.ssfStreams.list(realmId, who.id)).toEqual([]);

      // Public when it registers, private when it is delivered to.
      net?.dns.set('flip.egress.test', [OTHER_RECEIVER_ADDRESS]);
      const streamId = await createStream(app, who, 'https://flip.egress.test/events');
      net?.dns.set('flip.egress.test', [PRIVATE_ADDRESS]);
      const verify = await call(app, who, 'POST', '/ssf/verify', { stream_id: streamId });
      expect(verify.statusCode, verify.body).toBe(204);

      // The receiver reads one class for a refused and an unreachable
      // endpoint; the delivery history keeps which it was.
      await vi.waitFor(
        async () => {
          const status = await call(app, who, 'GET', `/ssf/status?stream_id=${streamId}`);
          expect(status.json()).toMatchObject({
            delivery_status: { last_failure: { error: 'destination_unreachable' } },
          });
        },
        { timeout: 15_000, interval: 100 }
      );
      const [eventId] = await verificationEventIds(app, streamId);
      expect((await app.repositories.eventDeliveries.listForEvent(eventId))[0]).toMatchObject({
        lastErrorClass: 'destination_blocked',
      });
      expect(internal.requests).toEqual([]);
      expect(otherReceiver.requests).toEqual([]);
    });

    it('keeps each realm to its own streams: no other realm’s receiver, stream or event reaches them', async () => {
      const app = await boot(on);
      const realmA = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const { realm } = await app.repositories.realms.createWithPrimaryHost(
        { name: `beta-${randomUUID()}`, issuer: ISSUER_B, enabled: true },
        HOST_B
      );
      await setRealmSwitch(app, realm.name, true);
      const realmB = realm.id;

      const inA = await newReceiver(app, realmA);
      const inB = await newReceiver(app, realmB, { audience: ISSUER_B, host: HOST_B });
      const streamA = await createStream(app, inA);
      // The second realm has no keys of its own (only the default realm's are
      // made at boot), so its receiver sends no header to encrypt, and its
      // SETs cannot be signed: what matters here is where its rows go.
      const streamB = await createStream(app, inB, 'https://other.egress.test/events', {
        host: HOST_B,
        authorizationHeader: null,
      });

      // A's token is no receiver of B, and A cannot name B's stream at its own host.
      expect((await call(app, inA, 'GET', '/ssf/stream', undefined, HOST_B)).statusCode).toBe(401);
      expect((await call(app, inA, 'GET', `/ssf/stream?stream_id=${streamB}`)).statusCode).toBe(
        404
      );
      expect((await call(app, inA, 'POST', '/ssf/verify', { stream_id: streamB })).statusCode).toBe(
        404
      );
      expect((await call(app, inA, 'GET', '/ssf/stream')).json()).toEqual([
        expect.objectContaining({ stream_id: streamA }),
      ]);

      // B's verification is B's stream's alone.
      const verify = await call(app, inB, 'POST', '/ssf/verify', { stream_id: streamB }, HOST_B);
      expect(verify.statusCode, verify.body).toBe(204);
      const [eventB] = await verificationEventIds(app, streamB);
      const rows = await app.repositories.eventDeliveries.listForEvent(eventB);
      expect(rows.map((row) => [row.destinationKind, row.destinationId, row.realmId])).toEqual([
        ['ssf', streamB, realmB],
      ]);

      // A's receiver gets A's own verification and nothing of B's.
      const verifyA = await call(app, inA, 'POST', '/ssf/verify', { stream_id: streamA });
      expect(verifyA.statusCode).toBe(204);
      await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
        timeout: 15_000,
        interval: 100,
      });
      await new Promise((resolve) => setTimeout(resolve, 1500));
      expect(receiver.requests).toHaveLength(1);
      const claims = JSON.parse(
        Buffer.from(receiver.requests[0].body.toString('utf8').split('.')[1], 'base64url').toString(
          'utf8'
        )
      );
      expect(claims).toMatchObject({ iss: ISSUER, sub_id: { id: streamA } });
    });

    it('refuses a token that is not a receiver’s', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const noScope = await newReceiver(app, realmId, { scopes: ['reports:read'] });
      const otherAudience = await newReceiver(app, realmId, {
        audience: 'https://resource.example',
      });
      // A valid token without the scope is a 403 (RFC 6750 §3.1); one for
      // another resource is not valid here at all.
      expect((await call(app, noScope, 'GET', '/ssf/stream')).statusCode).toBe(403);
      const response = await call(app, otherAudience, 'GET', '/ssf/stream');
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toMatch(/error="invalid_token"/);
      expect((await app.inject({ method: 'GET', url: '/ssf/stream' })).statusCode).toBe(401);

      // A receiver whose scope is taken away stops at once, not when its
      // token expires, as its deliveries do.
      const who = await newReceiver(app, realmId);
      expect((await call(app, who, 'GET', '/ssf/stream')).statusCode).toBe(200);
      await app.dbPool.query(`UPDATE oauth_clients SET scopes = '["reports:read"]' WHERE id = $1`, [
        who.id,
      ]);
      const scopeGone = await call(app, who, 'GET', '/ssf/stream');
      expect(scopeGone.statusCode).toBe(401);
      expect(scopeGone.headers['www-authenticate']).toMatch(/error="invalid_token"/);
    });

    it('refuses a token minted in another realm, even for a client of the same client_id there', async () => {
      const app = await boot(on);
      const realmA = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const { realm } = await app.repositories.realms.createWithPrimaryHost(
        { name: `gamma-${randomUUID()}`, issuer: ISSUER_C, enabled: true },
        HOST_C
      );
      const realmC = await setRealmSwitch(app, realm.name, true);
      // Realm A's client lists C's issuer in its audience too, and C has a
      // receiver with the same client_id.
      const clientId = `shared-${randomUUID()}`;
      const inA = await newReceiver(app, realmA, { clientId, audience: [ISSUER, ISSUER_C] });
      await newReceiver(app, realmC, { clientId, audience: ISSUER_C, host: HOST_C });

      const response = await call(app, inA, 'GET', '/ssf/stream', undefined, HOST_C);
      expect(response.statusCode).toBe(401);
      expect(response.headers['www-authenticate']).toMatch(/error="invalid_token"/);
    });

    it('updates, replaces, pauses and deletes a stream as SSF 1.0 §8.1 says', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const streamId = await createStream(app, who);

      expect(
        (
          await call(app, who, 'POST', '/ssf/stream', {
            delivery: { method: PUSH, endpoint_url: 'https://receiver.egress.test/other' },
          })
        ).statusCode
      ).toBe(409);

      const patched = await call(app, who, 'PATCH', '/ssf/stream', {
        stream_id: streamId,
        description: 'patched',
        aud: who.clientId,
      });
      expect(patched.statusCode, patched.body).toBe(200);
      expect(patched.json()).toMatchObject({
        description: 'patched',
        events_requested: [VERIFICATION],
      });
      const storedHeader = async () =>
        (
          await app.dbPool.query<{ h: string | null }>(
            'SELECT authorization_header AS h FROM ssf_streams WHERE id = $1',
            [streamId]
          )
        ).rows[0].h;
      const header = await storedHeader();
      expect(header).toMatch(/^v1\./);
      // Sending back what a read returns keeps the header QAuth never returns.
      const echoed = await call(app, who, 'PATCH', '/ssf/stream', {
        stream_id: streamId,
        delivery: patched.json<{ delivery: unknown }>().delivery,
      });
      expect(echoed.statusCode, echoed.body).toBe(200);
      expect(await storedHeader()).toBe(header);
      const wrongAud = await call(app, who, 'PATCH', '/ssf/stream', {
        stream_id: streamId,
        aud: 'someone-else',
      });
      expect(wrongAud.statusCode).toBe(400);

      const replaced = await call(app, who, 'PUT', '/ssf/stream', {
        stream_id: streamId,
        delivery: { method: PUSH, endpoint_url: 'https://receiver.egress.test/replaced' },
      });
      expect(replaced.statusCode, replaced.body).toBe(200);
      expect(replaced.json()).toMatchObject({
        events_requested: [],
        delivery: { endpoint_url: 'https://receiver.egress.test/replaced' },
      });
      expect(replaced.json()).not.toHaveProperty('description');
      // A new endpoint never gets the old header.
      expect(await storedHeader()).toBeNull();
      const poll = await call(app, who, 'PUT', '/ssf/stream', { stream_id: streamId });
      expect(poll.statusCode).toBe(400);

      const paused = await call(app, who, 'POST', '/ssf/status', {
        stream_id: streamId,
        status: 'paused',
        reason: 'maintenance',
      });
      expect(paused.json()).toMatchObject({ status: 'paused', reason: 'maintenance' });

      const removed = await call(app, who, 'POST', '/ssf/subjects/remove', {
        stream_id: streamId,
        subject: { format: 'opaque', id: 'never-added' },
      });
      expect(removed.statusCode).toBe(204);

      expect((await call(app, who, 'DELETE', `/ssf/stream?stream_id=${streamId}`)).statusCode).toBe(
        204
      );
      expect((await call(app, who, 'GET', `/ssf/stream?stream_id=${streamId}`)).statusCode).toBe(
        404
      );
      expect((await call(app, who, 'GET', '/ssf/stream')).json()).toEqual([]);
    });

    it('holds a paused stream’s events without spending attempts, and sends them once it is enabled', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const streamId = await createStream(app, who);
      const paused = await call(app, who, 'POST', '/ssf/status', {
        stream_id: streamId,
        status: 'paused',
      });
      expect(paused.statusCode, paused.body).toBe(200);
      expect(
        (await call(app, who, 'POST', '/ssf/verify', { stream_id: streamId })).statusCode
      ).toBe(204);
      const [eventId] = await verificationEventIds(app, streamId);
      const row = async () =>
        (
          await app.dbPool.query<{
            attempt_count: number;
            last_error_class: string | null;
            wait: string;
          }>(
            `SELECT attempt_count, last_error_class, (next_attempt_at - updated_at)::text AS wait
               FROM event_deliveries WHERE event_id = $1`,
            [eventId]
          )
        ).rows[0];

      // Looked at and held: the next look is the hold interval away, and the
      // look spent no attempt and recorded no failure.
      await vi.waitFor(async () => expect((await row()).wait).toBe('30000'), {
        timeout: 15_000,
        interval: 100,
      });
      expect(await row()).toMatchObject({ attempt_count: 0, last_error_class: null });
      expect(receiver.requests).toEqual([]);
      const status = await call(app, who, 'GET', `/ssf/status?stream_id=${streamId}`);
      expect(status.json()).toEqual({
        stream_id: streamId,
        status: 'paused',
        delivery_status: { pending: 1 },
      });

      // Enabled again, it is sent at the next look, which the test brings
      // forward rather than wait the interval out.
      await call(app, who, 'POST', '/ssf/status', { stream_id: streamId, status: 'enabled' });
      await app.dbPool.query(
        'UPDATE event_deliveries SET next_attempt_at = 0 WHERE event_id = $1',
        [eventId]
      );
      await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
        timeout: 15_000,
        interval: 100,
      });
      await vi.waitFor(
        async () =>
          expect((await app.repositories.eventDeliveries.listForEvent(eventId))[0]).toMatchObject({
            status: 'delivered',
            attemptCount: 1,
          }),
        { timeout: 5000, interval: 100 }
      );
    });

    it('answers a realm whose switch is off as if the routes did not exist, before reading the request', async () => {
      const app = await boot(on);
      await setRealmSwitch(app, E2E_REALM_NAME, false);
      const unknown = await app.inject({ method: 'POST', url: '/no-such-route', payload: {} });
      expect(unknown.statusCode).toBe(404);
      for (const [method, url] of [
        ['POST', '/ssf/status'],
        ['POST', '/ssf/stream'],
        ['GET', '/ssf/status'],
        ['GET', '/ssf/jwks.json'],
      ] as const) {
        // An empty body would fail validation: the 404 comes first.
        const response = await app.inject({ method, url, payload: {} });
        expect(response.statusCode, url).toBe(404);
        expect(response.json(), url).toEqual({
          ...unknown.json(),
          message: `Route ${method}:${url} not found`,
        });
      }
    });

    it('keeps the verification interval when the receiver deletes its stream and creates another', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const first = await createStream(app, who);
      expect((await call(app, who, 'POST', '/ssf/verify', { stream_id: first })).statusCode).toBe(
        204
      );
      expect((await call(app, who, 'DELETE', `/ssf/stream?stream_id=${first}`)).statusCode).toBe(
        204
      );
      const second = await createStream(app, who);
      const again = await call(app, who, 'POST', '/ssf/verify', { stream_id: second });
      expect(again.statusCode).toBe(429);
    });

    it('answers 404, not 500, when the receiver deletes its stream while a request on it runs', async () => {
      const app = await boot(on);
      const realmId = await setRealmSwitch(app, E2E_REALM_NAME, true);
      const who = await newReceiver(app, realmId);
      const streamId = await createStream(app, who);
      const found = await app.repositories.ssfStreams.find({
        realmId,
        receiverClientId: who.id,
        streamId,
      });
      // The request finds the stream; the receiver's DELETE lands before it
      // writes.
      expect((await call(app, who, 'DELETE', `/ssf/stream?stream_id=${streamId}`)).statusCode).toBe(
        204
      );
      const find = vi.spyOn(app.repositories.ssfStreams, 'find').mockResolvedValue(found);
      try {
        const added = await call(app, who, 'POST', '/ssf/subjects/add', {
          stream_id: streamId,
          subject: { format: 'opaque', id: 'late' },
        });
        expect(added.statusCode, added.body).toBe(404);
        const verify = await call(app, who, 'POST', '/ssf/verify', { stream_id: streamId });
        expect(verify.statusCode, verify.body).toBe(404);
      } finally {
        find.mockRestore();
      }
      // Nothing was recorded.
      expect(await verificationEventIds(app, streamId)).toEqual([]);
    });
  });
});
