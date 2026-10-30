import { createHash, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-ssf/src/testing/egress-network';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  type JSONWebKeySet,
  type JWTPayload,
  jwtVerify,
} from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * QAUTH'S SECURITY EVENTS ON SSF STREAMS, END TO END (issue #540).
 *
 * The real app boots with Postgres, Redis, the in-process signer and the
 * delivery role; receivers are local HTTPS servers behind the egress
 * client's two network edges, as in the transmitter suite of #410.
 *
 * Covers the integration acceptance criteria of #540: signing out a
 * subscribed user delivers a CAEP `session-revoked` SET with an `iss_sub`
 * `sub_id`, `event_timestamp` and `initiating_entity`; revoking an API key
 * delivers `credential-change`; withdrawing a consent delivers
 * `token-claims-change`, to the consent's own client only; an RFC 7009
 * revocation delivers the QAuth-defined event, whose identifier is a
 * versioned `urn:qauth:` one; a receiver cannot add a user with no consent
 * for and no token from its client, and can add one who has either. Every
 * delivered SET is checked for the claims RFC 8417 §2.2 requires.
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
const PUSH = 'urn:ietf:rfc:8935';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const SESSION_REVOKED = `${CAEP}session-revoked`;
const CREDENTIAL_CHANGE = `${CAEP}credential-change`;
const TOKEN_CLAIMS_CHANGE = `${CAEP}token-claims-change`;
const TOKEN_REVOKED = 'urn:qauth:secevent:token-revoked:v1-rc.0';
const ALL_EVENTS = [SESSION_REVOKED, CREDENTIAL_CHANGE, TOKEN_CLAIMS_CHANGE, TOKEN_REVOKED];

/** Public addresses the fixture DNS hands out; each is served by a local server. */
const RECEIVER_ADDRESS = '93.184.215.14';
const OTHER_RECEIVER_ADDRESS = '151.101.1.140';

interface Receiver {
  readonly clientId: string;
  /** The receiver's `oauth_clients.id`. */
  readonly id: string;
  readonly secret: string;
  readonly token: string;
}

/** A delivered SET, verified with the transmitter's own keys. */
interface DeliveredSet {
  readonly header: ReturnType<typeof decodeProtectedHeader>;
  readonly claims: JWTPayload & Record<string, unknown>;
}

describe('security events on SSF streams (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let net: FixtureNetwork | undefined;
  let receiver: FixtureServer;
  let otherReceiver: FixtureServer;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    net = await createFixtureNetwork();
    const accept = (_req: IncomingMessage, _body: Buffer, res: ServerResponse) => {
      res.writeHead(202);
      res.end();
    };
    receiver = await net.serve(RECEIVER_ADDRESS, accept);
    otherReceiver = await net.serve(OTHER_RECEIVER_ADDRESS, accept);
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
    for (const server of [receiver, otherReceiver]) server.requests.length = 0;
    network.current = net.transport;
  });

  afterEach(async () => {
    await Promise.all(booted.splice(0).map((server) => server.close()));
  });

  /** Boot the server with the transmitter on; the database keeps earlier tests' rows, so every id is new. */
  async function boot(): Promise<{ app: FastifyInstance; realmId: string }> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer({
      ...baseEnvironment(infra, jwt),
      SSF_TRANSMITTER_ENABLED: 'true',
      // Every request comes from one address, and the suite registers and
      // signs in more accounts than the per-address defaults allow.
      REGISTRATION_RATE_LIMIT: '100',
      LOGIN_RATE_LIMIT: '100',
      EVENT_DELIVERY_RETRY_INITIAL_DELAY: '1',
      EVENT_DELIVERY_RETRY_MAX_DELAY: '2',
    });
    booted.push(server);
    const { app } = server;
    const { rows } = await app.dbPool.query<{ id: string }>(
      'UPDATE realms SET ssf_transmitter_enabled = true WHERE name = $1 RETURNING id::text AS id',
      [E2E_REALM_NAME]
    );
    app.realmHostCache.clear();
    return { app, realmId: rows[0].id };
  }

  /** A receiver client of the realm, and an access token it got with its own credentials. */
  async function newReceiver(app: FastifyInstance, realmId: string): Promise<Receiver> {
    const clientId = `receiver-${randomUUID()}`;
    const secret = `secret-${randomUUID()}`;
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(secret),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'SSF receiver',
      redirectUris: [],
      scopes: ['ssf:stream'],
      grantTypes: ['client_credentials'],
      audience: [ISSUER],
      enabled: true,
      requirePkce: false,
    });
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: secret,
        scope: 'ssf:stream',
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return {
      clientId,
      id: client.id,
      secret,
      token: response.json<{ access_token: string }>().access_token,
    };
  }

  function call(app: FastifyInstance, who: Receiver, url: string, payload: unknown) {
    return app.inject({
      method: 'POST',
      url,
      headers: { authorization: `Bearer ${who.token}` },
      payload: payload as Record<string, unknown>,
    });
  }

  async function createStream(
    app: FastifyInstance,
    who: Receiver,
    endpoint = 'https://receiver.egress.test/events'
  ): Promise<string> {
    const response = await call(app, who, '/ssf/stream', {
      events_requested: ALL_EVENTS,
      delivery: { method: PUSH, endpoint_url: endpoint },
    });
    expect(response.statusCode, response.body).toBe(201);
    const created = response.json<{ stream_id: string; events_delivered: string[] }>();
    expect([...created.events_delivered].sort()).toEqual([...ALL_EVENTS].sort());
    return created.stream_id;
  }

  async function addSubject(
    app: FastifyInstance,
    who: Receiver,
    streamId: string,
    subject: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    return call(app, who, '/ssf/subjects/add', { stream_id: streamId, subject });
  }

  const userSubject = (userId: string) => ({ format: 'iss_sub', iss: ISSUER, sub: userId });

  /**
   * Wait until the fan-out has a position in the realm. The first fan-out
   * that sees an SSF stream in a realm starts at the horizon: an event
   * committed before it is not offered to the realm's streams, so a test acts
   * only once the position exists, after adding its subjects.
   */
  async function fanOutStarted(app: FastifyInstance, realmId: string): Promise<void> {
    await vi.waitFor(
      async () => {
        const { rows } = await app.dbPool.query(
          `SELECT 1 FROM event_delivery_positions WHERE realm_id = $1 AND destination_kind = 'ssf'`,
          [realmId]
        );
        expect(rows).toHaveLength(1);
      },
      { timeout: 10_000, interval: 100 }
    );
  }

  /** A verified user, consented to `clientRowId` when given, and the portal token `/auth/login` gives them. */
  async function newUser(app: FastifyInstance, realmId: string, consentTo?: string) {
    const email = `ssf-${randomUUID()}@example.test`;
    const userId = await registerPasswordAccount(app, email);
    const consent =
      consentTo === undefined
        ? undefined
        : await app.repositories.oauthConsents.upsertGrant(realmId, userId, consentTo, ['openid']);
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    return { userId, consent, token: login.json<{ access_token: string }>().access_token };
  }

  /** The SETs a receiver server got, verified with the keys at the metadata's `jwks_uri`. */
  async function deliveredSets(app: FastifyInstance, server: FixtureServer, audience: string) {
    const metadata = await app.inject({ method: 'GET', url: '/.well-known/ssf-configuration' });
    const jwksUri = new URL(metadata.json<{ jwks_uri: string }>().jwks_uri);
    const keys = createLocalJWKSet(
      (await app.inject({ method: 'GET', url: jwksUri.pathname })).json<JSONWebKeySet>()
    );
    const sets: DeliveredSet[] = [];
    for (const request of server.requests) {
      expect(request.headers['content-type']).toBe('application/secevent+jwt');
      const token = request.body.toString('utf8');
      const { payload } = await jwtVerify(token, keys, {
        issuer: ISSUER,
        audience,
        typ: 'secevent+jwt',
      });
      sets.push({
        header: decodeProtectedHeader(token),
        claims: payload as DeliveredSet['claims'],
      });
    }
    return sets;
  }

  /** Wait for a SET of `eventUri` to reach `server`, and return it. */
  async function waitForSet(
    app: FastifyInstance,
    server: FixtureServer,
    audience: string,
    eventUri: string
  ): Promise<DeliveredSet> {
    let found: DeliveredSet | undefined;
    await vi.waitFor(
      async () => {
        const sets = await deliveredSets(app, server, audience);
        found = sets.find((set) => Object.hasOwn(set.claims['events'] as object, eventUri));
        expect(found, `no ${eventUri} SET yet`).toBeDefined();
      },
      { timeout: 20_000, interval: 200 }
    );
    return found as DeliveredSet;
  }

  /** The id of the latest event of `type` about `userId`: the SET's `jti`. */
  async function eventIdOf(app: FastifyInstance, type: string, subjectId: string) {
    const { rows } = await app.dbPool.query<{ id: string }>(
      `SELECT id::text AS id FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq DESC LIMIT 1`,
      [type, subjectId]
    );
    return rows[0]?.id;
  }

  /**
   * RFC 8417 §2.2: `iss`, `iat` and `jti` are REQUIRED, and `events` holds
   * one event object; SSF 1.0 §4.1 forbids `sub` and `exp` and requires
   * explicit typing.
   */
  function expectRfc8417Claims(set: DeliveredSet): void {
    expect(set.header).toMatchObject({ typ: 'secevent+jwt', kid: expect.any(String) });
    expect(set.claims['iss']).toBe(ISSUER);
    expect(set.claims['iat']).toEqual(expect.any(Number));
    expect(set.claims['jti']).toEqual(expect.any(String));
    const events = set.claims['events'] as Record<string, unknown>;
    expect(Object.keys(events)).toHaveLength(1);
    expect(Object.values(events)[0]).toEqual(expect.any(Object));
    expect(set.claims).not.toHaveProperty('sub');
    expect(set.claims).not.toHaveProperty('exp');
  }

  it('delivers a sign-out of a subscribed user as session-revoked, with iss_sub, event_timestamp and initiating_entity', async () => {
    const { app, realmId } = await boot();
    const who = await newReceiver(app, realmId);
    const streamId = await createStream(app, who);
    const user = await newUser(app, realmId, who.id);
    const added = await addSubject(app, who, streamId, userSubject(user.userId));
    expect(added.statusCode, added.body).toBe(200);
    await fanOutStarted(app, realmId);

    const logout = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { authorization: `Bearer ${user.token}` },
    });
    expect(logout.statusCode, logout.body).toBe(200);

    const set = await waitForSet(app, receiver, who.clientId, SESSION_REVOKED);
    expectRfc8417Claims(set);
    const eventId = await eventIdOf(app, 'urn:qauth:event:user.signed_out:v1-rc.0', user.userId);
    expect(set.claims).toMatchObject({
      jti: eventId,
      aud: who.clientId,
      sub_id: { format: 'iss_sub', iss: ISSUER, sub: user.userId },
    });
    const members = (set.claims['events'] as Record<string, Record<string, unknown>>)[
      SESSION_REVOKED
    ];
    expect(members).toEqual({ event_timestamp: set.claims['iat'], initiating_entity: 'user' });
  });

  it('delivers a revoked API key as credential-change about its client', async () => {
    const { app, realmId } = await boot();
    const who = await newReceiver(app, realmId);
    const streamId = await createStream(app, who);
    const developer = await newUser(app, realmId);
    const owned = await app.repositories.oauthClients.create({
      realmId,
      clientId: `notes-${randomUUID()}`,
      clientSecretHash: 'unused',
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Notes',
      redirectUris: [],
      scopes: [],
      grantTypes: ['client_credentials'],
      enabled: true,
      requirePkce: false,
      developerId: developer.userId,
    });
    const key = await app.repositories.apiKeys.create({
      realmId,
      clientId: owned.id,
      developerId: developer.userId,
      name: 'ci',
      keyHash: createHash('sha256').update(randomUUID()).digest('hex'),
      prefix: `qk_${randomUUID().slice(0, 8)}`,
      last4: 'abcd',
    });
    const added = await addSubject(app, who, streamId, { format: 'opaque', id: owned.clientId });
    expect(added.statusCode, added.body).toBe(200);
    await fanOutStarted(app, realmId);

    const revoked = await app.inject({
      method: 'DELETE',
      url: `/api/clients/${owned.id}/api-keys/${key.id}`,
      headers: { authorization: `Bearer ${developer.token}` },
    });
    expect(revoked.statusCode, revoked.body).toBe(200);

    const set = await waitForSet(app, receiver, who.clientId, CREDENTIAL_CHANGE);
    expectRfc8417Claims(set);
    expect(set.claims).toMatchObject({
      jti: await eventIdOf(app, 'urn:qauth:event:api_key.revoked:v1-rc.0', key.id),
      sub_id: { format: 'opaque', id: owned.clientId },
      events: {
        [CREDENTIAL_CHANGE]: {
          credential_type: 'api-key',
          change_type: 'revoke',
          event_timestamp: expect.any(Number),
          initiating_entity: 'user',
        },
      },
    });
  });

  it('delivers a withdrawn consent as token-claims-change to that client’s stream only', async () => {
    const { app, realmId } = await boot();
    const who = await newReceiver(app, realmId);
    const other = await newReceiver(app, realmId);
    const streamId = await createStream(app, who);
    const otherStream = await createStream(app, other, 'https://other.egress.test/events');
    const user = await newUser(app, realmId, who.id);
    // Related to the other receiver too, through its own consent.
    await app.repositories.oauthConsents.upsertGrant(realmId, user.userId, other.id, ['openid']);
    for (const [receiverOf, stream] of [
      [who, streamId],
      [other, otherStream],
    ] as const) {
      const added = await addSubject(app, receiverOf, stream, userSubject(user.userId));
      expect(added.statusCode, added.body).toBe(200);
    }
    await fanOutStarted(app, realmId);

    const withdrawn = await app.inject({
      method: 'DELETE',
      url: `/api/consents/${user.consent?.id}`,
      headers: { authorization: `Bearer ${user.token}` },
    });
    expect(withdrawn.statusCode, withdrawn.body).toBeLessThan(300);

    const set = await waitForSet(app, receiver, who.clientId, TOKEN_CLAIMS_CHANGE);
    expectRfc8417Claims(set);
    expect(set.claims).toMatchObject({
      jti: await eventIdOf(app, 'urn:qauth:event:consent.revoked:v1-rc.0', user.userId),
      sub_id: { format: 'iss_sub', iss: ISSUER, sub: user.userId },
      events: {
        [TOKEN_CLAIMS_CHANGE]: {
          claims: { scope: '' },
          event_timestamp: expect.any(Number),
          initiating_entity: 'user',
        },
      },
    });
    // The other receiver added the same user, but the consent was not its
    // own: no SET, and no delivery row that could become one.
    const rows = await app.dbPool.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM event_deliveries
         WHERE destination_kind = 'ssf' AND destination_id = $1`,
      [otherStream]
    );
    expect(rows.rows[0].count).toBe(0);
    expect(otherReceiver.requests).toHaveLength(0);
  });

  it('delivers an RFC 7009 revocation as the QAuth-defined token-revoked event', async () => {
    const { app, realmId } = await boot();
    const who = await newReceiver(app, realmId);
    const streamId = await createStream(app, who);
    const user = await newUser(app, realmId);
    // A refresh token the receiver's client was issued for the user: it
    // relates the user to the client, with no consent.
    const refreshToken = `rt-${randomUUID()}`;
    await app.repositories.refreshTokens.create({
      userId: user.userId,
      oauthClientId: who.id,
      tokenHash: app.jwtUtils.hashRefreshToken(refreshToken),
      familyCreatedAt: Date.now(),
      familySessionExpiresAt: null,
      expiresAt: Date.now() + 3_600_000,
    });
    const added = await addSubject(app, who, streamId, userSubject(user.userId));
    expect(added.statusCode, added.body).toBe(200);
    await fanOutStarted(app, realmId);

    const revoked = await app.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: FORM,
      payload: new URLSearchParams({
        token: refreshToken,
        token_type_hint: 'refresh_token',
        client_id: who.clientId,
        client_secret: who.secret,
      }).toString(),
    });
    expect(revoked.statusCode, revoked.body).toBe(200);

    const set = await waitForSet(app, receiver, who.clientId, TOKEN_REVOKED);
    expectRfc8417Claims(set);
    // A versioned QAuth identifier, a release candidate until 1.0.0.
    expect(TOKEN_REVOKED).toMatch(/^urn:qauth:[a-z:-]+:v[1-9][0-9]*(-rc\.(0|[1-9][0-9]*))?$/);
    expect(set.claims).toMatchObject({
      jti: await eventIdOf(app, 'urn:qauth:event:token.revoked:v1-rc.0', user.userId),
      sub_id: { format: 'iss_sub', iss: ISSUER, sub: user.userId },
      events: {
        [TOKEN_REVOKED]: { token_type_hint: 'refresh_token', event_timestamp: expect.any(Number) },
      },
    });
  });

  it('refuses to add a user with no consent for and no token from the receiver’s client, and adds one who has', async () => {
    const { app, realmId } = await boot();
    const who = await newReceiver(app, realmId);
    const streamId = await createStream(app, who);
    const stranger = await newUser(app, realmId);
    const consented = await newUser(app, realmId, who.id);
    // Consented to another client only: still a stranger to this one.
    const elsewhere = await newReceiver(app, realmId);
    const otherwise = await newUser(app, realmId, elsewhere.id);

    for (const userId of [stranger.userId, otherwise.userId, randomUUID()]) {
      const refused = await addSubject(app, who, streamId, userSubject(userId));
      expect(refused.statusCode, refused.body).toBe(403);
      expect(refused.headers['content-type']).toMatch(/^application\/problem\+json/);
      expect(refused.json()).toMatchObject({ status: 403, code: 'forbidden' });
    }
    // An unknown user and an unrelated one get the same answer.
    const unknown = await addSubject(app, who, streamId, userSubject(randomUUID()));
    const unrelated = await addSubject(app, who, streamId, userSubject(stranger.userId));
    const comparable = (response: LightMyRequestResponse) => {
      const { trace_id: _traceId, ...body } = response.json<Record<string, unknown>>();
      return body;
    };
    expect(comparable(unknown)).toEqual(comparable(unrelated));

    const added = await addSubject(app, who, streamId, userSubject(consented.userId));
    expect(added.statusCode, added.body).toBe(200);
    const { rows } = await app.dbPool.query<{ event_subject_id: string }>(
      'SELECT event_subject_id FROM ssf_stream_subjects WHERE stream_id = $1',
      [streamId]
    );
    expect(rows.map((row) => row.event_subject_id)).toEqual([consented.userId]);
  });
});
