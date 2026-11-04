import { randomUUID } from 'node:crypto';

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
  createDatabaseUsers,
  databaseUrlAs,
  grantDatabaseUsers,
  PERMISSION_ERROR,
} from '../testing/database-users';
import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { SIGNER_LISTENER } from '../testing/service-role-env';
import type { ServiceRole } from './service-roles';

/**
 * OPENID CONNECT BACK-CHANNEL LOGOUT, END TO END (issue #624).
 *
 * The real app boots with Postgres, Redis, the in-process signer and the
 * delivery role; the apps that receive logout tokens are local HTTPS servers
 * behind the egress client's two network edges, as in the SSF suites, so the
 * egress client's address checks run as in production.
 *
 * Covers the integration acceptance criteria of #624: a client with a
 * back-channel logout URI receives one logout token when a session it served
 * ends, which verifies with a key from the realm's `jwks_uri`; a client
 * without a URI gets nothing; a URI on a private or loopback address is
 * refused at registration and at delivery; a receiver that answers 500 gets
 * retries while the sign-out has already succeeded.
 *
 * The suite runs twice: as one process holding every role, and with the
 * roles apart, each process on a database user that `db:grants` gave exactly
 * its roles' grants (#498), so the delivery role's column grants on
 * `oauth_clients` and `realms` are what the route reads with. A permission
 * error either logs fails the test.
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
const CLIENT_SESSION_ENDED = 'urn:qauth:event:user.client_session_ended:v1-rc.0';
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Public addresses the fixture DNS hands out; each is served by a local server. */
const RECEIVER_ADDRESS = '93.184.215.14';
const FLAKY_ADDRESS = '104.16.132.229';
/** A private address no server stands for: the egress client must never dial it. */
const PRIVATE_ADDRESS = '10.20.30.40';

type Deployment = 'one process' | 'split roles';

/** The split deployment's database users: one per role, and two with the signer's grants added. */
const USERS: Readonly<Record<ServiceRole, string>> = {
  web: 'qauth_bclogout_web',
  api: 'qauth_bclogout_api',
  admin: 'qauth_bclogout_admin',
  signer: 'qauth_bclogout_signer',
  delivery: 'qauth_bclogout_delivery',
};
const FRONT_USER = 'qauth_bclogout_front';
const DELIVERY_USER = 'qauth_bclogout_delivery_signer';

describe.each<Deployment>(['one process', 'split roles'])(
  'back-channel logout (%s, real containers)',
  (deployment) => {
    let infra: E2eInfrastructure | undefined;
    let jwt: PemKeyPair | undefined;
    let net: FixtureNetwork | undefined;
    let receiver: FixtureServer;
    let flaky: FixtureServer;
    /** How many requests the flaky receiver answers 500 before it answers 200. */
    let flakyFailures = 0;
    let dockerUp = false;
    const booted: BootedAuthServer[] = [];
    let fixture: BootedAuthServer | undefined;
    let owner: FastifyInstance['dbPool'] | undefined;
    const logLines: string[] = [];

    beforeAll(async () => {
      dockerUp = await requireDockerOrSkip();
      if (!dockerUp) return;
      infra = await startE2eInfrastructure();
      jwt = await generateJwtPem();
      net = await createFixtureNetwork();
      receiver = await net.serve(RECEIVER_ADDRESS, (_req, _body, res) => {
        res.writeHead(200);
        res.end();
      });
      flaky = await net.serve(FLAKY_ADDRESS, (_req, _body, res) => {
        if (flakyFailures > 0) {
          flakyFailures -= 1;
          res.writeHead(500);
        } else {
          res.writeHead(204);
        }
        res.end();
      });
      if (deployment === 'split roles') {
        // The owner's deployment, as the migration runner's user: the signer
        // alone, so it creates the default realm and its keys and delivers
        // nothing.
        fixture = await bootAuthServer({
          ...baseEnvironment(infra, jwt),
          ...SIGNER_LISTENER,
          SERVICE_ROLES: 'signer',
        });
        await createDatabaseUsers(fixture.app.dbPool, [
          ...Object.values(USERS),
          FRONT_USER,
          DELIVERY_USER,
        ]);
        const connectionString = infra.postgres.connectionString;
        await grantDatabaseUsers(connectionString, USERS);
        await grantDatabaseUsers(connectionString, {
          ...USERS,
          web: FRONT_USER,
          api: FRONT_USER,
          signer: FRONT_USER,
        });
        await grantDatabaseUsers(connectionString, {
          ...USERS,
          delivery: DELIVERY_USER,
          signer: DELIVERY_USER,
        });
      }
    }, 240_000);

    afterAll(async () => {
      await net?.close();
      await fixture?.close();
      await infra?.teardown();
    });

    beforeEach((ctx) => {
      if (!dockerUp || !net) {
        ctx.skip();
        return;
      }
      net.dns.clear();
      net.dns.set('rp.egress.test', [RECEIVER_ADDRESS]);
      net.dns.set('flaky.egress.test', [FLAKY_ADDRESS]);
      net.dns.set('private.egress.test', [PRIVATE_ADDRESS]);
      for (const server of [receiver, flaky]) server.requests.length = 0;
      net.dialled.length = 0;
      flakyFailures = 0;
      network.current = net.transport;
    });

    afterEach(async () => {
      await Promise.all(booted.splice(0).map((server) => server.close()));
      const denied = logLines.filter((line) => PERMISSION_ERROR.test(line));
      logLines.length = 0;
      expect(denied).toEqual([]);
    });

    function ownerPool(): FastifyInstance['dbPool'] {
      if (owner === undefined) throw new Error('not booted');
      return owner;
    }

    /**
     * Boot the server; the database keeps earlier tests' rows, so every id is
     * new. Split, it boots `web,api,signer` and `delivery,signer`, each on its
     * own user, and returns the first: the one that registers clients and
     * ends sessions.
     */
    async function boot(): Promise<{ app: FastifyInstance; realmId: string }> {
      if (!infra || !jwt) throw new Error('infrastructure not started');
      const environment: Record<string, string> = {
        ...baseEnvironment(infra, jwt),
        REGISTRATION_RATE_LIMIT: '100',
        EVENT_DELIVERY_RETRY_INITIAL_DELAY: '1',
        EVENT_DELIVERY_RETRY_MAX_DELAY: '2',
      };
      let app: FastifyInstance;
      if (deployment === 'one process') {
        const server = await bootAuthServer(environment);
        booted.push(server);
        app = server.app;
        owner = server.app.dbPool;
      } else {
        if (!fixture) throw new Error('no fixture');
        const connectionString = infra.postgres.connectionString;
        const log = { write: (line: string) => void logLines.push(line) };
        for (const [roles, user] of [
          ['web,api,signer', FRONT_USER],
          ['delivery,signer', DELIVERY_USER],
        ] as const) {
          booted.push(
            await bootAuthServer(
              {
                ...environment,
                ...SIGNER_LISTENER,
                SERVICE_ROLES: roles,
                DATABASE_URL: databaseUrlAs(connectionString, user),
              },
              { logStream: log }
            )
          );
        }
        app = booted[0].app;
        owner = fixture.app.dbPool;
      }
      const { rows } = await ownerPool().query<{ id: string }>(
        'SELECT id::text AS id FROM realms WHERE name = $1',
        [E2E_REALM_NAME]
      );
      return { app, realmId: rows[0].id };
    }

    /** A client of the realm, with the back-channel logout URI given, if any. */
    async function newClient(
      realmId: string,
      uri: string | null,
      options: { sessionRequired?: boolean } = {}
    ): Promise<{ id: string; clientId: string }> {
      const clientId = `rp-${randomUUID()}`;
      const { rows } = await ownerPool().query<{ id: string }>(
        `INSERT INTO oauth_clients
           (realm_id, client_id, client_secret_hash, name, redirect_uris,
            backchannel_logout_uri, backchannel_logout_uri_source,
            backchannel_logout_session_required)
         VALUES ($1, $2, 'h', 'Relying party', '["https://rp.example/cb"]', $3, $4, $5)
         RETURNING id::text AS id`,
        [realmId, clientId, uri, uri === null ? null : 'client', options.sessionRequired ?? false]
      );
      return { id: rows[0].id, clientId };
    }

    /** A signed-in user: a browser session that served `clients`, as the code mint records it. */
    async function sessionServing(
      app: FastifyInstance,
      realmId: string,
      clients: ReadonlyArray<{ id: string }>
    ): Promise<{ userId: string; sid: string }> {
      const userId = await registerPasswordAccount(app, `bcl-${randomUUID()}@example.test`);
      const { sid } = await app.sessionService.create({
        realmId,
        userId,
        authTime: Date.now(),
        amr: ['pwd'],
        ipAddress: '192.0.2.10',
        userAgent: 'Browser/1',
      });
      for (const client of clients) {
        await ownerPool().query(
          'INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)',
          [sid, client.id]
        );
      }
      return { userId, sid };
    }

    /** End the session as an RP-initiated logout does, and check it ended at once. */
    async function signOut(
      app: FastifyInstance,
      realmId: string,
      who: { userId: string; sid: string }
    ) {
      const result = await app.sessionService.revoke({
        realmId,
        sid: who.sid,
        userId: who.userId,
        reason: 'sign_out',
        actor: { type: 'user', id: who.userId },
      });
      expect(result.outcome).toBe('ended');
    }

    /**
     * Wait until the fan-out has a back-channel logout position in the realm.
     * The first fan-out that sees a destination of a kind starts at the
     * horizon, so a test ends its session only once the position exists.
     */
    async function fanOutStarted(realmId: string): Promise<void> {
      await vi.waitFor(
        async () => {
          const { rows } = await ownerPool().query(
            `SELECT 1 FROM event_delivery_positions
              WHERE realm_id = $1 AND destination_kind = 'backchannel_logout'`,
            [realmId]
          );
          expect(rows).toHaveLength(1);
        },
        { timeout: 15_000, interval: 100 }
      );
    }

    /** The logout tokens a server received, each verified with the realm's jwks_uri keys. */
    async function logoutTokens(app: FastifyInstance, server: FixtureServer, audience: string) {
      const discovery = await app.inject({
        method: 'GET',
        url: '/.well-known/openid-configuration',
      });
      const config = discovery.json<{
        jwks_uri: string;
        backchannel_logout_supported?: boolean;
        backchannel_logout_session_supported?: boolean;
      }>();
      expect(config.backchannel_logout_supported).toBe(true);
      expect(config.backchannel_logout_session_supported).toBe(true);
      const jwks = await app.inject({ method: 'GET', url: new URL(config.jwks_uri).pathname });
      const keys = createLocalJWKSet(jwks.json<JSONWebKeySet>());
      const tokens = [];
      for (const request of server.requests) {
        expect(request.method).toBe('POST');
        expect(request.headers['content-type']).toBe('application/x-www-form-urlencoded');
        const token = new URLSearchParams(request.body.toString('utf8')).get('logout_token');
        expect(token).toEqual(expect.any(String));
        const { payload, protectedHeader } = await jwtVerify(token as string, keys, {
          issuer: ISSUER,
          audience,
          typ: 'logout+jwt',
          requiredClaims: ['iss', 'aud', 'iat', 'exp', 'jti', 'events'],
        });
        tokens.push({ payload, protectedHeader, token: token as string });
      }
      return tokens;
    }

    async function deliveriesOf(destinationId: string) {
      const { rows } = await ownerPool().query<{
        status: string;
        attempt_count: number;
        last_error_class: string | null;
        last_status_code: number | null;
      }>(
        `SELECT status, attempt_count, last_error_class, last_status_code
           FROM event_deliveries
          WHERE destination_kind = 'backchannel_logout' AND destination_id = $1`,
        [destinationId]
      );
      return rows;
    }

    it('delivers one logout token per session to a client with a URI, verifiable at the realm’s jwks_uri (§2.4, §2.6)', async () => {
      const { app, realmId } = await boot();
      const rp = await newClient(realmId, 'https://rp.egress.test/backchannel', {
        sessionRequired: true,
      });
      await fanOutStarted(realmId);
      const first = await sessionServing(app, realmId, [rp]);
      const second = await sessionServing(app, realmId, [rp]);

      await signOut(app, realmId, first);
      await signOut(app, realmId, second);
      // A second revocation of the same session ends nothing and queues nothing.
      const again = await app.sessionService.revoke({
        realmId,
        sid: first.sid,
        userId: first.userId,
        reason: 'sign_out',
        actor: { type: 'user', id: first.userId },
      });
      expect(again.outcome).toBe('already_ended');

      await vi.waitFor(() => expect(receiver.requests).toHaveLength(2), {
        timeout: 20_000,
        interval: 200,
      });
      const tokens = await logoutTokens(app, receiver, rp.clientId);
      expect(tokens.map(({ payload }) => payload['sid']).sort()).toEqual(
        [first.sid, second.sid].sort()
      );
      for (const { payload, protectedHeader } of tokens) {
        expect(protectedHeader).toMatchObject({ typ: 'logout+jwt', kid: expect.any(String) });
        expect(payload['events']).toEqual({ [BACKCHANNEL_LOGOUT_EVENT]: {} });
        expect(payload).not.toHaveProperty('nonce');
        expect((payload.exp as number) - (payload.iat as number)).toBeLessThanOrEqual(120);
      }
      expect(tokens.find(({ payload }) => payload['sid'] === first.sid)?.payload.sub).toBe(
        first.userId
      );

      // Once per session: nothing more arrives, and each delivery is done.
      await new Promise((resolve) => setTimeout(resolve, 3_000));
      expect(receiver.requests).toHaveLength(2);
      const rows = await deliveriesOf(rp.id);
      expect(rows.map((row) => row.status)).toEqual(['delivered', 'delivered']);
    });

    it('sends nothing to a client without a backchannel_logout_uri', async () => {
      const { app, realmId } = await boot();
      const rp = await newClient(realmId, 'https://rp.egress.test/backchannel');
      const silent = await newClient(realmId, null);
      await fanOutStarted(realmId);
      const who = await sessionServing(app, realmId, [silent, rp]);

      await signOut(app, realmId, who);

      await vi.waitFor(() => expect(receiver.requests).toHaveLength(1), {
        timeout: 20_000,
        interval: 200,
      });
      const { rows: events } = await ownerPool().query<{ client_id: string }>(
        `SELECT client_id FROM events WHERE type = $1 AND data->>'sid' = $2`,
        [CLIENT_SESSION_ENDED, who.sid]
      );
      expect(events.map((row) => row.client_id)).toEqual([rp.clientId]);
      expect(await deliveriesOf(silent.id)).toEqual([]);
    });

    it('refuses a URI on a private or loopback address at registration, even for a development client', async () => {
      const { app } = await boot();
      for (const uri of [
        'https://127.0.0.1/backchannel',
        'https://[::1]/backchannel',
        'https://private.egress.test/backchannel',
      ]) {
        const refused = await app.inject({
          method: 'POST',
          url: '/oauth/register',
          payload: {
            redirect_uris: ['https://rp.example/cb'],
            backchannel_logout_uri: uri,
          },
        });
        expect(refused.statusCode, `${uri}: ${refused.body}`).toBe(400);
        expect(refused.json<{ error: string }>().error).toBe('invalid_client_metadata');
      }
      expect(net?.dialled.flat()).not.toContain(PRIVATE_ADDRESS);

      const accepted = await app.inject({
        method: 'POST',
        url: '/oauth/register',
        payload: {
          redirect_uris: ['https://rp.example/cb'],
          backchannel_logout_uri: 'https://rp.egress.test/backchannel',
          backchannel_logout_session_required: true,
        },
      });
      expect(accepted.statusCode, accepted.body).toBe(201);
      expect(accepted.json()).toMatchObject({
        backchannel_logout_uri: 'https://rp.egress.test/backchannel',
        backchannel_logout_session_required: true,
      });
    });

    it('refuses a URI whose host resolves to a private address at delivery, and the sign-out stands', async () => {
      const { app, realmId } = await boot();
      // Registered while it resolved publicly; it resolves privately now.
      const moved = await newClient(realmId, 'https://private.egress.test/backchannel');
      await fanOutStarted(realmId);
      const who = await sessionServing(app, realmId, [moved]);

      await signOut(app, realmId, who);

      await vi.waitFor(
        async () => {
          const [row] = await deliveriesOf(moved.id);
          expect(row?.last_error_class).toBe('destination_blocked');
        },
        { timeout: 20_000, interval: 200 }
      );
      expect(net?.dialled.flat()).not.toContain(PRIVATE_ADDRESS);
      expect(receiver.requests).toHaveLength(0);
      const session = await ownerPool().query<{ revoked_reason: string }>(
        'SELECT revoked_reason FROM sessions WHERE id = $1',
        [who.sid]
      );
      expect(session.rows[0].revoked_reason).toBe('sign_out');
    });

    it('retries a receiver that answers 500, with the same jti, while the sign-out has already succeeded', async () => {
      const { app, realmId } = await boot();
      flakyFailures = 2;
      const rp = await newClient(realmId, 'https://flaky.egress.test/backchannel');
      await fanOutStarted(realmId);
      const who = await sessionServing(app, realmId, [rp]);

      // The revocation returns before any delivery: the session is ended now.
      await signOut(app, realmId, who);
      expect(await app.sessionService.get({ realmId, sid: who.sid })).toBeNull();

      await vi.waitFor(
        async () => {
          const [row] = await deliveriesOf(rp.id);
          expect(row?.status).toBe('delivered');
        },
        { timeout: 30_000, interval: 250 }
      );
      expect(flaky.requests.length).toBeGreaterThanOrEqual(3);
      const tokens = await logoutTokens(app, flaky, rp.clientId);
      expect(new Set(tokens.map(({ payload }) => payload.jti)).size).toBe(1);
      expect(new Set(tokens.map(({ token }) => decodeProtectedHeader(token).typ))).toEqual(
        new Set(['logout+jwt'])
      );
      const [row] = await deliveriesOf(rp.id);
      expect(row.attempt_count).toBeGreaterThanOrEqual(3);
    });
  }
);
