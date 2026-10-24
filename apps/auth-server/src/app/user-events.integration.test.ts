import { type EventEnvelope, parseEvent, scanPayload } from '@qauth-labs/shared-events';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  E2E_PASSWORD,
  type E2eInfrastructure,
  extractCsrfToken,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * USER EVENTS THROUGH THE EVENT STORE (#458, ADR-019 Decision 8).
 *
 * The auth server records what a person or a client did with `emitUserEvent`,
 * in the event store, instead of `audit_logs`. On the real server, Postgres
 * and Redis, this suite drives a sign-in, an RFC 8693 token exchange and a
 * consent revocation, and checks each event's type, realm, actor and client
 * chain. A registration that rolls back must leave no event, and no event
 * written during the run may carry a secret: the contract's payload scanner
 * (`scanPayload`, #456) finds nothing, and no password, token or code of the
 * run appears in any stored event.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const REALM = REQUIRED_TEST_ENVIRONMENT['DEFAULT_REALM_NAME'] as string;
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const AGENT_CLIENT_ID = 'e2e-agent';
const AGENT_SECRET = 'agent-client-secret-of-sufficient-length-42';
const AGENT_REDIRECT_URI = 'https://agent.example.com/callback';
const AGENT_SCOPES = ['openid', 'notes:read'];
const APP_CLIENT_ID = 'e2e-app';
const APP_REDIRECT_URI = 'https://app.example.com/callback';

/** A row of `events`, as node-postgres returns it. */
interface EventRow {
  id: string;
  realm_id: string;
  category: EventEnvelope['category'];
  type: string;
  time: string;
  actor_type: string | null;
  actor_id: string | null;
  actor_delegation_chain: string[] | null;
  subject_type: string | null;
  subject_id: string | null;
  client_id: string | null;
  request_id: string | null;
  request_ip: string | null;
  request_user_agent: string | null;
  data: Record<string, unknown>;
}

/** The envelope a row stores, with every member the row has. */
function envelopeOf(row: EventRow): EventEnvelope {
  const request = {
    ...(row.request_id === null ? {} : { traceId: row.request_id }),
    ...(row.request_ip === null ? {} : { ip: row.request_ip }),
    ...(row.request_user_agent === null ? {} : { userAgent: row.request_user_agent }),
  };
  return {
    id: row.id,
    type: row.type,
    time: new Date(Number(row.time)).toISOString(),
    realm: row.realm_id,
    category: row.category,
    ...(row.actor_type === null
      ? {}
      : {
          actor: {
            type: row.actor_type,
            ...(row.actor_id === null ? {} : { id: row.actor_id }),
            ...(row.actor_delegation_chain === null
              ? {}
              : { delegationChain: row.actor_delegation_chain }),
          },
        }),
    ...(row.subject_type === null || row.subject_id === null
      ? {}
      : { subject: { type: row.subject_type, id: row.subject_id } }),
    ...(row.client_id === null ? {} : { client: { id: row.client_id } }),
    ...(Object.keys(request).length === 0 ? {} : { request }),
    data: row.data,
  } as EventEnvelope;
}

describe('user events go to the event store (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /**
   * Boot a default deployment, run the body, then check every event the body
   * left: the contract accepts it, the payload scanner finds nothing, and none
   * of the secrets the body saw appears in it.
   */
  async function withDeployment(
    body: (app: FastifyInstance, secrets: Set<string>) => Promise<void>
  ): Promise<void> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(baseEnvironment(infra, jwt));
      await resetE2eState(booted.app);
      const secrets = new Set<string>([E2E_PASSWORD, AGENT_SECRET]);
      await body(booted.app, secrets);
      await expectNoSecretInAnyEvent(booted.app, secrets);
    } finally {
      await booted?.close();
    }
  }

  async function storedEvents(app: FastifyInstance): Promise<EventEnvelope[]> {
    const { rows } = await app.dbPool.query<EventRow>(
      `SELECT id, realm_id, category, type, time::text AS time, actor_type, actor_id,
              actor_delegation_chain, subject_type, subject_id, client_id, request_id,
              request_ip, request_user_agent, data
       FROM events ORDER BY xid::text::numeric, seq`
    );
    return rows.map(envelopeOf);
  }

  async function eventsOfType(app: FastifyInstance, type: string): Promise<EventEnvelope[]> {
    return (await storedEvents(app)).filter((event) => event.type === type);
  }

  /** The acceptance criterion: no secret in any event stored during the run. */
  async function expectNoSecretInAnyEvent(
    app: FastifyInstance,
    secrets: ReadonlySet<string>
  ): Promise<void> {
    const events = await storedEvents(app);
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      expect(() => parseEvent(event), `${event.type}: ${JSON.stringify(event)}`).not.toThrow();
      expect(scanPayload(event.data), event.type).toEqual([]);
      const text = JSON.stringify(event);
      for (const secret of secrets) {
        expect(text.includes(secret), `${event.type} carries a secret of the run`).toBe(false);
      }
    }
  }

  async function defaultRealmId(app: FastifyInstance): Promise<string> {
    const realm = await app.repositories.realms.findByName(REALM);
    if (!realm) throw new Error('the default realm boot step left no realm');
    return realm.id;
  }

  /** Seed a client with a stored consent for `userId`, so the code flow skips the screen. */
  async function seedConsentedClient(
    app: FastifyInstance,
    userId: string,
    client: {
      clientId: string;
      redirectUri: string;
      scopes: string[];
      secret?: string;
      isAgent?: boolean;
      grantTypes?: ('authorization_code' | 'refresh_token' | typeof TOKEN_EXCHANGE)[];
    }
  ) {
    const realmId = await defaultRealmId(app);
    const row = await app.repositories.oauthClients.create({
      realmId,
      clientId: client.clientId,
      clientSecretHash:
        client.secret === undefined
          ? 'unused-public-client'
          : await app.passwordHasher.hashPassword(client.secret),
      tokenEndpointAuthMethod: client.secret === undefined ? 'none' : 'client_secret_post',
      name: `E2E ${client.clientId}`,
      redirectUris: [client.redirectUri],
      scopes: client.scopes,
      grantTypes: client.grantTypes ?? ['authorization_code'],
      isAgent: client.isAgent ?? false,
      enabled: true,
      requirePkce: true,
    });
    const consent = await app.repositories.oauthConsents.upsertGrant(
      userId,
      row.id,
      realmId,
      client.scopes
    );
    return { realmId, row, consent };
  }

  /** Run the authorization code flow for a signed-in browser and redeem the code. */
  async function codeFlowTokens(
    app: FastifyInstance,
    jar: CookieJar,
    client: { clientId: string; redirectUri: string; scopes: string[]; secret?: string },
    secrets: Set<string>
  ): Promise<{ access_token: string; refresh_token?: string }> {
    const pkce = pkcePair();
    secrets.add(pkce.verifier);
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: client.clientId,
        redirect_uri: client.redirectUri,
        scope: client.scopes.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'e2e-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode).toBe(302);
    const location = authorize.headers['location'];
    if (typeof location !== 'string') throw new Error('authorize did not redirect');
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);
    secrets.add(code);

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: client.redirectUri,
        client_id: client.clientId,
        code_verifier: pkce.verifier,
        ...(client.secret === undefined ? {} : { client_secret: client.secret }),
      }).toString(),
    });
    expect(token.statusCode).toBe(200);
    const tokens = token.json() as { access_token: string; refresh_token?: string };
    secrets.add(tokens.access_token);
    if (tokens.refresh_token) secrets.add(tokens.refresh_token);
    return tokens;
  }

  it('records a sign-in with its realm, the user as actor and subject, and the request', async () => {
    await withDeployment(async (app) => {
      const email = 'events-sign-in@example.test';
      const userId = await registerPasswordAccount(app, email);
      await signInWithPassword(app, email);
      const realmId = await defaultRealmId(app);

      const signIns = await eventsOfType(app, 'urn:qauth:event:user.signed_in:v1-rc.0');
      expect(signIns).toHaveLength(1);
      const [signIn] = signIns;
      expect(signIn).toMatchObject({
        realm: realmId,
        category: 'user',
        actor: { type: 'user', id: userId },
        subject: { type: 'user', id: userId },
        data: { method: 'password' },
      });
      // The request: its id as the trace id, and the client address.
      expect(signIn.request?.traceId).toEqual(expect.any(String));
      expect(signIn.request?.ip).toEqual(expect.any(String));
      expect(signIn.actor).not.toHaveProperty('delegationChain');

      // A refused sign-in is an event too, with no typed address in it.
      const refused = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: 'nobody@example.test', password: 'Wrong-Password-1234!' },
      });
      expect(refused.statusCode).toBe(401);
      const failures = await eventsOfType(app, 'urn:qauth:event:user.sign_in_failed:v1-rc.0');
      expect(failures).toHaveLength(1);
      expect(failures[0]).toMatchObject({
        realm: realmId,
        data: { method: 'password', reason: 'invalid_credentials' },
      });
      expect(failures[0]).not.toHaveProperty('subject');
      expect(JSON.stringify(failures[0])).not.toContain('nobody@example.test');
    });
  }, 120_000);

  it('records a token exchange with the acting agent and its delegation chain', async () => {
    await withDeployment(async (app, secrets) => {
      const email = 'events-exchange@example.test';
      const userId = await registerPasswordAccount(app, email);
      const jar = await signInWithPassword(app, email);
      const agent = {
        clientId: AGENT_CLIENT_ID,
        redirectUri: AGENT_REDIRECT_URI,
        scopes: AGENT_SCOPES,
        secret: AGENT_SECRET,
      };
      const { realmId } = await seedConsentedClient(app, userId, {
        ...agent,
        isAgent: true,
        grantTypes: ['authorization_code', TOKEN_EXCHANGE],
      });

      // The agent's own user token: its `aud` falls back to the agent's
      // client_id, which binds it to the agent (GATE 3c).
      const { access_token: subjectToken } = await codeFlowTokens(app, jar, agent, secrets);

      const exchange = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          grant_type: TOKEN_EXCHANGE,
          subject_token: subjectToken,
          subject_token_type: ACCESS_TOKEN_TYPE,
          client_id: AGENT_CLIENT_ID,
          client_secret: AGENT_SECRET,
          scope: 'notes:read',
        }).toString(),
      });
      expect(exchange.statusCode).toBe(200);
      secrets.add((exchange.json() as { access_token: string }).access_token);

      const issued = await eventsOfType(app, 'urn:qauth:event:token.issued:v1-rc.0');
      // The code redemption: the client acting for itself, no chain.
      const redemption = issued.find((event) => event.data['grantType'] === 'authorization_code');
      expect(redemption).toMatchObject({
        realm: realmId,
        actor: { type: 'client', id: AGENT_CLIENT_ID },
        subject: { type: 'user', id: userId },
        client: { id: AGENT_CLIENT_ID },
      });
      expect(redemption?.actor).not.toHaveProperty('delegationChain');

      // The exchange: the agent acted for the user, and the chain names it.
      const delegated = issued.find((event) => event.data['grantType'] === TOKEN_EXCHANGE);
      expect(delegated).toMatchObject({
        realm: realmId,
        category: 'user',
        actor: { type: 'client', id: AGENT_CLIENT_ID, delegationChain: [AGENT_CLIENT_ID] },
        subject: { type: 'user', id: userId },
        client: { id: AGENT_CLIENT_ID },
        data: { grantType: TOKEN_EXCHANGE, scopes: ['notes:read'], delegationDepth: 1 },
      });

      // A refused exchange is recorded as a failure, with the code it got.
      const refused = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          grant_type: TOKEN_EXCHANGE,
          subject_token: 'not-a-token',
          subject_token_type: ACCESS_TOKEN_TYPE,
          client_id: AGENT_CLIENT_ID,
          client_secret: AGENT_SECRET,
        }).toString(),
      });
      expect(refused.statusCode).toBe(400);
      const failed = await eventsOfType(app, 'urn:qauth:event:token.request_failed:v1-rc.0');
      expect(failed).toHaveLength(1);
      expect(failed[0]).toMatchObject({
        realm: realmId,
        actor: { type: 'client', id: AGENT_CLIENT_ID },
        client: { id: AGENT_CLIENT_ID },
        data: { grantType: TOKEN_EXCHANGE, error: 'invalid_request' },
      });
    });
  }, 120_000);

  it('records a consent revocation, in the transaction that revokes it', async () => {
    await withDeployment(async (app, secrets) => {
      const email = 'events-consent@example.test';
      const userId = await registerPasswordAccount(app, email);
      const jar = await signInWithPassword(app, email);
      const appClient = {
        clientId: APP_CLIENT_ID,
        redirectUri: APP_REDIRECT_URI,
        scopes: ['openid', 'email'],
      };
      const { realmId, consent } = await seedConsentedClient(app, userId, {
        ...appClient,
        grantTypes: ['authorization_code', 'refresh_token'],
      });
      await codeFlowTokens(app, jar, appClient, secrets);

      const list = await app.inject({
        method: 'GET',
        url: '/consents',
        headers: { cookie: jar.header() as string },
      });
      expect(list.statusCode).toBe(200);
      const { csrfToken } = list.json() as { csrfToken: string };
      secrets.add(csrfToken);

      const revoke = await app.inject({
        method: 'DELETE',
        url: `/consents/${consent.id}`,
        headers: { cookie: jar.header() as string, 'x-csrf-token': csrfToken },
      });
      expect(revoke.statusCode).toBe(204);

      const revoked = await eventsOfType(app, 'urn:qauth:event:consent.revoked:v1-rc.0');
      expect(revoked).toHaveLength(1);
      expect(revoked[0]).toMatchObject({
        realm: realmId,
        category: 'user',
        actor: { type: 'user', id: userId },
        subject: { type: 'user', id: userId },
        client: { id: APP_CLIENT_ID },
        data: { consentId: consent.id },
      });
      expect(revoked[0].actor).not.toHaveProperty('delegationChain');

      // The event and the revocation share one transaction: the refresh token
      // the revocation updated carries, as its row version's xmin, the 32-bit
      // id of the transaction that wrote the event (whose xid8 holds the epoch
      // above those 32 bits).
      const { rows } = await app.dbPool.query<{ revoked: number; same: number }>(
        `SELECT count(*)::int AS revoked,
                count(*) FILTER (
                  WHERE (e.xid::text::numeric % 4294967296) = t.xmin::text::numeric
                )::int AS same
         FROM events e, refresh_tokens t
         WHERE e.type = 'urn:qauth:event:consent.revoked:v1-rc.0' AND t.revoked`
      );
      expect(rows[0].revoked).toBeGreaterThan(0);
      expect(rows[0].same).toBe(rows[0].revoked);
      expect(revoked[0].data['revokedRefreshCount']).toBe(rows[0].revoked);

      // A forged revocation (no CSRF token) is refused and recorded.
      const forged = await app.inject({
        method: 'DELETE',
        url: `/consents/${consent.id}`,
        headers: { cookie: jar.header() as string },
      });
      expect(forged.statusCode).toBe(400);
      const csrf = await eventsOfType(app, 'urn:qauth:event:request.csrf_rejected:v1-rc.0');
      expect(csrf.map((event) => event.data)).toEqual([{ form: 'consent_revocation' }]);
    });
  }, 120_000);

  it('records a registration with its account, and a registration that rolls back with none', async () => {
    await withDeployment(async (app) => {
      const email = 'events-register@example.test';
      const userId = await registerPasswordAccount(app, email);

      const registered = await eventsOfType(app, 'urn:qauth:event:user.registered:v1-rc.0');
      expect(registered).toHaveLength(1);
      expect(registered[0]).toMatchObject({
        realm: await defaultRealmId(app),
        actor: { type: 'user', id: userId },
        subject: { type: 'user', id: userId },
        data: { method: 'password' },
      });

      // The address is taken: the credential insert fails and the transaction
      // rolls back, with no account and no event.
      const again = await app.inject({
        method: 'POST',
        url: '/auth/register',
        payload: { email, password: E2E_PASSWORD },
      });
      expect(again.statusCode).toBe(202);
      expect(await eventsOfType(app, 'urn:qauth:event:user.registered:v1-rc.0')).toHaveLength(1);

      // The event write itself fails: the account rolls back with it, so an
      // account and its event exist together or not at all.
      await app.dbPool.query(`
        CREATE FUNCTION e2e_refuse_event() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'e2e: event refused'; END $$;
        CREATE TRIGGER e2e_refuse_event BEFORE INSERT ON events
          FOR EACH ROW WHEN (NEW.type = 'urn:qauth:event:user.registered:v1-rc.0')
          EXECUTE FUNCTION e2e_refuse_event();
      `);
      try {
        const { rows: before } = await app.dbPool.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM users`
        );
        const refused = await app.inject({
          method: 'POST',
          url: '/auth/register',
          payload: { email: 'events-register-rollback@example.test', password: E2E_PASSWORD },
        });
        expect(refused.statusCode).toBe(500);
        const { rows: after } = await app.dbPool.query<{ n: number }>(
          `SELECT count(*)::int AS n FROM users`
        );
        expect(after[0].n).toBe(before[0].n);
        const { rows: credentials } = await app.dbPool.query(
          `SELECT 1 FROM user_credentials WHERE external_sub = 'events-register-rollback@example.test'`
        );
        expect(credentials).toEqual([]);
      } finally {
        await app.dbPool.query(`
          DROP TRIGGER e2e_refuse_event ON events;
          DROP FUNCTION e2e_refuse_event();
        `);
      }
      expect(await eventsOfType(app, 'urn:qauth:event:user.registered:v1-rc.0')).toHaveLength(1);
    });
  }, 120_000);

  it('stores no secret in any event of a run across the endpoints', async () => {
    await withDeployment(async (app, secrets) => {
      const email = 'events-run@example.test';
      const userId = await registerPasswordAccount(app, email);
      const jar = await signInWithPassword(app, email);
      const appClient = {
        clientId: APP_CLIENT_ID,
        redirectUri: APP_REDIRECT_URI,
        scopes: ['openid', 'email'],
      };
      await seedConsentedClient(app, userId, {
        ...appClient,
        grantTypes: ['authorization_code', 'refresh_token'],
      });
      const tokens = await codeFlowTokens(app, jar, appClient, secrets);

      // userinfo, a refresh, a revocation, a refused sign-in on the page and
      // the JSON API, and a sign-out.
      const userinfo = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      expect(userinfo.statusCode).toBe(200);

      if (tokens.refresh_token) {
        const refreshed = await app.inject({
          method: 'POST',
          url: '/oauth/token',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token,
            client_id: APP_CLIENT_ID,
          }).toString(),
        });
        expect(refreshed.statusCode).toBe(200);
        const rotated = refreshed.json() as { access_token: string; refresh_token?: string };
        secrets.add(rotated.access_token);
        if (rotated.refresh_token) secrets.add(rotated.refresh_token);

        // A replay of the rotated-away refresh token is refused.
        const replay = await app.inject({
          method: 'POST',
          url: '/oauth/token',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token,
            client_id: APP_CLIENT_ID,
          }).toString(),
        });
        expect(replay.statusCode).toBe(400);
      }

      const loginPage = await app.inject({ method: 'GET', url: '/ui/login' });
      const badLogin = await app.inject({
        method: 'POST',
        url: '/ui/login',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          cookie: [loginPage.headers['set-cookie']].flat().join('; '),
        },
        payload: new URLSearchParams({
          email,
          password: 'Not-The-Password-99!',
          csrf_token: extractCsrfToken(loginPage.body),
        }).toString(),
      });
      expect(badLogin.statusCode).not.toBe(302);
      secrets.add('Not-The-Password-99!');

      const apiLogin = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password: E2E_PASSWORD },
      });
      expect(apiLogin.statusCode).toBe(200);
      const apiTokens = apiLogin.json() as { access_token: string; refresh_token?: string };
      secrets.add(apiTokens.access_token);
      if (apiTokens.refresh_token) secrets.add(apiTokens.refresh_token);

      const logout = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { authorization: `Bearer ${apiTokens.access_token}` },
      });
      expect(logout.statusCode).toBe(200);

      const types = new Set((await storedEvents(app)).map((event) => event.type));
      for (const type of [
        'urn:qauth:event:user.registered:v1-rc.0',
        'urn:qauth:event:user.signed_in:v1-rc.0',
        'urn:qauth:event:user.sign_in_failed:v1-rc.0',
        'urn:qauth:event:authorization.completed:v1-rc.0',
        'urn:qauth:event:token.issued:v1-rc.0',
        'urn:qauth:event:userinfo.served:v1-rc.0',
        'urn:qauth:event:user.signed_out:v1-rc.0',
      ]) {
        expect(types.has(type), type).toBe(true);
      }
      // Nothing wrote the old table.
      const { rows } = await app.dbPool.query(`SELECT count(*)::int AS n FROM audit_logs`);
      expect(rows[0].n).toBe(0);
    });
  }, 180_000);
});
