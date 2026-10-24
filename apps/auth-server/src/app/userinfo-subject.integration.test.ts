import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  E2E_PASSWORD,
  type E2eInfrastructure,
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
 * USERINFO ANSWERS ONLY FOR A USER SUBJECT (#754).
 *
 * A `client_credentials` access token carries the client's `client_id` as
 * `sub`. Without an RFC 8707 `resource` and without a configured client
 * `audience`, `resolveAudience` also makes its `aud` the client_id, which is
 * exactly the audience `/oauth/userinfo` accepts for a client's own token. The
 * route then looked the client_id up as a `users.id`:
 *
 *  - a client_id that is not a UUID reached PostgreSQL as an invalid `uuid`
 *    (22P02) and the request failed with 500;
 *  - a client_id that is a UUID found no user.
 *
 * OIDC Core §5.3.3 and RFC 6750 §3.1 call for 401 `invalid_token` with a
 * `WWW-Authenticate: Bearer` challenge. Both cases need a real Postgres to
 * show: the mocked route tests cannot raise 22P02 or a foreign-key violation.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const REALM = REQUIRED_TEST_ENVIRONMENT['DEFAULT_REALM_NAME'] as string;
const USERINFO_ENDPOINT = `${REQUIRED_TEST_ENVIRONMENT['JWT_ISSUER']}/oauth/userinfo`;
const MACHINE_SECRET = 'machine-client-secret-of-sufficient-length-42';
const MACHINE_SCOPE = 'reports:read';
const OIDC_CLIENT_ID = 'e2e-oidc-client';
const OIDC_REDIRECT_URI = 'https://client.example.com/callback';
const OIDC_SCOPES = ['openid', 'email', 'profile'];

/** pino's numeric level for `error`; a 500 is logged at this level. */
const PINO_ERROR_LEVEL = 50;

/** One parsed line of the server's own log. */
interface LogLine {
  readonly level: number;
  readonly msg?: string;
  readonly [key: string]: unknown;
}

describe('userinfo and logout refuse a token whose subject is not a user (real containers)', () => {
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

  /** Boot a default deployment that records its own log, and hand both to the body. */
  async function withDeployment<T>(
    body: (app: FastifyInstance, log: readonly LogLine[]) => Promise<T>
  ): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    const log: LogLine[] = [];
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(baseEnvironment(infra, jwt), {
        logStream: { write: (line) => log.push(JSON.parse(line) as LogLine) },
      });
      await resetE2eState(booted.app);
      return await body(booted.app, log);
    } finally {
      await booted?.close();
    }
  }

  async function realmId(app: FastifyInstance): Promise<string> {
    const realm =
      (await app.repositories.realms.findByName(REALM)) ??
      (await app.repositories.realms.create({ name: REALM, enabled: true }));
    return realm.id;
  }

  /**
   * Register a confidential machine client allowed only `client_credentials`.
   * With no `audience`, its tokens fall back to `aud = client_id`.
   */
  async function seedMachineClient(
    app: FastifyInstance,
    clientId: string,
    audience?: string[]
  ): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: await realmId(app),
      clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'E2E machine client',
      redirectUris: [],
      scopes: [MACHINE_SCOPE],
      grantTypes: ['client_credentials'],
      ...(audience === undefined ? {} : { audience }),
      enabled: true,
    });
  }

  /** Mint a `client_credentials` access token through the real token endpoint. */
  async function clientCredentialsToken(
    app: FastifyInstance,
    clientId: string,
    resource?: string
  ): Promise<string> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: MACHINE_SECRET,
        scope: MACHINE_SCOPE,
        ...(resource === undefined ? {} : { resource }),
      }).toString(),
    });
    expect(response.statusCode).toBe(200);
    return (response.json() as { access_token: string }).access_token;
  }

  /** The three ways a token reaches userinfo: GET header, POST header, POST form body. */
  async function userinfoThreeWays(
    app: FastifyInstance,
    accessToken: string
  ): Promise<Record<'get' | 'postHeader' | 'postBody', LightMyRequestResponse>> {
    const get = await app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const postHeader = await app.inject({
      method: 'POST',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    const postBody = await app.inject({
      method: 'POST',
      url: '/oauth/userinfo',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ access_token: accessToken }).toString(),
    });
    return { get, postHeader, postBody };
  }

  /** RFC 6750 §3.1: 401 with a Bearer challenge naming `invalid_token`. */
  function expectInvalidToken(response: LightMyRequestResponse): void {
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toMatch(
      /^Bearer realm="OAuth", error="invalid_token"/
    );
  }

  /** Nothing the server logged was a 500 or a database error. */
  function expectNoDatabaseError(log: readonly LogLine[]): void {
    expect(log.filter((line) => line.level >= PINO_ERROR_LEVEL)).toEqual([]);
    const text = log.map((line) => JSON.stringify(line)).join('\n');
    expect(text).not.toMatch(/22P02|23503|invalid input syntax for type uuid|foreign key/i);
  }

  /** The failure events userinfo recorded, oldest first. */
  async function userinfoFailureEvents(app: FastifyInstance) {
    const result = await app.dbPool.query<{
      subject_id: string | null;
      client_id: string | null;
      data: unknown;
    }>(
      `SELECT subject_id, client_id, data FROM events
       WHERE type = 'urn:qauth:event:userinfo.request_failed:v1-rc.0' ORDER BY seq`
    );
    return result.rows;
  }

  it('answers 401 invalid_token, without a database error, when the client_id is not a UUID', async () => {
    await withDeployment(async (app, log) => {
      const clientId = 'reporting-service';
      await seedMachineClient(app, clientId);
      const token = await clientCredentialsToken(app, clientId);

      const { get, postHeader, postBody } = await userinfoThreeWays(app, token);

      expectInvalidToken(get);
      expectInvalidToken(postHeader);
      expectInvalidToken(postBody);
      expectNoDatabaseError(log);

      // Each refusal is an event with no user as its subject; the machine
      // token's subject is its own client, which the event names.
      const events = await userinfoFailureEvents(app);
      expect(events).toHaveLength(3);
      for (const event of events) {
        expect(event.subject_id).toBeNull();
        expect(event.client_id).toBe(clientId);
        expect(event.data).toEqual({ error: 'invalid_token', reason: 'subject_not_a_user' });
      }
    });
  }, 120_000);

  it('answers 401 invalid_token, without a database error, when the client_id is a UUID', async () => {
    await withDeployment(async (app, log) => {
      const clientId = randomUUID();
      await seedMachineClient(app, clientId);
      const token = await clientCredentialsToken(app, clientId);

      const { get, postHeader, postBody } = await userinfoThreeWays(app, token);

      expectInvalidToken(get);
      expectInvalidToken(postHeader);
      expectInvalidToken(postBody);
      expectNoDatabaseError(log);

      const events = await userinfoFailureEvents(app);
      expect(events).toHaveLength(3);
      for (const event of events) expect(event.subject_id).toBeNull();
    });
  }, 120_000);

  it('answers 401 invalid_token for a client_credentials token addressed to the userinfo endpoint', async () => {
    await withDeployment(async (app, log) => {
      // The other way past the audience rule: the client may name the userinfo
      // endpoint as an RFC 8707 resource. The subject is still no user.
      const clientId = 'userinfo-audience-service';
      await seedMachineClient(app, clientId, [USERINFO_ENDPOINT]);
      const token = await clientCredentialsToken(app, clientId, USERINFO_ENDPOINT);

      const { get, postHeader, postBody } = await userinfoThreeWays(app, token);

      expectInvalidToken(get);
      expectInvalidToken(postHeader);
      expectInvalidToken(postBody);
      expectNoDatabaseError(log);
    });
  }, 120_000);

  it("still returns a user's claims for the user's own token, at GET and POST", async () => {
    await withDeployment(async (app, log) => {
      const email = 'userinfo-owner@example.test';
      const userId = await registerPasswordAccount(app, email);
      const jar = await signInWithPassword(app, email, E2E_PASSWORD);
      const accessToken = await codeFlowAccessToken(app, jar, userId);

      const { get, postHeader, postBody } = await userinfoThreeWays(app, accessToken);

      for (const response of [get, postHeader, postBody]) {
        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ sub: userId, email, email_verified: true });
      }
      expectNoDatabaseError(log);
      expect(await userinfoFailureEvents(app)).toEqual([]);
    });
  }, 120_000);

  /**
   * `/auth/logout` had the same failure audit: it wrote the token's `sub` into
   * `audit_logs.user_id` before knowing a user owned it. A first-party token
   * outlives a deleted account, and its logout then failed the insert with
   * 23503 and answered 500 instead of the refusal. The event that replaced
   * the row has no foreign key, and names only a user the lookup confirmed.
   */
  it("answers 401 invalid_token at /auth/logout, without a database error, once the token's user is deleted", async () => {
    await withDeployment(async (app, log) => {
      const email = 'logout-deleted@example.test';
      const userId = await registerPasswordAccount(app, email);
      const login = await app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email, password: E2E_PASSWORD },
      });
      expect(login.statusCode).toBe(200);
      const accessToken = (login.json() as { access_token: string }).access_token;

      await app.dbPool.query('DELETE FROM users WHERE id = $1', [userId]);

      const logout = await app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { authorization: `Bearer ${accessToken}` },
      });

      expectInvalidToken(logout);
      expectNoDatabaseError(log);
      const events = await app.dbPool.query<{ subject_id: string | null }>(
        `SELECT subject_id FROM events WHERE type = 'urn:qauth:event:user.sign_out_failed:v1-rc.0'`
      );
      expect(events.rows).toEqual([{ subject_id: null }]);
    });
  }, 120_000);

  /**
   * A user's access token from an OIDC client's own code flow, with no
   * `resource`: `aud` falls back to the client_id, as for the machine token
   * above, and `sub` is the user. Consent is pre-granted at the repository so
   * the flow mints a code instead of rendering the consent screen.
   */
  async function codeFlowAccessToken(
    app: FastifyInstance,
    jar: CookieJar,
    userId: string
  ): Promise<string> {
    const realm = await realmId(app);
    const client = await app.repositories.oauthClients.create({
      realmId: realm,
      clientId: OIDC_CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'E2E OIDC client',
      redirectUris: [OIDC_REDIRECT_URI],
      scopes: OIDC_SCOPES,
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(userId, client.id, realm, OIDC_SCOPES);

    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: OIDC_CLIENT_ID,
        redirect_uri: OIDC_REDIRECT_URI,
        scope: OIDC_SCOPES.join(' '),
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

    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: OIDC_REDIRECT_URI,
        client_id: OIDC_CLIENT_ID,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode).toBe(200);
    return (token.json() as { access_token: string }).access_token;
  }
});
