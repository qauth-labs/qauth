import { createHash, randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { calculateJwkThumbprint, CompactSign, exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  decodeJwtClaims,
  E2E_REALM_NAME,
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
 * DPOP-BOUND TOKENS AT THE TOKEN ENDPOINT (RFC 9449; ADR-014 §3, ADR-017
 * phase F3; issue #480), end to end against real Postgres and Redis.
 *
 * With `DPOP_ENABLED=true`:
 *
 *  - a client the operator marked `dpop_bound_access_tokens` gets an access
 *    token bound to its proof key (`cnf.jkt`, `token_type: DPoP`), and a
 *    request without a proof is refused (`invalid_dpop_proof`, §5.2);
 *  - the code (`dpop_jkt`, §10) and a public client's refresh token (§5) are
 *    bound to the key; a confidential client's refresh token is not;
 *  - userinfo accepts the token only under the `DPoP` scheme with a valid
 *    proof, and refuses it as a Bearer token (§7.2);
 *  - introspection returns `cnf` and `token_type: DPoP` (§6.2);
 *  - discovery publishes `dpop_signing_alg_values_supported` (§5.1).
 *
 * With it off, the same requests, `DPoP` headers and `dpop_jkt` included,
 * get the answers a deployment without DPoP gives.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ISSUER = REQUIRED_TEST_ENVIRONMENT['JWT_ISSUER'] as string;
const REALM = E2E_REALM_NAME;
const PUBLIC_CLIENT_ID = 'dpop-native-app';
const AGENT_CLIENT_ID = 'dpop-agent';
const AGENT_SECRET = 'agent-client-secret-of-sufficient-length-42';
const RESOURCE_SERVER_ID = 'dpop-resource-server';
const RESOURCE_SERVER_SECRET = 'resource-server-secret-of-sufficient-length-42';
const MACHINE_CLIENT_ID = 'dpop-machine';
const MACHINE_SECRET = 'machine-client-secret-of-sufficient-length-42';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/** A DPoP key of the client's: the private key it signs proofs with and its thumbprint. */
interface DpopKey {
  readonly privateKey: CryptoKey;
  readonly jwk: JWK;
  readonly thumbprint: string;
}

async function dpopKey(): Promise<DpopKey> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, thumbprint: await calculateJwkThumbprint(jwk, 'sha256') };
}

/** A fresh DPoP proof for one request (RFC 9449 §4.2), with `ath` when a token rides along. */
async function proof(
  key: DpopKey,
  method: string,
  path: string,
  accessToken?: string
): Promise<string> {
  const claims = {
    jti: randomUUID(),
    htm: method,
    htu: `${ISSUER}${path}`,
    iat: Math.floor(Date.now() / 1000),
    ...(accessToken === undefined
      ? {}
      : { ath: createHash('sha256').update(accessToken).digest('base64url') }),
  };
  return new CompactSign(new TextEncoder().encode(JSON.stringify(claims)))
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: key.jwk })
    .sign(key.privateKey);
}

/** pino's numeric level for `error`; a 500 is logged at this level. */
const PINO_ERROR_LEVEL = 50;

interface LogLine {
  readonly level: number;
  readonly [key: string]: unknown;
}

describe('DPoP-bound tokens at the token endpoint (#480, real containers)', () => {
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

  /** Boot a deployment with DPoP on or off, recording its log, and hand it to the body. */
  async function withDeployment<T>(
    dpopEnabled: boolean,
    body: (app: FastifyInstance, log: readonly LogLine[]) => Promise<T>
  ): Promise<T> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    const log: LogLine[] = [];
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(
        { ...baseEnvironment(infra, jwt), DPOP_ENABLED: String(dpopEnabled) },
        { logStream: { write: (line) => log.push(JSON.parse(line) as LogLine) } }
      );
      await resetE2eState(booted.app);
      return await body(booted.app, log);
    } finally {
      await booted?.close();
    }
  }

  async function realmId(app: FastifyInstance): Promise<string> {
    const realm = await app.repositories.realms.findByName(REALM);
    if (!realm) throw new Error('default realm missing');
    return realm.id;
  }

  /**
   * A public native client the operator marked `dpop_bound_access_tokens`, with
   * the user's stored consent, so a code buys a refresh token too.
   */
  async function seedPublicDpopClient(app: FastifyInstance, userId: string): Promise<void> {
    const realm = await realmId(app);
    const client = await app.repositories.oauthClients.create({
      realmId: realm,
      clientId: PUBLIC_CLIENT_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'DPoP native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      dpopBoundAccessTokens: true,
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(userId, client.id, realm, SCOPES);
  }

  /** A confidential resource server allowed to introspect the public client's tokens. */
  async function seedResourceServer(app: FastifyInstance): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: await realmId(app),
      clientId: RESOURCE_SERVER_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(RESOURCE_SERVER_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Resource server',
      redirectUris: [],
      grantTypes: ['client_credentials'],
      audience: [PUBLIC_CLIENT_ID],
      enabled: true,
    });
  }

  /** Run the browser half of the code flow and return the code. */
  async function authorize(
    app: FastifyInstance,
    jar: CookieJar,
    clientId: string,
    challenge: string,
    dpopJkt?: string
  ): Promise<string> {
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state: 'dpop-state',
        ...(dpopJkt === undefined ? {} : { dpop_jkt: dpopJkt }),
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(response.statusCode).toBe(302);
    const code = new URL(response.headers['location'] as string).searchParams.get('code');
    if (code === null)
      throw new Error(`authorize returned no code: ${response.headers['location']}`);
    return code;
  }

  function tokenRequest(
    app: FastifyInstance,
    form: Record<string, string>,
    dpop?: string
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(dpop === undefined ? {} : { dpop }),
      },
      payload: new URLSearchParams(form).toString(),
    });
  }

  async function tokenFailureReasons(app: FastifyInstance): Promise<unknown[]> {
    const { rows } = await app.dbPool.query<{ data: { reason?: string; error: string } }>(
      `SELECT data FROM events WHERE type = 'urn:qauth:event:token.request_failed:v1-rc.0' ORDER BY seq`
    );
    return rows.map((row) => row.data);
  }

  function expectNoServerError(log: readonly LogLine[]): void {
    expect(log.filter((line) => line.level >= PINO_ERROR_LEVEL)).toEqual([]);
  }

  it('binds a DPoP client’s tokens to its key, and refuses the token without the proof', async () => {
    await withDeployment(true, async (app, log) => {
      const email = 'dpop-owner@example.test';
      const userId = await registerPasswordAccount(app, email);
      await seedPublicDpopClient(app, userId);
      await seedResourceServer(app);
      const jar = await signInWithPassword(app, email);
      const key = await dpopKey();
      const otherKey = await dpopKey();
      const pkce = pkcePair();

      // RFC 9449 §10: the authorization request binds the code to the key.
      const code = await authorize(app, jar, PUBLIC_CLIENT_ID, pkce.challenge, key.thumbprint);
      const codeRow = await app.dbPool.query<{ dpop_jkt: string | null }>(
        'SELECT dpop_jkt FROM authorization_codes WHERE code = $1',
        [code]
      );
      expect(codeRow.rows).toEqual([{ dpop_jkt: key.thumbprint }]);

      const codeForm = {
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: PUBLIC_CLIENT_ID,
        code_verifier: pkce.verifier,
      };

      // §5.2: the client is DPoP-bound, so a request without a proof is
      // refused, and the code is not spent by it.
      const withoutProof = await tokenRequest(app, codeForm);
      expect(withoutProof.statusCode).toBe(400);
      expect(withoutProof.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      expect(withoutProof.json()).not.toHaveProperty('error_description');

      // §10: a proof under another key does not redeem a code bound to this one.
      const wrongKey = await tokenRequest(
        app,
        codeForm,
        await proof(otherKey, 'POST', '/oauth/token')
      );
      expect(wrongKey.statusCode).toBe(400);
      expect(wrongKey.json()).toMatchObject({ error: 'invalid_dpop_proof' });

      const issued = await tokenRequest(app, codeForm, await proof(key, 'POST', '/oauth/token'));
      expect(issued.statusCode).toBe(200);
      const tokens = issued.json() as {
        access_token: string;
        refresh_token: string;
        token_type: string;
      };
      expect(tokens.token_type).toBe('DPoP');
      expect(decodeJwtClaims(tokens.access_token)['cnf']).toEqual({ jkt: key.thumbprint });

      // §5: a public client's refresh token is bound to the key too.
      const refreshRows = await app.dbPool.query<{ cnf_jkt: string | null }>(
        'SELECT cnf_jkt FROM refresh_tokens WHERE user_id = $1',
        [userId]
      );
      expect(refreshRows.rows).toEqual([{ cnf_jkt: key.thumbprint }]);

      // §7.1: userinfo accepts the token under the DPoP scheme with a proof
      // for this request, carrying the token's hash.
      const userinfo = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof(key, 'GET', '/oauth/userinfo', tokens.access_token),
        },
      });
      expect(userinfo.statusCode).toBe(200);
      expect(userinfo.json()).toEqual({ sub: userId, email, email_verified: true });

      // The same token without the proof is refused, with a DPoP challenge.
      const noProof = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: `DPoP ${tokens.access_token}` },
      });
      expect(noProof.statusCode).toBe(401);
      expect(noProof.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      expect(noProof.headers['www-authenticate']).toMatch(
        /^DPoP error="invalid_dpop_proof", algs="[A-Za-z0-9 ]+"$/
      );

      // A proof under another key is not the token's binding (RFC 9449 Figure 16).
      const otherProof = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          authorization: `DPoP ${tokens.access_token}`,
          dpop: await proof(otherKey, 'GET', '/oauth/userinfo', tokens.access_token),
        },
      });
      expect(otherProof.statusCode).toBe(401);
      expect(otherProof.json()).toMatchObject({ error: 'invalid_token' });
      expect(otherProof.headers['www-authenticate']).toMatch(
        /^DPoP error="invalid_token", error_description="[^"]*", algs="/
      );

      // A replayed proof is refused.
      const once = await proof(key, 'GET', '/oauth/userinfo', tokens.access_token);
      const first = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: `DPoP ${tokens.access_token}`, dpop: once },
      });
      const replay = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: { authorization: `DPoP ${tokens.access_token}`, dpop: once },
      });
      expect(first.statusCode).toBe(200);
      expect(replay.statusCode).toBe(401);
      expect(replay.json()).toMatchObject({ error: 'invalid_dpop_proof' });

      // §6.2: introspection reports the binding for the resource server to check.
      const introspection = await app.inject({
        method: 'POST',
        url: '/oauth/introspect',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          token: tokens.access_token,
          client_id: RESOURCE_SERVER_ID,
          client_secret: RESOURCE_SERVER_SECRET,
        }).toString(),
      });
      expect(introspection.statusCode).toBe(200);
      expect(introspection.json()).toMatchObject({
        active: true,
        token_type: 'DPoP',
        cnf: { jkt: key.thumbprint },
      });

      // §5: the refresh token is used only with a proof under the same key. A
      // refusal does not count as a replay: the family stays live.
      const refreshForm = {
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
        client_id: PUBLIC_CLIENT_ID,
      };
      const refreshWrongKey = await tokenRequest(
        app,
        refreshForm,
        await proof(otherKey, 'POST', '/oauth/token')
      );
      expect(refreshWrongKey.statusCode).toBe(400);
      expect(refreshWrongKey.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      const refreshed = await tokenRequest(
        app,
        refreshForm,
        await proof(key, 'POST', '/oauth/token')
      );
      expect(refreshed.statusCode).toBe(200);
      const rotated = refreshed.json() as { access_token: string; token_type: string };
      expect(rotated.token_type).toBe('DPoP');
      expect(decodeJwtClaims(rotated.access_token)['cnf']).toEqual({ jkt: key.thumbprint });
      const live = await app.dbPool.query<{ cnf_jkt: string | null }>(
        'SELECT cnf_jkt FROM refresh_tokens WHERE user_id = $1 AND revoked = false',
        [userId]
      );
      expect(live.rows).toEqual([{ cnf_jkt: key.thumbprint }]);

      // Every refusal is an event naming its reason; the wire named none.
      expect(await tokenFailureReasons(app)).toEqual([
        {
          grantType: 'authorization_code',
          error: 'invalid_dpop_proof',
          reason: 'dpop_missing_proof',
        },
        {
          grantType: 'authorization_code',
          error: 'invalid_dpop_proof',
          reason: 'dpop_key_mismatch',
        },
        { grantType: 'refresh_token', error: 'invalid_dpop_proof', reason: 'dpop_key_mismatch' },
      ]);
      expectNoServerError(log);
    });
  }, 180_000);

  it('refuses a DPoP-bound token sent as Bearer, at userinfo by header and by form body', async () => {
    await withDeployment(true, async (app, log) => {
      const email = 'dpop-bearer@example.test';
      const userId = await registerPasswordAccount(app, email);
      await seedPublicDpopClient(app, userId);
      const jar = await signInWithPassword(app, email);
      const key = await dpopKey();
      const pkce = pkcePair();
      const code = await authorize(app, jar, PUBLIC_CLIENT_ID, pkce.challenge);
      const issued = await tokenRequest(
        app,
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: PUBLIC_CLIENT_ID,
          code_verifier: pkce.verifier,
        },
        await proof(key, 'POST', '/oauth/token')
      );
      expect(issued.statusCode).toBe(200);
      const { access_token: accessToken } = issued.json() as { access_token: string };

      // RFC 9449 §7.2: never accepted as a bearer token.
      for (const request of [
        { method: 'GET' as const, headers: { authorization: `Bearer ${accessToken}` } },
        { method: 'POST' as const, headers: { authorization: `Bearer ${accessToken}` } },
        {
          method: 'POST' as const,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: new URLSearchParams({ access_token: accessToken }).toString(),
        },
      ]) {
        const response = await app.inject({ ...request, url: '/oauth/userinfo' });
        expect(response.statusCode).toBe(401);
        expect(response.json()).toMatchObject({ error: 'invalid_token' });
        expect(response.headers['www-authenticate']).toMatch(
          /^Bearer realm="OAuth", error="invalid_token", error_description="[^"]*"$/
        );
      }

      expectNoServerError(log);
    });
  }, 180_000);

  it('binds a token exchange and client credentials to the proof key, never a confidential refresh token', async () => {
    await withDeployment(true, async (app, log) => {
      const email = 'dpop-agent-user@example.test';
      const userId = await registerPasswordAccount(app, email);
      const realm = await realmId(app);
      // A confidential agent: its refresh tokens are bound by client
      // authentication, not by the key (RFC 9449 §5).
      const agent = await app.repositories.oauthClients.create({
        realmId: realm,
        clientId: AGENT_CLIENT_ID,
        clientSecretHash: await app.passwordHasher.hashPassword(AGENT_SECRET),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'DPoP agent',
        redirectUris: [REDIRECT_URI],
        scopes: SCOPES,
        grantTypes: ['authorization_code', 'refresh_token', TOKEN_EXCHANGE],
        isAgent: true,
        // Not marked DPoP-bound: what refuses the exchange below without a
        // proof is the subject token's own binding.
        enabled: true,
      });
      await app.repositories.oauthConsents.upsertGrant(userId, agent.id, realm, SCOPES);
      await app.repositories.oauthClients.create({
        realmId: realm,
        clientId: MACHINE_CLIENT_ID,
        clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'DPoP machine',
        redirectUris: [],
        scopes: ['reports:read'],
        grantTypes: ['client_credentials'],
        dpopBoundAccessTokens: true,
        enabled: true,
      });

      const jar = await signInWithPassword(app, email);
      const key = await dpopKey();
      const pkce = pkcePair();
      const code = await authorize(app, jar, AGENT_CLIENT_ID, pkce.challenge);
      const issued = await tokenRequest(
        app,
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: AGENT_CLIENT_ID,
          client_secret: AGENT_SECRET,
          code_verifier: pkce.verifier,
        },
        await proof(key, 'POST', '/oauth/token')
      );
      expect(issued.statusCode).toBe(200);
      const subject = issued.json() as { access_token: string; token_type: string };
      expect(subject.token_type).toBe('DPoP');
      const refreshRows = await app.dbPool.query<{ cnf_jkt: string | null }>(
        'SELECT cnf_jkt FROM refresh_tokens WHERE user_id = $1',
        [userId]
      );
      expect(refreshRows.rows).toEqual([{ cnf_jkt: null }]);

      const exchangeForm = {
        grant_type: TOKEN_EXCHANGE,
        subject_token: subject.access_token,
        subject_token_type: ACCESS_TOKEN_TYPE,
        client_id: AGENT_CLIENT_ID,
        client_secret: AGENT_SECRET,
      };
      // A bound subject token is exchanged only with a proof under its key:
      // the agent's secret and a copy of the token buy nothing.
      const exchangeWithoutProof = await tokenRequest(app, exchangeForm);
      expect(exchangeWithoutProof.statusCode).toBe(400);
      expect(exchangeWithoutProof.json()).toMatchObject({ error: 'invalid_dpop_proof' });
      const exchangeOtherKey = await tokenRequest(
        app,
        exchangeForm,
        await proof(await dpopKey(), 'POST', '/oauth/token')
      );
      expect(exchangeOtherKey.statusCode).toBe(400);
      expect(exchangeOtherKey.json()).toMatchObject({ error: 'invalid_request' });
      expect(await tokenFailureReasons(app)).toEqual([
        { grantType: TOKEN_EXCHANGE, error: 'invalid_dpop_proof', reason: 'dpop_missing_proof' },
        {
          grantType: TOKEN_EXCHANGE,
          error: 'invalid_request',
          reason: 'subject_token_key_mismatch',
        },
      ]);
      const exchanged = await tokenRequest(
        app,
        exchangeForm,
        await proof(key, 'POST', '/oauth/token')
      );
      expect(exchanged.statusCode).toBe(200);
      const delegated = exchanged.json() as {
        access_token: string;
        token_type: string;
        issued_token_type: string;
      };
      expect(delegated).toMatchObject({ token_type: 'DPoP', issued_token_type: ACCESS_TOKEN_TYPE });
      expect(decodeJwtClaims(delegated.access_token)).toMatchObject({
        act: { sub: AGENT_CLIENT_ID },
        cnf: { jkt: key.thumbprint },
      });

      const machineForm = {
        grant_type: 'client_credentials',
        client_id: MACHINE_CLIENT_ID,
        client_secret: MACHINE_SECRET,
        scope: 'reports:read',
      };
      expect((await tokenRequest(app, machineForm)).json()).toMatchObject({
        error: 'invalid_dpop_proof',
      });
      const machine = await tokenRequest(
        app,
        machineForm,
        await proof(key, 'POST', '/oauth/token')
      );
      expect(machine.statusCode).toBe(200);
      expect(machine.json()).toMatchObject({ token_type: 'DPoP' });
      expect(
        decodeJwtClaims((machine.json() as { access_token: string }).access_token)['cnf']
      ).toEqual({ jkt: key.thumbprint });
      expectNoServerError(log);
    });
  }, 180_000);

  it('publishes dpop_signing_alg_values_supported while DPoP is on', async () => {
    await withDeployment(true, async (app) => {
      for (const path of [
        '/.well-known/oauth-authorization-server',
        '/.well-known/openid-configuration',
      ]) {
        const metadata = (await app.inject({ method: 'GET', url: path })).json() as Record<
          string,
          unknown
        >;
        expect(metadata['dpop_signing_alg_values_supported']).toEqual([
          'ES256',
          'ES384',
          'ES512',
          'EdDSA',
          'Ed25519',
          'PS256',
          'PS384',
          'PS512',
        ]);
      }
    });
  }, 120_000);

  /**
   * DPOP_ENABLED off: the server reads no `DPoP` header and no `dpop_jkt`.
   * Each request below is sent twice, with and without the DPoP inputs, and
   * the two answers must be the same: what a deployment without DPoP gives.
   */
  it('answers as a deployment without DPoP while DPOP_ENABLED is off', async () => {
    await withDeployment(false, async (app, log) => {
      const email = 'dpop-off@example.test';
      const userId = await registerPasswordAccount(app, email);
      // Marked DPoP-bound, which nothing reads while DPoP is off.
      await seedPublicDpopClient(app, userId);
      const jar = await signInWithPassword(app, email);
      const key = await dpopKey();

      for (const path of [
        '/.well-known/oauth-authorization-server',
        '/.well-known/openid-configuration',
      ]) {
        const metadata = (await app.inject({ method: 'GET', url: path })).json() as Record<
          string,
          unknown
        >;
        expect('dpop_signing_alg_values_supported' in metadata).toBe(false);
      }

      /** Redeem a fresh code, with or without the DPoP inputs, and describe the answer. */
      async function codeFlow(withDpop: boolean) {
        const pkce = pkcePair();
        const code = await authorize(
          app,
          jar,
          PUBLIC_CLIENT_ID,
          pkce.challenge,
          withDpop ? key.thumbprint : undefined
        );
        const row = await app.dbPool.query<{ dpop_jkt: string | null }>(
          'SELECT dpop_jkt FROM authorization_codes WHERE code = $1',
          [code]
        );
        const response = await tokenRequest(
          app,
          {
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT_URI,
            client_id: PUBLIC_CLIENT_ID,
            code_verifier: pkce.verifier,
          },
          withDpop ? await proof(key, 'POST', '/oauth/token') : undefined
        );
        const body = response.json() as Record<string, unknown> & { access_token: string };
        const claims = decodeJwtClaims(body.access_token);
        return {
          status: response.statusCode,
          headers: {
            'cache-control': response.headers['cache-control'],
            pragma: response.headers['pragma'],
            'content-type': response.headers['content-type'],
          },
          bodyKeys: Object.keys(body),
          tokenType: body['token_type'],
          claimKeys: Object.keys(claims).sort(),
          codeBinding: row.rows[0]?.dpop_jkt,
          accessToken: body.access_token,
        };
      }

      // Before DPoP the parameter was stripped unread, so a repeated or
      // over-long one did not stop the request; it still does not.
      for (const query of [
        `dpop_jkt=${key.thumbprint}&dpop_jkt=${key.thumbprint}`,
        `dpop_jkt=${'x'.repeat(3000)}`,
      ]) {
        const pkce = pkcePair();
        const response = await app.inject({
          method: 'GET',
          url: `/oauth/authorize?${new URLSearchParams({
            response_type: 'code',
            client_id: PUBLIC_CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            scope: SCOPES.join(' '),
            code_challenge: pkce.challenge,
            code_challenge_method: 'S256',
            state: 'dpop-state',
          }).toString()}&${query}`,
          headers: { cookie: jar.header() as string },
        });
        expect(response.statusCode).toBe(302);
        expect(
          new URL(response.headers['location'] as string).searchParams.get('code')
        ).not.toBeNull();
      }

      const plain = await codeFlow(false);
      const dpop = await codeFlow(true);
      const { accessToken: plainToken, ...plainShape } = plain;
      const { accessToken: dpopToken, ...dpopShape } = dpop;
      expect(dpopShape).toEqual(plainShape);
      expect(plainShape).toMatchObject({ status: 200, tokenType: 'Bearer', codeBinding: null });
      expect(plainShape.claimKeys).not.toContain('cnf');
      const refreshRows = await app.dbPool.query<{ cnf_jkt: string | null }>(
        'SELECT DISTINCT cnf_jkt FROM refresh_tokens WHERE user_id = $1',
        [userId]
      );
      expect(refreshRows.rows).toEqual([{ cnf_jkt: null }]);

      // Both tokens are Bearer tokens at userinfo; the DPoP proof header is ignored.
      for (const token of [plainToken, dpopToken]) {
        const response = await app.inject({
          method: 'GET',
          url: '/oauth/userinfo',
          headers: {
            authorization: `Bearer ${token}`,
            dpop: await proof(key, 'GET', '/oauth/userinfo', token),
          },
        });
        expect(response.statusCode).toBe(200);
      }

      // The DPoP scheme is no credential: the same 401 as no header at all.
      const dpopScheme = await app.inject({
        method: 'GET',
        url: '/oauth/userinfo',
        headers: {
          authorization: `DPoP ${dpopToken}`,
          dpop: await proof(key, 'GET', '/oauth/userinfo', dpopToken),
        },
      });
      const noHeader = await app.inject({ method: 'GET', url: '/oauth/userinfo' });
      expect(dpopScheme.statusCode).toBe(401);
      expect(dpopScheme.body).toBe(noHeader.body);
      expect(dpopScheme.headers['www-authenticate']).toBe(noHeader.headers['www-authenticate']);

      expect(await tokenFailureReasons(app)).toEqual([]);
      expectNoServerError(log);
    });
  }, 180_000);

  it('refuses a code bound while DPoP was on once DPoP is off, rather than issue a bearer token for it', async () => {
    await withDeployment(false, async (app) => {
      const email = 'dpop-switched-off@example.test';
      const userId = await registerPasswordAccount(app, email);
      await seedPublicDpopClient(app, userId);
      const jar = await signInWithPassword(app, email);
      const key = await dpopKey();
      const pkce = pkcePair();
      const code = await authorize(app, jar, PUBLIC_CLIENT_ID, pkce.challenge);
      // The row as a deployment with DPoP on would have written it.
      await app.dbPool.query('UPDATE authorization_codes SET dpop_jkt = $1 WHERE code = $2', [
        key.thumbprint,
        code,
      ]);

      const response = await tokenRequest(
        app,
        {
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: PUBLIC_CLIENT_ID,
          code_verifier: pkce.verifier,
        },
        await proof(key, 'POST', '/oauth/token')
      );
      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({ error: 'invalid_grant' });
      expect(await tokenFailureReasons(app)).toEqual([
        { grantType: 'authorization_code', error: 'invalid_grant', reason: 'dpop_disabled' },
      ]);
    });
  }, 120_000);
});
