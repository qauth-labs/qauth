import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { decodeProtectedHeader, importPKCS8, type JSONWebKeySet, SignJWT } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  allowConsentScreen,
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type CookieJar,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  rotateRealmKeys,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * A TOKEN SIGNED BEFORE A KEY ROTATION STILL VERIFIES AFTER IT (ADR-019
 * Decision 9, ADR-001, issue #492), against a real Postgres and Redis.
 *
 * A rotation moves the realm's active `token_signing` key to `retired` and
 * activates a new one (`rotateRealmKeys`). The server verifies every token
 * with the realm's verification set: its active keys and its retired keys
 * still inside their retention, picked by the token's `(kid, alg)`. So a user
 * keeps working with the tokens they hold, and needs no new sign-in, until the
 * retired key's retention ends. A `next` or `compromised` key never verifies.
 *
 * Each rotation is seen by a server booted after it, as a node that starts
 * after a rotation sees it: a running server's signer reads key lists at most
 * once a minute.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ISSUER = 'https://auth.example.com';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const MACHINE_ID = 'rotation-machine';
const MACHINE_SECRET = 'rotation-machine-secret-of-sufficient-length';
const AGENT_ID = 'rotation-agent';
const AGENT_SECRET = 'rotation-agent-secret-of-sufficient-length-42';
const AGENT_REDIRECT_URI = 'https://agent.example.com/callback';
const AGENT_SCOPES = ['openid', 'notes:read'];
const HYBRID = { HYBRID_SIGNING_ENABLED: 'true', SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65' };

/** A `token_signing` key as the realm's key store holds it. */
interface StoredTokenKey {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: string;
}

describe('tokens of a retired key verify until its retention ends (#492)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

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

  afterEach(async () => {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /** The variables of a deployment from before the key store, plus `extra`. */
  function variables(extra: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return { ...baseEnvironment(infra, jwt), ...extra };
  }

  /** A deployment that sets no key variable: the store holds the keys. */
  function noKeyVariables(extra: Record<string, string> = {}): Record<string, string> {
    const environment = variables(extra);
    delete environment['JWT_PRIVATE_KEY'];
    delete environment['JWT_PUBLIC_KEY'];
    return environment;
  }

  async function boot(environment: Record<string, string>): Promise<FastifyInstance> {
    const server = await bootAuthServer(environment);
    booted.push(server);
    return server.app;
  }

  /** Close every server booted so far: the next one is the node after the rotation. */
  async function closeAll(): Promise<void> {
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  }

  /** Empty the database through a throwaway server, so the next boot is a first one. */
  async function emptyDatabase(): Promise<void> {
    const server = await bootAuthServer(variables());
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.close();
  }

  async function realmId(app: FastifyInstance): Promise<string> {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error(`no realm ${E2E_REALM_NAME}`);
    return realm.id;
  }

  async function storedTokenKeys(app: FastifyInstance): Promise<StoredTokenKey[]> {
    const { rows } = await app.dbPool.query<StoredTokenKey>(
      `SELECT kid, algorithm, status FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'token_signing' ORDER BY algorithm, kid`,
      [await realmId(app)]
    );
    return rows;
  }

  async function activeKid(app: FastifyInstance, algorithm: string): Promise<string> {
    const key = (await storedTokenKeys(app)).find(
      (row) => row.algorithm === algorithm && row.status === 'active'
    );
    if (!key) throw new Error(`no active ${algorithm} key`);
    return key.kid;
  }

  async function seedMachineClient(app: FastifyInstance): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId: await realmId(app),
      clientId: MACHINE_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Rotation test machine',
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
  }

  async function machineToken(app: FastifyInstance): Promise<string> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: MACHINE_ID,
        client_secret: MACHINE_SECRET,
        scope: 'reports:read',
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ access_token: string }>().access_token;
  }

  /** RFC 7662 introspection, authenticated as `clientId`. */
  async function introspect(
    app: FastifyInstance,
    token: string,
    client: { id: string; secret: string } = { id: MACHINE_ID, secret: MACHINE_SECRET }
  ): Promise<Record<string, unknown>> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: new URLSearchParams({
        token,
        client_id: client.id,
        client_secret: client.secret,
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<Record<string, unknown>>();
  }

  function userinfo(app: FastifyInstance, token: string): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${token}` },
    });
  }

  async function jwksKids(app: FastifyInstance): Promise<unknown[]> {
    const response = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(response.statusCode).toBe(200);
    return response.json<JSONWebKeySet>().keys.map((key) => key.kid);
  }

  /**
   * A signed-in user and an agent client with their consent, and the user's
   * access token from the code flow: its `aud` is the agent's client_id, so
   * userinfo, the agent's introspection and the agent's token exchange accept
   * it. Also a first-party `/auth/login` token, which `/auth/logout` takes.
   * The stored consent does not skip the screen for an agent (ADR-015
   * Decision 11, #845), so the code flow allows it there.
   */
  async function userTokens(
    app: FastifyInstance
  ): Promise<{ userId: string; accessToken: string; loginToken: string }> {
    const email = 'rotation-user@example.test';
    const userId = await registerPasswordAccount(app, email);
    const jar = await signInWithPassword(app, email, E2E_PASSWORD);
    const realm = await realmId(app);
    const client = await app.repositories.oauthClients.create({
      realmId: realm,
      clientId: AGENT_ID,
      clientSecretHash: await app.passwordHasher.hashPassword(AGENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Rotation test agent',
      redirectUris: [AGENT_REDIRECT_URI],
      scopes: AGENT_SCOPES,
      grantTypes: ['authorization_code', TOKEN_EXCHANGE],
      isAgent: true,
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realm, userId, client.id, AGENT_SCOPES);

    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);

    return {
      userId,
      accessToken: await codeFlowAccessToken(app, jar),
      loginToken: login.json<{ access_token: string }>().access_token,
    };
  }

  async function codeFlowAccessToken(app: FastifyInstance, jar: CookieJar): Promise<string> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: AGENT_ID,
        redirect_uri: AGENT_REDIRECT_URI,
        scope: AGENT_SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'rotation-state',
      }).toString()}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    let location = String(authorize.headers['location']);
    if (location.startsWith('/ui/consent?')) {
      location = await allowConsentScreen(app, jar.header() as string, location);
    }
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);
    const token = await app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: AGENT_REDIRECT_URI,
        client_id: AGENT_ID,
        client_secret: AGENT_SECRET,
        code_verifier: pkce.verifier,
      }).toString(),
    });
    expect(token.statusCode, token.body).toBe(200);
    return token.json<{ access_token: string }>().access_token;
  }

  /** A token as a release before tokens named their key signed one: no `kid`. */
  async function kidlessToken(privateKeyPem: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ sub: MACHINE_ID, client_id: MACHINE_ID, scope: 'reports:read' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuer(ISSUER)
      .setAudience(MACHINE_ID)
      .setJti(`kidless-${now}-${Math.random().toString(36).slice(2)}`)
      .setIssuedAt(now - 60)
      .setExpirationTime(now + 600)
      .sign(await importPKCS8(privateKeyPem, 'EdDSA'));
  }

  it('verifies tokens signed before a rotation at every verify site, with no new sign-in', async () => {
    const before = await boot(variables());
    await resetE2eState(before);
    await seedMachineClient(before);
    const { userId, accessToken, loginToken } = await userTokens(before);
    const machine = await machineToken(before);
    const oldKid = await activeKid(before, 'EdDSA');
    for (const token of [accessToken, loginToken, machine]) {
      expect(decodeProtectedHeader(token)['kid']).toBe(oldKid);
    }

    const rotation = await rotateRealmKeys(before, E2E_REALM_NAME);
    expect(rotation.retired).toEqual([
      expect.objectContaining({ kid: oldKid, algorithm: 'EdDSA' }),
    ]);
    const [{ kid: newKid }] = rotation.activated;
    expect(newKid).not.toBe(oldKid);
    await closeAll();

    const after = await boot(variables());
    expect(await storedTokenKeys(after)).toEqual(
      expect.arrayContaining([
        { kid: oldKid, algorithm: 'EdDSA', status: 'retired' },
        { kid: newKid, algorithm: 'EdDSA', status: 'active' },
      ])
    );

    // userinfo, behind requireJwt: the user's token of the old key still works.
    const claims = await userinfo(after, accessToken);
    expect(claims.statusCode, claims.body).toBe(200);
    expect(claims.json()).toMatchObject({ sub: userId });

    // Introspection, by the client the token was issued to.
    expect(await introspect(after, machine)).toMatchObject({ active: true, client_id: MACHINE_ID });
    expect(
      await introspect(after, accessToken, { id: AGENT_ID, secret: AGENT_SECRET })
    ).toMatchObject({ active: true, sub: userId });

    // Token exchange: the old key's token is a valid subject_token.
    const exchange = await after.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE,
        subject_token: accessToken,
        subject_token_type: ACCESS_TOKEN_TYPE,
        client_id: AGENT_ID,
        client_secret: AGENT_SECRET,
        scope: 'notes:read',
      }).toString(),
    });
    expect(exchange.statusCode, exchange.body).toBe(200);
    // Tokens issued after the rotation name the new key.
    const exchanged = exchange.json<{ access_token: string }>().access_token;
    expect(decodeProtectedHeader(exchanged)['kid']).toBe(newKid);
    expect(decodeProtectedHeader(await machineToken(after))['kid']).toBe(newKid);

    // Revocation verifies the token before it denylists it: introspection
    // then reports it inactive.
    const revoke = await after.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: FORM,
      payload: new URLSearchParams({
        token: machine,
        client_id: MACHINE_ID,
        client_secret: MACHINE_SECRET,
      }).toString(),
    });
    expect(revoke.statusCode, revoke.body).toBe(200);
    expect(await introspect(after, machine)).toEqual({ active: false });

    // /auth/logout takes the first-party token of the old key.
    const logout = await after.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: { authorization: `Bearer ${loginToken}` },
    });
    expect(logout.statusCode, logout.body).toBe(200);

    // The JWKS lists both keys, each under its own kid.
    expect(await jwksKids(after)).toEqual(expect.arrayContaining([oldKid, newKid]));
  }, 120_000);

  it('verifies both halves of a hybrid token signed before a rotation of the pair', async () => {
    await emptyDatabase();
    // A fresh hybrid deployment: the key boot step generates the pair.
    const before = await boot(noKeyVariables(HYBRID));
    await seedMachineClient(before);
    const token = await machineToken(before);
    const oldHeader = decodeProtectedHeader(token);
    expect(oldHeader).toMatchObject({
      kid: await activeKid(before, 'EdDSA'),
      pqc_kid: await activeKid(before, 'ML-DSA-65'),
    });

    const rotation = await rotateRealmKeys(before, E2E_REALM_NAME);
    expect(rotation.retired.map((key) => key.kid).sort()).toEqual(
      [oldHeader['kid'], oldHeader['pqc_kid']].sort()
    );
    await closeAll();

    const after = await boot(noKeyVariables(HYBRID));
    // Introspection hands out the detached ML-DSA-65 signature it stored.
    const introspection = await introspect(after, token);
    expect(introspection).toMatchObject({ active: true, pqc_alg: 'ML-DSA-65' });
    expect(typeof introspection['pqc_signature']).toBe('string');

    // Both signatures verify, the ML-DSA-65 one with the retired key its
    // signed pqc_kid names.
    await expect(
      after.jwtUtils.verifyHybridAccessToken(
        { id: await realmId(after), issuer: ISSUER },
        {
          token,
          pqcSignature: introspection['pqc_signature'] as string,
          pqcAlg: 'ML-DSA-65',
        },
        { requirePqc: true }
      )
    ).resolves.toMatchObject({ client_id: MACHINE_ID });

    // New tokens name the new pair, and the JWKS lists all four keys.
    const newHeader = decodeProtectedHeader(await machineToken(after));
    expect(newHeader).toMatchObject({
      kid: rotation.activated[0].kid,
      pqc_kid: rotation.activated[1].kid,
    });
    expect(await jwksKids(after)).toEqual(
      expect.arrayContaining([
        oldHeader['kid'],
        oldHeader['pqc_kid'],
        newHeader['kid'],
        newHeader['pqc_kid'],
      ])
    );
  }, 120_000);

  it('verifies a token with no kid, from before the upgrade, against the imported key, retired or not', async () => {
    if (!jwt) throw new Error('infrastructure not started');
    const app = await boot(variables());
    await resetE2eState(app);
    await seedMachineClient(app);

    const legacy = await kidlessToken(jwt.privateKey);
    expect(decodeProtectedHeader(legacy)).not.toHaveProperty('kid');
    expect(await introspect(app, legacy)).toMatchObject({ active: true, client_id: MACHINE_ID });
    // A key no variable imported verifies no token without a kid.
    expect(await introspect(app, await kidlessToken((await generateJwtPem()).privateKey))).toEqual({
      active: false,
    });

    // The imported key retires; its kid-less tokens keep verifying.
    await rotateRealmKeys(app, E2E_REALM_NAME);
    await closeAll();
    const after = await boot(variables());
    expect(await introspect(after, legacy)).toMatchObject({ active: true });
  }, 120_000);

  it('refuses a token of a retired key whose retention has ended', async () => {
    const before = await boot(variables());
    await resetE2eState(before);
    await seedMachineClient(before);
    const { accessToken } = await userTokens(before);
    const machine = await machineToken(before);
    const oldKid = await activeKid(before, 'EdDSA');

    // A retention of 0: the key leaves the verification set at the switch.
    await rotateRealmKeys(before, E2E_REALM_NAME, { retiredRetentionMs: 0 });
    await closeAll();

    const after = await boot(variables());
    expect(await introspect(after, machine)).toEqual({ active: false });
    const claims = await userinfo(after, accessToken);
    expect(claims.statusCode).toBe(401);
    expect(claims.json()).toMatchObject({ error: 'invalid_token' });
    expect(await jwksKids(after)).not.toContain(oldKid);
  }, 120_000);

  it.each(['next', 'compromised'] as const)(
    'refuses a token whose kid names a %s key',
    async (status) => {
      const before = await boot(variables());
      await resetE2eState(before);
      await seedMachineClient(before);
      const { accessToken } = await userTokens(before);
      const machine = await machineToken(before);
      const kid = await activeKid(before, 'EdDSA');

      // The key that signed the tokens moves to `status` in the table. No
      // signer signs with a `next` key, so a token naming one exists only this
      // way; the signature is that key's, so only its status can refuse it.
      await before.dbPool.query(
        status === 'next'
          ? `UPDATE realm_keys SET status = 'next', activate_at = NULL
              WHERE realm_id = $1 AND kid = $2`
          : `UPDATE realm_keys SET status = 'compromised', compromised_at = $3
              WHERE realm_id = $1 AND kid = $2`,
        status === 'next' ? [await realmId(before), kid] : [await realmId(before), kid, Date.now()]
      );
      await closeAll();

      // No key variable: the boot step refuses one that holds a compromised key.
      const after = await boot(noKeyVariables());
      expect(await introspect(after, machine)).toEqual({ active: false });
      const claims = await userinfo(after, accessToken);
      expect(claims.statusCode).toBe(401);
      expect(claims.json()).toMatchObject({ error: 'invalid_token' });
      // A next key is published before it signs; a compromised one never is.
      if (status === 'next') expect(await jwksKids(after)).toContain(kid);
      else expect(await jwksKids(after)).not.toContain(kid);
    },
    120_000
  );
});
