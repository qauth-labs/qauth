import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * TOKEN LIFETIMES COME FROM THE REALM ROW (ADR-019 Decision 10, ADR-008 §5,
 * issue #527), end to end against real Postgres and Redis.
 *
 * The access, development access and refresh token lifetimes are policies of
 * the realm: two realms of one deployment issue tokens with different `exp`
 * and `expires_in`, a development client gets its realm's development
 * lifetime, a refresh token its realm's refresh lifetime, an ID token its
 * realm's access lifetime, and a change of a realm's policies reaches its next
 * token without a restart. `ACCESS_TOKEN_LIFESPAN` and its siblings only seed
 * a new realm: a node that boots with another value issues the stored one.
 *
 * A policy change goes through the policy store, as the admin API's will, and
 * the test then drops the realm resolver's host cache, which stands in for its
 * cache time (30 s): the next request reads the row again.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** The environment's seeds: what the default realm, and every realm created after it, starts with. */
const SEEDED = Object.freeze({ access: 600, development: 7_200, refresh: 86_400 });

/** Keys this suite sets; the harness clears only its own prefixes between boots. */
const SUITE_KEYS = [
  'ACCESS_TOKEN_LIFESPAN',
  'DEV_ACCESS_TOKEN_LIFESPAN',
  'REFRESH_TOKEN_LIFESPAN',
  'TOKEN_RATE_LIMIT',
  'TOKEN_RATE_LIMIT_LENIENT',
] as const;

const HOST_B = 'beta.example.com';
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const MACHINE_ID = 'lifetime-machine';
const MACHINE_SECRET = 'secret-of-the-lifetime-machine-0123456789';
const NATIVE_ID = 'lifetime-native-app';
const REDIRECT_URI = 'https://client.example.com/callback';
const SCOPES = ['openid', 'email'];

interface IssuedToken {
  readonly expiresIn: number;
  readonly claims: Record<string, unknown>;
}

describe('token lifetimes read from the realm row (#527, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  /** The suite's deployment: the environment seeds {@link SEEDED}. */
  function environment(overrides: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      ACCESS_TOKEN_LIFESPAN: String(SEEDED.access),
      DEV_ACCESS_TOKEN_LIFESPAN: String(SEEDED.development),
      REFRESH_TOKEN_LIFESPAN: String(SEEDED.refresh),
      // Sized for humans; a test sends a burst from one address.
      TOKEN_RATE_LIMIT: '10000',
      TOKEN_RATE_LIMIT_LENIENT: '10000',
      ...overrides,
    };
  }

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer(environment());
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined) {
      ctx.skip();
      return;
    }
    // The boot step puts the default realm back, seeded from the environment.
    await resetE2eState(booted.app);
  });

  function server(): FastifyInstance {
    if (booted === undefined) throw new Error('server not booted');
    return booted.app;
  }

  async function realmIdOf(app: FastifyInstance, name: string): Promise<string> {
    const realm = await app.repositories.realms.findByName(name);
    if (!realm) throw new Error(`no realm ${name}`);
    return realm.id;
  }

  /**
   * Change a realm's policies through the policy store, at the counter it has
   * now, and drop the resolver's host cache so the next request reads the row.
   */
  async function updatePolicies(
    app: FastifyInstance,
    realmId: string,
    patch: Record<string, unknown>
  ): Promise<void> {
    const current = await app.policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    expect(current.hasPolicies).toBe(true);
    await app.policyStore.update(realmId, patch, { expectedVersion: current.version });
    app.realmHostCache.clear();
  }

  /** A second realm on its own host, with its own keys (#491), seeded as the default realm was. */
  async function createBetaRealm(app: FastifyInstance): Promise<string> {
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    await provisionRealmKeys(app, 'beta');
    return realm.id;
  }

  /** A confidential client_credentials client in a realm. */
  async function createMachine(
    app: FastifyInstance,
    realmId: string,
    environmentProfile: 'development' | 'production' = 'production',
    clientId = MACHINE_ID
  ): Promise<void> {
    await app.repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: await app.passwordHasher.hashPassword(MACHINE_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: `E2E ${clientId}`,
      redirectUris: [],
      scopes: ['read'],
      grantTypes: ['client_credentials'],
      environment: environmentProfile,
      enabled: true,
      requirePkce: false,
    });
  }

  function tokenRequest(
    app: FastifyInstance,
    form: Record<string, string>,
    host?: string
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: host === undefined ? FORM : { ...FORM, host },
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** A client_credentials token of `clientId` at `host` (the default realm's when unset). */
  async function machineToken(
    app: FastifyInstance,
    host?: string,
    clientId = MACHINE_ID
  ): Promise<IssuedToken> {
    const response = await tokenRequest(
      app,
      {
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: MACHINE_SECRET,
        scope: 'read',
      },
      host
    );
    expect(response.statusCode, response.body).toBe(200);
    const body = response.json<{ access_token: string; expires_in: number }>();
    return { expiresIn: body.expires_in, claims: decodeJwtClaims(body.access_token) };
  }

  /** How long a signed token lives: its `exp` less its `iat`, in seconds. */
  function signedLifetime(claims: Record<string, unknown>): number {
    return (claims['exp'] as number) - (claims['iat'] as number);
  }

  /**
   * A user of the default realm who consented to the native app, and a
   * browser session of theirs: the code flow issues an access token, an ID
   * token and a refresh token.
   */
  async function nativeAppUser(app: FastifyInstance): Promise<{ userId: string; cookie: string }> {
    const email = 'lifetime-owner@example.test';
    const userId = await registerPasswordAccount(app, email);
    const realmId = await realmIdOf(app, E2E_REALM_NAME);
    const client = await app.repositories.oauthClients.create({
      realmId,
      clientId: NATIVE_ID,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Lifetime native app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realmId, userId, client.id, SCOPES);
    const jar = await signInWithPassword(app, email);
    return { userId, cookie: jar.header() as string };
  }

  /** Authorize with the session's cookie and exchange the code. */
  async function codeExchange(
    app: FastifyInstance,
    cookie: string
  ): Promise<{ accessToken: string; idToken: string; refreshToken: string; expiresIn: number }> {
    const pkce = pkcePair();
    const authorize = await app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: NATIVE_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'lifetime-state',
      }).toString()}`,
      headers: { cookie },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    const code = new URL(String(authorize.headers['location'])).searchParams.get('code');
    if (code === null)
      throw new Error(`authorize returned no code: ${authorize.headers['location']}`);

    const exchange = await tokenRequest(app, {
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: NATIVE_ID,
      code_verifier: pkce.verifier,
    });
    expect(exchange.statusCode, exchange.body).toBe(200);
    const body = exchange.json<{
      access_token: string;
      id_token?: string;
      refresh_token?: string;
      expires_in: number;
    }>();
    if (body.id_token === undefined) throw new Error('the exchange issued no ID token');
    if (body.refresh_token === undefined) throw new Error('the exchange issued no refresh token');
    return {
      accessToken: body.access_token,
      idToken: body.id_token,
      refreshToken: body.refresh_token,
      expiresIn: body.expires_in,
    };
  }

  /**
   * The user's refresh token of one kind, with its times in epoch ms: the
   * native app's first (the code exchange's) or rotated one, or the one the
   * legacy `/auth/login` gave the system client.
   */
  async function refreshRow(
    app: FastifyInstance,
    userId: string,
    kind: 'exchanged' | 'rotated' | 'signed-in'
  ): Promise<{ familyCreatedAt: number; expiresAt: number }> {
    const { rows } = await app.dbPool.query<{
      client_id: string;
      previous_token_hash: string | null;
      family_created_at: string;
      expires_at: string;
    }>(
      `SELECT c.client_id, r.previous_token_hash, r.family_created_at, r.expires_at
       FROM refresh_tokens r JOIN oauth_clients c ON c.id = r.oauth_client_id
       WHERE r.user_id = $1`,
      [userId]
    );
    const matching = rows.filter((row) =>
      kind === 'signed-in'
        ? row.client_id !== NATIVE_ID
        : row.client_id === NATIVE_ID && (row.previous_token_hash !== null) === (kind === 'rotated')
    );
    expect(matching, kind).toHaveLength(1);
    return {
      familyCreatedAt: Number(matching[0].family_created_at),
      expiresAt: Number(matching[0].expires_at),
    };
  }

  it('starts every realm with the lifetimes the environment seeds', async () => {
    const app = server();
    const betaId = await createBetaRealm(app);

    for (const realmId of [await realmIdOf(app, E2E_REALM_NAME), betaId]) {
      expect((await app.policyStore.get(realmId))?.policies.tokens).toMatchObject({
        accessTokenLifespanSeconds: SEEDED.access,
        developmentAccessTokenLifespanSeconds: SEEDED.development,
        refreshTokenLifespanSeconds: SEEDED.refresh,
      });
    }
  });

  it('issues tokens with different exp and expires_in in two realms with different access lifetimes', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);
    await updatePolicies(app, betaId, { tokens: { accessTokenLifespanSeconds: 300 } });
    await createMachine(app, defaultId);
    await createMachine(app, betaId);

    const inDefault = await machineToken(app);
    const inBeta = await machineToken(app, HOST_B);

    expect(inDefault.expiresIn).toBe(SEEDED.access);
    expect(signedLifetime(inDefault.claims)).toBe(SEEDED.access);
    expect(inBeta.expiresIn).toBe(300);
    expect(signedLifetime(inBeta.claims)).toBe(300);
    // Each from its own realm.
    expect(inDefault.claims['iss']).toBe('https://auth.example.com');
    expect(inBeta.claims['iss']).toBe(`https://${HOST_B}`);
  });

  it("gives a development client its realm's development lifetime, and a production client its realm's access lifetime", async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    const betaId = await createBetaRealm(app);
    // Both realms let a client be a development one (ADR-008); beta's
    // development lifetime differs from the seed.
    await updatePolicies(app, defaultId, { posture: { maxEnvironmentLaxity: 'development' } });
    await updatePolicies(app, betaId, {
      posture: { maxEnvironmentLaxity: 'development' },
      tokens: { developmentAccessTokenLifespanSeconds: 1_800 },
    });
    await createMachine(app, defaultId, 'development');
    await createMachine(app, betaId, 'development');
    await createMachine(app, betaId, 'production', 'lifetime-production-machine');

    const developmentInDefault = await machineToken(app);
    const developmentInBeta = await machineToken(app, HOST_B);
    const productionInBeta = await machineToken(app, HOST_B, 'lifetime-production-machine');

    expect(developmentInDefault.expiresIn).toBe(SEEDED.development);
    expect(signedLifetime(developmentInDefault.claims)).toBe(SEEDED.development);
    expect(developmentInBeta.expiresIn).toBe(1_800);
    expect(signedLifetime(developmentInBeta.claims)).toBe(1_800);
    // The `short` tier is the access lifetime, as before.
    expect(productionInBeta.expiresIn).toBe(SEEDED.access);
    expect(signedLifetime(productionInBeta.claims)).toBe(SEEDED.access);
  });

  it("gives a refresh token the realm's refresh lifetime: at the code exchange, at each rotation, and at /auth/login", async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await updatePolicies(app, defaultId, { tokens: { refreshTokenLifespanSeconds: 3_600 } });
    const { userId, cookie } = await nativeAppUser(app);

    // The code exchange starts a family whose first token lives an hour.
    const exchanged = await codeExchange(app, cookie);
    const first = await refreshRow(app, userId, 'exchanged');
    expect(first.expiresAt - first.familyCreatedAt).toBe(3_600_000);

    // A rotation gives the new token an hour from the refresh.
    const before = Date.now();
    const refreshed = await tokenRequest(app, {
      grant_type: 'refresh_token',
      refresh_token: exchanged.refreshToken,
      client_id: NATIVE_ID,
    });
    const after = Date.now();
    expect(refreshed.statusCode, refreshed.body).toBe(200);
    const rotated = await refreshRow(app, userId, 'rotated');
    expect(rotated.expiresAt).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(rotated.expiresAt).toBeLessThanOrEqual(after + 3_600_000);
    // `expires_in` and `exp` of the rotation's access token stay the realm's.
    const rotatedAccess = refreshed.json<{ access_token: string; expires_in: number }>();
    expect(rotatedAccess.expires_in).toBe(SEEDED.access);
    expect(signedLifetime(decodeJwtClaims(rotatedAccess.access_token))).toBe(SEEDED.access);

    // The legacy sign-in starts a family of its own, under the same lifetimes.
    const login = await app.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: 'lifetime-owner@example.test', password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    const loginBody = login.json<{ access_token: string; expires_in: number }>();
    expect(loginBody.expires_in).toBe(SEEDED.access);
    expect(signedLifetime(decodeJwtClaims(loginBody.access_token))).toBe(SEEDED.access);
    const signedIn = await refreshRow(app, userId, 'signed-in');
    expect(signedIn.expiresAt - signedIn.familyCreatedAt).toBe(3_600_000);
  });

  it("signs an ID token with the realm's access lifetime", async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await updatePolicies(app, defaultId, { tokens: { accessTokenLifespanSeconds: 420 } });
    const { cookie } = await nativeAppUser(app);

    const exchanged = await codeExchange(app, cookie);

    expect(signedLifetime(decodeJwtClaims(exchanged.idToken))).toBe(420);
    // The access token of the same response, and its `expires_in`, agree.
    expect(exchanged.expiresIn).toBe(420);
    expect(signedLifetime(decodeJwtClaims(exchanged.accessToken))).toBe(420);
  });

  it('keeps issuing the stored lifetime when a node boots with another ACCESS_TOKEN_LIFESPAN, which seeds only a new realm', async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await createMachine(app, defaultId);

    // Another node of the deployment, booted with a longer lifetime, on the
    // same database, whose default realm already has its policies.
    const other = await bootAuthServer(environment({ ACCESS_TOKEN_LIFESPAN: '1200' }));
    try {
      const token = await machineToken(other.app);
      expect(token.expiresIn).toBe(SEEDED.access);
      expect(signedLifetime(token.claims)).toBe(SEEDED.access);
      expect((await other.app.policyStore.get(defaultId))?.policies.tokens).toMatchObject({
        accessTokenLifespanSeconds: SEEDED.access,
      });

      // A realm that node creates gets its environment's value.
      const { realm: gamma } = await other.app.repositories.realms.createWithPrimaryHost(
        { name: 'gamma', issuer: 'https://gamma.example.com', enabled: true },
        'gamma.example.com'
      );
      expect((await other.app.policyStore.get(gamma.id))?.policies.tokens).toMatchObject({
        accessTokenLifespanSeconds: 1_200,
      });
    } finally {
      await other.close();
      process.env['ACCESS_TOKEN_LIFESPAN'] = String(SEEDED.access);
    }

    // The first node, unchanged, issues the stored lifetime too.
    const token = await machineToken(app);
    expect(token.expiresIn).toBe(SEEDED.access);
    expect(signedLifetime(token.claims)).toBe(SEEDED.access);
  });

  it("issues the next token with a realm's changed lifetime, without a restart", async () => {
    const app = server();
    const defaultId = await realmIdOf(app, E2E_REALM_NAME);
    await createMachine(app, defaultId);
    const before = await machineToken(app);
    expect(before.expiresIn).toBe(SEEDED.access);

    await updatePolicies(app, defaultId, { tokens: { accessTokenLifespanSeconds: 240 } });

    const after = await machineToken(app);
    expect(after.expiresIn).toBe(240);
    expect(signedLifetime(after.claims)).toBe(240);
  });
});
