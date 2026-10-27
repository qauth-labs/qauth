import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  provisionRealmKeys,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * TOKENS ARE SIGNED AND VERIFIED PER REALM, THROUGH THE SIGNER (ADR-019
 * Decisions 1 and 9, issue #491), against a real Postgres and Redis.
 *
 * The JWT plugin holds no key. Every access, ID and hybrid token is signed by
 * the signer with the keys of its realm, which names the realm's issuer as
 * `iss` and its key as `kid`, and every token verifies only with the keys of
 * the realm that minted it. The key variables reach only the key boot step,
 * so once the store holds the keys the server boots without them.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const ISSUER_A = `https://${HOST_A}`;
const ISSUER_B = `https://${HOST_B}`;
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const CLIENT_ID = 'signing-machine';
const CLIENT_SECRET = 'signing-machine-secret-of-sufficient-length';

/** The `token_signing` keys of a realm, as its key store holds them. */
interface StoredTokenKey {
  readonly kid: string;
  readonly algorithm: string;
  readonly status: string;
}

describe('tokens are signed and verified per realm (#491)', () => {
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
    vi.restoreAllMocks();
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /** The variables of a deployment from before the key store, plus `extra`. */
  function variables(extra: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return { ...baseEnvironment(infra, jwt), ...extra };
  }

  /** What a deployment sets with no key variable at all. */
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

  /** Empty the database through a throwaway server, so the next boot is a first one. */
  async function emptyDatabase(): Promise<void> {
    const server = await bootAuthServer(variables());
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.close();
  }

  async function realmId(app: FastifyInstance, name: string): Promise<string> {
    const realm = await app.repositories.realms.findByName(name);
    if (!realm) throw new Error(`no realm ${name}`);
    return realm.id;
  }

  async function storedTokenKeys(app: FastifyInstance, id: string): Promise<StoredTokenKey[]> {
    const { rows } = await app.dbPool.query<StoredTokenKey>(
      `SELECT kid, algorithm, status FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'token_signing' ORDER BY algorithm, kid`,
      [id]
    );
    return rows;
  }

  async function activeKid(app: FastifyInstance, id: string, algorithm: string): Promise<string> {
    const key = (await storedTokenKeys(app, id)).find(
      (row) => row.algorithm === algorithm && row.status === 'active'
    );
    if (!key) throw new Error(`no active ${algorithm} key`);
    return key.kid;
  }

  /** The default realm and `beta` on HOST_B, each with its keys and a machine client. */
  async function twoRealms(app: FastifyInstance): Promise<{ a: string; b: string }> {
    await resetE2eState(app);
    const a = await realmId(app, E2E_REALM_NAME);
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: ISSUER_B, enabled: true },
      HOST_B
    );
    await provisionRealmKeys(app, 'beta');
    for (const id of [a, realm.id]) {
      await app.repositories.oauthClients.create({
        realmId: id,
        clientId: CLIENT_ID,
        clientSecretHash: await app.passwordHasher.hashPassword(CLIENT_SECRET),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'Signing test machine',
        redirectUris: [],
        scopes: ['reports:read'],
        grantTypes: ['client_credentials'],
        enabled: true,
      });
    }
    return { a, b: realm.id };
  }

  function machineToken(app: FastifyInstance, host: string): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope: 'reports:read',
      }).toString(),
    });
  }

  async function accessToken(app: FastifyInstance, host: string): Promise<string> {
    const response = await machineToken(app, host);
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ access_token: string }>().access_token;
  }

  async function jwksAt(app: FastifyInstance, host: string): Promise<JSONWebKeySet> {
    const response = await app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
      headers: { host },
    });
    expect(response.statusCode).toBe(200);
    return response.json<JSONWebKeySet>();
  }

  async function introspect(
    app: FastifyInstance,
    host: string,
    token: string
  ): Promise<{ active: boolean }> {
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: { ...FORM, host },
      payload: new URLSearchParams({
        token,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }).toString(),
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ active: boolean }>();
  }

  it("signs a realm's tokens with its issuer and kid; they verify with its JWKS and not another's", async () => {
    const app = await boot(variables());
    const { a, b } = await twoRealms(app);

    const tokenA = await accessToken(app, HOST_A);
    const tokenB = await accessToken(app, HOST_B);
    expect(decodeJwtClaims(tokenA)['iss']).toBe(ISSUER_A);
    expect(decodeJwtClaims(tokenB)['iss']).toBe(ISSUER_B);
    expect(decodeProtectedHeader(tokenA)).toMatchObject({
      alg: 'EdDSA',
      typ: 'at+jwt',
      kid: await activeKid(app, a, 'EdDSA'),
    });
    expect(decodeProtectedHeader(tokenB)).toMatchObject({
      alg: 'EdDSA',
      typ: 'at+jwt',
      kid: await activeKid(app, b, 'EdDSA'),
    });

    const jwksA = createLocalJWKSet(await jwksAt(app, HOST_A));
    const jwksB = createLocalJWKSet(await jwksAt(app, HOST_B));
    await expect(jwtVerify(tokenA, jwksA, { issuer: ISSUER_A })).resolves.toBeDefined();
    await expect(jwtVerify(tokenB, jwksB, { issuer: ISSUER_B })).resolves.toBeDefined();
    await expect(jwtVerify(tokenA, jwksB)).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });
    await expect(jwtVerify(tokenB, jwksA)).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });

    // The server's own verification is per realm too: each realm's
    // introspection knows its own token, and not the other realm's, though the
    // same client_id asks in both.
    expect(await introspect(app, HOST_A, tokenA)).toMatchObject({ active: true });
    expect(await introspect(app, HOST_B, tokenB)).toMatchObject({ active: true });
    expect(await introspect(app, HOST_B, tokenA)).toEqual({ active: false });
    expect(await introspect(app, HOST_A, tokenB)).toEqual({ active: false });
  });

  it('stamps kid on access tokens and on EdDSA and RS256 ID tokens', async () => {
    const app = await boot(variables());
    const { a, b } = await twoRealms(app);

    // The default realm imported JWT_PRIVATE_KEY and no RS256 key: EdDSA ID
    // tokens. `beta` is fresh, so it got an RS256 key too: RS256 ID tokens.
    const idTokenA = await app.jwtUtils.signIdToken({ id: a }, { sub: 'user-a', audience: 'rp' });
    const idTokenB = await app.jwtUtils.signIdToken({ id: b }, { sub: 'user-b', audience: 'rp' });
    expect(decodeProtectedHeader(idTokenA)).toEqual({
      alg: 'EdDSA',
      kid: await activeKid(app, a, 'EdDSA'),
      typ: 'JWT',
    });
    expect(decodeProtectedHeader(idTokenB)).toEqual({
      alg: 'RS256',
      kid: await activeKid(app, b, 'RS256'),
      typ: 'JWT',
    });
    await expect(
      jwtVerify(idTokenB, createLocalJWKSet(await jwksAt(app, HOST_B)), {
        issuer: ISSUER_B,
        audience: 'rp',
      })
    ).resolves.toBeDefined();

    // Discovery advertises what each realm can sign ID tokens with.
    const algorithms = async (host: string) =>
      (
        await app.inject({
          method: 'GET',
          url: '/.well-known/openid-configuration',
          headers: { host },
        })
      ).json<{ id_token_signing_alg_values_supported: string[] }>()
        .id_token_signing_alg_values_supported;
    expect(await algorithms(HOST_A)).toEqual(['EdDSA']);
    expect(await algorithms(HOST_B)).toEqual(['RS256', 'EdDSA']);
  });

  it('runs no database query to sign once the key cache is warm', async () => {
    const app = await boot(variables());
    const { b } = await twoRealms(app);
    const realm = { id: b };
    // The first signatures read the keys and unwrap them.
    await app.jwtUtils.signAccessToken(realm, { sub: 'warm-up', clientId: CLIENT_ID });
    await app.jwtUtils.signIdToken(realm, { sub: 'warm-up', audience: CLIENT_ID });

    // Every key the signer reads comes from `realms`, `realm_keys` or
    // `realm_public_keys`. Other queries (the job runner's, the delivery
    // role's) may run meanwhile and are not the signer's.
    const query = vi.spyOn(app.dbPool, 'query');
    const keyReads = () =>
      query.mock.calls.filter(([config]) =>
        /realm_keys|realm_public_keys|"realms"/.test(
          typeof config === 'string' ? config : ((config as { text?: string }).text ?? '')
        )
      );
    const token = await app.jwtUtils.signAccessToken(realm, { sub: 'user-1', clientId: CLIENT_ID });
    await app.jwtUtils.signIdToken(realm, { sub: 'user-1', audience: CLIENT_ID });
    await app.jwtUtils.verifyAccessToken({ id: b, issuer: ISSUER_B }, token);
    expect(keyReads()).toEqual([]);

    // The control: a realm the signer has not read yet costs key reads, so
    // the filter above sees them.
    const a = await realmId(app, E2E_REALM_NAME);
    await app.jwtUtils.signAccessToken({ id: a }, { sub: 'user-1', clientId: CLIENT_ID });
    expect(keyReads().length).toBeGreaterThan(0);
  });

  it('boots with no key variable once the store has the keys, and signs with the stored key', async () => {
    await emptyDatabase();
    // The upgrade boot imports JWT_PRIVATE_KEY.
    const first = await boot(variables());
    const a = await realmId(first, E2E_REALM_NAME);
    const importedKid = await activeKid(first, a, 'EdDSA');
    await first.repositories.oauthClients.create({
      realmId: a,
      clientId: CLIENT_ID,
      clientSecretHash: await first.passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Signing test machine',
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
    const before = await accessToken(first, HOST_A);
    await booted.splice(0)[0].close();

    // The next boot sets no key variable at all.
    const environment = noKeyVariables();
    expect(Object.keys(environment).filter((name) => name.startsWith('JWT_'))).toEqual([
      'JWT_ISSUER',
    ]);
    const second = await boot(environment);
    const after = await accessToken(second, HOST_A);
    expect(decodeProtectedHeader(after)['kid']).toBe(importedKid);
    expect(await activeKid(second, a, 'EdDSA')).toBe(importedKid);
    // A token of the earlier boot still verifies.
    await expect(
      second.jwtUtils.verifyAccessToken({ id: a, issuer: ISSUER_A }, before)
    ).resolves.toMatchObject({ clientId: CLIENT_ID });
  });

  it('boots with JWT_PRIVATE_KEY and no JWT_PUBLIC_KEY (#359)', async () => {
    await emptyDatabase();
    const environment = variables();
    delete environment['JWT_PUBLIC_KEY'];
    const app = await boot(environment);
    const a = await realmId(app, E2E_REALM_NAME);
    const token = await app.jwtUtils.signAccessToken({ id: a }, { sub: 'user-1', clientId: 'c' });
    await expect(
      app.jwtUtils.verifyAccessToken({ id: a, issuer: ISSUER_A }, token)
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('boots a fresh deployment with no key variable at all, on generated keys', async () => {
    await emptyDatabase();
    const app = await boot(noKeyVariables());
    const a = await realmId(app, E2E_REALM_NAME);
    expect((await storedTokenKeys(app, a)).map((key) => key.algorithm)).toEqual(['EdDSA', 'RS256']);
    const token = await app.jwtUtils.signAccessToken({ id: a }, { sub: 'user-1', clientId: 'c' });
    await expect(
      jwtVerify(token, createLocalJWKSet(await jwksAt(app, HOST_A)), { issuer: ISSUER_A })
    ).resolves.toBeDefined();
  });

  describe('hybrid signing', () => {
    const HYBRID = {
      HYBRID_SIGNING_ENABLED: 'true',
      SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65',
    };

    it('signs hybrid tokens with the kid and pqc_kid of the realm pair', async () => {
      await emptyDatabase();
      // A fresh hybrid deployment: the key boot step generates the pair.
      const app = await boot(noKeyVariables(HYBRID));
      const a = await realmId(app, E2E_REALM_NAME);
      expect(app.jwtUtils.isHybridSigningEnabled()).toBe(true);

      const hybrid = await app.jwtUtils.signHybridAccessToken(
        { id: a },
        { sub: 'user-1', clientId: CLIENT_ID }
      );
      expect(decodeProtectedHeader(hybrid.token)).toEqual({
        alg: 'EdDSA',
        kid: await activeKid(app, a, 'EdDSA'),
        typ: 'at+jwt',
        pqc_alg: 'ML-DSA-65',
        pqc_kid: await activeKid(app, a, 'ML-DSA-65'),
      });
      await expect(
        app.jwtUtils.verifyHybridAccessToken({ id: a, issuer: ISSUER_A }, hybrid, {
          requirePqc: true,
        })
      ).resolves.toMatchObject({ sub: 'user-1' });
    });

    it('refuses to boot with hybrid signing on and no ML-DSA-65 key for the realm', async () => {
      await emptyDatabase();
      // JWT_PRIVATE_KEY is imported as an EdDSA key without its ML-DSA-65 half.
      await expect(bootAuthServer(variables(HYBRID))).rejects.toThrow(
        /HYBRID_SIGNING_ENABLED=true needs the realm's token keys as a hybrid pair/
      );
    });
  });
});
