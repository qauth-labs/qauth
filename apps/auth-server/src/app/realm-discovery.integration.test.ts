import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet, jwtVerify } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  prepublishRealmKeys,
  provisionRealmKeys,
  resetE2eState,
  rotateRealmKeys,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * DISCOVERY AND THE JWKS ARE SERVED PER REALM (ADR-019 Decisions 1, 8 and 9,
 * issue #494), against a real Postgres and Redis.
 *
 * `/.well-known/oauth-authorization-server`, `/.well-known/openid-configuration`
 * and `/.well-known/jwks.json` are the documents of the realm the request's
 * host names: its issuer from its row, every endpoint URL on that issuer, the
 * ID-token algorithms of its active keys, and a JWKS of its published keys
 * (`realm_public_keys`). They are built from the database alone, so every
 * node of a deployment answers the same bytes for the same realm, whether it
 * holds the signer or reads the published keys without one (#495). An
 * endpoint host gets its realm's documents unchanged, and a host that names
 * no realm gets 421. The deployment switches stay global; CIMD is the
 * realm's own policy (#534).
 *
 * Each test boots the real auth-server, whose boot step creates the default
 * realm on `auth.example.com` (from `JWT_ISSUER`) by importing
 * `JWT_PRIVATE_KEY`, and adds a second realm, `beta`, on `beta.example.com`,
 * with keys of its own: a fresh realm also gets an RS256 key. A second node
 * boots on the same containers, as a node of the same deployment does.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const ISSUER_A = `https://${HOST_A}`;
const ISSUER_B = `https://${HOST_B}`;
/** An endpoint host of the default realm (DEFAULT_REALM_ENDPOINT_HOSTS). */
const ENDPOINT_HOST = 'auth-internal.example.com';
const AS_METADATA = '/.well-known/oauth-authorization-server';
const OIDC_CONFIGURATION = '/.well-known/openid-configuration';
const JWKS = '/.well-known/jwks.json';
const DISCOVERY_DOCUMENTS = [AS_METADATA, OIDC_CONFIGURATION] as const;
const DOCUMENTS = [...DISCOVERY_DOCUMENTS, JWKS] as const;
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const CLIENT_ID = 'discovery-machine';
const CLIENT_SECRET = 'discovery-machine-secret-of-sufficient-length';
const JWT_BEARER_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

/** The signer service settings of a process without the signer; never dialled here. */
const SIGNER_SERVICE: Record<string, string> = {
  SIGNER_URL: 'https://signer.internal:3443',
  INTERNAL_TLS_CERT_PATH: '/run/secrets/internal.crt',
  INTERNAL_TLS_KEY_PATH: '/run/secrets/internal.key',
  INTERNAL_TLS_CA_PATH: '/run/secrets/internal-ca.crt',
};

/** Settings a test here sets that `bootAuthServer` does not clear between boots. */
const UNCLEARED_SETTINGS = ['CIMD_ENABLED', 'ID_JAG_ENABLED', 'ID_JAG_TRUSTED_ISSUERS'] as const;

/** A JSON document as the server sent it. */
type Document = Record<string, unknown>;

/** The `max-age` of a response's `Cache-Control`, which must be public. */
function maxAge(response: LightMyRequestResponse): number {
  const header = String(response.headers['cache-control']);
  expect(header).toMatch(/^public,/);
  const match = /(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/.exec(header);
  if (match?.[1] === undefined) throw new Error(`no max-age in Cache-Control: ${header}`);
  return Number(match[1]);
}

describe('discovery and the JWKS are served per realm (#494)', () => {
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
    for (const key of UNCLEARED_SETTINGS) delete process.env[key];
  });

  /** The deployment's settings, plus `extra`. */
  function variables(extra: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return { ...baseEnvironment(infra, jwt), ...extra };
  }

  /**
   * The settings of a node of the same deployment without the signer role
   * (#495): no KEK and no private key, but the signer service's address. It
   * serves the JWKS from the published keys.
   */
  function withoutSigner(environment: Record<string, string>): Record<string, string> {
    const rest = { ...environment };
    delete rest['KEK'];
    delete rest['JWT_PRIVATE_KEY'];
    return { ...rest, ...SIGNER_SERVICE, SERVICE_ROLES: 'api' };
  }

  async function boot(environment: Record<string, string>): Promise<FastifyInstance> {
    const server = await bootAuthServer(environment);
    booted.push(server);
    return server.app;
  }

  async function realmIdOf(app: FastifyInstance, name: string): Promise<string> {
    const realm = await app.repositories.realms.findByName(name);
    if (!realm) throw new Error(`no realm ${name}`);
    return realm.id;
  }

  /**
   * The first node of the deployment, on an empty state: the default realm on
   * HOST_A, `beta` on HOST_B with its own keys, and a machine client in each.
   */
  async function firstNode(environment: Record<string, string>): Promise<FastifyInstance> {
    const app = await boot(environment);
    await resetE2eState(app);
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: ISSUER_B, enabled: true },
      HOST_B
    );
    await provisionRealmKeys(app, 'beta');
    for (const realmId of [await realmIdOf(app, E2E_REALM_NAME), realm.id]) {
      await app.repositories.oauthClients.create({
        realmId,
        clientId: CLIENT_ID,
        clientSecretHash: await app.passwordHasher.hashPassword(CLIENT_SECRET),
        tokenEndpointAuthMethod: 'client_secret_post',
        name: 'Discovery test machine',
        redirectUris: [],
        scopes: ['reports:read'],
        grantTypes: ['client_credentials'],
        enabled: true,
      });
    }
    return app;
  }

  function get(app: FastifyInstance, path: string, host: string): Promise<LightMyRequestResponse> {
    return app.inject({ method: 'GET', url: path, headers: { host } });
  }

  async function documentAt(app: FastifyInstance, path: string, host: string): Promise<Document> {
    const response = await get(app, path, host);
    expect(response.statusCode, response.body).toBe(200);
    return response.json<Document>();
  }

  async function jwksAt(app: FastifyInstance, host: string): Promise<JSONWebKeySet> {
    const response = await get(app, JWKS, host);
    expect(response.statusCode, response.body).toBe(200);
    return response.json<JSONWebKeySet>();
  }

  function kidsOf(jwks: JSONWebKeySet): string[] {
    return jwks.keys.map((key) => String(key.kid));
  }

  async function accessToken(app: FastifyInstance, host: string): Promise<string> {
    const response = await app.inject({
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
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ access_token: string }>().access_token;
  }

  /** The `kid` of the realm's active `token_signing` key of `algorithm`. */
  async function activeKid(app: FastifyInstance, algorithm: string): Promise<string> {
    const { rows } = await app.dbPool.query<{ kid: string }>(
      `SELECT kid FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'token_signing' AND status = 'active' AND algorithm = $2`,
      [await realmIdOf(app, E2E_REALM_NAME), algorithm]
    );
    const [row] = rows;
    if (rows.length !== 1 || row === undefined) {
      throw new Error(`no single active ${algorithm} key`);
    }
    return row.kid;
  }

  it("gives each realm its own issuer, jwks_uri and kid; each realm's JWKS verifies only its own tokens", async () => {
    const app = await firstNode(variables());

    const realms: { issuer: string; jwks: JSONWebKeySet; algorithms: unknown }[] = [];
    for (const [host, issuer] of [
      [HOST_A, ISSUER_A],
      [HOST_B, ISSUER_B],
    ] as const) {
      const metadata = await documentAt(app, AS_METADATA, host);
      const configuration = await documentAt(app, OIDC_CONFIGURATION, host);
      const jwksUri = `${issuer}/.well-known/jwks.json`;
      for (const document of [metadata, configuration]) {
        expect(document['issuer']).toBe(issuer);
        expect(document['jwks_uri']).toBe(jwksUri);
      }
      // A relying party follows jwks_uri, to the realm's own host.
      const { host: jwksHost, pathname } = new URL(jwksUri);
      expect(pathname).toBe(JWKS);
      const jwks = await jwksAt(app, jwksHost);
      expect(jwks.keys.length).toBeGreaterThan(0);
      // Every ID-token algorithm the realm advertises has a key in its JWKS.
      const algorithms = configuration['id_token_signing_alg_values_supported'];
      for (const alg of algorithms as string[]) {
        expect(jwks.keys.some((key) => key.alg === alg)).toBe(true);
      }
      realms.push({ issuer, jwks, algorithms });
    }
    const [a, b] = realms;
    if (!a || !b) throw new Error('two realms expected');

    // No key is shared: each realm publishes its own.
    expect(kidsOf(a.jwks).filter((kid) => kidsOf(b.jwks).includes(kid))).toEqual([]);
    // The ID-token algorithms are the realm's, not the process's: the default
    // realm imported only an Ed25519 key, while `beta` also has an RS256 key.
    expect(a.algorithms).toEqual(['EdDSA']);
    expect(b.algorithms).toEqual(['RS256', 'EdDSA']);

    const tokenA = await accessToken(app, HOST_A);
    const tokenB = await accessToken(app, HOST_B);
    expect(kidsOf(a.jwks)).toContain(decodeProtectedHeader(tokenA).kid);
    expect(kidsOf(b.jwks)).toContain(decodeProtectedHeader(tokenB).kid);
    const keysA = createLocalJWKSet(a.jwks);
    const keysB = createLocalJWKSet(b.jwks);
    await expect(jwtVerify(tokenA, keysA, { issuer: ISSUER_A })).resolves.toBeDefined();
    await expect(jwtVerify(tokenB, keysB, { issuer: ISSUER_B })).resolves.toBeDefined();
    await expect(jwtVerify(tokenA, keysB)).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });
    await expect(jwtVerify(tokenB, keysA)).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });
  }, 120_000);

  it('answers byte-identical discovery and JWKS for a realm from every node over one database', async () => {
    const environment = variables({ DEFAULT_REALM_ENDPOINT_HOSTS: ENDPOINT_HOST });
    const first = await firstNode(environment);
    // The default realm publishes a retired, an active and a next key, so
    // every node applies the publication windows, not only the active keys.
    // No node has read the realm's keys yet: the reset gave it a new id.
    const rotation = await rotateRealmKeys(first, E2E_REALM_NAME);
    const { prepublished } = await prepublishRealmKeys(first, E2E_REALM_NAME);
    const second = await boot(environment);
    // A node without the signer reads the published keys with no KEK (#495).
    const withoutSignerNode = await boot(withoutSigner(environment));
    const nodes = [first, second, withoutSignerNode];

    for (const host of [HOST_A, HOST_B]) {
      for (const path of DOCUMENTS) {
        const [reference, ...others] = await Promise.all(
          nodes.map((node) => get(node, path, host))
        );
        if (reference === undefined) throw new Error('no answer');
        expect(reference.statusCode, reference.body).toBe(200);
        for (const answer of others) {
          expect(answer.statusCode, answer.body).toBe(200);
          expect(answer.body).toBe(reference.body);
          expect(answer.headers['cache-control']).toBe(reference.headers['cache-control']);
          expect(answer.headers['content-type']).toBe(reference.headers['content-type']);
        }
      }
    }

    const published = kidsOf((await get(second, JWKS, HOST_A)).json<JSONWebKeySet>());
    expect(published).toEqual(
      expect.arrayContaining(
        [...rotation.retired, ...rotation.activated, ...prepublished].map((key) => key.kid)
      )
    );

    // An endpoint host gets its realm's documents, the same bytes on every
    // node, with the realm issuer inside: endpoint hosts are not advertised.
    for (const path of DOCUMENTS) {
      const reference = await get(first, path, HOST_A);
      for (const node of nodes) {
        const viaEndpoint = await get(node, path, ENDPOINT_HOST);
        expect(viaEndpoint.statusCode, viaEndpoint.body).toBe(200);
        expect(viaEndpoint.body).toBe(reference.body);
        expect(viaEndpoint.body).not.toContain(ENDPOINT_HOST);
      }
    }
    for (const path of DISCOVERY_DOCUMENTS) {
      expect((await documentAt(second, path, ENDPOINT_HOST))['issuer']).toBe(ISSUER_A);
    }
  }, 180_000);

  it('publishes a next key before it signs, so a JWKS read before the switch verifies the tokens after it', async () => {
    const first = await firstNode(variables());
    const oldKid = await activeKid(first, 'EdDSA');
    const { prepublished } = await prepublishRealmKeys(first, E2E_REALM_NAME);
    expect(prepublished).toEqual([expect.objectContaining({ algorithm: 'EdDSA' })]);
    const [{ kid: nextKid }] = prepublished;

    // A node that reads the keys after the publication: the next key is in
    // the realm's JWKS, and only in the realm's.
    const second = await boot(variables());
    const cached = await jwksAt(second, HOST_A);
    expect(kidsOf(cached)).toEqual(expect.arrayContaining([oldKid, nextKid]));
    expect(kidsOf(await jwksAt(second, HOST_B))).not.toContain(nextKid);
    // It signs nothing yet: tokens still name the active key.
    const before = await accessToken(second, HOST_A);
    expect(decodeProtectedHeader(before).kid).toBe(oldKid);

    // The rotation activates the pre-published key, not a new one.
    const rotation = await rotateRealmKeys(first, E2E_REALM_NAME);
    expect(rotation.activated).toEqual([{ kid: nextKid, algorithm: 'EdDSA' }]);
    expect(rotation.retired).toEqual([expect.objectContaining({ kid: oldKid })]);

    // A node that reads the keys after the switch signs with it, and the
    // relying party's JWKS from before the switch verifies the token.
    const third = await boot(variables());
    const after = await accessToken(third, HOST_A);
    expect(decodeProtectedHeader(after).kid).toBe(nextKid);
    await expect(
      jwtVerify(after, createLocalJWKSet(cached), { issuer: ISSUER_A })
    ).resolves.toBeDefined();
    // The retired key stays published beside it until its retention ends.
    expect(kidsOf(await jwksAt(third, HOST_A))).toEqual(expect.arrayContaining([oldKid, nextKid]));
  }, 180_000);

  it("advertises an ID-token algorithm only once the realm's key for it is active", async () => {
    const first = await firstNode(variables());
    const { prepublished } = await prepublishRealmKeys(first, E2E_REALM_NAME, {
      algorithm: 'RS256',
    });
    const [{ kid: rs256Kid }] = prepublished;

    // Published, not yet signing: in the JWKS, not in discovery.
    const second = await boot(variables());
    expect(kidsOf(await jwksAt(second, HOST_A))).toContain(rs256Kid);
    expect(
      (await documentAt(second, OIDC_CONFIGURATION, HOST_A))[
        'id_token_signing_alg_values_supported'
      ]
    ).toEqual(['EdDSA']);

    await rotateRealmKeys(first, E2E_REALM_NAME, { algorithm: 'RS256' });
    const third = await boot(variables());
    expect(
      (await documentAt(third, OIDC_CONFIGURATION, HOST_A))['id_token_signing_alg_values_supported']
    ).toEqual(['RS256', 'EdDSA']);
    // The other realm's document never moved.
    expect(
      (await documentAt(third, OIDC_CONFIGURATION, HOST_B))['id_token_signing_alg_values_supported']
    ).toEqual(['RS256', 'EdDSA']);
  }, 180_000);

  it('answers a host that names no realm with 421 on all three documents, on every node', async () => {
    const environment = variables();
    const first = await firstNode(environment);
    const withoutSignerNode = await boot(withoutSigner(environment));

    for (const node of [first, withoutSignerNode]) {
      for (const host of ['unknown.example', 'example.com', `${HOST_A}.evil.example`]) {
        for (const path of DOCUMENTS) {
          const response = await get(node, path, host);
          expect(response.statusCode, `${host}${path}`).toBe(421);
          expect(response.json()).toMatchObject({ status: 421, code: 'misdirected_request' });
          // No realm's document, no fallback to the default realm.
          expect(response.json()).not.toHaveProperty('issuer');
          expect(response.json()).not.toHaveProperty('keys');
          expect(response.body).not.toContain(ISSUER_A);
          expect(response.body).not.toContain(ISSUER_B);
          expect(String(response.headers['cache-control'])).not.toMatch(/public/);
        }
      }
    }
  }, 120_000);

  it('lets the JWKS be cached for at most five minutes, and the discovery documents longer', async () => {
    const app = await firstNode(variables({ DEFAULT_REALM_ENDPOINT_HOSTS: ENDPOINT_HOST }));

    for (const host of [HOST_A, HOST_B, ENDPOINT_HOST]) {
      const jwks = await get(app, JWKS, host);
      expect(jwks.statusCode, jwks.body).toBe(200);
      expect(jwks.headers['content-type']).toBe('application/jwk-set+json; charset=utf-8');
      const jwksMaxAge = maxAge(jwks);
      expect(jwksMaxAge).toBeGreaterThan(0);
      expect(jwksMaxAge).toBeLessThanOrEqual(300);
      for (const path of DISCOVERY_DOCUMENTS) {
        const document = await get(app, path, host);
        expect(document.statusCode, document.body).toBe(200);
        expect(maxAge(document)).toBeGreaterThan(jwksMaxAge);
      }
    }
  }, 120_000);

  it('keeps ID-JAG a deployment switch, the same in every realm, and advertises CIMD per realm, from its policies (#534)', async () => {
    // CIMD_ENABLED is on by default and seeds both realms; ID-JAG is
    // advertised once an issuer is trusted.
    const app = await firstNode(
      variables({ ID_JAG_ENABLED: 'true', ID_JAG_TRUSTED_ISSUERS: 'https://idp.example.com' })
    );

    for (const path of DISCOVERY_DOCUMENTS) {
      const a = await documentAt(app, path, HOST_A);
      const b = await documentAt(app, path, HOST_B);
      for (const document of [a, b]) {
        expect(document['client_id_metadata_document_supported']).toBe(true);
        expect(document['grant_types_supported']).toContain(JWT_BEARER_GRANT_TYPE);
      }
      expect(b['grant_types_supported']).toEqual(a['grant_types_supported']);
      expect(b['authorization_grant_profiles_supported']).toEqual(
        a['authorization_grant_profiles_supported']
      );
      expect(a['authorization_grant_profiles_supported']).toBeDefined();
    }

    // Realm B switches CIMD off in its policies: only its documents drop it.
    const realmB = await realmIdOf(app, 'beta');
    const current = await app.policyStore.get(realmB);
    if (current === undefined) throw new Error('beta has no policies');
    await app.policyStore.update(
      realmB,
      { registration: { cimd: { enabled: false } } },
      { expectedVersion: current.version }
    );
    app.realmHostCache.clear();
    for (const path of DISCOVERY_DOCUMENTS) {
      expect((await documentAt(app, path, HOST_A))['client_id_metadata_document_supported']).toBe(
        true
      );
      expect(await documentAt(app, path, HOST_B)).not.toHaveProperty(
        'client_id_metadata_document_supported'
      );
    }

    // A node with both switches off advertises ID-JAG in no realm, and CIMD
    // still as each realm stores it: CIMD_ENABLED only seeds a new realm. The
    // harness leaves these settings in place between boots: drop them first.
    for (const key of UNCLEARED_SETTINGS) delete process.env[key];
    const off = await boot(variables({ CIMD_ENABLED: 'false' }));
    for (const path of DISCOVERY_DOCUMENTS) {
      for (const host of [HOST_A, HOST_B]) {
        const document = await documentAt(off, path, host);
        expect(document).not.toHaveProperty('authorization_grant_profiles_supported');
        expect(document['grant_types_supported']).not.toContain(JWT_BEARER_GRANT_TYPE);
      }
      expect((await documentAt(off, path, HOST_A))['client_id_metadata_document_supported']).toBe(
        true
      );
      expect(await documentAt(off, path, HOST_B)).not.toHaveProperty(
        'client_id_metadata_document_supported'
      );
    }
  }, 180_000);
});
