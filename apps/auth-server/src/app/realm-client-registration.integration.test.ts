import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  provisionRealmKeys,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * CLIENT REGISTRATION FOLLOWS THE REALM ROW (ADR-019 Decisions 1 and 10,
 * ADR-007, issue #534), end to end against real Postgres and Redis.
 *
 * The dynamic registration scope ceiling and the CIMD policy (switch, trust
 * policy, trusted domains) are policies of the realm: `/oauth/register` caps
 * a registration with the realm's list and never writes the environment's
 * into it, two realms of one deployment accept different scopes, a CIMD
 * client resolves in a realm whose policy accepts its host and not in one
 * whose allowlist is empty, and a realm that switched CIMD off treats a URL
 * `client_id` as unknown and stops advertising CIMD. `CIMD_ENABLED` and
 * `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` only seed a new realm: a node that
 * boots with other values serves the stored ones.
 *
 * A CIMD client's metadata document is served by a fixture server on a public
 * address of the fixture network, which replaces only the production egress
 * client's two network edges (DNS and dialler), as the egress suites do.
 * A policy change goes through the policy store, as the admin API's does, and
 * the test then drops the realm resolver's host cache, which stands in for its
 * cache time (30 s): the next request reads the row again.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

// The production client's network edges: the fixture network while a test
// sets one, the real ones otherwise.
vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const real = actual['NODE_TRANSPORT'] as EgressTransport;
  const current = (): EgressTransport => network.current ?? real;
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

/** The environment's seed of the dynamic registration allowlist. */
const SEEDED_SCOPES = 'openid profile email offline_access';

/** Keys this suite sets that the harness does not clear between boots. */
const SUITE_KEYS = [
  'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
  'CIMD_ENABLED',
  'REGISTER_CLIENT_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT',
  'AUTHORIZE_RATE_LIMIT_LENIENT',
] as const;

/** The default realm's host (`JWT_ISSUER` of the harness). */
const HOST_A = 'auth.example.com';
const HOST_B = 'beta.example.com';
const HOST_C = 'gamma.example.com';

/** A CIMD client of the fixture network: its document's URL is its client_id. */
const CIMD_HOST = 'notes.egress.test';
const CIMD_ID = `https://${CIMD_HOST}/client.json`;
/** A public address, as the CIMD fetch (`source: client`) requires. */
const CIMD_ADDRESS = '93.184.215.14';
const REDIRECT_URI = 'https://app.example.com/callback';

const DISCOVERY_DOCUMENTS = [
  '/.well-known/oauth-authorization-server',
  '/.well-known/openid-configuration',
] as const;

describe('client registration read from the realm row (#534, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let net: FixtureNetwork | undefined;
  let documentHost: FixtureServer;
  let booted: BootedAuthServer | undefined;
  const others: BootedAuthServer[] = [];
  let dockerUp = false;

  /** The suite's deployment: the environment seeds {@link SEEDED_SCOPES} and CIMD on. */
  function environment(overrides: Record<string, string> = {}): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return {
      ...baseEnvironment(infra, jwt),
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: SEEDED_SCOPES,
      CIMD_ENABLED: 'true',
      // Sized for humans; a test sends a burst from one address.
      REGISTER_CLIENT_RATE_LIMIT: '1000',
      AUTHORIZE_RATE_LIMIT: '10000',
      AUTHORIZE_RATE_LIMIT_LENIENT: '10000',
      ...overrides,
    };
  }

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    net = await createFixtureNetwork();
    documentHost = await net.serve(CIMD_ADDRESS, () => undefined);
    booted = await bootAuthServer(environment());
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await net?.close();
    await infra?.teardown();
    for (const key of SUITE_KEYS) delete process.env[key];
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || booted === undefined || net === undefined) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set(CIMD_HOST, [CIMD_ADDRESS]);
    documentHost.requests.length = 0;
    documentHost.handler = (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'max-age=600' });
      res.end(
        JSON.stringify({
          client_id: CIMD_ID,
          client_name: 'Notes',
          redirect_uris: [REDIRECT_URI],
        })
      );
    };
    network.current = net.transport;
    // The boot step puts the default realm back, seeded from the environment,
    // and Redis (the CIMD document cache among it) is emptied.
    await resetE2eState(booted.app);
  });

  afterEach(async () => {
    network.current = undefined;
    const extra = others.splice(0);
    await Promise.all(extra.map((server) => server.close()));
    // A node booted with its own settings left them in process.env
    // (`bootAuthServer` writes its environment there): put the suite's back,
    // so a later test or boot never seeds a realm with CIMD off.
    if (extra.length > 0) Object.assign(process.env, environment());
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

  /** A second realm on its own host, with its own keys (#491), seeded from the environment. */
  async function createRealm(app: FastifyInstance, name: string, host: string): Promise<string> {
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app, name);
    return realm.id;
  }

  /**
   * Change a realm's policies through the policy store, at the counter it has
   * now, and drop the resolver's host cache so the next request reads the row.
   * Returns the counter after the change.
   */
  async function updatePolicies(
    app: FastifyInstance,
    realmId: string,
    patch: Record<string, unknown>
  ): Promise<number> {
    const current = await app.policyStore.get(realmId);
    if (current === undefined) throw new Error(`no policies for realm ${realmId}`);
    expect(current.hasPolicies).toBe(true);
    const updated = await app.policyStore.update(realmId, patch, {
      expectedVersion: current.version,
    });
    app.realmHostCache.clear();
    return updated.version;
  }

  /** `POST /oauth/register` of a public client asking for `scope`, at `host`. */
  function register(app: FastifyInstance, host: string, scope: string) {
    return app.inject({
      method: 'POST',
      url: '/oauth/register',
      headers: { host, 'content-type': 'application/json' },
      payload: {
        client_name: 'Registration policy client',
        redirect_uris: [REDIRECT_URI],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope,
      },
    });
  }

  /** The scopes a registration was granted, from its response. */
  function grantedScopes(response: LightMyRequestResponse): string[] {
    expect(response.statusCode, response.body).toBe(201);
    const scope = response.json<{ scope?: string }>().scope;
    return scope === undefined ? [] : scope.split(' ');
  }

  /** The realm row's list and policy counter. */
  async function storedList(
    app: FastifyInstance,
    realmId: string
  ): Promise<{ scopes: string[]; version: number }> {
    const row = await app.repositories.realms.findById(realmId);
    if (!row) throw new Error(`no realm ${realmId}`);
    return { scopes: [...row.dynamicRegistrationAllowedScopes], version: row.policiesVersion };
  }

  /** `GET /oauth/authorize` without a session, for `clientId`, at `host`. */
  function authorize(app: FastifyInstance, host: string, clientId: string) {
    return app.inject({
      method: 'GET',
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: 'code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        code_challenge: pkcePair().challenge,
        code_challenge_method: 'S256',
        state: 'registration-policy-state',
      }).toString()}`,
      headers: { host },
    });
  }

  /** The authorize request went on to sign the user in: the client resolved. */
  function expectResolved(response: LightMyRequestResponse): void {
    expect(response.statusCode, response.body).toBe(302);
    expect(String(response.headers['location'])).toContain('/ui/login?return_to=');
  }

  /** The authorize request was refused in place: no client of the realm (RFC 6749 §4.1.2.1). */
  function refusal(response: LightMyRequestResponse): { error: string; description: string } {
    expect(response.statusCode, response.body).toBe(400);
    expect(response.headers['location']).toBeUndefined();
    const body = response.json<{ error: string; error_description: string }>();
    return { error: body.error, description: body.error_description };
  }

  async function discovery(app: FastifyInstance, host: string): Promise<Record<string, unknown>[]> {
    return Promise.all(
      DISCOVERY_DOCUMENTS.map(async (url) => {
        const response = await app.inject({ method: 'GET', url, headers: { host } });
        expect(response.statusCode, response.body).toBe(200);
        return response.json<Record<string, unknown>>();
      })
    );
  }

  describe('the dynamic registration allowlist', () => {
    it("drops a requested scope outside the realm's list, and the request never rewrites the list from the environment", async () => {
      const app = server();
      const realmId = await realmIdOf(app, E2E_REALM_NAME);
      // The realm was seeded with the environment's list.
      expect((await storedList(app, realmId)).scopes).toEqual(SEEDED_SCOPES.split(' '));

      const narrowed = await updatePolicies(app, realmId, {
        registration: { dynamicRegistrationAllowedScopes: ['openid', 'profile'] },
      });
      expect(grantedScopes(await register(app, HOST_A, 'openid email profile'))).toEqual([
        'openid',
        'profile',
      ]);
      expect(await storedList(app, realmId)).toEqual({
        scopes: ['openid', 'profile'],
        version: narrowed,
      });

      // An emptied list stays empty: the environment's seed does not refill it.
      const emptied = await updatePolicies(app, realmId, {
        registration: { dynamicRegistrationAllowedScopes: [] },
      });
      expect(grantedScopes(await register(app, HOST_A, 'openid email'))).toEqual([]);
      expect(await storedList(app, realmId)).toEqual({ scopes: [], version: emptied });
    });

    it('gives two realms with different lists different scopes, each client in its own realm', async () => {
      const app = server();
      const realmA = await realmIdOf(app, E2E_REALM_NAME);
      const realmB = await createRealm(app, 'beta', HOST_B);
      await updatePolicies(app, realmA, {
        registration: { dynamicRegistrationAllowedScopes: ['openid', 'profile'] },
      });
      await updatePolicies(app, realmB, {
        registration: { dynamicRegistrationAllowedScopes: ['openid', 'email'] },
      });

      const onA = await register(app, HOST_A, 'openid profile email');
      const onB = await register(app, HOST_B, 'openid profile email');

      expect(grantedScopes(onA)).toEqual(['openid', 'profile']);
      expect(grantedScopes(onB)).toEqual(['openid', 'email']);
      const clientB = onB.json<{ client_id: string }>().client_id;
      await expect(
        app.repositories.oauthClients.findByClientId(realmB, clientB)
      ).resolves.toMatchObject({ scopes: ['openid', 'email'] });
      await expect(
        app.repositories.oauthClients.findByClientId(realmA, clientB)
      ).resolves.toBeUndefined();
    });
  });

  describe('the CIMD policy', () => {
    it('resolves a CIMD client in a realm that accepts any HTTPS host and refuses it in one whose allowlist is empty, whatever was cached', async () => {
      const app = server();
      const realmA = await realmIdOf(app, E2E_REALM_NAME);
      const realmB = await createRealm(app, 'beta', HOST_B);
      await updatePolicies(app, realmB, {
        registration: { cimd: { trustPolicy: 'allowlist', trustedDomains: [] } },
      });

      // Refused before any fetch.
      expect(refusal(await authorize(app, HOST_B, CIMD_ID)).error).toBe('invalid_request');
      expect(documentHost.requests).toHaveLength(0);

      // The default realm keeps the seeded policy: any HTTPS host.
      expectResolved(await authorize(app, HOST_A, CIMD_ID));
      expect(documentHost.requests.map(({ url }) => url)).toEqual(['/client.json']);
      await expect(
        app.repositories.oauthClients.findByClientId(realmA, CIMD_ID)
      ).resolves.toMatchObject({ metadata: { registrationType: 'cimd' } });

      // The document realm A cached does not let it into realm B.
      expect(refusal(await authorize(app, HOST_B, CIMD_ID)).error).toBe('invalid_request');
      expect(documentHost.requests).toHaveLength(1);
      await expect(
        app.repositories.oauthClients.findByClientId(realmB, CIMD_ID)
      ).resolves.toBeUndefined();

      // Trusting the host lets it in.
      await updatePolicies(app, realmB, {
        registration: { cimd: { trustedDomains: ['*.egress.test'] } },
      });
      expectResolved(await authorize(app, HOST_B, CIMD_ID));
    });

    it('treats a URL client_id as unknown in a realm with CIMD switched off, and does not advertise CIMD there', async () => {
      const app = server();
      const realmB = await createRealm(app, 'beta', HOST_B);
      await updatePolicies(app, realmB, { registration: { cimd: { enabled: false } } });

      const cimd = refusal(await authorize(app, HOST_B, CIMD_ID));
      const unknown = refusal(await authorize(app, HOST_B, 'no-such-client'));
      expect(cimd).toEqual(unknown);
      expect(cimd.error).toBe('invalid_request');
      expect(documentHost.requests).toHaveLength(0);
      await expect(
        app.repositories.oauthClients.findByClientId(realmB, CIMD_ID)
      ).resolves.toBeUndefined();

      for (const document of await discovery(app, HOST_B)) {
        expect(document).not.toHaveProperty('client_id_metadata_document_supported');
      }
      // The default realm is untouched.
      for (const document of await discovery(app, HOST_A)) {
        expect(document['client_id_metadata_document_supported']).toBe(true);
      }
      expectResolved(await authorize(app, HOST_A, CIMD_ID));
    });

    it('keeps a stored policy over a node that boots with CIMD_ENABLED=false, which seeds only the realms it creates', async () => {
      const app = server();
      const realmA = await realmIdOf(app, E2E_REALM_NAME);
      const second = await bootAuthServer(environment({ CIMD_ENABLED: 'false' }));
      others.push(second);

      // The default realm has its policies: the second node's key changes nothing.
      await expect(second.app.policyStore.get(realmA)).resolves.toMatchObject({
        hasPolicies: true,
        policies: { registration: { cimd: { enabled: true } } },
      });
      expectResolved(await authorize(second.app, HOST_A, CIMD_ID));
      for (const document of await discovery(second.app, HOST_A)) {
        expect(document['client_id_metadata_document_supported']).toBe(true);
      }

      // A realm the second node creates is seeded from its environment, and
      // every node reads that realm's stored policy.
      const realmC = await createRealm(second.app, 'gamma', HOST_C);
      await expect(second.app.policyStore.get(realmC)).resolves.toMatchObject({
        hasPolicies: true,
        policies: { registration: { cimd: { enabled: false } } },
      });
      for (const node of [app, second.app]) {
        node.realmHostCache.clear();
        expect(refusal(await authorize(node, HOST_C, CIMD_ID)).error).toBe('invalid_request');
      }
      expect(documentHost.requests).toHaveLength(1);
    });
  });
});
