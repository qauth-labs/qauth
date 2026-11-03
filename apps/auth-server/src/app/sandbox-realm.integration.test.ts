import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import {
  type CompactJWSHeaderParameters,
  CompactSign,
  decodeProtectedHeader,
  importPKCS8,
} from 'jose';
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
  provisionRealmKeys,
  realmKeyProvisioner,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import type { RealmRow } from './helpers/request-realm';
import {
  createSandboxRealm,
  sandboxPairingOf,
  type SandboxRealmDependencies,
} from './helpers/sandbox-realm';

/**
 * THE PAIRED SANDBOX REALM (ADR-019 Decision 11, ADR-020 §4, issue #554).
 *
 * One deployment: the default realm, which is the operator realm in simple
 * mode, a live realm on `live.example.com`, and its sandbox, created by
 * `createSandboxRealm` on `sandbox.live.example.com`. The sandbox is a realm
 * in its own right: its own host, issuer and keys, none of the live realm's
 * users, the `staging` ceiling and the test mail transport.
 *
 * The rules of the pairing are proven on the database alone in
 * `libs/infra/db/.../realm-sandbox.integration.test.ts`; this suite proves
 * them through the server's own wiring, and what the pairing means for
 * sign-in, tokens and the policy update.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const HOST_LIVE = 'live.example.com';
const HOST_SANDBOX = 'sandbox.live.example.com';
const ALICE = 'alice@example.com';
const BOB = 'bob@example.com';
const CAROL = 'carol@example.com';

/**
 * The server's own helpers, imported after its boot. The harness resets the
 * module registry when it boots a server, so a class imported at the top of
 * this file is not the class the server throws, and a helper imported there
 * would not recognise the server's errors (`instanceof`). An error of a
 * library is matched by its `name` instead.
 */
async function serverModules() {
  const [{ SandboxCeilingError }, { updateRealmPolicies }] = await Promise.all([
    import('./helpers/api-request-errors'),
    import('./helpers/realm-policy-update'),
  ]);
  return { SandboxCeilingError, updateRealmPolicies };
}

interface World {
  readonly app: FastifyInstance;
  readonly operator: RealmRow;
  readonly live: RealmRow;
  /** The live realm's token signing key (PKCS#8 PEM), which the test holds. */
  readonly liveTokenKey: string;
  readonly sandbox: RealmRow;
  readonly deps: SandboxRealmDependencies;
}

describe('the paired sandbox realm (#554)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let server: BootedAuthServer | undefined;
  let world: World | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await server?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /** One boot for the suite: no test below changes what another reads. */
  async function setUp(): Promise<World> {
    if (world) return world;
    if (!infra || !jwt) throw new Error('infrastructure not started');
    server = await bootAuthServer(baseEnvironment(infra, jwt));
    const { app } = server;
    await resetE2eState(app);

    const operator = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!operator) throw new Error('the default realm boot step left no realm');
    const { realm: live } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'live', issuer: `https://${HOST_LIVE}`, enabled: true },
      HOST_LIVE
    );
    // A realm signs its tokens only with its own keys (#491). The test holds
    // the live realm's token key, to sign a token that differs in one claim.
    const liveTokenKey = (await generateJwtPem()).privateKey;
    await provisionRealmKeys(app, 'live', { tokenSigningKeyPem: liveTokenKey });
    // The live realm's own policies, which the sandbox must not copy.
    const livePolicies = await app.policyStore.get(live.id);
    await app.policyStore.update(
      live.id,
      { password: { minScore: 4 } },
      { expectedVersion: livePolicies?.version ?? 0 }
    );

    const deps: SandboxRealmDependencies = {
      db: app.db,
      realms: app.repositories.realms,
      policies: app.policyStore,
      provisionKeys: realmKeyProvisioner(app),
    };
    const created = await createSandboxRealm(deps, live.id, {
      name: 'live-sandbox',
      issuer: `https://${HOST_SANDBOX}`,
    });

    world = { app, operator, live, liveTokenKey, sandbox: created.realm, deps };
    return world;
  }

  /** `/auth/login` at `host`. */
  function login(app: FastifyInstance, host: string, email: string) {
    return app.inject({
      method: 'POST',
      url: '/auth/login',
      headers: { host },
      payload: { email, password: E2E_PASSWORD },
    });
  }

  /** The `kid`s of the JWKS at `host`. */
  async function kidsAt(app: FastifyInstance, host: string): Promise<string[]> {
    const response = await app.inject({
      method: 'GET',
      url: '/.well-known/jwks.json',
      headers: { host },
    });
    expect(response.statusCode, response.body).toBe(200);
    return response.json<{ keys: { kid: string }[] }>().keys.map((key) => key.kid);
  }

  it('creates the sandbox as a realm in its own right: own host, issuer, keys and RP ID, and the staging ceiling', async () => {
    const { app, live, sandbox } = await setUp();

    expect(sandbox).toMatchObject({
      sandboxOfRealmId: live.id,
      issuer: `https://${HOST_SANDBOX}`,
      maxEnvironmentLaxity: 'staging',
      isOperator: false,
      enabled: true,
      // NULL: the RP ID is the sandbox's own host.
      webauthnRpId: null,
    });
    expect((await app.repositories.realms.findByHost(HOST_SANDBOX))?.realm.id).toBe(sandbox.id);

    const discovery = await app.inject({
      method: 'GET',
      url: '/.well-known/openid-configuration',
      headers: { host: HOST_SANDBOX },
    });
    expect(discovery.statusCode, discovery.body).toBe(200);
    expect(discovery.json<{ issuer: string }>().issuer).toBe(`https://${HOST_SANDBOX}`);

    const sandboxKids = await kidsAt(app, HOST_SANDBOX);
    const liveKids = await kidsAt(app, HOST_LIVE);
    expect(sandboxKids.length).toBeGreaterThan(0);
    expect(sandboxKids.filter((kid) => liveKids.includes(kid))).toEqual([]);
  });

  it("seeds the sandbox from the environment with the test mail transport, and copies nothing of the live realm's", async () => {
    const { app, operator, live, sandbox } = await setUp();

    const policies = await app.policyStore.get(sandbox.id);
    const seeded = await app.policyStore.get(operator.id);
    const livePolicies = await app.policyStore.get(live.id);
    expect(policies?.policies.mail.provider).toBe('mock');
    expect(policies?.policies.posture.maxEnvironmentLaxity).toBe('staging');
    expect(livePolicies?.policies.password.minScore).toBe(4);
    expect(policies?.policies.password.minScore).toBe(seeded?.policies.password.minScore);
    expect(policies?.policies.password.minScore).not.toBe(4);

    const { rows } = await app.dbPool.query<{ n: number }>(
      `SELECT (SELECT count(*) FROM users WHERE realm_id = $1)::int
            + (SELECT count(*) FROM oauth_clients WHERE realm_id = $1)::int AS n`,
      [sandbox.id]
    );
    expect(rows[0]?.n).toBe(0);
  });

  it('shows the pairing as read-only fields of the realm representation', async () => {
    const { app, operator, live, sandbox } = await setUp();
    const realms = app.repositories.realms;

    expect(await sandboxPairingOf(realms, live)).toEqual({ sandboxOf: null, sandbox: sandbox.id });
    expect(await sandboxPairingOf(realms, sandbox)).toEqual({ sandboxOf: live.id, sandbox: null });
    expect(await sandboxPairingOf(realms, operator)).toEqual({ sandboxOf: null, sandbox: null });
  });

  it('does not let a user of the live realm sign in to the sandbox', async () => {
    const { app } = await setUp();
    await registerPasswordAccount(app, ALICE, E2E_PASSWORD, { host: HOST_LIVE });

    const atSandbox = await login(app, HOST_SANDBOX, ALICE);
    expect(atSandbox.statusCode, atSandbox.body).toBe(401);
    const atLive = await login(app, HOST_LIVE, ALICE);
    expect(atLive.statusCode, atLive.body).toBe(200);
  });

  it("refuses a sandbox token at the live realm's guard: its issuer and its keys are the sandbox's", async () => {
    const { app } = await setUp();
    await registerPasswordAccount(app, BOB, E2E_PASSWORD, { host: HOST_SANDBOX });
    const signedIn = await login(app, HOST_SANDBOX, BOB);
    expect(signedIn.statusCode, signedIn.body).toBe(200);
    const token = signedIn.json<{ access_token: string }>().access_token;
    expect(decodeJwtClaims(token)['iss']).toBe(`https://${HOST_SANDBOX}`);

    // The token is good in the sandbox...
    const atSandbox = await app.inject({
      method: 'GET',
      url: '/api/clients',
      headers: { host: HOST_SANDBOX, authorization: `Bearer ${token}` },
    });
    expect(atSandbox.statusCode, atSandbox.body).toBe(200);

    // ...and refused at the live realm, with no claim of its own to check.
    for (const url of ['/api/clients', '/oauth/userinfo']) {
      const atLive = await app.inject({
        method: 'GET',
        url,
        headers: { host: HOST_LIVE, authorization: `Bearer ${token}` },
      });
      expect(atLive.statusCode, `${url}: ${atLive.body}`).toBe(401);
    }
  });

  it("refuses, at the live realm's guard, a token of the live realm's own key that names the sandbox's issuer", async () => {
    const { app, liveTokenKey } = await setUp();
    await registerPasswordAccount(app, CAROL, E2E_PASSWORD, { host: HOST_LIVE });
    const signedIn = await login(app, HOST_LIVE, CAROL);
    expect(signedIn.statusCode, signedIn.body).toBe(200);
    const token = signedIn.json<{ access_token: string }>().access_token;

    // The live realm's token, signed again with the live realm's own key: the
    // same header and claims, `iss` alone set to the value given.
    const key = await importPKCS8(liveTokenKey, 'EdDSA');
    const withIssuer = (iss: string) =>
      new CompactSign(Buffer.from(JSON.stringify({ ...decodeJwtClaims(token), iss })))
        .setProtectedHeader(decodeProtectedHeader(token) as CompactJWSHeaderParameters)
        .sign(key);
    const atLive = async (bearer: string) =>
      app.inject({
        method: 'GET',
        url: '/api/clients',
        headers: { host: HOST_LIVE, authorization: `Bearer ${bearer}` },
      });

    // Under the live issuer the key and the claims pass the guard...
    const asLive = await atLive(await withIssuer(`https://${HOST_LIVE}`));
    expect(asLive.statusCode, asLive.body).toBe(200);
    // ...and under the sandbox's issuer, nothing else changed, they do not.
    const asSandbox = await atLive(await withIssuer(`https://${HOST_SANDBOX}`));
    expect(asSandbox.statusCode, asSandbox.body).toBe(401);
  });

  it('refuses the development ceiling on the sandbox in the policy update (422 sandbox_ceiling) and in the database', async () => {
    const { app, live, sandbox } = await setUp();
    const { SandboxCeilingError, updateRealmPolicies } = await serverModules();
    const before = await app.policyStore.get(sandbox.id);
    if (!before) throw new Error('the sandbox has no policies');

    const refused = updateRealmPolicies(
      app,
      sandbox.id,
      { posture: { maxEnvironmentLaxity: 'development' } },
      { expectedVersion: before.version }
    );
    await expect(refused).rejects.toBeInstanceOf(SandboxCeilingError);
    await expect(refused).rejects.toMatchObject({ statusCode: 422, code: 'SANDBOX_CEILING' });

    const after = await app.policyStore.get(sandbox.id);
    expect(after?.version).toBe(before.version);
    expect(after?.policies.posture.maxEnvironmentLaxity).toBe('staging');
    await expect(
      app.dbPool.query(`UPDATE realms SET max_environment_laxity = 'development' WHERE id = $1`, [
        sandbox.id,
      ])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_sandbox_ceiling' });

    // A stricter ceiling is a change like any other; the live realm may be development.
    const tightened = await updateRealmPolicies(
      app,
      sandbox.id,
      { posture: { maxEnvironmentLaxity: 'production' } },
      { expectedVersion: before.version }
    );
    expect(tightened.policies.posture.maxEnvironmentLaxity).toBe('production');
    await updateRealmPolicies(
      app,
      sandbox.id,
      { posture: { maxEnvironmentLaxity: 'staging' } },
      { expectedVersion: tightened.version }
    );
    const livePolicies = await app.policyStore.get(live.id);
    const loosened = await updateRealmPolicies(
      app,
      live.id,
      { posture: { maxEnvironmentLaxity: 'development' } },
      { expectedVersion: livePolicies?.version ?? 0 }
    );
    expect(loosened.policies.posture.maxEnvironmentLaxity).toBe('development');
  });

  it('refuses a second sandbox, a sandbox of the sandbox and a sandbox of the operator realm, leaving nothing behind', async () => {
    const { app, operator, live, sandbox, deps } = await setUp();
    expect(operator.isOperator).toBe(true);

    for (const [liveRealmId, rule, host] of [
      [live.id, 'one_sandbox', 'second.live.example.com'],
      [sandbox.id, 'sandbox_of_sandbox', 'nested.live.example.com'],
      [operator.id, 'operator', 'sandbox.auth.example.com'],
    ] as const) {
      const attempt = createSandboxRealm(deps, liveRealmId, {
        name: `refused-${rule}`,
        issuer: `https://${host}`,
      });
      await expect(attempt).rejects.toMatchObject({ name: 'SandboxPairingError' });
      await expect(attempt).rejects.toMatchObject({ rule });
      expect(await app.repositories.realms.findByName(`refused-${rule}`)).toBeUndefined();
      expect(await app.repositories.realms.findByHost(host)).toBeUndefined();
    }
  });

  it("refuses a sandbox on another realm's host, the sandbox twin's included", async () => {
    const { app, deps } = await setUp();
    const { realm: other } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'other', issuer: 'https://other.example.com', enabled: true },
      'other.example.com'
    );

    for (const host of [`${HOST_SANDBOX}:8443`, `${HOST_LIVE}:8443`, 'auth.example.com:8443']) {
      const attempt = createSandboxRealm(deps, other.id, {
        name: 'other-sandbox',
        issuer: `https://${host}`,
      });
      await expect(attempt).rejects.toMatchObject({ name: 'UniqueConstraintError' });
      await expect(attempt).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
    }
    expect(await app.repositories.realms.findSandboxOf(other.id)).toBeUndefined();
  });

  it('refuses deleting the live realm while its sandbox exists', async () => {
    const { app, live } = await setUp();

    const deleted = app.repositories.realms.delete(live.id);
    await expect(deleted).rejects.toMatchObject({ name: 'SandboxPairingError' });
    await expect(deleted).rejects.toMatchObject({ rule: 'live_realm_has_sandbox' });
    expect(await app.repositories.realms.findById(live.id)).toBeDefined();
  });
});
