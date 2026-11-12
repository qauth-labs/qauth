import {
  requireDockerOrSkip,
  startPostgresContainer,
  startRedisContainer,
  testPrimaryCredential,
} from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import { fixturePluginImporter, fixturePluginMethod } from '../testing/auth-method-plugins';
import {
  createDatabaseUsers,
  databaseUrlAs,
  grantDatabaseUsers,
  PERMISSION_ERROR,
} from '../testing/database-users';
import {
  allowConsentScreen,
  baseEnvironment,
  bootAuthServer,
  type BootAuthServerOptions,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  pkcePair,
  registerPasswordAccount,
  signInWithPassword,
} from '../testing/e2e-harness';
import { SIGNER_LISTENER, SIGNER_SERVICE } from '../testing/service-role-env';
import { API_FAMILY_AUDIENCES, API_FAMILY_SCOPES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';
import { serverJobs } from './jobs';
import { SERVICE_ROLE_NAMES, type ServiceRole } from './service-roles';

/**
 * EACH SERVICE ROLE ON A DATABASE USER OF ITS OWN (ADR-019 Decisions 8 and 9,
 * issue #498).
 *
 * The operator's `db:grants` command, run as an operator runs it, gives each
 * role's database user exactly the grants of the map
 * (`libs/infra/db/src/lib/database-users/grants-map.ts`). Then each role
 * boots on its own user, its boot steps included, answers `/ready`, runs
 * each of its jobs once and serves its routes: `web` the sign-in, the
 * authorization and the consents; `api` the token, introspection, userinfo,
 * revocation and registration endpoints, the discovery documents and the
 * developer and account APIs; `admin` its admin API on the admin listener.
 * A permission error anywhere fails the suite, which is how the map was
 * filled. The SSF transmitter's streams on `api` and its deliveries on
 * `delivery` run under their own users in `ssf-security-events.integration.test.ts`.
 *
 * A process without the signer cannot sign or set a signed cookie until the
 * signer service is reachable (#497), so the routes that need one run on a
 * process holding the role and the signer, on a user `db:grants` gives both
 * roles' grants and nothing else: the signer adds only the realm tables, so
 * those runs still fail on any other table the role lacks. The same role
 * alone, on its own user, serves what needs no signature.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** Each role's own user. */
const USERS: Readonly<Record<ServiceRole, string>> = {
  web: 'qauth_web',
  api: 'qauth_api',
  admin: 'qauth_admin',
  signer: 'qauth_signer',
  delivery: 'qauth_delivery',
};

/** A user `db:grants` gives the grants of web and signer. */
const WEB_SIGNER = 'qauth_web_signer';
/** A user `db:grants` gives the grants of api and signer. */
const API_SIGNER = 'qauth_api_signer';

const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
const EMAIL = 'roles@example.test';
const CLIENT_ID = 'roles-app';
const CLIENT_SECRET = 'roles-app-secret-of-sufficient-length-42';
const REDIRECT_URI = 'https://app.example.com/callback';
const SCOPES = ['openid', 'email'];
const MACHINE_CLIENT_ID = 'roles-machine';
const DEVELOPER = '/developer/v1-rc.0';
const ACCOUNT = '/account/v1-rc.0';

/** The admin process's one AuthMethod plugin, for its plugin operations (#600). */
const PLUGIN_PACKAGE = '@example/qauth-plugin-corp-sso';

interface RoleProcess {
  readonly server: BootedAuthServer;
  readonly roles: readonly ServiceRole[];
  /** The lines it logged, `warn` and up. */
  readonly log: string[];
}

describe('each service role on a database user of its own (#498)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let fixture: BootedAuthServer | undefined;
  const processes = new Map<string, RoleProcess>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    // A Postgres server of the suite's own: the users are cluster-wide.
    const [postgres, redis] = await Promise.all([
      startPostgresContainer({ schema: 'migrated', privateContainer: true }),
      startRedisContainer(),
    ]);
    infra = {
      postgres,
      redis,
      async teardown() {
        await redis.stop();
        await postgres.stop();
      },
    };
    jwt = await generateJwtPem();

    // The owner's deployment: it creates the default realm and its keys, and
    // the fixtures below. Its pool connects as the owner of the tables.
    fixture = await bootAuthServer(baseEnvironment(infra, jwt));
    await createDatabaseUsers(fixture.app.dbPool, [
      ...Object.values(USERS),
      WEB_SIGNER,
      API_SIGNER,
    ]);
    // Each run names the five roles; a user it does not name keeps its
    // grants. The last two give a role's user and the signer's one user.
    const owner = infra.postgres.connectionString;
    await grantDatabaseUsers(owner, USERS);
    await grantDatabaseUsers(owner, { ...USERS, web: WEB_SIGNER, signer: WEB_SIGNER });
    await grantDatabaseUsers(owner, { ...USERS, api: API_SIGNER, signer: API_SIGNER });

    // The signer first, as a deployment starts it. One at a time: each boot
    // sets the process environment its app reads.
    await boot('signer', ['signer'], USERS.signer);
    await boot('web', ['web'], USERS.web);
    await boot('api', ['api'], USERS.api);
    // With its admin API on (#511) and one plugin to administer (#600).
    await boot(
      'admin',
      ['admin'],
      USERS.admin,
      {
        ...ADMIN_LISTENER_ENVIRONMENT,
        AUTH_METHOD_PLUGINS: PLUGIN_PACKAGE,
        PLUGIN_API_ENABLED: 'true',
      },
      {
        adminListener: async () => ({}),
        authMethodPlugins: {
          importPackage: fixturePluginImporter({
            [PLUGIN_PACKAGE]: {
              authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }),
            },
          }),
        },
      }
    );
    await boot('delivery', ['delivery'], USERS.delivery);
    await boot('web+signer', ['web', 'signer'], WEB_SIGNER);
    await boot('api+signer', ['api', 'signer'], API_SIGNER);
  }, 300_000);

  afterAll(async () => {
    await Promise.all([...processes.values()].map(async ({ server }) => server.close()));
    await fixture?.close();
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  /**
   * Boot `roles` on `user`, with `extra` in its environment: a process with
   * the signer keeps the key variables and serves the signer; one without it
   * gets the signer service's settings instead, as a split deployment has
   * them.
   */
  async function boot(
    name: string,
    roles: readonly ServiceRole[],
    user: string,
    extra: Record<string, string> = {},
    options: Omit<BootAuthServerOptions, 'logStream'> = {}
  ): Promise<void> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const base: Record<string, string> = {
      ...baseEnvironment(infra, jwt),
      ...extra,
      DATABASE_URL: databaseUrlAs(infra.postgres.connectionString, user),
      SERVICE_ROLES: roles.join(','),
    };
    const withoutKeys = Object.fromEntries(
      Object.entries(base).filter(([key]) => key !== 'KEK' && key !== 'JWT_PRIVATE_KEY')
    );
    const environment = roles.includes('signer')
      ? { ...base, ...SIGNER_LISTENER }
      : { ...withoutKeys, ...SIGNER_SERVICE };
    const log: string[] = [];
    const server = await bootAuthServer(environment, {
      ...options,
      logStream: { write: (line) => void log.push(line) },
    });
    processes.set(name, { server, roles, log });
  }

  function role(name: string): FastifyInstance {
    const found = processes.get(name);
    if (found === undefined) throw new Error(`no process ${name}`);
    return found.server.app;
  }

  /** The default realm, as the owner's fixture process reads it. */
  async function defaultRealm(): Promise<{ id: string; issuer: string }> {
    if (!fixture) throw new Error('no fixture');
    const realm = await fixture.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('the default realm was not booted');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** The suite's acceptance criterion: no process logged a permission error. */
  function expectNoPermissionError(): void {
    for (const [name, { log }] of processes) {
      expect(
        log.filter((line) => PERMISSION_ERROR.test(line)),
        name
      ).toEqual([]);
    }
  }

  function form(values: Record<string, string>): string {
    return new URLSearchParams(values).toString();
  }

  function json<T>(response: LightMyRequestResponse): T {
    return response.json<T>();
  }

  it('boots each role on its own user, its boot steps included, and answers /ready', async () => {
    for (const [name, { server, roles }] of processes) {
      const ready = await server.app.inject({ method: 'GET', url: '/ready' });
      expect(ready.statusCode, `${name}: ${ready.body}`).toBe(200);
      expect(ready.json(), name).toMatchObject({ status: 'ok', roles });
    }
    expectNoPermissionError();
  });

  it.each(SERVICE_ROLE_NAMES)('runs each job of %s once on its own user', async (name) => {
    const app = role(name);
    const jobs = serverJobs(app, {}, [name]);
    for (const job of jobs) {
      await expect(
        job.run({
          signal: new AbortController().signal,
          now: () => Date.now(),
          log: app.log.child({ job: job.name }),
        }),
        job.name
      ).resolves.toBeUndefined();
    }
    expectNoPermissionError();
  });

  it('signs a person in, runs the code flow and uses its tokens, each step on the users of its roles', async () => {
    if (!fixture) throw new Error('no fixture');
    const realm = await fixture.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('the default realm was not booted');
    await fixture.app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: CLIENT_ID,
      clientSecretHash: await fixture.app.passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Roles app',
      redirectUris: [REDIRECT_URI],
      scopes: SCOPES,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    const clientCredentials = { client_id: CLIENT_ID, client_secret: CLIENT_SECRET };

    // api registers the account and verifies its address (api + signer: the
    // mail's sender reads the realm's sealed settings through the signer).
    await registerPasswordAccount(role('api+signer'), EMAIL);

    // web signs the person in, asks for consent and issues the code.
    const web = role('web+signer');
    const jar = await signInWithPassword(web, EMAIL, E2E_PASSWORD);
    const pkce = pkcePair();
    const authorize = await web.inject({
      method: 'GET',
      url: `/oauth/authorize?${form({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPES.join(' '),
        code_challenge: pkce.challenge,
        code_challenge_method: 'S256',
        state: 'roles-state',
      })}`,
      headers: { cookie: jar.header() as string },
    });
    expect(authorize.statusCode, authorize.body).toBe(302);
    let location = authorize.headers['location'];
    if (typeof location !== 'string') throw new Error('authorize did not redirect');
    if (location.startsWith('/ui/consent?')) {
      location = await allowConsentScreen(web, jar.header() as string, location);
    }
    const code = new URL(location).searchParams.get('code');
    if (code === null) throw new Error(`authorize returned no code: ${location}`);

    // api redeems the code and refreshes the tokens.
    const api = role('api+signer');
    const redeemed = await api.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: form({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: pkce.verifier,
        ...clientCredentials,
      }),
    });
    expect(redeemed.statusCode, redeemed.body).toBe(200);
    const first = json<{ access_token: string; refresh_token: string }>(redeemed);
    const refreshed = await api.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: form({
        grant_type: 'refresh_token',
        refresh_token: first.refresh_token,
        ...clientCredentials,
      }),
    });
    expect(refreshed.statusCode, refreshed.body).toBe(200);
    const tokens = json<{ access_token: string; refresh_token: string }>(refreshed);

    // api alone, on its own user: introspection, userinfo and revocation.
    const apiAlone = role('api');
    const introspection = await apiAlone.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: form({ token: tokens.access_token, ...clientCredentials }),
    });
    expect(introspection.statusCode, introspection.body).toBe(200);
    expect(introspection.json()).toMatchObject({ active: true });
    const userinfo = await apiAlone.inject({
      method: 'GET',
      url: '/oauth/userinfo',
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfo.statusCode, userinfo.body).toBe(200);
    expect(userinfo.json()).toHaveProperty('sub');
    const revoked = await apiAlone.inject({
      method: 'POST',
      url: '/oauth/revoke',
      headers: FORM,
      payload: form({ token: tokens.refresh_token, ...clientCredentials }),
    });
    expect(revoked.statusCode, revoked.body).toBe(200);
    const afterRevocation = await apiAlone.inject({
      method: 'POST',
      url: '/oauth/introspect',
      headers: FORM,
      payload: form({ token: tokens.refresh_token, ...clientCredentials }),
    });
    expect(afterRevocation.json()).toMatchObject({ active: false });

    // web lists the person's consents and withdraws the app's.
    const listed = await web.inject({
      method: 'GET',
      url: '/consents',
      headers: { cookie: jar.header() as string },
    });
    expect(listed.statusCode, listed.body).toBe(200);
    const { consents, csrfToken } = json<{ consents: { id: string }[]; csrfToken: string }>(listed);
    expect(consents).toHaveLength(1);
    const withdrawn = await web.inject({
      method: 'DELETE',
      url: `/consents/${consents[0].id}`,
      headers: { cookie: jar.header() as string, 'x-csrf-token': csrfToken },
    });
    expect(withdrawn.statusCode, withdrawn.body).toBe(204);

    expectNoPermissionError();
  });

  it('refuses a wrong password, and registers a client on api alone, on its own user', async () => {
    // The failure ladder keys its counts with the realm's cookie key, which
    // a process without the signer cannot read yet (#497): api + signer.
    const login = await role('api+signer').inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: EMAIL, password: 'not-the-password-of-this-account' },
    });
    expect(login.statusCode, login.body).toBe(401);

    const api = role('api');

    const registered = await api.inject({
      method: 'POST',
      url: '/oauth/register',
      payload: { client_name: 'Roles DCR', redirect_uris: ['https://dcr.example.com/callback'] },
    });
    expect(registered.statusCode, registered.body).toBe(201);

    for (const url of ['/.well-known/openid-configuration', '/.well-known/jwks.json']) {
      const response = await api.inject({ method: 'GET', url });
      expect(response.statusCode, `${url}: ${response.body}`).toBe(200);
    }
    expectNoPermissionError();
  });

  it('serves the developer and account APIs on api alone, on its own user', async () => {
    if (!fixture) throw new Error('no fixture');
    const realm = await defaultRealm();
    // Signing in mints a token, which needs the signer.
    const email = 'developer@example.test';
    const userId = await registerPasswordAccount(role('api+signer'), email);
    const login = await role('api+signer').inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    const portal = json<{ access_token: string }>(login).access_token;

    const api = role('api');
    const call = (
      method: 'GET' | 'POST' | 'DELETE',
      url: string,
      token: string,
      payload?: object
    ) =>
      api.inject({
        method,
        url,
        headers: { authorization: `Bearer ${token}` },
        ...(payload === undefined ? {} : { payload }),
      });

    const created = await call('POST', '/api/clients', portal, {
      name: 'Roles developer app',
      redirectUris: ['https://developer.example.com/callback'],
      scopes: ['openid'],
      tokenEndpointAuthMethod: 'client_secret_post',
    });
    expect(created.statusCode, created.body).toBe(201);
    const clientRowId = json<{ id: string }>(created).id;
    expect((await call('GET', `${DEVELOPER}/clients`, portal)).statusCode).toBe(200);

    // Static API keys are for a development client in a development realm.
    await fixture.app.dbPool.query(
      `UPDATE oauth_clients SET environment = 'development' WHERE id = $1`,
      [clientRowId]
    );
    await fixture.app.dbPool.query(
      `UPDATE realms SET max_environment_laxity = 'development' WHERE id = $1`,
      [realm.id]
    );
    api.realmHostCache.clear();
    const keys = `${DEVELOPER}/clients/${clientRowId}/api-keys`;
    const minted = await call('POST', keys, portal, { name: 'roles key' });
    expect(minted.statusCode, minted.body).toBe(201);
    expect((await call('GET', keys, portal)).statusCode).toBe(200);
    const revoked = await call('DELETE', `${keys}/${json<{ id: string }>(minted).id}`, portal);
    expect(revoked.statusCode, revoked.body).toBe(200);

    // The account API, with a token the account console's backend holds.
    await fixture.app.repositories.oauthConsents.upsertGrant(realm.id, userId, clientRowId, [
      'openid',
    ]);
    const account = await fixture.app.jwtUtils.signAccessToken(
      { id: realm.id },
      {
        sub: userId,
        clientId: 'account-console',
        aud: API_FAMILY_AUDIENCES.account,
        // Both account scopes (#933): the list reads, the withdrawal writes.
        scope: `${API_FAMILY_SCOPES.account.read} ${API_FAMILY_SCOPES.account.write}`,
      }
    );
    const consents = await call('GET', `${ACCOUNT}/consents`, account);
    expect(consents.statusCode, consents.body).toBe(200);
    const [consent] = json<{ items: { id: string }[] }>(consents).items;
    if (consent === undefined) throw new Error('the account API listed no consent');
    const withdrawn = await call('DELETE', `${ACCOUNT}/consents/${consent.id}`, account);
    expect(withdrawn.statusCode, withdrawn.body).toBe(204);
    expectNoPermissionError();
  });

  it('serves the admin API on admin alone, on its own user, through the admin pipeline', async () => {
    if (!fixture) throw new Error('no fixture');
    const realm = await defaultRealm();
    const adminApi = processes.get('admin')?.server.admin;
    if (adminApi === undefined) throw new Error('the admin listener was not booted');
    // An administrator of the realm, and a DPoP-bound admin token the
    // signer minted for them (#520).
    const userId = (
      await fixture.app.repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await fixture.app.repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    const token = await signBoundAccessToken(fixture.app, realm, {
      sub: userId,
      clientId: 'admin-console',
      aud: API_FAMILY_AUDIENCES.admin,
      scope: ADMIN_SCOPE_LIST.join(' '),
    });
    const send = async (
      method: 'GET' | 'POST',
      url: string,
      payload?: object,
      headers: Record<string, string> = {}
    ) =>
      adminApi.inject({
        method,
        url,
        headers: { ...(await adminCallHeaders(token, method, url)), ...headers },
        ...(payload === undefined ? {} : { payload }),
      });

    const plugins = `/admin/v1-rc.0/realms/${realm.id}/plugins`;
    const listed = await send('GET', plugins);
    expect(listed.statusCode, listed.body).toBe(200);
    const one = await send('GET', `${plugins}/corp`);
    expect(one.statusCode, one.body).toBe(200);

    const approvals = `/admin/v1-rc.0/realms/${realm.id}/approvals`;
    const filed = await send('POST', approvals, {
      operation: 'plugins.enable',
      params: { plugin: 'corp' },
      body: { version: 0 },
    });
    expect(filed.statusCode, filed.body).toBe(201);
    const approvalId = json<{ id: string }>(filed).id;
    const read = await send('GET', `${approvals}/${approvalId}`);
    expect(read.statusCode, read.body).toBe(200);
    const cancelled = await send('POST', `${approvals}/${approvalId}/cancel`, undefined, {
      'if-match': '"pending.0"',
    });
    expect(cancelled.statusCode, cancelled.body).toBe(200);
    expect(cancelled.json()).toMatchObject({ status: 'cancelled' });

    // users.verify (#1052), approved and run as the admin user: it reads the
    // account, what its credentials prove through user_credential_proofs,
    // records the verification through users_record_operator_verification
    // (it holds no SELECT on user_credentials and no UPDATE on users), and
    // records user.verified in the event store.
    const account = (
      await fixture.app.repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    const verifyFiled = await send('POST', approvals, {
      operation: 'users.verify',
      params: { userId: account },
      body: {},
    });
    expect(verifyFiled.statusCode, verifyFiled.body).toBe(201);
    const verifyApproval = json<{ id: string }>(verifyFiled).id;
    // Imported once the boots reset the modules.
    const { createTestApprovalFactor } = await import('../testing/approval-factor');
    const engine = await import('./admin/approvals/engine');
    const test = createTestApprovalFactor();
    const approver = { realmId: realm.id, accountId: userId };
    const decision = {
      realmId: realm.id,
      approvalId: verifyApproval,
      approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(fixture.app, test.factor, decision);
    await engine.completeApproval(fixture.app, test.factor, {
      ...decision,
      response: test.answer(challenge, approver),
    });
    const verified = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/users/${account}/verification`,
      {},
      { 'if-match': '*', 'qauth-approval': verifyApproval }
    );
    expect(verified.statusCode, verified.body).toBe(200);
    const recorded = await fixture.app.dbPool.query<{ count: number }>(
      `SELECT count(*)::int AS count FROM events
        WHERE realm_id = $1 AND type = 'urn:qauth:event:user.verified:v1-rc.0'`,
      [realm.id]
    );
    expect(recorded.rows[0]?.count).toBe(1);

    // The pipeline audited every call, in the admin user's transactions.
    const { rows } = await fixture.app.dbPool.query<{ count: number }>(
      'SELECT count(*)::int AS count FROM admin_audit_log WHERE realm_id = $1',
      [realm.id]
    );
    expect(rows[0]?.count).toBeGreaterThan(0);
    expectNoPermissionError();
  });

  it('answers a CORS preflight on a process with no routes of its own as a path no route serves', async () => {
    for (const name of ['admin', 'signer', 'delivery']) {
      const preflight = await role(name).inject({
        method: 'OPTIONS',
        url: '/oauth/token',
        headers: { origin: 'https://app.example.com', 'access-control-request-method': 'POST' },
      });
      expect(preflight.statusCode, `${name}: ${preflight.body}`).toBe(404);
    }
    expectNoPermissionError();
  });

  it('answers what needs the signer on a process without it with 503, not a database error', async () => {
    if (!fixture) throw new Error('no fixture');
    const realm = await fixture.app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('the default realm was not booted');
    await fixture.app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: MACHINE_CLIENT_ID,
      clientSecretHash: await fixture.app.passwordHasher.hashPassword(CLIENT_SECRET),
      tokenEndpointAuthMethod: 'client_secret_post',
      name: 'Roles machine client',
      redirectUris: [],
      scopes: ['reports:read'],
      grantTypes: ['client_credentials'],
      enabled: true,
    });
    const token = await role('api').inject({
      method: 'POST',
      url: '/oauth/token',
      headers: FORM,
      payload: form({
        grant_type: 'client_credentials',
        scope: 'reports:read',
        client_id: MACHINE_CLIENT_ID,
        client_secret: CLIENT_SECRET,
      }),
    });
    expect(token.statusCode, token.body).toBe(503);
    // The legacy login's failure ladder needs the realm's cookie key.
    const login = await role('api').inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: EMAIL, password: 'not-the-password-of-this-account' },
    });
    expect(login.statusCode, login.body).toBe(503);

    const web = role('web');
    expect((await web.inject({ method: 'GET', url: '/ui/login' })).statusCode).toBe(503);
    expect((await web.inject({ method: 'GET', url: '/consents' })).statusCode).toBe(401);
    expectNoPermissionError();
  });
});
