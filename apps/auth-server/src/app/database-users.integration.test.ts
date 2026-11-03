import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

import {
  requireDockerOrSkip,
  startPostgresContainer,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  allowConsentScreen,
  baseEnvironment,
  bootAuthServer,
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
 * each of its jobs once and serves its routes; a permission error anywhere
 * fails the suite, which is how the map was filled.
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

const DB_LIB = path.resolve(process.cwd(), 'libs/infra/db');
const TSX_CLI = createRequire(path.join(DB_LIB, 'package.json')).resolve('tsx/cli');

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

/** What Postgres logs and answers when a user lacks a privilege. */
const PERMISSION_ERROR = /permission denied|insufficient_privilege|"code":"42501"/;

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
    for (const user of [...Object.values(USERS), WEB_SIGNER, API_SIGNER]) {
      await fixture.app.dbPool.query(`CREATE ROLE ${user} LOGIN PASSWORD '${user}'`);
    }
    // Each run names the five roles; a user it does not name keeps its
    // grants. The last two give a role's user and the signer's one user.
    await grant(USERS);
    await grant({ ...USERS, web: WEB_SIGNER, signer: WEB_SIGNER });
    await grant({ ...USERS, api: API_SIGNER, signer: API_SIGNER });

    // The signer first, as a deployment starts it. One at a time: each boot
    // sets the process environment its app reads.
    await boot('signer', ['signer'], USERS.signer);
    await boot('web', ['web'], USERS.web);
    await boot('api', ['api'], USERS.api);
    await boot('admin', ['admin'], USERS.admin);
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

  /** The suite's database URL, connecting as `user`. */
  function urlFor(user: string): string {
    if (!infra) throw new Error('infrastructure not started');
    const url = new URL(infra.postgres.connectionString);
    url.username = user;
    url.password = user;
    return url.toString();
  }

  /** Run `db:grants` as an operator runs it, as the owner of the tables. */
  async function grant(users: Readonly<Record<ServiceRole, string>>): Promise<void> {
    if (!infra) throw new Error('infrastructure not started');
    const child = spawn(process.execPath, [TSX_CLI, 'src/scripts/grant-database-users.ts'], {
      cwd: DB_LIB,
      env: {
        PATH: process.env['PATH'] ?? '',
        DATABASE_URL: infra.postgres.connectionString,
        DB_USER_WEB: users.web,
        DB_USER_API: users.api,
        DB_USER_ADMIN: users.admin,
        DB_USER_SIGNER: users.signer,
        DB_USER_DELIVERY: users.delivery,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
    const code = await new Promise<number | null>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', resolve);
    });
    if (code !== 0) throw new Error(`db:grants exited ${String(code)}:\n${output}`);
  }

  /**
   * Boot `roles` on `user`: a process with the signer keeps the key
   * variables and serves the signer; one without it gets the signer
   * service's settings instead, as a split deployment has them.
   */
  async function boot(name: string, roles: readonly ServiceRole[], user: string): Promise<void> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const base: Record<string, string> = {
      ...baseEnvironment(infra, jwt),
      DATABASE_URL: urlFor(user),
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
      logStream: { write: (line) => void log.push(line) },
    });
    processes.set(name, { server, roles, log });
  }

  function role(name: string): FastifyInstance {
    const found = processes.get(name);
    if (found === undefined) throw new Error(`no process ${name}`);
    return found.server.app;
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

  it('refuses a wrong password and registers a client on api alone, on its own user', async () => {
    const api = role('api');
    const login = await api.inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email: EMAIL, password: 'not-the-password-of-this-account' },
    });
    expect(login.statusCode, login.body).toBe(401);

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

    const web = role('web');
    expect((await web.inject({ method: 'GET', url: '/ui/login' })).statusCode).toBe(503);
    expect((await web.inject({ method: 'GET', url: '/consents' })).statusCode).toBe(401);
    expectNoPermissionError();
  });
});
