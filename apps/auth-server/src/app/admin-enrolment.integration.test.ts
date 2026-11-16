import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  CookieJar,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { softPasskey } from '../testing/soft-passkey';
import type { BreakGlassHost } from './helpers/break-glass-host';

/**
 * THE ONE-TIME ADMIN ENROLMENT (#621; ADR-019 Decision 7,
 * `graphs/flows/core/admin-enrolment`), end to end against real Postgres and
 * Redis: the break-glass CLI's `enrol-admin` prints the URL, the ceremony
 * app's page posts its token to `POST /auth/admin-enrolment`, and the
 * Interaction API's `admin_enrolment` step registers the account's first
 * passkey. The passkey is a software authenticator
 * (`testing/soft-passkey.ts`) whose registration the server's own WebAuthn
 * verifier checks. It proves the issue's criteria:
 *
 * - The CLI's token enrols a passkey, and a second use fails: after the
 *   enrolment, and for a second browser that started with the same token.
 * - The enrolled admin has no password, and cannot approve for 7 days from
 *   its enrolment (the two-admin rule's rule 3, read at a given clock).
 * - An expired token is refused with the same answer as an unknown one, a
 *   used one and a damaged one.
 *
 * And the step's own rules: a registration without user verification is
 * refused with a new ceremony and leaves the token unspent, a cancel leaves
 * it unspent, and a start from another origin is refused.
 *
 * The CLI runs over a database plugin of its own, as its process registers
 * one, beside the booted server (as `break-glass.integration.test.ts` runs
 * it). App modules are imported after each boot, so they are the instances
 * the server loaded.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ORIGIN = 'https://auth.example.com';
const RP_ID = 'auth.example.com';
const ADMIN_ENROLMENT = stepUrn('admin_enrolment');
const FORM = { 'content-type': 'application/x-www-form-urlencoded' };
/** A post from a page of the realm origin, as the ceremony app's pages send it. */
const SAME_ORIGIN = { origin: ORIGIN, 'sec-fetch-site': 'same-origin' };
const OPERATOR = Object.freeze({
  name: 'break-glass-operator',
  uid: 4242,
  loginUid: 1000,
  sudoUser: 'alice',
  host: 'db-host-1',
});
const DAY = 24 * 60 * 60 * 1000;
const WINDOW = 7 * DAY;

/** The step view the ceremony page reads. */
interface StepView {
  readonly step: string;
  readonly csrf: string;
  readonly alternatives?: readonly string[];
  readonly params?: Record<string, Record<string, unknown>>;
  readonly error?: string;
}

/** An enrolment in progress: its browser and its interaction id. */
interface Flow {
  readonly jar: CookieJar;
  readonly id: string;
}

describe('the one-time admin enrolment (#621, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];
  /** The database plugins of the CLI, closed after each test. */
  const commandDatabases: FastifyInstance[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    const server = await bootAuthServer(variables());
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.app.redis.flushdb();
    await server.close();
  }, 120_000);

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await Promise.all(commandDatabases.splice(0).map(async (database) => database.close()));
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /**
   * A deployment whose store holds the keys, as the CLI's custody proof
   * needs, with passkey sign-in on, so the admin can sign in afterwards.
   */
  function variables(): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const environment: Record<string, string> = {
      ...baseEnvironment(infra, jwt),
      WEBAUTHN_ENABLED: 'true',
    };
    delete environment['JWT_PRIVATE_KEY'];
    delete environment['JWT_PUBLIC_KEY'];
    return environment;
  }

  async function boot(): Promise<FastifyInstance> {
    const server = await bootAuthServer(variables());
    booted.push(server);
    return server.app;
  }

  async function realmOf(app: FastifyInstance) {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error(`no realm ${E2E_REALM_NAME}`);
    return realm;
  }

  /**
   * `enrol-admin` over a database plugin of its own, as the CLI process
   * registers it, and the booted server's Redis and session service: the
   * token of the URL it printed, and the account it made.
   */
  async function enrolAdmin(
    app: FastifyInstance,
    ...extra: string[]
  ): Promise<{ readonly token: string; readonly accountId: string }> {
    const { breakGlassDependencies } = await import('./helpers/break-glass-host');
    const { parseBreakGlassArguments, runBreakGlass } = await import('./helpers/break-glass');
    const { ADMIN_ROLE_CATALOG } = await import('./helpers/admin-roles');
    const { env } = await import('../config/env');
    const database = Fastify({ logger: false });
    commandDatabases.push(database);
    await database.register(databasePlugin, {
      config: { connectionString: variables()['DATABASE_URL'] ?? '', pool: { max: 2, min: 0 } },
      adminRoleCatalog: ADMIN_ROLE_CATALOG,
    });
    await database.ready();
    const host: BreakGlassHost = {
      db: database.db,
      log: database.log,
      repositories: database.repositories,
      redis: app.redis,
      sessionService: app.sessionService,
    };
    const out: string[] = [];
    const err: string[] = [];
    const deps = breakGlassDependencies(host, {
      kekEnv: process.env,
      signing: {
        enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        hybridSigning: env.HYBRID_SIGNING_ENABLED,
      },
      operator: () => OPERATOR,
      out: (line) => out.push(line),
      err: (line) => err.push(line),
    });
    const command = parseBreakGlassArguments([
      'enrol-admin',
      '--realm',
      E2E_REALM_NAME,
      '--role',
      'security-admin',
      ...extra,
    ]);
    if (command === 'help') throw new Error('not a command');
    expect(await runBreakGlass(command, deps)).toBe(0);
    expect(err).toEqual([]);
    const line = out.find((printed) => printed.includes('#token='));
    if (line === undefined) throw new Error('no enrolment URL printed');
    const url = line.trim();
    expect(url.startsWith(`${ORIGIN}/ui/admin-enrolment#token=`)).toBe(true);
    const token = url.slice(url.indexOf('#token=') + '#token='.length);
    // The enrolment holds the token's hash alone.
    const { rows } = await app.dbPool.query<{ user_id: string }>(
      'SELECT user_id FROM admin_enrolments WHERE token_hash = $1',
      [createHash('sha256').update(Buffer.from(token, 'base64url')).digest()]
    );
    const accountId = rows[0]?.user_id;
    if (accountId === undefined) throw new Error('no enrolment holds the printed token');
    return { token, accountId };
  }

  /** The enrolment page's form post of `token`, from a browser with `jar`. */
  async function postToken(
    app: FastifyInstance,
    token: string,
    jar = new CookieJar(),
    headers: Record<string, string> = SAME_ORIGIN
  ): Promise<LightMyRequestResponse> {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/admin-enrolment',
      headers: { ...FORM, ...headers },
      payload: new URLSearchParams({ token }).toString(),
    });
    jar.absorb(response.headers['set-cookie']);
    return response;
  }

  /** The path of a redirect, without the realm origin. */
  function locationOf(response: LightMyRequestResponse): string {
    expect(response.statusCode, response.body).toBe(303);
    const location = String(response.headers['location']);
    return location.startsWith(`${ORIGIN}/`) ? location.slice(ORIGIN.length) : location;
  }

  /** A start that must lead to the ceremony page of a new interaction. */
  async function start(app: FastifyInstance, token: string): Promise<Flow> {
    const jar = new CookieJar();
    const location = locationOf(await postToken(app, token, jar));
    expect(location.startsWith(CEREMONY_PAGE_PREFIX), location).toBe(true);
    return { jar, id: location.slice(CEREMONY_PAGE_PREFIX.length) };
  }

  /** The step read, as the ceremony app's server makes it: the id alone, no cookie. */
  async function read(app: FastifyInstance, id: string): Promise<StepView> {
    const response = await app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
    expect(response.statusCode, response.body).toBe(200);
    return response.json();
  }

  /** The step's options and user entity: what the page hands the browser's ceremony. */
  async function ceremonyOf(app: FastifyInstance, flow: Flow) {
    const view = await read(app, flow.id);
    expect(view.step).toBe(ADMIN_ENROLMENT);
    const options = view.params?.[ADMIN_ENROLMENT]?.['options'] as {
      readonly challenge: string;
      readonly rp: { readonly id: string; readonly name: string };
    };
    const response = await app.inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${flow.id}/personal`,
      headers: { cookie: flow.jar.header() ?? '' },
    });
    expect(response.statusCode, response.body).toBe(200);
    const personal = response.json<{ data: Record<string, { user: { id: string } }> }>().data;
    const user = personal[ADMIN_ENROLMENT]?.user as { id: string; name: string };
    return { view, options, user };
  }

  /** Answer the step with a form post from the ceremony page. */
  async function answer(
    app: FastifyInstance,
    flow: Flow,
    fields: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const { csrf } = await read(app, flow.id);
    const response = await app.inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${flow.id}/answer`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: flow.jar.header() ?? '' },
      payload: new URLSearchParams({ type: ADMIN_ENROLMENT, csrf, ...fields }).toString(),
    });
    flow.jar.absorb(response.headers['set-cookie']);
    return response;
  }

  async function credentialsOf(app: FastifyInstance, userId: string) {
    const { rows } = await app.dbPool.query<{ provider_type: string; external_sub: string }>(
      'SELECT provider_type, external_sub FROM user_credentials WHERE user_id = $1',
      [userId]
    );
    return rows;
  }

  async function usedAtOf(app: FastifyInstance, userId: string): Promise<number | null> {
    const { rows } = await app.dbPool.query<{ used_at: string | null }>(
      'SELECT used_at FROM admin_enrolments WHERE user_id = $1',
      [userId]
    );
    return rows[0]?.used_at === null || rows[0] === undefined ? null : Number(rows[0].used_at);
  }

  async function eventsOf(app: FastifyInstance, type: string, userId: string) {
    const { rows } = await app.dbPool.query<{ data: Record<string, unknown>; category: string }>(
      'SELECT data, category FROM events WHERE type = $1 AND subject_id = $2 ORDER BY seq',
      [`urn:qauth:event:${type}:v1-rc.0`, userId]
    );
    return rows;
  }

  /** What a browser is shown: the parts of an answer every refusal must share. */
  function shownOf(response: LightMyRequestResponse) {
    return {
      status: response.statusCode,
      type: response.headers['content-type'],
      cacheControl: response.headers['cache-control'],
      referrerPolicy: response.headers['referrer-policy'],
      setsCookie: response.headers['set-cookie'] !== undefined,
      body: response.body,
    };
  }

  it('enrols a passkey with the CLI token, stores no password, and a second use fails', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const { token, accountId } = await enrolAdmin(app);
    expect(await credentialsOf(app, accountId)).toEqual([]);

    // Two browsers start with the same token: starting spends nothing.
    const flow = await start(app, token);
    const other = await start(app, token);
    expect(await usedAtOf(app, accountId)).toBeNull();

    const { view, options, user } = await ceremonyOf(app, flow);
    expect(view.alternatives).toEqual([]);
    expect(options).toMatchObject({
      rp: { id: RP_ID },
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
    });
    expect(user.name).toMatch(/^admin-/);
    const passkey = softPasskey(RP_ID, user.id);
    const enrolled = await answer(app, flow, { webauthn_response: passkey.create(options) });
    expect(locationOf(enrolled)).toBe('/auth/admin-enrolment/status?result=enrolled');

    // One passkey, no password, the token spent.
    expect(await credentialsOf(app, accountId)).toEqual([
      { provider_type: 'webauthn', external_sub: passkey.credentialId },
    ]);
    expect(await usedAtOf(app, accountId)).not.toBeNull();
    const added = await eventsOf(app, 'user.credential_added', accountId);
    expect(added).toHaveLength(1);
    expect(added[0]?.data).toMatchObject({ type: 'passkey' });
    const completed = await eventsOf(app, 'admin.enrolment_completed', accountId);
    expect(completed).toEqual([{ category: 'admin', data: { credentialId: expect.any(String) } }]);
    // The admin events still form one chain.
    expect((await app.repositories.events.verifyChain(realm.id)).ok).toBe(true);

    // The page it ends on.
    const page = await app.inject({
      method: 'GET',
      url: '/auth/admin-enrolment/status?result=enrolled',
    });
    expect(page.statusCode).toBe(200);
    expect(page.body).toContain('Your passkey is registered');

    // The second browser's passkey is refused: the token is spent. Nothing
    // is stored, and the interaction ends as refused.
    const second = await ceremonyOf(app, other);
    const late = softPasskey(RP_ID, second.user.id);
    const refused = await answer(app, other, { webauthn_response: late.create(second.options) });
    expect(locationOf(refused)).toBe('/auth/admin-enrolment/status?result=refused');
    expect(await credentialsOf(app, accountId)).toHaveLength(1);

    // A new start with the used token is refused, and starts nothing.
    const again = await postToken(app, token);
    expect(again.statusCode).toBe(400);
    expect(again.headers['set-cookie']).toBeUndefined();
    expect(again.body).toContain('This enrolment link is no longer valid');
  }, 180_000);

  it('leaves the enrolled admin with no password and unable to approve for 7 days from its enrolment', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const { token, accountId } = await enrolAdmin(app);
    const flow = await start(app, token);
    const { options, user } = await ceremonyOf(app, flow);
    const before = Date.now();
    const enrolled = await answer(app, flow, {
      webauthn_response: softPasskey(RP_ID, user.id).create(options),
    });
    expect(locationOf(enrolled)).toBe('/auth/admin-enrolment/status?result=enrolled');

    const providers = (await credentialsOf(app, accountId)).map((row) => row.provider_type);
    expect(providers).toEqual(['webauthn']);
    expect(providers).not.toContain('password');

    // The enrolment moved the grant's security change: the window runs
    // from it, whatever the account's and the grant's creation.
    const { approverRefusal, loadApprover } = await import('./admin/approvals/two-admin');
    const loaded = await loadApprover(app, { realmId: realm.id, accountId, kind: 'human' }, realm);
    if (loaded === undefined) throw new Error('the enrolled account is not found');
    const { record } = loaded;
    const changed = Math.max(...record.grants.map((grant) => grant.lastSecurityChangeAt));
    expect(changed).toBeGreaterThanOrEqual(before - 1_000);
    const made = Math.max(record.createdAt, ...record.grants.map((grant) => grant.createdAt));
    expect(changed).toBeGreaterThanOrEqual(made);
    const requester = { realmId: realm.id, accountId: randomUUID(), kind: 'human' as const };
    const refusalAt = (at: number) =>
      approverRefusal(record, { realmId: realm.id, requester, createdAt: at }, realm, at);
    for (const at of [changed + 1, changed + DAY, changed + WINDOW - 1]) {
      expect(refusalAt(at)).not.toBeNull();
    }
    expect(refusalAt(changed + WINDOW - 1)).toBe('security-change');
    expect(refusalAt(changed + WINDOW)).toBeNull();
  }, 180_000);

  it('refuses an expired token with the same answer as an unknown, a used and a damaged one', async () => {
    const app = await boot();
    const used = await enrolAdmin(app);
    const flow = await start(app, used.token);
    const { options, user } = await ceremonyOf(app, flow);
    await answer(app, flow, { webauthn_response: softPasskey(RP_ID, user.id).create(options) });
    expect(await usedAtOf(app, used.accountId)).not.toBeNull();

    // An enrolment of one minute, read two minutes on.
    const expiring = await enrolAdmin(app, '--expires-in', '1');
    const unknown = randomBytes(32).toString('base64url');
    const damaged = expiring.token.slice(1);

    const usedAnswer = shownOf(await postToken(app, used.token));
    const unknownAnswer = shownOf(await postToken(app, unknown));
    const damagedAnswer = shownOf(await postToken(app, damaged));
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 2 * 60_000 });
    const expiredAnswer = shownOf(await postToken(app, expiring.token));
    vi.useRealTimers();

    expect(expiredAnswer.status).toBe(400);
    expect(expiredAnswer.setsCookie).toBe(false);
    expect(expiredAnswer.cacheControl).toBe('no-store');
    expect(expiredAnswer.referrerPolicy).toBe('no-referrer');
    expect(expiredAnswer).toEqual(unknownAnswer);
    expect(usedAnswer).toEqual(unknownAnswer);
    expect(damagedAnswer).toEqual(unknownAnswer);
    // The expired token was read, not spent; it stays refused.
    expect(await usedAtOf(app, expiring.accountId)).toBeNull();
    expect(await credentialsOf(app, expiring.accountId)).toEqual([]);
  }, 180_000);

  it('refuses a passkey that did not verify the user, with a new ceremony, and leaves the token unspent', async () => {
    const app = await boot();
    const { token, accountId } = await enrolAdmin(app);
    const flow = await start(app, token);
    const first = await ceremonyOf(app, flow);
    const passkey = softPasskey(RP_ID, first.user.id);

    const unverified = await answer(app, flow, {
      webauthn_response: passkey.create(first.options, { userVerified: false }),
    });
    expect(locationOf(unverified)).toBe(`${CEREMONY_PAGE_PREFIX}${flow.id}`);
    const shown = await ceremonyOf(app, flow);
    expect(shown.view.error).toBe('invalid_credentials');
    expect(shown.options.challenge).not.toBe(first.options.challenge);
    // The same account, the same handle.
    expect(shown.user.id).toBe(first.user.id);
    expect(await credentialsOf(app, accountId)).toEqual([]);
    expect(await usedAtOf(app, accountId)).toBeNull();

    // The new ceremony, answered with user verification, enrols.
    const enrolled = await answer(app, flow, {
      webauthn_response: passkey.create(shown.options),
    });
    expect(locationOf(enrolled)).toBe('/auth/admin-enrolment/status?result=enrolled');
    expect(await credentialsOf(app, accountId)).toHaveLength(1);
  }, 180_000);

  it('leaves the token unspent on a cancel, and refuses a start from another origin', async () => {
    const app = await boot();
    const { token, accountId } = await enrolAdmin(app);

    const crossSite = await postToken(app, token, new CookieJar(), {
      origin: 'https://attacker.example',
      'sec-fetch-site': 'cross-site',
    });
    expect(crossSite.statusCode).toBe(403);
    expect(crossSite.headers['set-cookie']).toBeUndefined();

    const flow = await start(app, token);
    const { csrf } = await read(app, flow.id);
    const cancelled = await app.inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${flow.id}/cancel`,
      headers: { ...FORM, ...SAME_ORIGIN, cookie: flow.jar.header() ?? '' },
      payload: new URLSearchParams({ csrf }).toString(),
    });
    expect(locationOf(cancelled)).toBe('/auth/admin-enrolment/status?result=cancelled');
    expect(await usedAtOf(app, accountId)).toBeNull();

    // The URL works again until it expires.
    const again = await start(app, token);
    const { options, user } = await ceremonyOf(app, again);
    const enrolled = await answer(app, again, {
      webauthn_response: softPasskey(RP_ID, user.id).create(options),
    });
    expect(locationOf(enrolled)).toBe('/auth/admin-enrolment/status?result=enrolled');
  }, 180_000);
});
