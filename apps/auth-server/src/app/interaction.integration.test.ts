import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyBaseLogger, FastifyInstance, LightMyRequestResponse } from 'fastify';
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
  pkcePair,
  registerPasswordAccount,
  resetE2eState,
  signInWithPassword,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { sessionIdOfCookie } from '../testing/session-cookie-value';
import type { InteractionDecision, InteractionState } from './helpers/interaction';
import type { InteractionStep } from './helpers/interaction-record';

/**
 * THE INTERACTION RECORD AND THE FLOW COOKIE ON A REAL REDIS AND POSTGRES
 * (#592, ADR-019 Decision 6).
 *
 * Each test boots the real auth server, empties its state and drives test
 * routes that call the interaction helpers the way the Interaction API's
 * routes will (#616, #628), through the app's realm resolver, error handler
 * and event store. It proves the issue's integration criteria: the id alone
 * reads the step but neither the personal data nor an answer; one browser's
 * cookie opens no other interaction; of two concurrent answers exactly one is
 * processed; the browser session id changes at authentication; an expired
 * interaction is refused and its expiry audited; a user switch starts a new
 * interaction for the same request, and one after authentication ends the
 * first user's session so no client gets SSO from it (#896), as "Not you?"
 * on an interaction started for an already signed-in browser does, while
 * "Use another account" at the account chooser leaves it signed in (#964); a
 * finish after that session was signed out is refused (#963); and no audit
 * row holds an id or a flow secret.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/**
 * Where the stand-in routes live: beside the Interaction API's own routes
 * (#616), which the app now registers at `/interaction/v1-rc.0`, under a
 * release candidate no route serves. The log censor and the bare problem
 * documents cover every `/interaction/v<N>-rc.<M>` path, so these paths get
 * the same treatment.
 */
const TEST_PREFIX = '/interaction/v1-rc.999';

const EMAIL = 'interaction-owner@example.com';
const FLOW_COOKIE = '__Host-qauth_flow';
/** `SESSION_COOKIE_NAME`, written out: importing it would load the env module first. */
const SESSION_COOKIE = '__Host-qauth_session';
const INTERACTION_TTL_SECONDS = 60;

const AUTHORIZE_REQUEST = {
  response_type: 'code' as const,
  client_id: 'interaction-client',
  redirect_uri: 'https://client.example.com/callback',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256' as const,
  state: 'af0ifjsldkj',
  scope: 'openid email',
  resource: undefined,
};

const PASSWORD_STEP: InteractionStep = {
  name: stepUrn('password'),
  params: {},
  alternatives: [stepUrn('identifier')],
};
const SELECT_ACCOUNT_STEP: InteractionStep = {
  name: stepUrn('select_account'),
  params: {},
  alternatives: [],
};
const CONSENT_STEP: InteractionStep = { name: stepUrn('consent'), params: {}, alternatives: [] };
const IDENTIFIER_STEP: InteractionStep = {
  name: stepUrn('identifier'),
  params: {},
  alternatives: [],
};

type DecisionSpec =
  | {
      kind: 'step';
      step: InteractionStep;
      /** The identifier the sign-in engine's transaction holds from now on (#964). */
      identifier?: string;
    }
  | { kind: 'authenticated'; userId: string; amr: string[]; step: InteractionStep }
  | { kind: 'finished' };

/** The states the engine stand-in saw: one per processed answer. */
const decided: InteractionState[] = [];

/** The test routes, on the Interaction API's own paths and surface. */
async function interactionRoutes(app: FastifyInstance): Promise<void> {
  // Imported here, after the boot reset the module registry, so these are the
  // instances the app loaded.
  const interaction = await import('./helpers/interaction');
  const browserSessions = await import('./helpers/browser-session');
  const { requestRealm } = await import('./helpers/request-realm');
  const browser = { config: { surface: 'browser' as const } };
  const idOf = (request: { params: unknown }) => (request.params as { id: string }).id;

  app.post('/test/interactions', browser, async (request, reply) => {
    const body = (request.body ?? {}) as {
      step?: InteractionStep;
      personal?: object;
      /** Carry the browser's session in, as `/oauth/authorize` does (#964). */
      carry?: boolean;
    };
    const session =
      body.carry === true ? await browserSessions.resolveBrowserSession(app, request, reply) : null;
    return interaction.startInteraction(request, reply, {
      request: AUTHORIZE_REQUEST,
      step: body.step ?? PASSWORD_STEP,
      ...(body.personal === undefined ? {} : { personal: body.personal as never }),
      ...(session === null ? {} : { carriedSession: { userId: session.userId, sid: session.sid } }),
    });
  });
  app.get(`${TEST_PREFIX}/:id`, browser, async (request) =>
    interaction.readInteractionStep(request, idOf(request))
  );
  app.get(`${TEST_PREFIX}/:id/personal`, browser, async (request) =>
    interaction.readInteractionPersonalData(request, idOf(request))
  );
  app.post(`${TEST_PREFIX}/:id/answer`, browser, async (request, reply) => {
    const { revision, decision, delayMs } = request.body as {
      revision: number;
      decision: DecisionSpec;
      delayMs?: number;
    };
    return interaction.answerInteraction(
      request,
      reply,
      { id: idOf(request), revision },
      async (state): Promise<InteractionDecision> => {
        decided.push(state);
        if (delayMs !== undefined) await new Promise((resolve) => setTimeout(resolve, delayMs));
        if (decision.kind === 'authenticated') {
          return {
            kind: 'authenticated',
            signIn: { userId: decision.userId, amr: decision.amr, identifier: EMAIL },
            step: decision.step,
          };
        }
        if (decision.kind === 'step' && decision.identifier !== undefined) {
          // As the engine answers an identifier: the next step, for it.
          return {
            kind: 'step',
            step: decision.step,
            signInTransaction: {
              v: 1,
              realmId: requestRealm(request).id,
              clientId: AUTHORIZE_REQUEST.client_id,
              createdAt: Date.now(),
              identifier: decision.identifier,
              verified: [],
            },
          };
        }
        return decision;
      }
    );
  });
  app.post(`${TEST_PREFIX}/:id/cancel`, browser, async (request, reply) =>
    interaction.cancelInteraction(request, reply, idOf(request))
  );
  app.post(`${TEST_PREFIX}/:id/switch`, browser, async (request, reply) =>
    interaction.switchInteractionUser(request, reply, idOf(request))
  );
}

/** One browser, driving the test routes with its own cookie jar. */
class Browser {
  readonly jar: CookieJar;
  /** Every flow cookie value the browser was given. */
  readonly flowValues: string[] = [];

  constructor(
    private readonly app: FastifyInstance,
    jar = new CookieJar()
  ) {
    this.jar = jar;
  }

  async request(method: 'GET' | 'POST', url: string, body?: object) {
    const cookie = this.jar.header();
    const response = await this.app.inject({
      method,
      url,
      headers: cookie === undefined ? {} : { cookie },
      ...(body === undefined ? {} : { payload: body }),
    });
    this.jar.absorb(response.headers['set-cookie']);
    const flow = this.jar.get(FLOW_COOKIE);
    if (flow !== undefined) this.flowValues.push(flow);
    return response;
  }

  async start(body: object = {}): Promise<string> {
    const response = await this.request('POST', '/test/interactions', body);
    expect(response.statusCode, response.body).toBe(200);
    return (response.json() as { id: string }).id;
  }

  read(id: string) {
    return this.request('GET', `${TEST_PREFIX}/${id}`);
  }

  personal(id: string) {
    return this.request('GET', `${TEST_PREFIX}/${id}/personal`);
  }

  answer(id: string, revision: number, decision: DecisionSpec, delayMs?: number) {
    return this.request('POST', `${TEST_PREFIX}/${id}/answer`, {
      revision,
      decision,
      delayMs,
    });
  }
}

/** A response with its per-request values blanked, for a byte-for-byte comparison. */
function comparable(response: LightMyRequestResponse) {
  const headers = { ...response.headers };
  for (const name of [
    'date',
    'x-request-id',
    'content-length',
    'x-ratelimit-remaining',
    'x-ratelimit-reset',
  ]) {
    delete headers[name];
  }
  if (typeof headers['content-security-policy'] === 'string') {
    headers['content-security-policy'] = headers['content-security-policy'].replace(
      /'nonce-[^']*'/g,
      "'nonce-X'"
    );
  }
  const traceId = (JSON.parse(response.body) as { trace_id?: string }).trace_id;
  return {
    status: response.statusCode,
    headers,
    body: traceId === undefined ? response.body : response.body.replace(traceId, 'TRACE'),
  };
}

describe('the interaction record and the flow cookie (#592, real containers)', () => {
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
    decided.length = 0;
  });

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  async function boot(): Promise<FastifyInstance> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), INTERACTION_TTL: String(INTERACTION_TTL_SECONDS) },
      { routes: interactionRoutes }
    );
    booted.push(server);
    await resetE2eState(server.app);
    return server.app;
  }

  /** The interaction events the event store holds, oldest first. */
  async function interactionEvents(app: FastifyInstance) {
    const { rows } = await app.dbPool.query<{
      type: string;
      data: Record<string, unknown>;
      client_id: string | null;
      subject_id: string | null;
      actor_type: string | null;
    }>(
      "SELECT type, data, client_id, subject_id, actor_type FROM events WHERE type LIKE 'urn:qauth:event:interaction.%' ORDER BY seq"
    );
    return rows;
  }

  it('lets the id without the cookie read the step, but not the personal data, and not answer', async () => {
    const app = await boot();
    const owner = new Browser(app);
    const id = await owner.start({
      step: SELECT_ACCOUNT_STEP,
      personal: { accounts: ['owner@x'] },
    });
    const holderOfId = new Browser(app);

    const read = await holderOfId.read(id);
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({ step: SELECT_ACCOUNT_STEP, revision: 0 });
    expect(read.body).not.toContain('owner@x');
    expect((await holderOfId.personal(id)).statusCode).toBe(410);
    expect((await holderOfId.answer(id, 0, { kind: 'finished' })).statusCode).toBe(410);
    expect(decided).toHaveLength(0);

    // The owner's cookie opens both, and its interaction was not touched.
    expect((await owner.personal(id)).json()).toEqual({
      step: SELECT_ACCOUNT_STEP.name,
      data: { accounts: ['owner@x'] },
      current: SELECT_ACCOUNT_STEP,
    });
    expect((await owner.answer(id, 0, { kind: 'step', step: CONSENT_STEP })).statusCode).toBe(200);
    expect(decided).toHaveLength(1);
  });

  it('lets the cookie of interaction A neither read nor answer interaction B', async () => {
    const app = await boot();
    const browserA = new Browser(app);
    const browserB = new Browser(app);
    await browserA.start();
    const idB = await browserB.start({
      step: SELECT_ACCOUNT_STEP,
      personal: { accounts: ['b@x'] },
    });

    expect((await browserA.personal(idB)).statusCode).toBe(410);
    expect((await browserA.answer(idB, 0, { kind: 'finished' })).statusCode).toBe(410);
    expect((await browserA.request('POST', `${TEST_PREFIX}/${idB}/cancel`)).statusCode).toBe(410);
    expect(decided).toHaveLength(0);
    expect((await browserB.personal(idB)).statusCode).toBe(200);
  });

  it('processes exactly one of two concurrent answers to one step', async () => {
    const app = await boot();
    const owner = new Browser(app);
    const id = await owner.start();

    const [first, second, readMeanwhile] = await Promise.all([
      owner.answer(id, 0, { kind: 'step', step: CONSENT_STEP }, 150),
      owner.answer(id, 0, { kind: 'step', step: CONSENT_STEP }, 150),
      new Promise<LightMyRequestResponse>((resolve) =>
        setTimeout(() => resolve(owner.read(id)), 50)
      ),
    ]);

    expect(decided).toHaveLength(1);
    expect([first.statusCode, second.statusCode]).toEqual([200, 200]);
    expect(
      [first.json(), second.json()].map((result) => (result as { kind: string }).kind).sort()
    ).toEqual(['stale', 'step']);
    // The interaction stayed readable while the engine worked on the answer.
    expect(readMeanwhile.statusCode).toBe(200);
    expect((await owner.read(id)).json()).toMatchObject({ step: CONSENT_STEP, revision: 1 });
    const answered = (await interactionEvents(app)).filter(
      (row) => row.type === 'urn:qauth:event:interaction.answered:v1-rc.0'
    );
    expect(answered).toHaveLength(1);
  });

  it('gives the browser a new session id when the user authenticates (session fixation)', async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    // The browser already holds a session: the one a fixation attack plants.
    const jar = await signInWithPassword(app, EMAIL);
    const sessionBefore = jar.get(SESSION_COOKIE);
    expect(sessionBefore).toBeDefined();
    const owner = new Browser(app, jar);
    const id = await owner.start();
    const flowBefore = owner.jar.get(FLOW_COOKIE);

    const answered = await owner.answer(id, 0, {
      kind: 'authenticated',
      userId,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });

    expect(answered.statusCode).toBe(200);
    const sessionAfter = owner.jar.get(SESSION_COOKIE);
    expect(sessionAfter).toBeDefined();
    const sidOf = (cookie: string | undefined) =>
      cookie === undefined ? undefined : sessionIdOfCookie(cookie);
    expect(sidOf(sessionAfter)).not.toBe(sidOf(sessionBefore));
    // The new session is a real one, in Postgres, for the user.
    const { rows } = await app.dbPool.query<{ id: string; user_id: string }>(
      'SELECT id, user_id FROM sessions WHERE id = $1',
      [sidOf(sessionAfter)]
    );
    expect(rows).toEqual([{ id: sidOf(sessionAfter), user_id: userId }]);
    // The flow binding rotated too: the old secret opens nothing.
    expect(owner.jar.get(FLOW_COOKIE)).not.toBe(flowBefore);
    const old = await app.inject({
      method: 'GET',
      url: `${TEST_PREFIX}/${id}/personal`,
      headers: { cookie: `${FLOW_COOKIE}=${flowBefore}` },
    });
    expect(old.statusCode).toBe(410);
    // The next answer sees the new session in the transaction.
    await owner.answer(id, 1, { kind: 'finished' });
    expect(decided.at(-1)?.transaction).toMatchObject({ userId, sid: sidOf(sessionAfter) });
  });

  it('refuses an interaction past its expiry, and the sweep audits the expiry once', async () => {
    const app = await boot();
    const owner = new Browser(app);
    const id = await owner.start();
    const live = await owner.start();
    const unknown = await owner.personal('Z'.repeat(43));
    const wrongCookie = await new Browser(app).personal(live);

    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + INTERACTION_TTL_SECONDS * 1000 + 1 });
    const read = await owner.read(id);
    const personal = await owner.personal(id);
    const answer = await owner.answer(id, 0, { kind: 'finished' });

    for (const response of [read, personal, answer]) expect(response.statusCode).toBe(410);
    expect(decided).toHaveLength(0);
    // Expired, unknown and a wrong cookie: the same answer, byte for byte.
    expect(comparable(personal)).toEqual(comparable(unknown));
    expect(comparable(personal)).toEqual(comparable(wrongCookie));

    const { createInteractionExpiryJob } = await import('./jobs/interaction-expiry');
    const job = createInteractionExpiryJob({ redis: app.redis, events: app.repositories.events });
    const log = { info: vi.fn(), warn: vi.fn() } as unknown as FastifyBaseLogger;
    const context = { signal: new AbortController().signal, now: () => Date.now(), log };
    await job.run(context);
    await job.run(context);

    const expired = (await interactionEvents(app)).filter(
      (row) => row.type === 'urn:qauth:event:interaction.expired:v1-rc.0'
    );
    expect(expired).toHaveLength(2);
    expect(expired[0]).toMatchObject({
      client_id: 'interaction-client',
      actor_type: 'system',
      data: { step: PASSWORD_STEP.name },
    });
    expect(await app.redis.keys('interaction*')).toEqual([]);
  });

  it('starts a new interaction for the same request on a user switch, and answers the old id as expired', async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    const owner = new Browser(app);
    const id = await owner.start();
    await owner.answer(id, 0, { kind: 'authenticated', userId, amr: ['pwd'], step: CONSENT_STEP });

    const switched = await owner.request('POST', `${TEST_PREFIX}/${id}/switch`);
    expect(switched.statusCode).toBe(200);
    const { kind, id: newId } = switched.json() as { kind: string; id: string };
    expect(kind).toBe('switched');

    const old = await owner.read(id);
    const unknown = await owner.read('Y'.repeat(43));
    expect(old.statusCode).toBe(410);
    expect(comparable(old)).toEqual(comparable(unknown));
    expect((await owner.read(newId)).json()).toMatchObject({
      step: { name: stepUrn('identifier') },
      revision: 0,
    });
    await owner.answer(newId, 0, { kind: 'finished' });
    const state = decided.at(-1);
    expect(state?.request).toEqual(AUTHORIZE_REQUEST);
    expect(state?.transaction).toEqual({ amr: [] });

    const events = await interactionEvents(app);
    const created = events.filter(
      (row) => row.type === 'urn:qauth:event:interaction.created:v1-rc.0'
    );
    expect(created).toHaveLength(2);
    expect(created[1]?.data).toMatchObject({
      step: stepUrn('identifier'),
      replaces: created[0]?.data['interaction'],
    });
    expect(
      events.find((row) => row.type === 'urn:qauth:event:interaction.cancelled:v1-rc.0')
    ).toMatchObject({ data: { reason: 'user_switch' }, subject_id: userId });
  });

  /**
   * A client `userId` already granted its scopes: with a live session,
   * `/oauth/authorize` answers it with a code at once. Its authorize request,
   * from a browser sending `cookie`.
   */
  async function grantedClient(app: FastifyInstance, userId: string) {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const scopes = AUTHORIZE_REQUEST.scope.split(' ');
    const client = await app.repositories.oauthClients.create({
      realmId: realm.id,
      clientId: AUTHORIZE_REQUEST.client_id,
      clientSecretHash: 'unused-public-client',
      tokenEndpointAuthMethod: 'none',
      name: 'Interaction client',
      redirectUris: [AUTHORIZE_REQUEST.redirect_uri],
      scopes,
      grantTypes: ['authorization_code', 'refresh_token'],
      enabled: true,
      requirePkce: true,
    });
    await app.repositories.oauthConsents.upsertGrant(realm.id, userId, client.id, scopes);
    return (cookie: string | undefined) =>
      app.inject({
        method: 'GET',
        url: `/oauth/authorize?${new URLSearchParams({
          response_type: 'code',
          client_id: AUTHORIZE_REQUEST.client_id,
          redirect_uri: AUTHORIZE_REQUEST.redirect_uri,
          scope: AUTHORIZE_REQUEST.scope,
          code_challenge: pkcePair().challenge,
          code_challenge_method: 'S256',
          state: AUTHORIZE_REQUEST.state,
        }).toString()}`,
        headers: cookie === undefined ? {} : { cookie },
      });
  }

  /** How the session `sid` stands in Postgres: ended or not, and why. */
  async function sessionEnd(app: FastifyInstance, sid: string) {
    const { rows } = await app.dbPool.query<{ revoked: boolean; revoked_reason: string | null }>(
      'SELECT revoked_at IS NOT NULL AS revoked, revoked_reason FROM sessions WHERE id = $1',
      [sid]
    );
    return rows[0];
  }

  it("ends the first user's session on a switch after authentication, so a client starting authorize afterwards gets no SSO from it (#896)", async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    const authorize = await grantedClient(app, userId);

    const owner = new Browser(app);
    const id = await owner.start();
    await owner.answer(id, 0, { kind: 'authenticated', userId, amr: ['pwd'], step: CONSENT_STEP });
    const firstCookie = owner.jar.get(SESSION_COOKIE);
    if (firstCookie === undefined) throw new Error('the authentication set no session cookie');
    const sid = sessionIdOfCookie(firstCookie);
    // The session signs the browser in: SSO gives the client a code.
    const before = await authorize(owner.jar.header());
    expect(before.statusCode).toBe(302);
    expect(new URL(before.headers['location'] as string).searchParams.get('code')).not.toBeNull();

    const switched = await owner.request('POST', `${TEST_PREFIX}/${id}/switch`);
    expect(switched.statusCode).toBe(200);
    expect(switched.json()).toMatchObject({ kind: 'switched' });

    // The session is ended for good, and its cookie cleared.
    const { rows } = await app.dbPool.query<{ revoked: boolean; revoked_reason: string | null }>(
      'SELECT revoked_at IS NOT NULL AS revoked, revoked_reason FROM sessions WHERE id = $1',
      [sid]
    );
    expect(rows).toEqual([{ revoked: true, revoked_reason: 'sign_out' }]);
    expect(String(switched.headers['set-cookie'])).toContain(`${SESSION_COOKIE}=;`);
    expect(owner.jar.get(SESSION_COOKIE)).toBeUndefined();

    // A client starting authorize afterwards gets the login page, not the
    // first user: from the browser as it is now, and from one that kept the
    // old cookie.
    for (const cookie of [owner.jar.header(), `${SESSION_COOKIE}=${firstCookie}`]) {
      const after = await authorize(cookie);
      expect(after.statusCode).toBe(302);
      expect(after.headers['location']).toMatch(/^\/ui\/login\?/);
    }

    // An event records it: the switch's cancel, about the first user.
    expect(
      (await interactionEvents(app)).find(
        (row) => row.type === 'urn:qauth:event:interaction.cancelled:v1-rc.0'
      )
    ).toMatchObject({
      data: { reason: 'user_switch', sessionEnded: true },
      subject_id: userId,
      actor_type: 'user',
    });
  });

  it('leaves a browser signed in before the interaction signed in on "Use another account" and on "Not you?" beside another account, and signs it out on "Not you?" beside its own (#964)', async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    const authorize = await grantedClient(app, userId);
    const owner = new Browser(app, await signInWithPassword(app, EMAIL));
    const cookie = owner.jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the sign-in set no session cookie');
    const sid = sessionIdOfCookie(cookie);
    const codeOf = (response: LightMyRequestResponse) =>
      new URL(String(response.headers['location'])).searchParams.get('code');

    // "Use another account", at the account chooser of an interaction started
    // for this browser: the account it lists stays signed in, and SSO with it.
    const chooser = await owner.start({ step: SELECT_ACCOUNT_STEP, carry: true });
    const another = await owner.request('POST', `${TEST_PREFIX}/${chooser}/switch`);
    expect(another.json()).toMatchObject({ kind: 'switched' });
    expect(await sessionEnd(app, sid)).toEqual({ revoked: false, revoked_reason: null });
    expect(owner.jar.get(SESSION_COOKIE)).toBe(cookie);
    expect(codeOf(await authorize(owner.jar.header()))).not.toBeNull();

    // "Not you?" next to another account's identifier, at the password step
    // of an interaction started for it: the screen does not show the
    // signed-in account, so it stays signed in.
    const other = await owner.start({ step: IDENTIFIER_STEP, carry: true });
    await owner.answer(other, 0, {
      kind: 'step',
      step: PASSWORD_STEP,
      identifier: 'someone-else@example.com',
    });
    const notThem = await owner.request('POST', `${TEST_PREFIX}/${other}/switch`);
    expect(notThem.json()).toMatchObject({ kind: 'switched' });
    expect(await sessionEnd(app, sid)).toEqual({ revoked: false, revoked_reason: null });
    expect(owner.jar.get(SESSION_COOKIE)).toBe(cookie);

    // "Not you?" next to its own identifier: the browser is signed out, and
    // the client gets the login page.
    const id = await owner.start({ step: IDENTIFIER_STEP, carry: true });
    await owner.answer(id, 0, { kind: 'step', step: PASSWORD_STEP, identifier: EMAIL });
    const notYou = await owner.request('POST', `${TEST_PREFIX}/${id}/switch`);
    expect(notYou.json()).toMatchObject({ kind: 'switched' });
    expect(await sessionEnd(app, sid)).toEqual({ revoked: true, revoked_reason: 'sign_out' });
    expect(owner.jar.get(SESSION_COOKIE)).toBeUndefined();
    for (const sent of [owner.jar.header(), `${SESSION_COOKIE}=${cookie}`]) {
      expect((await authorize(sent)).headers['location']).toMatch(/^\/ui\/login\?/);
    }

    const cancelled = (await interactionEvents(app)).filter(
      (row) => row.type === 'urn:qauth:event:interaction.cancelled:v1-rc.0'
    );
    expect(cancelled.map((row) => [row.data['sessionEnded'], row.subject_id])).toEqual([
      [undefined, null],
      [undefined, null],
      [true, userId],
    ]);
  });

  it('refuses to finish an interaction whose session was signed out after its sign-in (#963)', async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('default realm missing');
    const owner = new Browser(app);
    const id = await owner.start();
    await owner.answer(id, 0, { kind: 'authenticated', userId, amr: ['pwd'], step: CONSENT_STEP });
    const cookie = owner.jar.get(SESSION_COOKIE);
    if (cookie === undefined) throw new Error('the authentication set no session cookie');
    const sid = sessionIdOfCookie(cookie);
    // Another request ends the session the sign-in started: a sign-out in
    // another tab.
    await app.sessionService.revoke({
      realmId: realm.id,
      sid,
      reason: 'sign_out',
      actor: { type: 'user', id: userId },
      userId,
    });

    const refused = await owner.answer(id, 1, { kind: 'finished' });

    // The engine decided the finish, and the answer an ended interaction
    // gets came back instead: nothing finished, so no request completes.
    expect(decided).toHaveLength(2);
    expect(refused.statusCode).toBe(410);
    expect(refused.json()).toMatchObject({ code: 'interaction_expired' });
    expect(
      (await interactionEvents(app))
        .filter((row) => row.type === 'urn:qauth:event:interaction.answered:v1-rc.0')
        .map((row) => row.data['outcome'])
    ).toEqual(['authenticated']);
    // The session keeps its revocation.
    const { rows } = await app.dbPool.query<{ revoked: boolean; revoked_reason: string | null }>(
      'SELECT revoked_at IS NOT NULL AS revoked, revoked_reason FROM sessions WHERE id = $1',
      [sid]
    );
    expect(rows).toEqual([{ revoked: true, revoked_reason: 'sign_out' }]);
  });

  it('writes audit rows for create, answer and cancel that hold neither the id nor the cookie', async () => {
    const app = await boot();
    const userId = await registerPasswordAccount(app, EMAIL);
    const owner = new Browser(app);
    const first = await owner.start();
    await owner.answer(first, 0, {
      kind: 'authenticated',
      userId,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });
    await owner.answer(first, 1, { kind: 'finished' });
    const second = await owner.start();
    await owner.request('POST', `${TEST_PREFIX}/${second}/cancel`);

    const types = (await interactionEvents(app)).map((row) => row.type);
    expect(types).toEqual([
      'urn:qauth:event:interaction.created:v1-rc.0',
      'urn:qauth:event:interaction.answered:v1-rc.0',
      'urn:qauth:event:interaction.answered:v1-rc.0',
      'urn:qauth:event:interaction.created:v1-rc.0',
      'urn:qauth:event:interaction.cancelled:v1-rc.0',
    ]);

    const { rows } = await app.dbPool.query<{ row: string }>(
      'SELECT row_to_json(events)::text AS row FROM events'
    );
    const audited = rows.map((row) => row.row).join('\n');
    const secrets = [
      first,
      second,
      ...owner.flowValues.flatMap((value) => value.split('.')),
    ].filter((value) => value.length === 43);
    expect(secrets.length).toBeGreaterThanOrEqual(4);
    for (const secret of secrets) expect(audited).not.toContain(secret);
    // Nor anywhere in Redis: the record is keyed by the id's hash.
    const redisKeys = (await app.redis.keys('*')).join('\n');
    for (const secret of secrets) expect(redisKeys).not.toContain(secret);
  });
});
