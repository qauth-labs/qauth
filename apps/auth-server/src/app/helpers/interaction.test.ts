import { Writable } from 'node:stream';

import { InvalidRequestError } from '@qauth-labs/shared-errors';
import { INTERACTION_API_PREFIX, stepUrn } from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: true,
    INTERACTION_TTL: 1800,
  },
}));

vi.mock('./user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./user-events')>();
  const { checkedEmitUserEvent } = await import('../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { buildLoggerOptions } from '../../config/logger';
import { createBrowserSessionFixture, sessionCookie } from '../../testing/browser-sessions';
import { createMemoryInteractionRedis } from '../../testing/interaction-redis';
import { supplyRequestRealm, testRealm } from '../../testing/request-realm';
import { REDIS_KEYS } from '../constants';
import errorHandler from '../plugins/error-handler';
import {
  answerInteraction,
  cancelInteraction,
  type InteractionDecision,
  type InteractionState,
  readInteractionPersonalData,
  readInteractionStep,
  startInteraction,
  switchInteractionUser,
} from './interaction';
import {
  IDENTIFIER_STEP,
  interactionIdHash,
  type InteractionStep,
  readInteractionRecord,
  takeInteractionTurn,
  writeInteractionState,
} from './interaction-record';
import { answerRouteNotFound } from './request-bounds';
import { SESSION_COOKIE_NAME, verifySignedSessionId } from './session-cookie';
import { emitUserEvent } from './user-events';

/**
 * THE INTERACTION RECORD AND THE FLOW COOKIE (#592, ADR-019 Decision 6), as
 * unit tests on an in-memory Redis: who may read and answer an interaction,
 * the one generic refusal, the taking of the state, the rotation at
 * authentication, the user switch, and what reaches the log and the events.
 *
 * The routes below are test routes that call the helpers as the Interaction
 * API's routes will (#616, #628); the container suite
 * (`interaction.integration.test.ts`) drives the same rules on a real Redis
 * and Postgres.
 */

const REALM = testRealm({ id: '22222222-2222-4222-8222-222222222222' });
const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '33333333-3333-4333-8333-333333333333';
const FLOW_COOKIE = '__Host-qauth_flow';

const AUTHORIZE_REQUEST = {
  response_type: 'code' as const,
  client_id: 'notes-app',
  redirect_uri: 'https://notes.example.com/callback',
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

/** A decision as a test sends it in a request body. */
type DecisionSpec =
  | { kind: 'step'; step: InteractionStep; amr?: string[] }
  | {
      kind: 'authenticated';
      userId: string;
      amr: string[];
      step: InteractionStep;
      personal?: Record<string, unknown>;
    }
  | { kind: 'finished' };

interface Harness {
  app: FastifyInstance;
  redis: ReturnType<typeof createMemoryInteractionRedis>;
  sessions: ReturnType<typeof createBrowserSessionFixture>;
  /** The states `decide` saw, in order: one per processed answer. */
  decided: InteractionState[];
  /** Run inside `decide`, for a test that acts while the engine works. */
  duringDecide: { action?: () => Promise<void> };
  logs: string[];
}

let harness: Harness;

async function buildHarness(): Promise<Harness> {
  const logs: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      logs.push(chunk.toString());
      callback();
    },
  });
  const loggerOptions = buildLoggerOptions({
    LOG_LEVEL: 'debug',
    LOG_PRETTY: false,
    NODE_ENV: 'test',
  }) as Exclude<ReturnType<typeof buildLoggerOptions>, boolean | undefined>;
  const app = Fastify({ logger: { ...loggerOptions, stream } });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(errorHandler);
  app.setNotFoundHandler(answerRouteNotFound);
  supplyRequestRealm(app, REALM);
  const sessions = createBrowserSessionFixture();
  const redis = createMemoryInteractionRedis(sessions.redis);
  app.decorate('redis', redis as unknown as FastifyInstance['redis']);
  app.decorate('sessionService', sessions.service);
  const decided: InteractionState[] = [];
  const duringDecide: Harness['duringDecide'] = {};

  app.post('/start', async (request, reply) => {
    const body = (request.body ?? {}) as {
      step?: InteractionStep;
      personal?: object;
      request?: object;
    };
    return startInteraction(request, reply, {
      request: {
        ...AUTHORIZE_REQUEST,
        ...((request.query as object) ?? {}),
        ...(body.request ?? {}),
      },
      step: body.step ?? PASSWORD_STEP,
      ...(body.personal === undefined ? {} : { personal: body.personal as never }),
    });
  });
  app.get(`${INTERACTION_API_PREFIX}/:id`, async (request) =>
    readInteractionStep(request, (request.params as { id: string }).id)
  );
  app.get(`${INTERACTION_API_PREFIX}/:id/personal`, async (request) =>
    readInteractionPersonalData(request, (request.params as { id: string }).id)
  );
  app.post(`${INTERACTION_API_PREFIX}/:id/answer`, async (request, reply) => {
    const { revision, decision, delayMs } = request.body as {
      revision: number;
      decision: DecisionSpec;
      delayMs?: number;
    };
    return answerInteraction(
      request,
      reply,
      { id: (request.params as { id: string }).id, revision },
      async (state): Promise<InteractionDecision> => {
        decided.push(state);
        const action = duringDecide.action;
        duringDecide.action = undefined;
        if (action !== undefined) await action();
        if (delayMs !== undefined) await new Promise((resolve) => setTimeout(resolve, delayMs));
        if (decision.kind === 'authenticated') {
          return {
            kind: 'authenticated',
            signIn: { userId: decision.userId, amr: decision.amr, identifier: 'alice@example.com' },
            step: decision.step,
            ...(decision.personal === undefined ? {} : { personal: decision.personal }),
          };
        }
        return decision;
      }
    );
  });
  app.post(`${INTERACTION_API_PREFIX}/:id/fail`, async () => {
    throw new InvalidRequestError('the answer names a field twice');
  });
  app.post(`${INTERACTION_API_PREFIX}/:id/cancel`, async (request, reply) =>
    cancelInteraction(request, reply, (request.params as { id: string }).id)
  );
  app.post(`${INTERACTION_API_PREFIX}/:id/switch`, async (request, reply) =>
    switchInteractionUser(request, reply, (request.params as { id: string }).id)
  );
  await app.ready();
  return { app, redis, sessions, decided, duringDecide, logs };
}

/** A browser: its cookie jar, replayed on every request. */
class Browser {
  readonly cookies = new Map<string, string>();
  /** Every cookie value the browser was ever given. */
  readonly seen: string[] = [];

  absorb(response: LightMyRequestResponse): void {
    const header = response.headers['set-cookie'];
    for (const line of header === undefined ? [] : Array.isArray(header) ? header : [header]) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      if (/Max-Age=0/.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, value);
      if (value.length > 0) this.seen.push(value);
    }
  }

  get header(): Record<string, string> {
    const cookie = [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
    return cookie.length === 0 ? {} : { cookie };
  }

  async request(
    method: 'GET' | 'POST',
    url: string,
    body?: object,
    query?: Record<string, string>
  ): Promise<LightMyRequestResponse> {
    const response = await harness.app.inject({
      method,
      url,
      headers: this.header,
      ...(body === undefined ? {} : { payload: body }),
      ...(query === undefined ? {} : { query }),
    });
    this.absorb(response);
    return response;
  }

  async start(body: object = {}, query?: Record<string, string>): Promise<string> {
    const response = await this.request('POST', '/start', body, query);
    expect(response.statusCode, response.body).toBe(200);
    return (response.json() as { id: string }).id;
  }

  answer(id: string, revision: number, decision: DecisionSpec, delayMs?: number) {
    return this.request('POST', `${INTERACTION_API_PREFIX}/${id}/answer`, {
      revision,
      decision,
      delayMs,
    });
  }
}

/** The response with its per-request values blanked, for a byte-for-byte comparison. */
function comparable(response: LightMyRequestResponse) {
  const body = JSON.parse(response.body) as Record<string, unknown>;
  const headers = { ...response.headers };
  delete headers['date'];
  delete headers['content-length'];
  return {
    status: response.statusCode,
    headers,
    body: response.body.replace(JSON.stringify(body['trace_id']), '"TRACE"'),
  };
}

beforeEach(async () => {
  vi.mocked(emitUserEvent).mockClear();
  harness = await buildHarness();
});

afterEach(async () => {
  vi.useRealTimers();
  await harness.app.close();
});

describe('who may read and answer an interaction (#592)', () => {
  it('lets the id alone read the step, but not the personal data, and not answer, cancel or switch', async () => {
    const owner = new Browser();
    const id = await owner.start({ step: SELECT_ACCOUNT_STEP, personal: { accounts: ['a@x'] } });
    const stranger = new Browser();

    const read = await stranger.request('GET', `${INTERACTION_API_PREFIX}/${id}`);
    expect(read.statusCode).toBe(200);
    expect(read.json()).toMatchObject({
      step: SELECT_ACCOUNT_STEP,
      clientId: 'notes-app',
      revision: 0,
    });
    expect(read.body).not.toContain('a@x');

    for (const response of [
      await stranger.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`),
      await stranger.answer(id, 0, { kind: 'step', step: PASSWORD_STEP }),
      await stranger.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`),
      await stranger.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`),
    ]) {
      expect(response.statusCode).toBe(410);
      expect(response.json()).toMatchObject({ code: 'interaction_expired' });
    }
    expect(harness.decided).toHaveLength(0);

    // The owner's interaction is untouched by those attempts.
    const personal = await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`);
    expect(personal.statusCode).toBe(200);
    expect(personal.json()).toEqual({
      step: SELECT_ACCOUNT_STEP.name,
      data: { accounts: ['a@x'] },
    });
    expect((await owner.answer(id, 0, { kind: 'step', step: PASSWORD_STEP })).statusCode).toBe(200);
  });

  it('lets the cookie of interaction A neither read nor answer interaction B', async () => {
    const browserA = new Browser();
    const browserB = new Browser();
    await browserA.start();
    const idB = await browserB.start({
      step: SELECT_ACCOUNT_STEP,
      personal: { accounts: ['b@x'] },
    });

    expect(
      (await browserA.request('GET', `${INTERACTION_API_PREFIX}/${idB}/personal`)).statusCode
    ).toBe(410);
    expect((await browserA.answer(idB, 0, { kind: 'finished' })).statusCode).toBe(410);
    expect(
      (await browserA.request('POST', `${INTERACTION_API_PREFIX}/${idB}/cancel`)).statusCode
    ).toBe(410);
    expect(harness.decided).toHaveLength(0);
    expect(
      (await browserB.request('GET', `${INTERACTION_API_PREFIX}/${idB}/personal`)).statusCode
    ).toBe(200);
  });

  it('lets one browser hold several ceremonies, each bound to its own secret', async () => {
    const browser = new Browser();
    const first = await browser.start();
    const second = await browser.start();
    expect(browser.cookies.get(FLOW_COOKIE)?.split('.')).toHaveLength(2);

    expect(
      (await browser.request('GET', `${INTERACTION_API_PREFIX}/${first}/personal`)).statusCode
    ).toBe(200);
    expect(
      (await browser.request('GET', `${INTERACTION_API_PREFIX}/${second}/personal`)).statusCode
    ).toBe(200);
    expect((await browser.answer(first, 0, { kind: 'finished' })).statusCode).toBe(200);
    // Finishing the first drops its secret and keeps the second's.
    expect(browser.cookies.get(FLOW_COOKIE)?.split('.')).toHaveLength(1);
    expect(
      (await browser.request('GET', `${INTERACTION_API_PREFIX}/${second}/personal`)).statusCode
    ).toBe(200);
  });

  it('stores the id only as a hash, and keys the record by the realm', async () => {
    const id = await new Browser().start();
    const keys = [...harness.redis.strings.keys()].sort();
    expect(keys).toEqual(
      [
        REDIS_KEYS.INTERACTION(REALM.id, interactionIdHash(id)),
        REDIS_KEYS.INTERACTION_TURN(REALM.id, interactionIdHash(id)),
      ].sort()
    );
    for (const [key, { value }] of harness.redis.strings) {
      expect(key).not.toContain(id);
      expect(value).not.toContain(id);
    }
  });
});

describe('the one generic refusal (#592)', () => {
  it('answers an unknown id, an expired id, a wrong cookie, a malformed id and a finished interaction byte for byte alike', async () => {
    const owner = new Browser();
    const finished = await owner.start();
    expect((await owner.answer(finished, 0, { kind: 'finished' })).statusCode).toBe(200);
    const live = await owner.start();
    const expiring = await owner.start();
    const stranger = new Browser();
    stranger.cookies.set(FLOW_COOKIE, 'A'.repeat(43));

    const unknown = await owner.request(
      'GET',
      `${INTERACTION_API_PREFIX}/${'B'.repeat(43)}/personal`
    );
    const malformed = await owner.request('GET', `${INTERACTION_API_PREFIX}/not-an-id/personal`);
    const wrongCookie = await stranger.request('GET', `${INTERACTION_API_PREFIX}/${live}/personal`);
    const noCookie = await new Browser().request(
      'GET',
      `${INTERACTION_API_PREFIX}/${live}/personal`
    );
    const ended = await owner.request('GET', `${INTERACTION_API_PREFIX}/${finished}/personal`);
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 1_801_000 });
    const expired = await owner.request('GET', `${INTERACTION_API_PREFIX}/${expiring}/personal`);

    const reference = comparable(unknown);
    expect(reference.status).toBe(410);
    expect(JSON.parse(unknown.body)).toEqual({
      type: 'https://docs.qauth.dev/reference/problem-types/#interaction-expired',
      title: 'Interaction expired',
      status: 410,
      code: 'interaction_expired',
      trace_id: expect.any(String),
    });
    for (const response of [malformed, wrongCookie, noCookie, ended, expired]) {
      expect(comparable(response)).toEqual(reference);
    }
  });

  it('refuses an interaction past its expiry to every operation, the id-only read included', async () => {
    const owner = new Browser();
    const id = await owner.start();
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 1_800_000 });

    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`)).statusCode).toBe(410);
    expect(
      (await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`)).statusCode
    ).toBe(410);
    expect((await owner.answer(id, 0, { kind: 'finished' })).statusCode).toBe(410);
    expect((await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`)).statusCode).toBe(
      410
    );
    expect((await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`)).statusCode).toBe(
      410
    );
    expect(harness.decided).toHaveLength(0);
  });
});

describe('answers (#592)', () => {
  it('processes exactly one of two concurrent answers to one step', async () => {
    const owner = new Browser();
    const id = await owner.start();
    const decision: DecisionSpec = { kind: 'step', step: CONSENT_STEP };

    const [first, second, readMeanwhile] = await Promise.all([
      owner.answer(id, 0, decision, 20),
      owner.answer(id, 0, decision, 20),
      // While the engine works, the interaction still reads as live.
      new Promise<LightMyRequestResponse>((resolve) =>
        setTimeout(
          () => resolve(owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`)),
          5
        )
      ),
    ]);

    expect(harness.decided).toHaveLength(1);
    expect(readMeanwhile.statusCode).toBe(200);
    const results = [first.json(), second.json()] as { kind: string }[];
    expect(results.map((result) => result.kind).sort()).toEqual(['stale', 'step']);
    const read = await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`);
    expect(read.json()).toMatchObject({ step: CONSENT_STEP, revision: 1 });
  });

  it('refuses an answer to a step view that is no longer current, and keeps the state', async () => {
    const owner = new Browser();
    const id = await owner.start();
    expect((await owner.answer(id, 0, { kind: 'step', step: CONSENT_STEP })).json()).toMatchObject({
      kind: 'step',
    });

    expect((await owner.answer(id, 0, { kind: 'finished' })).json()).toEqual({ kind: 'stale' });
    expect(harness.decided).toHaveLength(1);
    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`)).json()).toMatchObject({
      revision: 1,
    });
  });

  it('keeps the interaction at its step, answerable, when the engine fails while it decides', async () => {
    const owner = new Browser();
    const id = await owner.start();
    harness.app.log.level = 'fatal';
    const failed = await owner.answer(id, 0, {
      kind: 'step',
      step: { name: 'urn:qauth:ia:no_such_step:v1-rc.0', params: {}, alternatives: [] },
    });
    expect(failed.statusCode).toBe(500);

    // Nothing changed, and the turn came back: the retry is processed.
    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`)).json()).toMatchObject({
      step: PASSWORD_STEP,
      revision: 0,
    });
    const retry = await owner.answer(id, 0, { kind: 'step', step: CONSENT_STEP });
    expect(retry.json()).toMatchObject({ kind: 'step', view: { revision: 1 } });
  });

  it('gives a turn back that it took for a later state: a cancel racing an answer leaves the next step answerable', async () => {
    const owner = new Browser();
    const id = await owner.start();
    const idHash = interactionIdHash(id);
    const redis = harness.redis as unknown as FastifyInstance['redis'];
    // The cancel reads revision 0; before it takes the turn, an answer on
    // another node takes turn 0 and writes revision 1 with turn 1.
    harness.redis.beforeNextGetdel(
      (key) => key === REDIS_KEYS.INTERACTION_TURN(REALM.id, idHash),
      async () => {
        const silent = harness.app.log;
        expect(await takeInteractionTurn(redis, silent, REALM.id, idHash)).toBe(0);
        const record = await readInteractionRecord(redis, silent, REALM.id, idHash);
        if (record === null) throw new Error('no record');
        await writeInteractionState(redis, idHash, {
          ...record,
          step: CONSENT_STEP,
          revision: 1,
        });
      }
    );

    const cancel = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`);

    expect(cancel.json()).toEqual({ kind: 'stale' });
    // Turn 1 was given back: the owner answers the consent step.
    const next = await owner.answer(id, 1, { kind: 'finished' });
    expect(next.json()).toMatchObject({ kind: 'finished' });
  });

  it('refuses an answer whose interaction the expiry sweep took while the engine worked, and brings nothing back', async () => {
    const owner = new Browser();
    const id = await owner.start();
    const idHash = interactionIdHash(id);
    harness.duringDecide.action = async () => {
      harness.redis.strings.delete(REDIS_KEYS.INTERACTION(REALM.id, idHash));
    };

    const answered = await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });

    expect(answered.statusCode).toBe(410);
    expect(harness.redis.strings.has(REDIS_KEYS.INTERACTION(REALM.id, idHash))).toBe(false);
    expect(harness.redis.strings.has(REDIS_KEYS.INTERACTION_TURN(REALM.id, idHash))).toBe(false);
    // The session created for the answer was ended: no browser holds it.
    expect(harness.sessions.service.create).toHaveBeenCalledTimes(1);
    expect(harness.sessions.service.revoke).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM.id, reason: 'sign_out' })
    );
    expect(harness.sessions.service.sessions.size).toBe(0);
  });

  it('gives the turn back and ends the new session when the authenticated state cannot be written, even if the revoke fails', async () => {
    const owner = new Browser();
    const id = await owner.start();
    harness.app.log.level = 'fatal';
    // The first revoke fails: the turn must come back all the same.
    harness.sessions.service.revoke.mockRejectedValueOnce(new Error('session store down'));

    const tooLarge = await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: SELECT_ACCOUNT_STEP,
      personal: { accounts: ['a'.repeat(70 * 1024)] },
    });

    expect(tooLarge.statusCode).toBe(500);
    expect(harness.sessions.service.revoke).toHaveBeenCalledTimes(1);
    expect(owner.cookies.has(SESSION_COOKIE_NAME)).toBe(false);
    // Nothing was written, and the turn is back: the retry is processed.
    const retry = await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });
    expect(retry.statusCode).toBe(200);
    expect(harness.sessions.service.revoke).toHaveBeenCalledTimes(1);
  });

  it('leaves the browser able to go on when ending a replaced session fails', async () => {
    const owner = new Browser();
    const id = await owner.start();
    await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: PASSWORD_STEP,
    });
    harness.app.log.level = 'fatal';
    harness.sessions.service.revoke.mockRejectedValueOnce(new Error('session store down'));

    const stepUp = await owner.answer(id, 1, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['otp'],
      step: CONSENT_STEP,
    });

    expect(stepUp.statusCode).toBe(200);
    // The new flow secret reached the browser: it reads and answers on.
    expect(
      (await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`)).statusCode
    ).toBe(200);
    expect((await owner.answer(id, 2, { kind: 'finished' })).json()).toMatchObject({
      kind: 'finished',
    });
  });

  it('gives the turn back when a cancel cannot delete the interaction', async () => {
    const owner = new Browser();
    const id = await owner.start();
    harness.app.log.level = 'fatal';
    // The connection drops on the delete's MULTI: Redis ran none of it.
    const multi = harness.redis.multi;
    harness.redis.multi = () => {
      harness.redis.multi = multi;
      const failing = {
        del: () => failing,
        zrem: () => failing,
        exec: async () => {
          throw new Error('redis down');
        },
      };
      return failing as unknown as ReturnType<typeof multi>;
    };

    const failed = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`);
    expect(failed.statusCode).toBe(500);

    const again = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`);
    expect(again.json()).toMatchObject({ kind: 'cancelled' });
  });

  it('does not finish or cancel an interaction the expiry sweep claimed first', async () => {
    for (const finish of [
      (owner: Browser, id: string) => owner.answer(id, 0, { kind: 'finished' }),
      (owner: Browser, id: string) =>
        owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/cancel`),
      (owner: Browser, id: string) =>
        owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`),
    ]) {
      vi.mocked(emitUserEvent).mockClear();
      const owner = new Browser();
      const id = await owner.start();
      // The sweep claims the member just before the take.
      harness.redis.beforeNextGetdel(
        (key) => key === REDIS_KEYS.INTERACTION_TURN(REALM.id, interactionIdHash(id)),
        async () => {
          harness.redis.sortedSets.clear();
        }
      );

      const response = await finish(owner, id);

      expect(response.statusCode).toBe(410);
      expect(response.json()).toMatchObject({ code: 'interaction_expired' });
      const types = vi.mocked(emitUserEvent).mock.calls.map(([, type]) => type);
      expect(types).toEqual(['urn:qauth:event:interaction.created:v1-rc.0']);
    }
  });

  it('refuses an answer that outlasted the expiry while the engine worked', async () => {
    const owner = new Browser();
    const id = await owner.start();
    harness.duringDecide.action = async () => {
      vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 1_800_000 });
    };

    const answered = await owner.answer(id, 0, { kind: 'finished' });

    expect(answered.statusCode).toBe(410);
    // Left for the sweep: still listed for expiry.
    expect(harness.redis.sortedSets.get(REDIS_KEYS.INTERACTION_EXPIRY_INDEX())?.size).toBe(1);
  });

  it('finishes the interaction: the request goes back to the caller, the id is dead and its secret leaves the cookie', async () => {
    const owner = new Browser();
    const id = await owner.start();
    const finished = await owner.answer(id, 0, { kind: 'finished' });

    expect(finished.json()).toEqual({
      kind: 'finished',
      request: AUTHORIZE_REQUEST,
      transaction: { amr: [] },
    });
    expect(owner.cookies.has(FLOW_COOKIE)).toBe(false);
    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`)).statusCode).toBe(410);
    expect((await owner.answer(id, 0, { kind: 'finished' })).statusCode).toBe(410);
    expect(harness.redis.sortedSets.size).toBe(0);
  });
});

describe('authentication (#592)', () => {
  it('rotates the browser session id and the flow binding', async () => {
    const owner = new Browser();
    // The browser arrives with a session cookie, perhaps one an attacker planted.
    const { session: before } = await harness.sessions.signIn({
      realmId: REALM.id,
      userId: USER_B,
    });
    owner.cookies.set(SESSION_COOKIE_NAME, sessionCookie(before.sid).split('=')[1]);
    const id = await owner.start();
    const flowBefore = owner.cookies.get(FLOW_COOKIE);
    const beforeCookies = owner.header;

    const answered = await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });

    expect(answered.statusCode).toBe(200);
    const sidAfter = verifySignedSessionId(owner.cookies.get(SESSION_COOKIE_NAME));
    expect(sidAfter).not.toBeNull();
    expect(sidAfter).not.toBe(before.sid);
    expect(harness.sessions.service.create).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM.id, userId: USER_A })
    );
    expect(owner.cookies.get(FLOW_COOKIE)).not.toBe(flowBefore);

    // The old flow secret opens nothing; the new one does.
    const old = await harness.app.inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}/personal`,
      headers: beforeCookies,
    });
    expect(old.statusCode).toBe(410);
    expect(
      (await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`)).statusCode
    ).toBe(200);

    // The next answer sees the proved user, the session and the amr.
    await owner.answer(id, 1, { kind: 'finished' });
    expect(harness.decided[1]?.transaction).toEqual({
      userId: USER_A,
      sid: sidAfter,
      authTime: expect.any(Number),
      amr: ['pwd'],
    });
  });

  it('ends the session a first authentication created when a second one in the interaction replaces it', async () => {
    const owner = new Browser();
    const id = await owner.start();
    await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: PASSWORD_STEP,
    });
    const first = verifySignedSessionId(owner.cookies.get(SESSION_COOKIE_NAME));

    await owner.answer(id, 1, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['otp'],
      step: CONSENT_STEP,
    });

    const second = verifySignedSessionId(owner.cookies.get(SESSION_COOKIE_NAME));
    expect(second).not.toBe(first);
    expect([...harness.sessions.service.sessions.keys()]).toEqual([second]);
    await owner.answer(id, 2, { kind: 'finished' });
    expect(harness.decided.at(-1)?.transaction).toMatchObject({ sid: second, amr: ['pwd', 'otp'] });
  });

  it('refuses a second subject in one transaction', async () => {
    const owner = new Browser();
    const id = await owner.start();
    await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });
    harness.app.log.level = 'fatal';

    const second = await owner.answer(id, 1, {
      kind: 'authenticated',
      userId: USER_B,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });

    expect(second.statusCode).toBe(500);
    expect(harness.sessions.service.create).toHaveBeenCalledTimes(1);
    // Nothing of the second user was written: the interaction stays with the first.
    await owner.answer(id, 1, { kind: 'finished' });
    expect(harness.decided.at(-1)?.transaction).toMatchObject({ userId: USER_A });
  });
});

describe('the user switch (#592)', () => {
  it('ends the interaction and starts a new one for the same request at the identifier step, with nothing carried over', async () => {
    const owner = new Browser();
    const id = await owner.start({}, { nonce: 'n-0S6_WzA2Mj' });
    await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });
    const flowBefore = owner.cookies.get(FLOW_COOKIE);

    const switched = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`);
    expect(switched.statusCode).toBe(200);
    const { kind, id: newId } = switched.json() as { kind: string; id: string };
    expect(kind).toBe('switched');
    expect(newId).not.toBe(id);

    // The old id gets the generic answer, exactly as an unknown one.
    const old = await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`);
    const unknown = await owner.request('GET', `${INTERACTION_API_PREFIX}/${'C'.repeat(43)}`);
    expect(comparable(old)).toEqual(comparable(unknown));

    // The new one starts at the identifier step, for the same request, with an
    // empty transaction, bound to a new secret that replaced the old one.
    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${newId}`)).json()).toMatchObject(
      {
        step: { name: IDENTIFIER_STEP, params: {}, alternatives: [] },
        revision: 0,
      }
    );
    expect(owner.cookies.get(FLOW_COOKIE)).not.toContain(flowBefore);
    expect(owner.cookies.get(FLOW_COOKIE)?.split('.')).toHaveLength(1);
    await owner.answer(newId, 0, { kind: 'finished' });
    const state = harness.decided.at(-1);
    expect(state?.request).toEqual({ ...AUTHORIZE_REQUEST, nonce: 'n-0S6_WzA2Mj' });
    expect(state?.transaction).toEqual({ amr: [] });
  });

  it('keeps the absolute expiry of the authorization request: switching never extends it', async () => {
    const owner = new Browser();
    const id = await owner.start();
    const { expiresAt } = (
      await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`)
    ).json() as {
      expiresAt: number;
    };
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 600_000 });

    const switched = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`);
    const newId = (switched.json() as { id: string }).id;

    expect((switched.json() as { expiresAt: number }).expiresAt).toBe(expiresAt);
    expect((await owner.request('GET', `${INTERACTION_API_PREFIX}/${newId}`)).json()).toMatchObject(
      {
        expiresAt,
      }
    );
  });
});

describe('audit and logs (#592)', () => {
  it('audits create, answer and cancel by reference, and never logs or audits the id or the cookie', async () => {
    const owner = new Browser();
    const stranger = new Browser();
    const id = await owner.start();
    await stranger.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`);
    await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}`);
    await owner.request('GET', `${INTERACTION_API_PREFIX}/${id}/personal`);
    await owner.answer(id, 0, {
      kind: 'authenticated',
      userId: USER_A,
      amr: ['pwd'],
      step: CONSENT_STEP,
    });
    const switched = await owner.request('POST', `${INTERACTION_API_PREFIX}/${id}/switch`);
    const newId = (switched.json() as { id: string }).id;
    await owner.request('POST', `${INTERACTION_API_PREFIX}/${newId}/cancel`);
    const third = await owner.start();
    await owner.answer(third, 0, { kind: 'finished' });

    const calls = vi.mocked(emitUserEvent).mock.calls.map(([, type, data, options]) => ({
      type,
      data,
      options,
    }));
    expect(calls.map((call) => call.type)).toEqual([
      'urn:qauth:event:interaction.created:v1-rc.0',
      'urn:qauth:event:interaction.answered:v1-rc.0',
      'urn:qauth:event:interaction.cancelled:v1-rc.0',
      'urn:qauth:event:interaction.created:v1-rc.0',
      'urn:qauth:event:interaction.cancelled:v1-rc.0',
      'urn:qauth:event:interaction.created:v1-rc.0',
      'urn:qauth:event:interaction.answered:v1-rc.0',
    ]);
    expect(calls[1]?.data).toMatchObject({ outcome: 'authenticated', step: PASSWORD_STEP.name });
    expect(calls[1]?.options).toMatchObject({ userId: USER_A, clientId: 'notes-app' });
    expect(calls[2]?.data).toMatchObject({ reason: 'user_switch' });
    expect(calls[3]?.data).toMatchObject({
      step: IDENTIFIER_STEP,
      replaces: (calls[0]?.data as { interaction: string } | undefined)?.interaction,
    });
    expect(calls[4]?.data).toMatchObject({ reason: 'user' });
    expect(calls[6]?.data).toMatchObject({ outcome: 'finished' });

    // Every id, and every flow secret the browser was given along the way.
    const flowSecrets = owner.seen
      .flatMap((value) => value.split('.'))
      .filter((value) => /^[A-Za-z0-9_-]{43}$/.test(value));
    expect(flowSecrets.length).toBeGreaterThanOrEqual(4);
    const audited = JSON.stringify(calls);
    const logged = harness.logs.join('');
    expect(logged).toContain('interaction request refused');
    for (const secret of [id, newId, third, ...flowSecrets]) {
      expect(audited).not.toContain(secret);
      expect(logged).not.toContain(secret);
    }
  });
});

describe('bounds (#592)', () => {
  /** `count` RFC 8707 resources of `length` characters each. */
  const resources = (count: number, length: number) =>
    Array.from({ length: count }, (_, index) => {
      const base = `https://api${index}.example.com/`;
      return base + 'r'.repeat(length - base.length);
    });

  it('holds a request near its ceiling, and leaves room for the steps', async () => {
    const browser = new Browser();
    const id = await browser.start({
      request: {
        state: '"'.repeat(2048),
        nonce: '"'.repeat(2048),
        scope: 'x'.repeat(2048),
        resource: resources(10, 2048),
      },
    });
    expect((await browser.request('GET', `${INTERACTION_API_PREFIX}/${id}`)).statusCode).toBe(200);
    // The next state still fits beside it.
    const answered = await browser.answer(id, 0, { kind: 'step', step: SELECT_ACCOUNT_STEP });
    expect(answered.statusCode).toBe(200);
  });

  it('refuses a request too large to hold through a ceremony with invalid_request, and stores nothing', async () => {
    const response = await new Browser().request('POST', '/start', {
      request: {
        state: '\u0001'.repeat(2048),
        nonce: '\u0001'.repeat(2048),
        scope: '\u0001'.repeat(2048),
        resource: resources(10, 2048),
      },
    });
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: 'invalid_request' });
    expect(harness.redis.strings.size).toBe(0);
    expect(harness.redis.sortedSets.size).toBe(0);
  });

  it('answers any error on an Interaction API path without instance, detail or errors', async () => {
    harness.app.log.level = 'fatal';
    const response = await harness.app.inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${'D'.repeat(43)}/fail`,
    });
    expect(response.statusCode).toBe(400);
    expect(Object.keys(response.json() as object).sort()).toEqual(
      ['code', 'status', 'title', 'trace_id', 'type'].sort()
    );
    expect(response.body).not.toContain('D'.repeat(43));
  });

  it('answers a 404 on an Interaction API path, and a routed decoded spelling of one, without echoing the path', async () => {
    const id = 'E'.repeat(43);
    const missing = await harness.app.inject({
      method: 'GET',
      url: `${INTERACTION_API_PREFIX}/${id}/nowhere`,
    });
    expect(missing.statusCode).toBe(404);
    expect(Object.keys(missing.json() as object).sort()).toEqual(
      ['code', 'status', 'title', 'trace_id', 'type'].sort()
    );
    expect(missing.body).not.toContain(id);

    harness.app.log.level = 'fatal';
    const decoded = await harness.app.inject({
      method: 'POST',
      url: `/%69nteraction/v1-rc%2E0/${id}/fail`,
    });
    expect([400, 404]).toContain(decoded.statusCode);
    expect(Object.keys(decoded.json() as object).sort()).toEqual(
      ['code', 'status', 'title', 'trace_id', 'type'].sort()
    );
    expect(decoded.body).not.toContain(id);
  });

  it('names no client in an event when the client_id is longer than an event holds', async () => {
    const longClientId = `https://client.example.com/${'c'.repeat(300)}`;
    await new Browser().start({ request: { client_id: longClientId } });
    const [, , , options] = vi.mocked(emitUserEvent).mock.calls[0] ?? [];
    expect(options).toMatchObject({ clientId: null });
  });
});
