import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: true,
    INTERACTION_TTL: 1800,
    LOGIN_RATE_LIMIT: 5,
    LOGIN_RATE_WINDOW: 900,
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
  },
}));

vi.mock('../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

/** The engine the route builds: one stand-in, whose rounds each test scripts. */
const engine = vi.hoisted(() => ({ advance: vi.fn() }));

vi.mock('@qauth-labs/fastify-plugin-sign-in-engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@qauth-labs/fastify-plugin-sign-in-engine')>();
  return {
    ...actual,
    createCheckedSignInEngine: vi.fn(() => engine),
    createRepositoryAccountDirectory: vi.fn(() => ({})),
    createArgon2PasswordVerifier: vi.fn(() => ({})),
  };
});

vi.mock('../helpers/password-attempts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../helpers/password-attempts')>();
  return {
    ...actual,
    createServerLadderParts: vi.fn(() => ({
      identifierDigest: async () => 'h'.repeat(43),
      ladder: {},
      hardAction: {},
      hardActionArmed: async () => false,
    })),
  };
});

vi.mock('../helpers/account-policies', () => ({
  accountPoliciesOf: vi.fn(() => ({ requireVerifiedAccount: true })),
}));

import { createBrowserSessionFixture } from '../../testing/browser-sessions';
import { createMemoryInteractionRedis } from '../../testing/interaction-redis';
import { supplyRequestRealm, testRealm } from '../../testing/request-realm';
import { IDENTIFIER_STEP } from '../helpers/interaction-record';
import { answerRouteNotFound } from '../helpers/request-bounds';
import { SESSION_COOKIE_NAME } from '../helpers/session-cookie';
import { emitUserEvent } from '../helpers/user-events';
import { corsPlugin } from '../plugins/cors';
import errorHandler from '../plugins/error-handler';
import interactionApi, {
  ANSWER_BODY_LIMIT,
  checkAnswerBodySize,
  comesFromRealmOrigin,
  parseAnswerForm,
  WEBAUTHN_CREATE_BODY_LIMIT,
} from './interaction-api';

/**
 * THE INTERACTION API'S ROUTES (#616), on a bare app with the real error
 * handler, CORS plugin, interaction helpers and an in-memory Redis; the
 * sign-in engine is a stand-in whose rounds each test scripts. The container
 * suite (`interaction-api.integration.test.ts`) runs the real engine.
 */

const REALM = testRealm({ id: '22222222-2222-4222-8222-222222222222' });
const ORIGIN = 'https://auth.example.com';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const FLOW_COOKIE = '__Host-qauth_flow';
const SPA_ORIGIN = 'https://spa.example.com';

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

const IDENTIFIER = stepUrn('identifier');
const PASSWORD = stepUrn('password');

/** The engine's round result: the password step, after the identifier. */
const PASSWORD_ROUND = {
  kind: 'step',
  transaction: {
    v: 1,
    realmId: REALM.id,
    clientId: 'notes-app',
    createdAt: Date.now(),
    identifier: 'alice@example.com',
    verified: [],
  },
  offer: {
    current: { step: 'password', params: {} },
    alternatives: [{ step: 'identifier', params: {} }],
  },
  personal: { identifier: 'alice@example.com' },
};

const COMPLETE_ROUND = {
  kind: 'complete',
  transaction: null,
  signIn: {
    subject: USER_ID,
    identifier: 'alice@example.com',
    amr: ['pwd'],
    authTime: Date.now(),
  },
};

let app: FastifyInstance;
let updateLastLogin: ReturnType<typeof vi.fn>;

async function buildApp(): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  instance.setValidatorCompiler(validatorCompiler);
  instance.setSerializerCompiler(serializerCompiler);
  await instance.register(errorHandler);
  instance.setNotFoundHandler(answerRouteNotFound);
  supplyRequestRealm(instance, REALM);
  const sessions = createBrowserSessionFixture();
  instance.decorate(
    'redis',
    createMemoryInteractionRedis(sessions.redis) as unknown as FastifyInstance['redis']
  );
  instance.decorate('sessionService', sessions.service);
  instance.decorate('signer', sessions.signer as unknown as FastifyInstance['signer']);
  updateLastLogin = vi.fn(async () => undefined);
  instance.decorate('repositories', {
    users: { updateLastLogin },
    userCredentials: {},
    adminGrants: {},
  } as unknown as FastifyInstance['repositories']);
  instance.decorate('passwordHasher', {} as FastifyInstance['passwordHasher']);
  await instance.register(async (scope) => {
    // As `app.ts` registers it: CORS for every origin, before the routes.
    await scope.register(corsPlugin, { corsOrigin: SPA_ORIGIN, production: false });
    // A route of another surface, which CORS answers: the check's control.
    scope.get('/api-route', { config: { surface: 'api' } }, async () => ({ ok: true }));
    scope.post('/start', { config: { surface: 'browser' } }, async (request, reply) => {
      const { startInteraction } = await import('../helpers/interaction');
      return startInteraction(request, reply, {
        request: AUTHORIZE_REQUEST,
        step: { name: IDENTIFIER_STEP, params: {}, alternatives: [] },
      });
    });
    await scope.register(interactionApi);
  });
  await instance.ready();
  return instance;
}

/** A browser on the realm origin: its cookie jar, replayed on every request. */
class Browser {
  readonly cookies = new Map<string, string>();

  absorb(response: LightMyRequestResponse): void {
    const header = response.headers['set-cookie'];
    for (const line of header === undefined ? [] : Array.isArray(header) ? header : [header]) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (/Max-Age=0/.test(line)) this.cookies.delete(pair.slice(0, eq));
      else this.cookies.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  get cookie(): Record<string, string> {
    const value = [...this.cookies].map(([name, v]) => `${name}=${v}`).join('; ');
    return value.length === 0 ? {} : { cookie: value };
  }

  async start(): Promise<string> {
    const response = await app.inject({ method: 'POST', url: '/start', headers: this.cookie });
    this.absorb(response);
    expect(response.statusCode, response.body).toBe(200);
    return (response.json() as { id: string }).id;
  }

  async read(id: string): Promise<{ csrf: string; step: string }> {
    const response = await app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
    expect(response.statusCode, response.body).toBe(200);
    return response.json() as { csrf: string; step: string };
  }

  async send(
    id: string,
    operation: 'answer' | 'cancel',
    body: string | object,
    headers: Record<string, string> = { 'sec-fetch-site': 'same-origin' }
  ): Promise<LightMyRequestResponse> {
    const form = typeof body === 'string';
    const response = await app.inject({
      method: 'POST',
      url: `${INTERACTION_API_PREFIX}/${id}/${operation}`,
      headers: {
        ...this.cookie,
        'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json',
        ...headers,
      },
      payload: form ? body : JSON.stringify(body),
    });
    this.absorb(response);
    return response;
  }
}

/** The `Access-Control-*` header fields of an answer. */
function corsHeaders(response: LightMyRequestResponse): string[] {
  return Object.keys(response.headers).filter((name) => name.startsWith('access-control-'));
}

function eventTypes(): string[] {
  return vi.mocked(emitUserEvent).mock.calls.map(([, type]) => type);
}

beforeEach(async () => {
  vi.mocked(emitUserEvent).mockClear();
  engine.advance.mockReset();
  app = await buildApp();
});

afterEach(async () => {
  await app.close();
});

describe('the step read (#616)', () => {
  it('returns the step, its CSRF value, the brand and the expiry, and no personal data', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const response = await app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.json()).toEqual({
      step: IDENTIFIER,
      alternatives: [],
      params: { [IDENTIFIER]: {} },
      csrf: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      brand: { font: 'system', darkMode: 'enabled' },
      expiresAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
  });
});

describe('the answer, before the engine runs (#616)', () => {
  it('refuses a body over 16 KiB with 413', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf,
      login_hint: 'a'.repeat(ANSWER_BODY_LIMIT),
    });
    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ code: 'content_too_large' });
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it('refuses a body over 64 KiB with 413, whatever it answers', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: stepUrn('webauthn_create'),
      padding: 'a'.repeat(WEBAUTHN_CREATE_BODY_LIMIT),
    });
    expect(response.statusCode).toBe(413);
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it('refuses a repeated form field with 400', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(IDENTIFIER)}&csrf=${csrf}&login_hint=a%40x.com&login_hint=b%40x.com`
    );
    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it.each(['text/plain', 'multipart/form-data; boundary=x', 'application/xml'])(
    'refuses a body sent as %s with 415',
    async (contentType) => {
      const browser = new Browser();
      const id = await browser.start();
      const response = await browser.send(id, 'answer', 'type=x', {
        'sec-fetch-site': 'same-origin',
        'content-type': contentType,
      });
      expect(response.statusCode).toBe(415);
      expect(response.json()).toMatchObject({ code: 'unsupported_media_type' });
      expect(engine.advance).not.toHaveBeenCalled();
    }
  );

  it.each([
    ['Sec-Fetch-Site: cross-site', { 'sec-fetch-site': 'cross-site' }],
    ['Sec-Fetch-Site: same-site', { 'sec-fetch-site': 'same-site' }],
    ['an Origin of another site', { origin: 'https://evil.example' }],
    ['Origin: null', { origin: 'null' }],
    ['an Origin of another site and no Sec-Fetch-Site', { origin: SPA_ORIGIN }],
    ['Sec-Fetch-Site: none', { 'sec-fetch-site': 'none', origin: ORIGIN }],
    ['neither header', {}],
  ])('refuses %s with a generic 403, audited', async (_label, headers) => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      { type: IDENTIFIER, csrf, login_hint: 'alice@example.com' },
      headers
    );
    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ code: 'forbidden' });
    expect(eventTypes()).toContain('urn:qauth:event:request.csrf_rejected:v1-rc.0');
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it('lets a form post through with Sec-Fetch-Site: same-origin and Origin: null, as a no-referrer page sends it', async () => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(IDENTIFIER)}&csrf=${csrf}&login_hint=alice%40example.com`,
      { 'sec-fetch-site': 'same-origin', origin: 'null' }
    );
    expect(response.statusCode, response.body).toBe(303);
  });

  it('lets a request through with only an Origin of the realm, as from a browser without Sec-Fetch-Site', async () => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      { type: IDENTIFIER, csrf, login_hint: 'alice@example.com' },
      { origin: ORIGIN }
    );
    expect(response.statusCode, response.body).toBe(200);
  });

  it('refuses a missing or wrong CSRF value with 403', async () => {
    const browser = new Browser();
    const id = await browser.start();
    for (const csrf of [undefined, 'A'.repeat(43)]) {
      const response = await browser.send(id, 'answer', {
        type: IDENTIFIER,
        ...(csrf === undefined ? {} : { csrf }),
        login_hint: 'alice@example.com',
      });
      expect(response.statusCode).toBe(403);
    }
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it.each([
    ['a step the read did not offer', { type: PASSWORD, password: 'x' }],
    [
      'an undeclared member',
      { type: IDENTIFIER, login_hint: 'a@x.com', redirect_uri: 'https://x' },
    ],
    ['no step', { login_hint: 'a@x.com' }],
    ['a member of the wrong type', { type: IDENTIFIER, login_hint: 7 }],
  ])('refuses %s with 400 invalid_answer, and the CSRF value stays good', async (_label, body) => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const refused = await browser.send(id, 'answer', { ...body, csrf });
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toMatchObject({ code: 'invalid_answer' });
    expect(engine.advance).not.toHaveBeenCalled();
    const retry = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf,
      login_hint: 'alice@example.com',
    });
    expect(retry.statusCode, retry.body).toBe(200);
  });
});

describe('the answer, through the engine (#616)', () => {
  it('answers JSON with the next step view, with a new CSRF value', async () => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf,
      login_hint: 'alice@example.com',
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    const body = response.json() as { result: string; interaction: { step: string; csrf: string } };
    expect(body.result).toBe('step');
    expect(body.interaction).toMatchObject({ step: PASSWORD, alternatives: [IDENTIFIER] });
    expect(body.interaction.csrf).not.toBe(csrf);
    // The engine got the stored transaction (none yet), the answer and the context.
    expect(engine.advance).toHaveBeenCalledWith(
      null,
      expect.objectContaining({ step: IDENTIFIER, encoding: 'json' }),
      expect.objectContaining({ realm: { id: REALM.id }, client: { id: 'notes-app' } })
    );
  });

  it('answers a form post with 303 to the ceremony page, and the next round sees the kept transaction', async () => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(IDENTIFIER)}&csrf=${csrf}&login_hint=alice%40example.com`
    );
    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(`${ORIGIN}${CEREMONY_PAGE_PREFIX}${id}`);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toBe('');

    engine.advance.mockResolvedValueOnce(COMPLETE_ROUND);
    const next = await browser.read(id);
    await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(PASSWORD)}&csrf=${next.csrf}&password=correct+horse`
    );
    expect(engine.advance.mock.calls[1]?.[0]).toEqual(PASSWORD_ROUND.transaction);
    expect(engine.advance.mock.calls[1]?.[1]).toMatchObject({ encoding: 'form' });
  });

  it('signs in on a completed round: the session cookie, then 303 to the redirect the record holds', async () => {
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND).mockResolvedValueOnce(COMPLETE_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'alice@example.com',
    });
    const response = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(PASSWORD)}&csrf=${(await browser.read(id)).csrf}&password=pw`
    );

    expect(response.statusCode).toBe(303);
    const location = new URL(String(response.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(AUTHORIZE_REQUEST.redirect_uri);
    expect(location.searchParams.get('state')).toBe(AUTHORIZE_REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
    expect(location.searchParams.get('code')).toBeNull();
    expect(browser.cookies.has(SESSION_COOKIE_NAME)).toBe(true);
    expect(browser.cookies.has(FLOW_COOKIE)).toBe(false);
    expect(updateLastLogin).toHaveBeenCalledWith(REALM.id, USER_ID);
    expect(eventTypes()).toContain('urn:qauth:event:user.signed_in:v1-rc.0');
  });

  it('throttles with 429 and Retry-After, and keeps the step and its CSRF value', async () => {
    engine.advance.mockResolvedValueOnce({
      kind: 'refused',
      reason: 'throttled',
      retryAfterSeconds: 42,
      transaction: PASSWORD_ROUND.transaction,
    });
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf,
      login_hint: 'alice@example.com',
    });
    expect(response.statusCode).toBe(429);
    expect(response.headers['retry-after']).toBe('42');
    expect(response.json()).toMatchObject({ code: 'too_many_requests' });
    expect((await browser.read(id)).csrf).toBe(csrf);
  });

  it('answers 503 with Retry-After when a store the engine needs is down', async () => {
    engine.advance.mockResolvedValueOnce({
      kind: 'refused',
      reason: 'unavailable',
      transaction: PASSWORD_ROUND.transaction,
    });
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'alice@example.com',
    });
    expect(response.statusCode).toBe(503);
    expect(response.headers['retry-after']).toBeDefined();
  });

  it('starts the sign-in again when the engine ended its transaction', async () => {
    engine.advance
      .mockResolvedValueOnce({ kind: 'refused', reason: 'transaction_ended', transaction: null })
      .mockResolvedValueOnce({
        kind: 'step',
        transaction: { ...PASSWORD_ROUND.transaction, identifier: undefined },
        offer: { current: { step: 'identifier', params: {} }, alternatives: [] },
        personal: {},
      });
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'alice@example.com',
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(engine.advance).toHaveBeenLastCalledWith(null, null, expect.anything());
  });
});

describe('the cancel (#616)', () => {
  it('redirects to the client with access_denied, its state and iss', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'cancel', `csrf=${(await browser.read(id)).csrf}`);
    expect(response.statusCode).toBe(303);
    const location = new URL(String(response.headers.location));
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe(AUTHORIZE_REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('answers JSON with the redirect', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'cancel', { csrf: (await browser.read(id)).csrf });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      result: 'redirect',
      location: expect.stringContaining('error=access_denied'),
    });
  });

  it('refuses a member beside the CSRF value, and a request from another site', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const extra = await browser.send(id, 'cancel', {
      csrf,
      redirect_uri: 'https://evil.example/cb',
    });
    expect(extra.statusCode).toBe(400);
    const crossSite = await browser.send(
      id,
      'cancel',
      { csrf },
      { 'sec-fetch-site': 'cross-site' }
    );
    expect(crossSite.statusCode).toBe(403);
    expect((await browser.read(id)).csrf).toBe(csrf);
  });
});

describe('the personal read (#616)', () => {
  it('answers the owner, from the realm origin or with no origin header, and never another origin', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const url = `${INTERACTION_API_PREFIX}/${id}/personal`;
    for (const headers of [{}, { 'sec-fetch-site': 'same-origin' }, { origin: ORIGIN }]) {
      const response = await app.inject({
        method: 'GET',
        url,
        headers: { ...browser.cookie, ...headers },
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers['cache-control']).toBe('no-store');
      expect(response.json()).toEqual({ step: IDENTIFIER, data: {} });
    }
    for (const headers of [{ 'sec-fetch-site': 'cross-site' }, { origin: SPA_ORIGIN }]) {
      const response = await app.inject({
        method: 'GET',
        url,
        headers: { ...browser.cookie, ...headers },
      });
      expect(response.statusCode).toBe(403);
    }
  });
});

describe('no CORS (#616)', () => {
  it('sends no Access-Control header on any answer, nor a preflight, even to an origin CORS_ORIGIN lists', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const base = `${INTERACTION_API_PREFIX}/${id}`;
    const responses = [
      await app.inject({ method: 'GET', url: base, headers: { origin: SPA_ORIGIN } }),
      await app.inject({
        method: 'GET',
        url: `${base}/personal`,
        headers: { ...browser.cookie, origin: SPA_ORIGIN },
      }),
      await browser.send(id, 'answer', { csrf }, { origin: SPA_ORIGIN }),
      await browser.send(id, 'cancel', { csrf }, { origin: SPA_ORIGIN }),
      // A refusal and an unknown interaction too.
      await app.inject({
        method: 'GET',
        url: `${INTERACTION_API_PREFIX}/x`,
        headers: { origin: SPA_ORIGIN },
      }),
    ];
    for (const path of [base, `${base}/personal`, `${base}/answer`, `${base}/cancel`]) {
      responses.push(
        await app.inject({
          method: 'OPTIONS',
          url: path,
          headers: { origin: SPA_ORIGIN, 'access-control-request-method': 'POST' },
        })
      );
    }
    for (const response of responses) {
      expect(corsHeaders(response), `${response.statusCode} ${response.body}`).toEqual([]);
    }
    // The control: the same origin gets CORS on a route of another surface.
    const control = await app.inject({
      method: 'GET',
      url: '/api-route',
      headers: { origin: SPA_ORIGIN },
    });
    expect(control.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);
  });
});

describe('the parts (#616)', () => {
  it('reads a form post as a null-prototype object of strings', () => {
    const fields = parseAnswerForm('a=1&b=two+words&c=%C3%A9');
    expect(Object.getPrototypeOf(fields)).toBeNull();
    expect({ ...fields }).toEqual({ a: '1', b: 'two words', c: 'é' });
  });

  it.each([
    ['a repeated member', 'a=1&a=2'],
    ['a repeated member, empty', 'a=&a='],
    ['too many members', Array.from({ length: 33 }, (_, i) => `f${i}=1`).join('&')],
    ['a name too long', `${'n'.repeat(65)}=1`],
  ])('refuses %s', (_label, text) => {
    expect(() => parseAnswerForm(text)).toThrow(expect.objectContaining({ statusCode: 400 }));
  });

  it('bounds a body at 16 KiB, and at 64 KiB only for webauthn_create', () => {
    expect(() => checkAnswerBodySize({ type: IDENTIFIER }, ANSWER_BODY_LIMIT)).not.toThrow();
    expect(() => checkAnswerBodySize({ type: IDENTIFIER }, ANSWER_BODY_LIMIT + 1)).toThrow();
    expect(() =>
      checkAnswerBodySize({ type: stepUrn('webauthn_create') }, ANSWER_BODY_LIMIT + 1)
    ).not.toThrow();
    expect(() =>
      checkAnswerBodySize({ type: stepUrn('webauthn_create') }, WEBAUTHN_CREATE_BODY_LIMIT + 1)
    ).toThrow();
  });

  it('takes the realm origin from the issuer, never from the request', () => {
    const realm = { issuer: 'https://auth.example.com/tenant' };
    expect(comesFromRealmOrigin({ origin: ORIGIN }, realm, 'required')).toBe(true);
    expect(comesFromRealmOrigin({ origin: `${ORIGIN}/tenant` }, realm, 'required')).toBe(false);
    expect(
      comesFromRealmOrigin(
        { host: 'evil.example', origin: 'https://evil.example' },
        realm,
        'required'
      )
    ).toBe(false);
    expect(comesFromRealmOrigin({}, realm, 'required')).toBe(false);
    expect(comesFromRealmOrigin({}, realm, 'unless_absent')).toBe(true);
    // Sec-Fetch-Site decides an answer when the browser sent it.
    const sameOriginNull = { 'sec-fetch-site': 'same-origin', origin: 'null' };
    expect(comesFromRealmOrigin(sameOriginNull, realm, 'required')).toBe(true);
    expect(
      comesFromRealmOrigin({ 'sec-fetch-site': 'same-site', origin: ORIGIN }, realm, 'required')
    ).toBe(false);
    expect(comesFromRealmOrigin({ origin: 'null' }, realm, 'required')).toBe(false);
    // The read refuses any header that names another origin.
    expect(comesFromRealmOrigin(sameOriginNull, realm, 'unless_absent')).toBe(false);
    expect(comesFromRealmOrigin({ 'sec-fetch-site': 'cross-site' }, realm, 'unless_absent')).toBe(
      false
    );
  });
});
