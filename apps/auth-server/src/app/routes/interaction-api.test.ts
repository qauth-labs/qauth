import { randomBytes } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import { REGISTRATION_NOT_ALLOWED } from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  CEREMONY_PAGE_PREFIX,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import Fastify, {
  type FastifyInstance,
  type FastifyRequest,
  type LightMyRequestResponse,
} from 'fastify';
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
    REGISTRATION_RATE_LIMIT: 3,
    REGISTRATION_RATE_WINDOW: 3600,
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
    // The ceremony app server's address (#982): its step reads count per
    // interaction, three a minute each; inject's own 127.0.0.1 is not listed.
    CEREMONY_APP_PEERS: ['198.51.100.7'],
    CEREMONY_APP_PEER_RATE_LIMIT: 3,
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
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

/**
 * Where a finished interaction's authorization request goes on (#628): the
 * code redirect, which `authorization-interaction.test.ts` and the container
 * suite cover; here a stand-in that answers one, from the record's request.
 */
const finishAuthorization = vi.hoisted(() =>
  vi.fn(
    async (
      _fastify: unknown,
      _request: unknown,
      _reply: unknown,
      finished: { readonly request: { readonly redirect_uri: string; readonly state?: string } }
    ) => {
      const url = new URL(finished.request.redirect_uri);
      url.searchParams.set('code', 'c0de');
      if (finished.request.state !== undefined)
        url.searchParams.set('state', finished.request.state);
      url.searchParams.set('iss', 'https://auth.example.com');
      return url.href;
    }
  )
);

/**
 * Where a cancelled interaction's authorization request goes (#628): the
 * access_denied redirect, here without the checks it runs again first, which
 * `authorization-interaction.test.ts` covers.
 */
const cancelAuthorization = vi.hoisted(() => vi.fn());

/**
 * Where an answered consent step's request goes (#629): the code redirect,
 * decided by `finishConsent`, which `authorization-interaction.test.ts` covers;
 * here a stand-in that answers one fixed location.
 */
const CONSENT_LOCATION = 'https://notes.example.com/callback?code=c0n5ent&state=af0ifjsldkj';
const finishConsent = vi.hoisted(() => vi.fn());

vi.mock('../helpers/authorization-interaction', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../helpers/authorization-interaction')>();
  const { interactionCancelRedirect } = await import('../helpers/interaction-redirect');
  const { requestRealm } = await import('../helpers/request-realm');
  cancelAuthorization.mockImplementation(
    async (_fastify: unknown, request: FastifyRequest, cancelled: InteractionRequest) =>
      interactionCancelRedirect(requestRealm(request), cancelled)
  );
  return { ...actual, finishAuthorization, cancelAuthorization, finishConsent };
});

import type { ClientDisplay } from '@qauth-labs/shared-interaction-client';
import { INTERACTION_OPENAPI } from '@qauth-labs/shared-interaction-contract';
import {
  componentValidator,
  describeErrors,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';

import {
  type BrowserSessionFixture,
  createBrowserSessionFixture,
} from '../../testing/browser-sessions';
import { createMemoryInteractionRedis } from '../../testing/interaction-redis';
import { supplyRequestRealm, testRealm } from '../../testing/request-realm';
import { REDIS_KEYS } from '../constants';
import { CONSENT_STEP } from '../helpers/authorization-interaction';
import { END_SESSION_STATUS_PATH, LOGOUT_CONFIRM_STEP } from '../helpers/end-session';
import {
  IDENTIFIER_STEP,
  type InteractionRequest,
  type InteractionStep,
  type LogoutRequest,
} from '../helpers/interaction-record';
import { interactionIdHash } from '../helpers/interaction-record';
import { createPeerAddressList } from '../helpers/peer-address-list';
import { answerRouteNotFound } from '../helpers/request-bounds';
import { SESSION_COOKIE_NAME } from '../helpers/session-cookie';
import { emitUserEvent } from '../helpers/user-events';
import { corsPlugin } from '../plugins/cors';
import errorHandler from '../plugins/error-handler';
import interactionApi, {
  ANSWER_BODY_LIMIT,
  carriesCredential,
  checkAnswerBodySize,
  comesFromRealmOrigin,
  interactionReadRateLimitKey,
  parseAnswerForm,
  readsPerInteraction,
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
/** The browser sessions of the app under test (#675's logout cases sign in with them). */
let sessions: BrowserSessionFixture;
/** The clients the logout cases resolve, by `client_id`: a test may change them. */
const logoutClients = new Map<string, Record<string, unknown>>();

/** The browser session a logout interaction ends. */
const LOGOUT_SID = '44444444-4444-4444-8444-444444444444';

/**
 * The app under test. `rateLimit` registers `@fastify/rate-limit` before the
 * routes, as `app.ts` does; `clientId` is the client of every interaction.
 */
async function buildApp(
  options: {
    readonly rateLimit?: boolean;
    readonly clientId?: string;
    readonly step?: InteractionStep;
    /** The client display data the interaction starts with (the consent step's, #629). */
    readonly client?: ClientDisplay;
    /**
     * Start a logout's confirm step for this request instead (#675), for the
     * session {@link LOGOUT_SID} of {@link USER_ID}.
     */
    readonly logout?: LogoutRequest;
    /** Members of the authorization request the interaction holds, such as `prompt` (#640). */
    readonly request?: Partial<InteractionRequest>;
  } = {}
): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  if (options.rateLimit === true) await instance.register(rateLimit, { global: false });
  instance.setValidatorCompiler(validatorCompiler);
  instance.setSerializerCompiler(serializerCompiler);
  await instance.register(errorHandler);
  instance.setNotFoundHandler(answerRouteNotFound);
  supplyRequestRealm(instance, REALM);
  sessions = createBrowserSessionFixture();
  instance.decorate(
    'redis',
    createMemoryInteractionRedis(sessions.redis) as unknown as FastifyInstance['redis']
  );
  instance.decorate('sessionService', sessions.service);
  instance.decorate('sessionEpochs', sessions.epochs);
  instance.decorate('signer', sessions.signer as unknown as FastifyInstance['signer']);
  updateLastLogin = vi.fn(async () => undefined);
  instance.decorate('repositories', {
    users: {
      updateLastLogin,
      findById: vi.fn(async (realmId: string, id: string) => ({ id, realmId, enabled: true })),
    },
    oauthClients: {
      findByClientId: vi.fn(async (_realmId: string, clientId: string) =>
        logoutClients.get(clientId)
      ),
    },
    userCredentials: {},
    adminGrants: {},
    userRequiredActions: {},
  } as unknown as FastifyInstance['repositories']);
  instance.decorate('passwordHasher', {} as FastifyInstance['passwordHasher']);
  // The breach list (#635): every realm here checks nothing.
  instance.decorate('breachedPasswords', {
    check: async () => ({ kind: 'off' }),
    engine: { check: async () => ({ kind: 'off' }) },
  } as FastifyInstance['breachedPasswords']);
  await instance.register(async (scope) => {
    // As `app.ts` registers it: CORS for every origin, before the routes.
    await scope.register(corsPlugin, { corsOrigin: SPA_ORIGIN, production: false });
    // A route of another surface, which CORS answers: the check's control.
    scope.get('/api-route', { config: { surface: 'api' } }, async () => ({ ok: true }));
    scope.post('/start', { config: { surface: 'browser' } }, async (request, reply) => {
      const { startInteraction, startLogoutInteraction } = await import('../helpers/interaction');
      if (options.logout !== undefined) {
        return startLogoutInteraction(request, reply, {
          request: options.logout,
          step: { name: LOGOUT_CONFIRM_STEP, params: {}, alternatives: [] },
          personal: { accounts: [{ identifier: 'alice@example.com', current: true }] },
          carriedSession: { userId: USER_ID, sid: LOGOUT_SID },
        });
      }
      return startInteraction(request, reply, {
        request: {
          ...AUTHORIZE_REQUEST,
          client_id: options.clientId ?? AUTHORIZE_REQUEST.client_id,
          ...options.request,
        },
        step: options.step ?? { name: IDENTIFIER_STEP, params: {}, alternatives: [] },
        ...(options.client === undefined ? {} : { client: options.client }),
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
  finishAuthorization.mockClear();
  cancelAuthorization.mockClear();
  finishConsent.mockReset();
  finishConsent.mockResolvedValue(CONSENT_LOCATION);
  app = await buildApp();
});

afterEach(async () => {
  await app.close();
});

describe('the step read (#616)', () => {
  it('returns the step, its CSRF value, where a finishing answer goes, the brand and the expiry, and no personal data', async () => {
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
      // The origin of the request's redirect_uri: a form answer that finishes
      // is a 303 there, which the page allows in `form-action`.
      formAction: 'https://notes.example.com',
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

  it('refuses a POST with no Content-Type and no body with 415', async () => {
    const browser = new Browser();
    const id = await browser.start();
    for (const operation of ['answer', 'cancel']) {
      const response = await app.inject({
        method: 'POST',
        url: `${INTERACTION_API_PREFIX}/${id}/${operation}`,
        headers: { ...browser.cookie, 'sec-fetch-site': 'same-origin' },
      });
      expect(response.statusCode, operation).toBe(415);
      expect(response.json()).toMatchObject({ code: 'unsupported_media_type' });
    }
    expect(engine.advance).not.toHaveBeenCalled();
  });

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

  it('signs in on a completed round: the session cookie, then 303 to where the request goes on (#628)', async () => {
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
    expect(location.searchParams.get('code')).toBe('c0de');
    // The request the record holds, for the user the sign-in proved, once the
    // interaction has ended: its secret has left the flow cookie.
    expect(finishAuthorization).toHaveBeenCalledOnce();
    expect(finishAuthorization.mock.calls[0]?.[3]).toMatchObject({
      request: { client_id: AUTHORIZE_REQUEST.client_id, state: AUTHORIZE_REQUEST.state },
      transaction: { userId: USER_ID, amr: ['pwd'] },
      continuation: { secrets: [], expiresAt: expect.any(Number) },
    });
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

describe('the consent answer (#629)', () => {
  /** The consent step the interaction holds: what the person saw. */
  const CONSENT: InteractionStep = {
    name: CONSENT_STEP,
    params: {
      scopes: [
        { scope: 'openid', text: 'Verify your identity', sensitive: false, dangerous: false },
        { scope: 'email', text: 'View your email address', sensitive: false, dangerous: false },
      ],
      resources: [],
      remember_default: true,
    },
    alternatives: [],
  };

  /** Who the client is, as `clientDisplay` computed it when the consent started. */
  const CLIENT_DISPLAY: ClientDisplay = {
    kind: 'admin_registered',
    verifiedDomain: {
      host: 'notes.example.com',
      registrableDomain: 'example.com',
      sharedHosting: false,
    },
    redirect: { target: 'host', host: 'notes.example.com' },
    declaredName: 'Notes',
    newClient: false,
  };

  const validateInteraction = componentValidator(INTERACTION_OPENAPI).schema('Interaction');

  beforeEach(async () => {
    await app.close();
    app = await buildApp({ step: CONSENT, client: CLIENT_DISPLAY });
  });

  it('reads the consent step with the client’s display data, as the contract’s Interaction', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const read = await browser.read(id);

    expect(read).toMatchObject({
      step: CONSENT_STEP,
      params: { [CONSENT_STEP]: CONSENT.params },
      client: CLIENT_DISPLAY,
    });
    expect(validateInteraction(read), describeErrors(validateInteraction)).toBe(true);
  });

  it('refuses to read or decide a consent record that holds no client', async () => {
    // Every consent interaction starts with its client since #629. A consent
    // record without one (the optional member joined record version 2) was
    // never shown with its client: it reads as expired and decides nothing.
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const key = REDIS_KEYS.INTERACTION(REALM.id, interactionIdHash(id));
    const stored = JSON.parse((await app.redis.get(key)) as string) as Record<string, unknown>;
    delete stored['client'];
    await app.redis.set(key, JSON.stringify(stored));

    const read = await app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}` });
    expect(read.statusCode).toBe(410);
    expect(read.json()).toMatchObject({ code: 'interaction_expired' });
    const answer = await browser.send(id, 'answer', {
      type: CONSENT_STEP,
      csrf,
      decision: 'allow',
    });
    expect(answer.statusCode).toBe(410);
    expect(answer.json()).toMatchObject({ code: 'interaction_expired' });
    expect(finishConsent).not.toHaveBeenCalled();

    // A step that names no client, the identifier step, meets the contract without one.
    await app.close();
    app = await buildApp();
    const other = new Browser();
    const identifier = await other.read(await other.start());
    expect(identifier).not.toHaveProperty('client');
    expect(validateInteraction(identifier), describeErrors(validateInteraction)).toBe(true);
  });

  it('finishes the interaction on a JSON allow, and answers where finishConsent sends the browser', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(id, 'answer', {
      type: CONSENT_STEP,
      csrf,
      decision: 'allow',
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.json()).toEqual({ result: 'redirect', location: CONSENT_LOCATION });
    // No engine round: the step grammar reads the answer, and the grant is
    // decided once the interaction has ended, for the step it held.
    expect(engine.advance).not.toHaveBeenCalled();
    expect(finishAuthorization).not.toHaveBeenCalled();
    expect(finishConsent).toHaveBeenCalledOnce();
    expect(finishConsent.mock.calls[0]?.[3]).toMatchObject({
      request: { client_id: AUTHORIZE_REQUEST.client_id, state: AUTHORIZE_REQUEST.state },
      transaction: { amr: [] },
      continuation: { secrets: [], expiresAt: expect.any(Number) },
      step: CONSENT,
      // "Remember" is false unless the answer says otherwise.
      answer: { decision: 'allow', remember: false },
    });
    // The interaction is over: its secret left the flow cookie.
    expect(browser.cookies.has(FLOW_COOKIE)).toBe(false);
    expect(eventTypes()).toContain('urn:qauth:event:interaction.answered:v1-rc.0');
  });

  it('answers a form post that remembers the decision with 303 to the location', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(CONSENT_STEP)}&csrf=${csrf}&decision=allow&remember=true`
    );

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(CONSENT_LOCATION);
    expect(finishConsent).toHaveBeenCalledOnce();
    expect(finishConsent.mock.calls[0]?.[3]).toMatchObject({
      step: CONSENT,
      answer: { decision: 'allow', remember: true },
    });
  });

  it('hands a deny to finishConsent, which decides it', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const response = await browser.send(id, 'answer', {
      type: CONSENT_STEP,
      csrf,
      decision: 'deny',
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(finishConsent.mock.calls[0]?.[3]).toMatchObject({
      answer: { decision: 'deny', remember: false },
    });
  });

  it('signs nobody in: no last-login update and no user.signed_in event', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    await browser.send(id, 'answer', { type: CONSENT_STEP, csrf, decision: 'allow' });

    expect(finishConsent).toHaveBeenCalledOnce();
    expect(updateLastLogin).not.toHaveBeenCalled();
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_in:v1-rc.0');
    expect(browser.cookies.has(SESSION_COOKIE_NAME)).toBe(false);
  });

  it('refuses an answer that names a scope or a resource, and keeps the step and its CSRF value', async () => {
    // The grant is the scope set the interaction holds: no answer member can
    // add to it, so the grammar refuses any member beside its own.
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    for (const extra of [
      { scope: 'openid email write:notes' },
      { scopes: ['write:notes'] },
      { resource: 'https://evil.example/' },
    ]) {
      const response = await browser.send(id, 'answer', {
        type: CONSENT_STEP,
        csrf,
        decision: 'allow',
        ...extra,
      });
      expect(response.statusCode, JSON.stringify(extra)).toBe(400);
      expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    }
    const form = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(CONSENT_STEP)}&csrf=${csrf}&decision=allow&scope=write%3Anotes`
    );
    expect(form.statusCode).toBe(400);
    expect(finishConsent).not.toHaveBeenCalled();
    const again = await browser.read(id);
    expect(again.step).toBe(CONSENT_STEP);
    expect(again.csrf).toBe(csrf);
  });

  it('refuses a decision that is neither allow nor deny, and a missing one', async () => {
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    for (const decision of ['maybe', 'ALLOW', '', true, undefined]) {
      const response = await browser.send(id, 'answer', { type: CONSENT_STEP, csrf, decision });
      expect(response.statusCode, String(decision)).toBe(400);
      expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    }
    expect(finishConsent).not.toHaveBeenCalled();
    expect((await browser.read(id)).csrf).toBe(csrf);
  });
});

describe('the logout confirm answer (RP-Initiated Logout 1.0 §2, #675)', () => {
  const RETURN_URI = 'https://notes.example.com/signed-out';
  const STATE = 'af0ifjsldkj';
  const STATUS_PAGE = `${ORIGIN}${END_SESSION_STATUS_PATH}`;
  const LOGOUT_REQUEST: LogoutRequest = {
    client_id: 'notes-app',
    post_logout_redirect_uri: RETURN_URI,
    state: STATE,
  };
  /** The client the logout request named, as the resolver returns it. */
  const NOTES = {
    id: 'row-notes',
    clientId: 'notes-app',
    name: 'Notes',
    enabled: true,
    suspended: false,
    postLogoutRedirectUris: [RETURN_URI],
    environment: 'production',
    metadata: null,
    dynamicRegisteredAt: null,
  };

  beforeEach(async () => {
    logoutClients.clear();
    logoutClients.set('notes-app', { ...NOTES });
    await app.close();
    app = await buildApp({ logout: LOGOUT_REQUEST });
  });

  /** A browser signed in as {@link USER_ID} in session {@link LOGOUT_SID}, at the confirm step. */
  async function atConfirm(): Promise<{ browser: Browser; id: string; csrf: string }> {
    const browser = new Browser();
    const { cookie } = await sessions.signIn({
      sid: LOGOUT_SID,
      realmId: REALM.id,
      userId: USER_ID,
    });
    const eq = cookie.indexOf('=');
    browser.cookies.set(cookie.slice(0, eq), cookie.slice(eq + 1));
    const id = await browser.start();
    const { csrf, step } = await browser.read(id);
    expect(step).toBe(LOGOUT_CONFIRM_STEP);
    return { browser, id, csrf };
  }

  function formAnswer(csrf: string, decision: string): string {
    return `type=${encodeURIComponent(LOGOUT_CONFIRM_STEP)}&csrf=${csrf}&decision=${decision}`;
  }

  /** The data of the one event of `type`. */
  function eventData(type: string): unknown {
    const calls = vi.mocked(emitUserEvent).mock.calls.filter(([, t]) => t === type);
    expect(calls, type).toHaveLength(1);
    return calls[0]?.[2];
  }

  function expectEnded(browser: Browser): void {
    expect(sessions.service.revoke).toHaveBeenCalledOnce();
    expect(sessions.service.revoke).toHaveBeenCalledWith(
      expect.objectContaining({
        realmId: REALM.id,
        sid: LOGOUT_SID,
        userId: USER_ID,
        reason: 'sign_out',
        actor: { type: 'user', id: USER_ID },
      })
    );
    expect(sessions.service.revokeAllForUser).not.toHaveBeenCalled();
    expect(sessions.service.sessions.has(LOGOUT_SID)).toBe(false);
    expect(browser.cookies.has(SESSION_COOKIE_NAME)).toBe(false);
    expect(eventData('urn:qauth:event:user.signed_out:v1-rc.0')).toEqual({ sid: LOGOUT_SID });
  }

  function expectNothingEnded(browser: Browser, reason: string): void {
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(sessions.service.sessions.has(LOGOUT_SID)).toBe(true);
    expect(browser.cookies.has(SESSION_COOKIE_NAME)).toBe(true);
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
    expect(eventData('urn:qauth:event:user.sign_out_failed:v1-rc.0')).toEqual({ reason });
  }

  it('a confirmed logout ends the session the step was started for, clears its cookie and goes back with state (RP-Initiated Logout 1.0 §3)', async () => {
    const { browser, id, csrf } = await atConfirm();
    const response = await browser.send(id, 'answer', formAnswer(csrf, 'logout'));

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expect(engine.advance).not.toHaveBeenCalled();
    expectEnded(browser);
    expect(browser.cookies.has(FLOW_COOKIE)).toBe(false);
  });

  it('a confirmed logout_all ends the same session, answered as JSON', async () => {
    const { browser, id, csrf } = await atConfirm();
    const response = await browser.send(id, 'answer', {
      type: LOGOUT_CONFIRM_STEP,
      csrf,
      decision: 'logout_all',
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(response.json()).toEqual({
      result: 'redirect',
      location: `${RETURN_URI}?state=${STATE}`,
    });
    expectEnded(browser);
  });

  it('a confirmed logout without a return URI goes to the status page', async () => {
    await app.close();
    app = await buildApp({ logout: {} });
    const { browser, id, csrf } = await atConfirm();
    const response = await browser.send(id, 'answer', formAnswer(csrf, 'logout'));

    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(STATUS_PAGE);
    expectEnded(browser);
  });

  it('stay ends nothing and goes back to the app: declined', async () => {
    const { browser, id, csrf } = await atConfirm();
    const response = await browser.send(id, 'answer', formAnswer(csrf, 'stay'));

    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expectNothingEnded(browser, 'declined');
  });

  it('a cancel ends nothing and goes back to the app: declined', async () => {
    const { browser, id, csrf } = await atConfirm();
    const response = await browser.send(id, 'cancel', `csrf=${csrf}`);

    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expectNothingEnded(browser, 'declined');
  });

  it('a session that ended meanwhile is no_session, and the browser still goes back', async () => {
    const { browser, id, csrf } = await atConfirm();
    sessions.service.sessions.delete(LOGOUT_SID);
    const response = await browser.send(id, 'answer', formAnswer(csrf, 'logout'));

    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
    expect(eventData('urn:qauth:event:user.sign_out_failed:v1-rc.0')).toEqual({
      reason: 'no_session',
    });
  });

  const CLIENT_CHANGES: [string, () => void][] = [
    ['deleted', () => logoutClients.delete('notes-app')],
    ['disabled', () => logoutClients.set('notes-app', { ...NOTES, enabled: false })],
    ['suspended', () => logoutClients.set('notes-app', { ...NOTES, suspended: true })],
    [
      'no longer registering the URI',
      () => logoutClients.set('notes-app', { ...NOTES, postLogoutRedirectUris: [] }),
    ],
  ];

  it.each(CLIENT_CHANGES)(
    'checks the return URI again: a client %s since sends a confirmed logout to the status page, never the app (RP-Initiated Logout 1.0 §3)',
    async (_label, change) => {
      const { browser, id, csrf } = await atConfirm();
      change();
      const response = await browser.send(id, 'answer', formAnswer(csrf, 'logout'));
      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(STATUS_PAGE);
      expectEnded(browser);
    }
  );

  it.each(CLIENT_CHANGES)(
    'checks the return URI again: a client %s since sends a cancel to the status page',
    async (_label, change) => {
      const { browser, id, csrf } = await atConfirm();
      change();
      const response = await browser.send(id, 'cancel', `csrf=${csrf}`);
      expect(response.statusCode).toBe(303);
      expect(response.headers.location).toBe(STATUS_PAGE);
      expectNothingEnded(browser, 'declined');
    }
  );

  it('refuses a malformed answer with 400 invalid_answer, and the step and its CSRF value stay', async () => {
    const { browser, id, csrf } = await atConfirm();
    for (const body of [
      { type: LOGOUT_CONFIRM_STEP, csrf, decision: 'maybe' },
      { type: LOGOUT_CONFIRM_STEP, csrf },
      { type: LOGOUT_CONFIRM_STEP, csrf, decision: 'logout', redirect_uri: 'https://evil.example' },
      { type: CONSENT_STEP, csrf, decision: 'allow' },
    ]) {
      const response = await browser.send(id, 'answer', body);
      expect(response.statusCode, JSON.stringify(body)).toBe(400);
      expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    }
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    const again = await browser.read(id);
    expect(again.step).toBe(LOGOUT_CONFIRM_STEP);
    expect(again.csrf).toBe(csrf);
    // The turn stayed: the answer still ends the session.
    const response = await browser.send(id, 'answer', formAnswer(csrf, 'logout'));
    expect(response.statusCode).toBe(303);
    expectEnded(browser);
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
    // The request the record holds goes through the checks again (#628).
    expect(cancelAuthorization).toHaveBeenCalledOnce();
    expect(cancelAuthorization.mock.calls[0]?.[2]).toMatchObject({
      redirect_uri: AUTHORIZE_REQUEST.redirect_uri,
    });
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

  it('sends a cancel another answer beat back to the ceremony page, as JSON and as a form', async () => {
    let release: (value: unknown) => void = () => undefined;
    engine.advance.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          release = () => resolve(PASSWORD_ROUND);
        })
    );
    const browser = new Browser();
    const id = await browser.start();
    const { csrf } = await browser.read(id);
    const answering = browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf,
      login_hint: 'alice@example.com',
    });
    await vi.waitFor(() => expect(engine.advance).toHaveBeenCalled());
    const page = `${ORIGIN}${CEREMONY_PAGE_PREFIX}${id}`;
    const json = await browser.send(id, 'cancel', { csrf });
    expect(json.statusCode).toBe(200);
    expect(json.json()).toEqual({ result: 'redirect', location: page });
    const form = await browser.send(id, 'cancel', `csrf=${csrf}`);
    expect(form.statusCode).toBe(303);
    expect(form.headers.location).toBe(page);
    release(PASSWORD_ROUND);
    expect((await answering).statusCode).toBe(200);
    expect((await browser.read(id)).step).toBe(PASSWORD);
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

describe('the events of a client whose id is longer than an event holds (#616)', () => {
  it('signs in, and the event names no client', async () => {
    await app.close();
    const clientId = `https://notes.example.com/${'c'.repeat(300)}`;
    app = await buildApp({ clientId });
    // The round carries the long id, as the engine writes it, so the stored
    // record holds it too.
    const longRound = {
      ...PASSWORD_ROUND,
      transaction: { ...PASSWORD_ROUND.transaction, clientId },
    };
    engine.advance.mockResolvedValueOnce(longRound).mockResolvedValueOnce(COMPLETE_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'alice@example.com',
    });
    const response = await browser.send(id, 'answer', {
      type: PASSWORD,
      csrf: (await browser.read(id)).csrf,
      password: 'correct horse',
    });
    expect(response.statusCode, response.body).toBe(200);
    const signedIn = vi
      .mocked(emitUserEvent)
      .mock.calls.find(([, type]) => type === 'urn:qauth:event:user.signed_in:v1-rc.0');
    expect(signedIn?.[3]).toMatchObject({ userId: USER_ID, clientId: null });
  });
});

describe('the method of user.signed_in (#639)', () => {
  /** The `user.signed_in` event's data of the sign-in that completes after `round`. */
  async function signedInAfter(round: object): Promise<unknown> {
    engine.advance.mockResolvedValueOnce(round).mockResolvedValueOnce(COMPLETE_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'alice@example.com',
    });
    const response = await browser.send(id, 'answer', {
      type: PASSWORD,
      csrf: (await browser.read(id)).csrf,
      password: 'correct horse',
    });
    expect(response.statusCode, response.body).toBe(200);
    return vi
      .mocked(emitUserEvent)
      .mock.calls.find(([, type]) => type === 'urn:qauth:event:user.signed_in:v1-rc.0')?.[2];
  }

  it('is upstream when a provider proved the account before the step that completed', async () => {
    const afterUpstream = {
      ...PASSWORD_ROUND,
      transaction: {
        ...PASSWORD_ROUND.transaction,
        verified: [
          {
            step: 'upstream',
            params: { providers: [{ provider: 'oidc_corp', name: 'Example Corp' }] },
          },
        ],
      },
    };
    expect(await signedInAfter(afterUpstream)).toEqual({ method: 'upstream' });
  });

  it('is password otherwise', async () => {
    expect(await signedInAfter(PASSWORD_ROUND)).toEqual({ method: 'password' });
  });
});

describe('a registration, through the engine (#640)', () => {
  /** The engine's round that registered an account. */
  const REGISTERED_ROUND = {
    kind: 'complete',
    transaction: null,
    signIn: { subject: 'user-new', identifier: 'new@example.com', registered: true },
  };

  /** Answer the identifier step of a fresh interaction; the engine answers `round`. */
  async function answerIdentifier(round: object) {
    engine.advance.mockResolvedValueOnce(round);
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: IDENTIFIER,
      csrf: (await browser.read(id)).csrf,
      login_hint: 'new@example.com',
    });
    return { browser, response };
  }

  it('runs the rounds of a prompt=create request as a registration', async () => {
    app = await buildApp({ request: { prompt: 'create' } });
    await answerIdentifier(PASSWORD_ROUND);

    expect(engine.advance).toHaveBeenCalledWith(
      null,
      expect.objectContaining({ step: IDENTIFIER }),
      expect.objectContaining({ flow: 'register' })
    );
  });

  it('runs the rounds of any other request as a sign-in', async () => {
    await answerIdentifier(PASSWORD_ROUND);

    expect(engine.advance.mock.calls[0]?.[2]).not.toHaveProperty('flow');
  });

  it('finishes for the new account with no session and no sign-in recorded', async () => {
    app = await buildApp({ request: { prompt: 'create' } });
    const { browser, response } = await answerIdentifier(REGISTERED_ROUND);

    expect(response.statusCode, response.body).toBe(200);
    expect(finishAuthorization).toHaveBeenCalledOnce();
    expect(finishAuthorization.mock.calls[0]?.[3]).toMatchObject({
      transaction: { userId: 'user-new', amr: [], registered: true },
    });
    // No browser session, no last-login stamp, no `user.signed_in`.
    expect(browser.cookies.has(SESSION_COOKIE_NAME)).toBe(false);
    expect(updateLastLogin).not.toHaveBeenCalled();
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_in:v1-rc.0');
  });

  it('ends the interaction as an expired one when registration closed since it started', async () => {
    app = await buildApp({ request: { prompt: 'create' } });
    const { response } = await answerIdentifier({
      kind: 'refused',
      reason: 'request_refused',
      code: REGISTRATION_NOT_ALLOWED,
      transaction: PASSWORD_ROUND.transaction,
    });

    expect(response.statusCode).toBe(410);
    expect(finishAuthorization).not.toHaveBeenCalled();
  });
});

describe('the switch between a sign-in and a registration (#1079)', () => {
  const REGISTER = stepUrn('register');
  const SIGN_IN = stepUrn('sign_in');

  it('lets the engine switch on an authorization request’s rounds, and hands it an offered marker', async () => {
    await app.close();
    app = await buildApp({ step: { name: IDENTIFIER, params: {}, alternatives: [REGISTER] } });
    engine.advance.mockResolvedValueOnce(PASSWORD_ROUND);
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: REGISTER,
      csrf: (await browser.read(id)).csrf,
    });

    expect(response.statusCode, response.body).toBe(200);
    expect(engine.advance).toHaveBeenCalledWith(
      null,
      expect.objectContaining({ step: REGISTER }),
      expect.objectContaining({ switchFlows: true })
    );
    expect(engine.advance.mock.calls[0]?.[2]).not.toHaveProperty('flow');
  });

  it.each([
    ['register', REGISTER],
    ['sign_in', SIGN_IN],
  ])('refuses a %s answer its step did not offer with 400, before the engine', async (_, type) => {
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type,
      csrf: (await browser.read(id)).csrf,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    expect(engine.advance).not.toHaveBeenCalled();
  });

  it('answers the engine’s refusal of a marker the gate no longer allows with the same 400', async () => {
    await app.close();
    app = await buildApp({ step: { name: IDENTIFIER, params: {}, alternatives: [REGISTER] } });
    engine.advance.mockResolvedValueOnce({
      kind: 'refused',
      reason: 'invalid_answer',
      transaction: PASSWORD_ROUND.transaction,
    });
    const browser = new Browser();
    const id = await browser.start();
    const response = await browser.send(id, 'answer', {
      type: REGISTER,
      csrf: (await browser.read(id)).csrf,
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ code: 'invalid_answer' });
    expect(finishAuthorization).not.toHaveBeenCalled();
  });
});

describe('the rate limits (#616)', () => {
  beforeEach(async () => {
    await app.close();
    app = await buildApp({ rateLimit: true });
  });

  it('counts an answer with a credential against the sign-in form budget, and any other apart', async () => {
    const browser = new Browser();
    const id = await browser.start();
    // A wrong CSRF value is refused after the limit has counted the answer.
    const identifier = { type: IDENTIFIER, csrf: 'x', login_hint: 'alice@example.com' };
    for (let n = 0; n < 6; n += 1) {
      expect((await browser.send(id, 'answer', identifier)).statusCode).toBe(403);
    }
    for (let n = 0; n < 5; n += 1) {
      const guess = await browser.send(id, 'answer', {
        type: PASSWORD,
        csrf: 'x',
        password: 'guess',
      });
      expect(guess.statusCode).toBe(403);
    }
    const sixth = await browser.send(
      id,
      'answer',
      `type=${encodeURIComponent(PASSWORD)}&csrf=x&password=guess`
    );
    expect(sixth.statusCode).toBe(429);
    expect((await browser.send(id, 'answer', identifier)).statusCode).toBe(403);
    expect(engine.advance).not.toHaveBeenCalled();
  });

  /** A step read from `remoteAddress`, as the ceremony app's server or any caller makes it. */
  const read = (id: string, remoteAddress = '127.0.0.1') =>
    app.inject({ method: 'GET', url: `${INTERACTION_API_PREFIX}/${id}`, remoteAddress });
  /** A well-formed interaction id no interaction has. */
  const randomId = () => randomBytes(32).toString('base64url');

  it('counts an unlisted caller per address, so random well-formed ids reach 429 (#982)', async () => {
    const id = await new Browser().start();
    for (let n = 0; n < 60; n += 1) expect((await read(randomId())).statusCode).toBe(410);
    expect((await read(randomId())).statusCode).toBe(429);
    // The address's one bucket: a real interaction too, and a listed peer's
    // or another address's reads are apart.
    expect((await read(id)).statusCode).toBe(429);
    expect((await read(id, '203.0.113.9')).statusCode).toBe(200);
    expect((await read(id, '198.51.100.7')).statusCode).toBe(200);
  });

  it("counts a listed peer's reads per interaction, each under the peer cap (#982)", async () => {
    const first = await new Browser().start();
    const second = await new Browser().start();
    for (let n = 0; n < 3; n += 1) {
      expect((await read(first, '198.51.100.7')).statusCode).toBe(200);
    }
    expect((await read(first, '198.51.100.7')).statusCode).toBe(429);
    expect((await read(second, '198.51.100.7')).statusCode).toBe(200);
    // No address bucket: more reads than the address budget, each of its own
    // interaction, are never refused.
    for (let n = 0; n < 61; n += 1) {
      const unknown = await read(randomId(), '::ffff:198.51.100.7');
      expect(unknown.statusCode).toBe(410);
      expect(unknown.headers['x-ratelimit-remaining']).toBe('2');
    }
    // The unlisted address's budget is untouched.
    expect((await read(first)).statusCode).toBe(200);
  });

  it('counts a listed peer per address for a junk id (#982)', async () => {
    for (let n = 0; n < 60; n += 1) {
      expect((await read('junk', '198.51.100.7')).statusCode).not.toBe(429);
    }
    expect((await read('junk', '198.51.100.7')).statusCode).toBe(429);
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
      // The identifier step's personal data: its prefill, none here (#628).
      expect(response.json()).toEqual({ step: IDENTIFIER, data: { [IDENTIFIER]: {} } });
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
  it('keys a step read per interaction only from a listed peer and for a well-formed id (#982)', () => {
    const peers = createPeerAddressList(['198.51.100.7', '2001:db8:1:2::/64']);
    const id = randomBytes(32).toString('base64url');
    const request = (interactionId: string, ip: string) =>
      ({ params: { interactionId }, ip, realm: { id: REALM.id } }) as unknown as FastifyRequest;
    const perInteraction = `${REALM.id}:interaction:${interactionIdHash(id)}`;

    expect(interactionReadRateLimitKey(request(id, '198.51.100.7'), peers)).toBe(perInteraction);
    expect(interactionReadRateLimitKey(request(id, '2001:db8:1:2::9'), peers)).toBe(perInteraction);
    expect(readsPerInteraction(request(id, '198.51.100.7'), peers)).toBe(true);

    expect(interactionReadRateLimitKey(request(id, '203.0.113.9'), peers)).toBe(
      `${REALM.id}:203.0.113.9`
    );
    expect(interactionReadRateLimitKey(request('junk', '198.51.100.7'), peers)).toBe(
      `${REALM.id}:198.51.100.7`
    );
    expect(readsPerInteraction(request('junk', '198.51.100.7'), peers)).toBe(false);
    // With no peer listed, as by default, every read counts per address.
    expect(
      interactionReadRateLimitKey(request(id, '198.51.100.7'), createPeerAddressList([]))
    ).toBe(`${REALM.id}:198.51.100.7`);
  });

  it('tells an answer that carries a credential, as JSON or as a form post', () => {
    for (const name of ['password', 'otp', 'recovery_code', 'webauthn_response', 'user_code']) {
      expect(carriesCredential({ type: 'x', csrf: 'y', [name]: 'z' }), name).toBe(true);
      expect(carriesCredential(parseAnswerForm(`type=x&${name}=z`)), name).toBe(true);
    }
    expect(carriesCredential({ type: 'x', csrf: 'y', login_hint: 'alice@example.com' })).toBe(
      false
    );
    expect(carriesCredential(parseAnswerForm('type=x&decision=allow'))).toBe(false);
    for (const body of [undefined, null, 'password', 42])
      expect(carriesCredential(body)).toBe(false);
    // An inherited member is no member of the body.
    expect(carriesCredential(Object.create({ password: 'z' }))).toBe(false);
  });

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
