import formbody from '@fastify/formbody';
import type { IdTokenHint } from '@qauth-labs/fastify-plugin-jwt';
import { JWTInvalidError } from '@qauth-labs/shared-errors';
import {
  ceremonyPagePath,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    NODE_ENV: 'test',
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_LIMIT_LENIENT: 600,
    AUTHORIZE_RATE_WINDOW: 60,
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
    INTERACTION_UI_ENABLED: false,
    INTERACTION_TTL: 1800,
    SESSION_COOKIE_SECURE: true,
    SESSION_COOKIE_TTL: 3600,
    SECURITY_HSTS_ENABLED: false,
    SECURITY_HSTS_MAX_AGE: 31536000,
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

import { env } from '../../../config/env';
import {
  type BrowserSessionFixture,
  createBrowserSessionFixture,
} from '../../../testing/browser-sessions';
import { createMemoryInteractionRedis } from '../../../testing/interaction-redis';
import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { REDIS_KEYS } from '../../constants';
import { interactionIdHash, interactionRecordSchema } from '../../helpers/interaction-record';
import { tokenRealm } from '../../helpers/realm-url';
import { answerRouteNotFound } from '../../helpers/request-bounds';
import { SESSION_COOKIE_NAME } from '../../helpers/session-cookie';
import { emitUserEvent } from '../../helpers/user-events';
import errorHandler from '../../plugins/error-handler';
import { securityHeadersPlugin } from '../../plugins/security-headers';
import endSessionRoutes from './end-session';

/**
 * THE END-SESSION ENDPOINT (#675; OpenID Connect RP-Initiated Logout 1.0), on
 * a bare app with the real error handler, security headers, session cookie,
 * interaction store and client resolution, over a fake session service, an
 * in-memory Redis and a stand-in hint verifier. The flow graph is
 * `graphs/flows/core/logout`; the confirm step's answer is the Interaction
 * API's (`interaction-api.test.ts`).
 */

const REALM = testRealm({ id: '22222222-2222-4222-8222-222222222222' });
const ISSUER = 'https://auth.example.com';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_USER_ID = '33333333-3333-4333-8333-333333333333';
const RETURN_URI = 'https://notes.example.com/signed-out';
const DCR_RETURN_URI = 'https://registered.example.net/signed-out';
const STATE = 'af0ifjsldkj';
const LOGOUT_CONFIRM = stepUrn('logout_confirm');

/** A client row as the resolver returns it: only what the end-session rules read. */
function clientRow(overrides: Record<string, unknown>) {
  return {
    id: `row-${String(overrides['clientId'])}`,
    clientSecretHash: 'h',
    enabled: true,
    suspended: false,
    grantTypes: ['authorization_code'],
    responseTypes: ['code'],
    scopes: ['openid'],
    audience: null,
    idJagTargets: [],
    dpopBoundAccessTokens: false,
    redirectUris: ['https://notes.example.com/callback'],
    postLogoutRedirectUris: [] as string[],
    tokenEndpointAuthMethod: 'none',
    name: 'Notes',
    dynamicRegisteredAt: null,
    isAgent: false,
    maxAgentMode: null,
    environment: 'production',
    // Set up by the operator (the seed manifest): trusted with an automatic
    // redirect. `dcr-app` below is not.
    provisionedByOperator: true,
    verifiedDomain: null,
    developerId: null,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    metadata: null,
    ...overrides,
  };
}

/** The clients of the realm, by `client_id`. */
const CLIENTS: Record<string, ReturnType<typeof clientRow>> = {
  'notes-app': clientRow({ clientId: 'notes-app', postLogoutRedirectUris: [RETURN_URI] }),
  // A client that registered no return URI.
  'quiet-app': clientRow({ clientId: 'quiet-app', name: 'Quiet' }),
  // A client of open dynamic registration: it registered its own return URI.
  'dcr-app': clientRow({
    clientId: 'dcr-app',
    name: 'Registered',
    provisionedByOperator: false,
    postLogoutRedirectUris: [DCR_RETURN_URI],
  }),
  'disabled-app': clientRow({
    clientId: 'disabled-app',
    enabled: false,
    postLogoutRedirectUris: [RETURN_URI],
  }),
  'suspended-app': clientRow({
    clientId: 'suspended-app',
    suspended: true,
    postLogoutRedirectUris: [RETURN_URI],
  }),
};

const SID = '44444444-4444-4444-8444-444444444444';

/** The hints the stand-in verifier accepts: anything else does not verify. */
const HINTS: Record<string, IdTokenHint> = {
  'hint.alice': { sub: USER_ID, aud: ['notes-app'], sid: SID, expired: false },
  'hint.alice.expired': {
    sub: USER_ID,
    aud: ['notes-app'],
    sid: SID,
    exp: 1_700_000_000,
    expired: true,
  },
  // The account's ID token from another of its sessions.
  'hint.alice.other-session': {
    sub: USER_ID,
    aud: ['notes-app'],
    sid: '55555555-5555-4555-8555-555555555555',
    expired: false,
  },
  // An ID token issued before ID tokens carried sid.
  'hint.alice.no-sid': { sub: USER_ID, aud: ['notes-app'], expired: false },
  'hint.bob': { sub: OTHER_USER_ID, aud: ['notes-app'], expired: false },
  'hint.alice.dcr-app': { sub: USER_ID, aud: ['dcr-app'], sid: SID, expired: false },
  'hint.alice.quiet': { sub: USER_ID, aud: ['quiet-app'], expired: false },
  'hint.alice.disabled-app': { sub: USER_ID, aud: ['disabled-app'], expired: false },
  'hint.alice.suspended-app': { sub: USER_ID, aud: ['suspended-app'], expired: false },
  // A client deleted since: the realm resolves no such client.
  'hint.alice.deleted-app': { sub: USER_ID, aud: ['deleted-app'], expired: false },
};

let app: FastifyInstance;
let sessions: BrowserSessionFixture;
let verifyIdTokenHint: ReturnType<typeof vi.fn>;

const mutableEnv = env as { INTERACTION_UI_ENABLED: boolean };

async function buildApp(): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  instance.setValidatorCompiler(validatorCompiler);
  instance.setSerializerCompiler(serializerCompiler);
  await instance.register(errorHandler);
  instance.setNotFoundHandler(answerRouteNotFound);
  // As `app.ts` registers them: the security headers (the CSP the confirm
  // page widens) and the form body parser, before the routes.
  await instance.register(securityHeadersPlugin);
  await instance.register(formbody);
  supplyRequestRealm(instance, REALM);
  sessions = createBrowserSessionFixture();
  instance.decorate(
    'redis',
    createMemoryInteractionRedis(sessions.redis) as unknown as FastifyInstance['redis']
  );
  instance.decorate('sessionService', sessions.service);
  instance.decorate('signer', sessions.signer as unknown as FastifyInstance['signer']);
  verifyIdTokenHint = vi.fn(async (_realm: unknown, token: string) => {
    const hint = HINTS[token];
    if (hint === undefined) throw new JWTInvalidError('the hint does not verify');
    return hint;
  });
  instance.decorate('jwtUtils', { verifyIdTokenHint } as unknown as FastifyInstance['jwtUtils']);
  instance.decorate('repositories', {
    oauthClients: {
      findByClientId: vi.fn(async (_realmId: string, clientId: string) => CLIENTS[clientId]),
    },
    users: {
      findById: vi.fn(async (realmId: string, id: string) => ({ id, realmId, enabled: true })),
    },
  } as unknown as FastifyInstance['repositories']);
  await instance.register(endSessionRoutes, { prefix: '/oauth' });
  await instance.ready();
  return instance;
}

beforeEach(async () => {
  vi.mocked(emitUserEvent).mockClear();
  mutableEnv.INTERACTION_UI_ENABLED = false;
  app = await buildApp();
});

afterEach(async () => {
  mutableEnv.INTERACTION_UI_ENABLED = false;
  await app.close();
});

/** A browser signed in to the realm as Alice: its `Cookie` header. */
async function signedIn(): Promise<string> {
  const { cookie } = await sessions.signIn({
    sid: SID,
    realmId: REALM.id,
    userId: USER_ID,
    side: { identifier: 'alice@example.com' },
  });
  return cookie;
}

function query(params: Record<string, string>): string {
  return new URLSearchParams(params).toString();
}

async function endSession(
  params: Record<string, string>,
  cookie?: string
): Promise<LightMyRequestResponse> {
  return app.inject({
    method: 'GET',
    url: `/oauth/end-session?${query(params)}`,
    headers: cookie === undefined ? {} : { cookie },
  });
}

function eventTypes(): string[] {
  return vi.mocked(emitUserEvent).mock.calls.map(([, type]) => type);
}

/** The data and options of the one event of `type` the request emitted. */
function eventOf(type: string): { data: unknown; options: unknown } {
  const calls = vi.mocked(emitUserEvent).mock.calls.filter(([, t]) => t === type);
  expect(calls, type).toHaveLength(1);
  return { data: calls[0]?.[2], options: calls[0]?.[3] };
}

/** The `Set-Cookie` lines of a response. */
function setCookies(response: LightMyRequestResponse): string[] {
  const header = response.headers['set-cookie'];
  return header === undefined ? [] : Array.isArray(header) ? header : [header];
}

function clearsSessionCookie(response: LightMyRequestResponse): boolean {
  return setCookies(response).some(
    (line) => line.startsWith(`${SESSION_COOKIE_NAME}=;`) && /Max-Age=0/.test(line)
  );
}

/** The session ended through the service, by Alice, for signing out. */
function expectSessionEnded(): void {
  expect(sessions.service.revoke).toHaveBeenCalledOnce();
  expect(sessions.service.revoke).toHaveBeenCalledWith(
    expect.objectContaining({
      realmId: REALM.id,
      sid: SID,
      userId: USER_ID,
      reason: 'sign_out',
      actor: { type: 'user', id: USER_ID },
    })
  );
  expect(sessions.service.sessions.has(SID)).toBe(false);
  // No refresh token is revoked here, nor any other session of the user.
  expect(sessions.service.revokeAllForUser).not.toHaveBeenCalled();
  expect(eventOf('urn:qauth:event:user.signed_out:v1-rc.0')).toEqual({
    data: { sid: SID },
    options: expect.objectContaining({ realmId: REALM.id, userId: USER_ID, actor: 'user' }),
  });
}

/** Nothing ended, and the refusal page answered: 400, HTML, never a redirect. */
function expectRefused(response: LightMyRequestResponse, reason: string): void {
  expect(response.statusCode, response.body).toBe(400);
  expect(response.headers.location).toBeUndefined();
  expect(response.headers['content-type']).toMatch(/^text\/html/);
  expect(response.headers['cache-control']).toBe('no-store');
  expect(response.body).toContain('This sign-out request is not valid');
  expect(sessions.service.revoke).not.toHaveBeenCalled();
  expect(clearsSessionCookie(response)).toBe(false);
  expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
  expect(eventOf('urn:qauth:event:user.sign_out_failed:v1-rc.0').data).toEqual({ reason });
}

describe('a valid hint that names the account of the session (RP-Initiated Logout 1.0 §2, #675)', () => {
  it('ends the session at once, verified with the realm keys and issuer, and goes back with state (RP-Initiated Logout 1.0 §3)', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice',
        post_logout_redirect_uri: RETURN_URI,
        state: STATE,
      },
      cookie
    );

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expect(verifyIdTokenHint).toHaveBeenCalledWith(tokenRealm(REALM), 'hint.alice');
    expect(clearsSessionCookie(response)).toBe(true);
    expectSessionEnded();
    expect(eventOf('urn:qauth:event:user.signed_out:v1-rc.0').options).toMatchObject({
      clientId: 'notes-app',
    });
  });

  it('accepts an expired hint the same way: the session ends and the browser goes back', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      { id_token_hint: 'hint.alice.expired', post_logout_redirect_uri: RETURN_URI, state: STATE },
      cookie
    );

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expect(clearsSessionCookie(response)).toBe(true);
    expectSessionEnded();
  });

  it('goes back without a state when the request carried none, and shows the signed-out page with no return URI', async () => {
    const cookie = await signedIn();
    const back = await endSession(
      { id_token_hint: 'hint.alice', post_logout_redirect_uri: RETURN_URI },
      cookie
    );
    expect(back.statusCode).toBe(303);
    expect(back.headers.location).toBe(RETURN_URI);

    const again = await signedIn();
    const page = await endSession({ id_token_hint: 'hint.alice' }, again);
    expect(page.statusCode).toBe(200);
    expect(page.headers['content-type']).toMatch(/^text\/html/);
    expect(page.body).toContain('You are signed out');
    expect(clearsSessionCookie(page)).toBe(true);
  });

  it('takes the parameters in the query of a GET and the form body of a POST alike', async () => {
    const cookie = await signedIn();
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/end-session',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      payload: query({
        id_token_hint: 'hint.alice',
        post_logout_redirect_uri: RETURN_URI,
        state: STATE,
      }),
    });

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expectSessionEnded();
  });

  it('sends a POST without the session cookie again as a GET with its parameters, and ends or records nothing', async () => {
    // A cross-site form post: the SameSite=Lax session cookie stays behind.
    await signedIn();
    const params = {
      id_token_hint: 'hint.alice',
      client_id: 'notes-app',
      post_logout_redirect_uri: RETURN_URI,
      state: STATE,
      ui_locales: 'fr-CA fr',
      logout_hint: 'alice@example.com',
    };
    const response = await app.inject({
      method: 'POST',
      url: '/oauth/end-session',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      // An unknown parameter is dropped on the way.
      payload: query({ ...params, extra: 'dropped' }),
    });

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers['cache-control']).toBe('no-store');
    const location = new URL(String(response.headers.location));
    expect(`${location.origin}${location.pathname}`).toBe(`${ISSUER}/oauth/end-session`);
    expect(Object.fromEntries(location.searchParams)).toEqual(params);
    expect(verifyIdTokenHint).not.toHaveBeenCalled();
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(sessions.service.sessions.has(SID)).toBe(true);
    expect(clearsSessionCookie(response)).toBe(false);
    expect(eventTypes()).toEqual([]);

    // With no parameter, the bare endpoint.
    const bare = await app.inject({
      method: 'POST',
      url: '/oauth/end-session',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: '',
    });
    expect(bare.statusCode).toBe(303);
    expect(bare.headers.location).toBe(`${ISSUER}/oauth/end-session`);
  });

  it('accepts ui_locales and logout_hint it does not read, whatever locales they name', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice',
        post_logout_redirect_uri: RETURN_URI,
        ui_locales: 'tlh-Latn x-none',
        logout_hint: 'alice@example.com',
      },
      cookie
    );
    expect(response.statusCode, response.body).toBe(303);
    expectSessionEnded();
  });
});

describe('a hint that does not verify (RP-Initiated Logout 1.0 §4, #675)', () => {
  it('counts a hint that does not verify as absent: it names no client and ends nothing', async () => {
    const cookie = await signedIn();
    // Without the hint the return URI names no client: refused.
    const refused = await endSession(
      { id_token_hint: 'not-a-token', post_logout_redirect_uri: RETURN_URI },
      cookie
    );
    expectRefused(refused, 'post_logout_redirect_uri_without_client');

    // Without a return URI, the browser is asked to confirm.
    vi.mocked(emitUserEvent).mockClear();
    const asked = await endSession({ id_token_hint: 'not-a-token' }, cookie);
    expect(asked.statusCode).toBe(200);
    expect(asked.body).toContain('Sign out?');
    expect(sessions.service.revoke).not.toHaveBeenCalled();
  });
});

describe('the client and the return URI (RP-Initiated Logout 1.0 §2, #675)', () => {
  it('refuses a client_id that is not the hint’s aud: an information page, nothing ended', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice',
        client_id: 'quiet-app',
        post_logout_redirect_uri: RETURN_URI,
      },
      cookie
    );
    expectRefused(response, 'client_id_mismatch');
    expect(sessions.service.sessions.has(SID)).toBe(true);
  });

  it('accepts a client_id that is the hint’s aud', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice',
        client_id: 'notes-app',
        post_logout_redirect_uri: RETURN_URI,
        state: STATE,
      },
      cookie
    );
    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expectSessionEnded();
  });

  it('refuses a return URI without any client, never redirecting (RP-Initiated Logout 1.0 §3)', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      { post_logout_redirect_uri: RETURN_URI, state: STATE },
      cookie
    );
    expectRefused(response, 'post_logout_redirect_uri_without_client');
  });

  it.each([
    ['another path', 'https://notes.example.com/elsewhere'],
    ['a trailing slash', `${RETURN_URI}/`],
    ['an added query', `${RETURN_URI}?next=1`],
    ['another host', 'https://evil.example/signed-out'],
    ['plain http', 'http://notes.example.com/signed-out'],
  ])(
    'refuses an unregistered post_logout_redirect_uri (%s) with no Location, as the exact match requires (RP-Initiated Logout 1.0 §3, §4)',
    async (_label, uri) => {
      const cookie = await signedIn();
      const response = await endSession(
        { client_id: 'notes-app', post_logout_redirect_uri: uri, state: STATE },
        cookie
      );
      expectRefused(response, 'post_logout_redirect_uri_not_registered');
      expect(eventOf('urn:qauth:event:user.sign_out_failed:v1-rc.0').options).toMatchObject({
        clientId: 'notes-app',
      });
    }
  );

  it('refuses an unregistered post_logout_redirect_uri of an unknown client too (RP-Initiated Logout 1.0 §3)', async () => {
    const response = await endSession({
      client_id: 'nobody',
      post_logout_redirect_uri: RETURN_URI,
    });
    expectRefused(response, 'post_logout_redirect_uri_not_registered');
  });

  it('never redirects for a client that registered no post_logout_redirect_uris (RP-Initiated Logout 1.0 §3.1)', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      { id_token_hint: 'hint.alice.quiet', post_logout_redirect_uri: RETURN_URI },
      cookie
    );
    expectRefused(response, 'post_logout_redirect_uri_not_registered');
  });

  it.each(['disabled-app', 'suspended-app'])(
    'refuses the registered return URI of a client that may not be used (%s): client_unusable',
    async (clientId) => {
      const cookie = await signedIn();
      const response = await endSession(
        { client_id: clientId, post_logout_redirect_uri: RETURN_URI },
        cookie
      );
      expectRefused(response, 'client_unusable');
    }
  );

  it('shows the trace id on the refusal page, and no request parameter', async () => {
    const response = await endSession({
      client_id: 'notes-app',
      post_logout_redirect_uri: 'https://evil.example/landing',
      state: 'st<b>ate',
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).toMatch(/Reference: \S+/);
    expect(response.body).not.toContain('evil.example');
    expect(response.body).not.toContain('st&lt;b&gt;ate');
    expect(response.body).not.toContain('st<b>ate');
    expect(response.body).not.toContain('notes-app');
  });
});

describe('no session to end (RP-Initiated Logout 1.0 §4, #675)', () => {
  it('goes back to a registered URI with state, and records nothing_to_end as no_session', async () => {
    const response = await endSession({
      id_token_hint: 'hint.alice',
      post_logout_redirect_uri: RETURN_URI,
      state: STATE,
    });
    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe(`${RETURN_URI}?state=${STATE}`);
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(eventOf('urn:qauth:event:user.sign_out_failed:v1-rc.0').data).toEqual({
      reason: 'no_session',
    });
  });

  it('shows the signed-out page without a return URI', async () => {
    const response = await endSession({});
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('You are signed out');
    expect(eventOf('urn:qauth:event:user.sign_out_failed:v1-rc.0').data).toEqual({
      reason: 'no_session',
    });
  });
});

describe('a client the operator did not set up (RFC 9700 §4.11.2, #675)', () => {
  const back = `${DCR_RETURN_URI}?state=${STATE}`;

  it('offers its registered return URI as a link, never a redirect, when there is no session to end', async () => {
    const response = await endSession({
      client_id: 'dcr-app',
      post_logout_redirect_uri: DCR_RETURN_URI,
      state: STATE,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers.location).toBeUndefined();
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.body).toContain('You are signed out');
    expect(response.body).toContain('not set up by the operator');
    expect(response.body).toContain(`href="${back}"`);
    expect(response.body).toContain('Continue to registered.example.net');
    expect(eventOf('urn:qauth:event:user.sign_out_failed:v1-rc.0').data).toEqual({
      reason: 'no_session',
    });
  });

  it('ends the session at once for a valid hint, then offers the return URI as a link', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice.dcr-app',
        post_logout_redirect_uri: DCR_RETURN_URI,
        state: STATE,
      },
      cookie
    );
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toContain(`href="${back}"`);
    expect(sessions.service.revoke).toHaveBeenCalledTimes(1);
    expect(clearsSessionCookie(response)).toBe(true);
    expect(eventTypes()).toContain('urn:qauth:event:user.signed_out:v1-rc.0');
  });

  it('still refuses a URI it did not register, with no link', async () => {
    const response = await endSession({
      client_id: 'dcr-app',
      post_logout_redirect_uri: 'https://registered.example.net/elsewhere',
      state: STATE,
    });
    expect(response.statusCode).toBe(400);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).not.toContain('href=');
  });
});

describe('the confirm step (RP-Initiated Logout 1.0 §2, #675)', () => {
  /** The interaction the request started, read back from the store. */
  async function storedInteraction(id: string) {
    const raw = await app.redis.get(REDIS_KEYS.INTERACTION(REALM.id, interactionIdHash(id)));
    expect(raw).not.toBeNull();
    return interactionRecordSchema.parse(JSON.parse(raw as string));
  }

  it('asks the person to confirm when no hint is given: a form posting to the Interaction API, nothing ended', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      { client_id: 'notes-app', post_logout_redirect_uri: RETURN_URI, state: STATE },
      cookie
    );

    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['content-type']).toMatch(/^text\/html/);
    expect(response.headers['cache-control']).toBe('no-store');
    const action = /action="([^"]+)"/.exec(response.body)?.[1];
    expect(action).toMatch(new RegExp(`^${INTERACTION_API_PREFIX}/[A-Za-z0-9_-]{43}/answer$`));
    expect(response.body).toContain(`name="type" value="${LOGOUT_CONFIRM}"`);
    expect(response.body).toMatch(/name="csrf" value="[A-Za-z0-9_-]{43}"/);
    expect(response.body).toContain('alice@example.com');
    expect(response.body).toContain('Notes');
    for (const decision of ['logout', 'logout_all', 'stay']) {
      expect(response.body).toContain(`name="decision" value="${decision}"`);
    }

    // Nothing ended: the session is live and its cookie stays.
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(clearsSessionCookie(response)).toBe(false);
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
    const created = eventOf('urn:qauth:event:interaction.created:v1-rc.0');
    expect(created.data).toMatchObject({ purpose: 'logout', step: LOGOUT_CONFIRM });
    expect(created.options).toMatchObject({ userId: USER_ID, clientId: 'notes-app' });

    // The record holds the checked request and the session, never a hint.
    const id = String(action).split('/').at(-2) as string;
    const record = await storedInteraction(id);
    expect(record).toMatchObject({
      purpose: 'logout',
      request: { client_id: 'notes-app', post_logout_redirect_uri: RETURN_URI, state: STATE },
      carriedSession: { userId: USER_ID, sid: SID },
      step: { name: LOGOUT_CONFIRM },
    });
  });

  it('asks the person to confirm when a valid hint names another account', async () => {
    const cookie = await signedIn();
    const response = await endSession({ id_token_hint: 'hint.bob' }, cookie);
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('Sign out?');
    expect(sessions.service.revoke).not.toHaveBeenCalled();
  });

  it('asks the person to confirm when a valid hint names the account but another session by its sid, a suspect request (RP-Initiated Logout 1.0 §2)', async () => {
    const cookie = await signedIn();
    const response = await endSession(
      {
        id_token_hint: 'hint.alice.other-session',
        post_logout_redirect_uri: RETURN_URI,
        state: STATE,
      },
      cookie
    );
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toContain('Sign out?');
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(clearsSessionCookie(response)).toBe(false);
    expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
  });

  it('asks the person to confirm when a valid hint of the account carries no sid: it names no session', async () => {
    const cookie = await signedIn();
    const response = await endSession({ id_token_hint: 'hint.alice.no-sid' }, cookie);
    expect(response.statusCode, response.body).toBe(200);
    expect(response.body).toContain('Sign out?');
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(clearsSessionCookie(response)).toBe(false);
  });

  it.each(['deleted-app', 'disabled-app', 'suspended-app'])(
    'asks the person to confirm when a valid hint names the account but its client (%s) may no longer be used',
    async (clientId) => {
      const cookie = await signedIn();
      const response = await endSession({ id_token_hint: `hint.alice.${clientId}` }, cookie);
      expect(response.statusCode, response.body).toBe(200);
      expect(response.body).toContain('Sign out?');
      // No client is shown: the request names none the realm trusts.
      expect(response.body).toContain('A sign-out was requested for this browser.');
      expect(sessions.service.revoke).not.toHaveBeenCalled();
      expect(clearsSessionCookie(response)).toBe(false);
      expect(eventTypes()).not.toContain('urn:qauth:event:user.signed_out:v1-rc.0');
    }
  );

  it('asks the person to confirm through the ceremony app with INTERACTION_UI_ENABLED on', async () => {
    mutableEnv.INTERACTION_UI_ENABLED = true;
    const cookie = await signedIn();
    const response = await endSession({ client_id: 'notes-app' }, cookie);

    expect(response.statusCode, response.body).toBe(303);
    expect(response.headers['cache-control']).toBe('no-store');
    const location = String(response.headers.location);
    const id = location.split('/').at(-1) as string;
    expect(location).toBe(ceremonyPagePath(id));
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(eventOf('urn:qauth:event:interaction.created:v1-rc.0').data).toMatchObject({
      purpose: 'logout',
    });
    // The interaction is bound to this browser by its flow cookie.
    expect(setCookies(response).some((line) => line.startsWith('__Host-qauth_flow='))).toBe(true);
    expect((await storedInteraction(id)).purpose).toBe('logout');
  });

  it('widens the confirm page’s form-action to the return URI’s origin only', async () => {
    const cookie = await signedIn();
    const withReturn = await endSession(
      { client_id: 'notes-app', post_logout_redirect_uri: RETURN_URI },
      cookie
    );
    expect(withReturn.headers['content-security-policy']).toContain(
      "form-action 'self' https://notes.example.com;"
    );

    const without = await endSession({ client_id: 'notes-app' }, cookie);
    expect(without.headers['content-security-policy']).toContain("form-action 'self';");
  });
});

describe('a malformed request (#675)', () => {
  it.each([
    ['a repeated parameter', 'state=a&state=b'],
    ['a repeated hint', 'id_token_hint=x&id_token_hint=y'],
    ['an over-long hint', `id_token_hint=${'a'.repeat(8193)}`],
    ['an over-long ui_locales', `ui_locales=${'a'.repeat(257)}`],
    ['a return URI that is no URL', 'post_logout_redirect_uri=not%20a%20url'],
  ])('refuses %s with a 400 validation_error problem, as GET and as POST', async (_label, raw) => {
    const cookie = await signedIn();
    const get = await app.inject({
      method: 'GET',
      url: `/oauth/end-session?${raw}`,
      headers: { cookie },
    });
    expect(get.statusCode).toBe(400);
    expect(get.json()).toMatchObject({ code: 'validation_error' });
    const post = await app.inject({
      method: 'POST',
      url: '/oauth/end-session',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      payload: raw,
    });
    expect(post.statusCode).toBe(400);
    expect(post.json()).toMatchObject({ code: 'validation_error' });
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(eventTypes()).toEqual([]);
  });
});

describe('the status page (#675)', () => {
  it('says signed in while the browser holds a session, and signed out once it does not', async () => {
    const cookie = await signedIn();
    const inside = await app.inject({
      method: 'GET',
      url: '/oauth/end-session/status',
      headers: { cookie },
    });
    expect(inside.statusCode).toBe(200);
    expect(inside.headers['content-type']).toMatch(/^text\/html/);
    expect(inside.body).toContain('You are still signed in');

    const outside = await app.inject({ method: 'GET', url: '/oauth/end-session/status' });
    expect(outside.statusCode).toBe(200);
    expect(outside.body).toContain('You are signed out');
  });

  it('takes no parameter: whatever the query says, the page says only the truth', async () => {
    const response = await app.inject({
      method: 'GET',
      url: `/oauth/end-session/status?${query({ message: 'Your account is locked', state: STATE })}`,
    });
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('You are signed out');
    expect(response.body).not.toContain('locked');
    expect(response.body).not.toContain(STATE);
  });
});

describe('the issuer of the hint (#675)', () => {
  it('reads the hint with the realm’s issuer, never one the request names', async () => {
    await endSession({ id_token_hint: 'hint.bob' });
    expect(verifyIdTokenHint).toHaveBeenCalledWith({ id: REALM.id, issuer: ISSUER }, 'hint.bob');
  });
});
