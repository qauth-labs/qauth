import type { SessionAssuranceLevel } from '@qauth-labs/fastify-plugin-sessions';
import {
  InvalidCsrfTokenError,
  InvalidRequestError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

vi.mock('../../../config/env', () => ({
  env: {
    AUTHORIZE_RATE_LIMIT: 60,
    AUTHORIZE_RATE_WINDOW: 60,
    DEFAULT_REALM_NAME: 'master',
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
    REDIRECT_URI_CUSTOM_SCHEMES: [] as string[],
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
  type FakeSessionSeed,
  type FakeSideRecordSeed,
} from '../../../testing/browser-sessions';
import { testRealm } from '../../../testing/request-realm';
import { OAUTH_OPAQUE_PARAM_MAX_LENGTH } from '../../constants';
import { buildAuthorizationServerMetadata } from '../../helpers/discovery';
import { emitUserEvent } from '../../helpers/user-events';
import consentRoute from './consent';

const emitUserEventMock = vi.mocked(emitUserEvent);

/** The realm the realm resolver (#486) decorated every request with. */
const REALM = testRealm({ id: 'realm-1' });

beforeEach(() => {
  emitUserEventMock.mockClear();
});

/** The event types the route emitted, in order. */
function emittedTypes(): string[] {
  return emitUserEventMock.mock.calls.map((c) => c[1]);
}

/** The `data` and options of the first event of a type the route emitted. */
function emitted(type: string): { data: unknown; options: unknown } | undefined {
  const call = emitUserEventMock.mock.calls.find((c) => c[1] === type);
  return call === undefined ? undefined : { data: call[2], options: call[3] };
}

/** Issuer the mock AS is configured with; discovery shapes it the same way. */
const ISSUER = 'https://auth.example.com';

/** The `issuer` value discovery publishes — what every `iss` must byte-match. */
const DISCOVERY_ISSUER = buildAuthorizationServerMetadata({ issuer: ISSUER })['issuer'] as string;

/** The `iss` a redirect carried, percent-decoded as a conforming client reads it. */
function issOf(redirected: string | undefined): string | null {
  expect(redirected).toBeDefined();
  return new URL(redirected as string).searchParams.get('iss');
}

interface TestContext {
  get?: (request: any, reply: any) => Promise<unknown>;
  post?: (request: any, reply: any) => Promise<unknown>;
  /**
   * Route options as registered, so tests can reach the schemas Fastify would
   * apply. These handlers are invoked directly here, which BYPASSES Fastify's
   * validation — the POST body schema is module-private, so #316's form-mirror
   * regression is only observable through the registered options.
   */
  postOpts?: any;
}

/** A captured route handler, called with a plain-object request. */
type RouteHandler = NonNullable<TestContext['post']>;

function createReply() {
  const state: {
    statusCode?: number;
    headers: Record<string, string>;
    redirected?: string;
    body?: unknown;
  } = { headers: {} };
  const reply: any = {
    // Mirrors @fastify/helmet's enableCSPNonces decorator (issue #113): the
    // consent/login renderers read reply.cspNonce.style for the inline <style>.
    cspNonce: { script: 'test-script-nonce', style: 'test-style-nonce' },
    code(n: number) {
      state.statusCode = n;
      return reply;
    },
    header(k: string, v: string) {
      state.headers[k] = v;
      return reply;
    },
    redirect(url: string, code: number) {
      state.redirected = url;
      state.statusCode = code;
      return reply;
    },
    send(body: unknown) {
      state.body = body;
      return body;
    },
  };
  return { reply, state };
}

/**
 * The realm resolver's decoration (#486): a request reaches its handler with
 * the realm of its host. A request that names its own realm keeps it.
 */
function withRealm(handler: RouteHandler): RouteHandler {
  return (request, reply) => {
    request.realm ??= REALM;
    return handler(request, reply);
  };
}

function makeFastify() {
  const ctx: TestContext = {};
  // The browser session (the session service) and its side record (#488).
  const sessions = createBrowserSessionFixture();
  const fastify: any = {
    withTypeProvider: () => ({
      get: (_url: string, _opts: unknown, handler: any) => {
        ctx.get = withRealm(handler);
        return fastify;
      },
      post: (_url: string, opts: any, handler: any) => {
        ctx.post = withRealm(handler);
        ctx.postOpts = opts;
        return fastify;
      },
    }),
    repositories: {
      oauthClients: {
        findByClientId: vi.fn(),
      },
      oauthConsents: {
        upsertGrant: vi.fn().mockResolvedValue({}),
      },
      authorizationCodes: {
        create: vi.fn().mockResolvedValue({ id: 'code-1' }),
      },
      // `resolveBrowserSession` only accepts a session whose user is still enabled.
      users: {
        findById: vi.fn(async (id: string) => ({ id, enabled: true })),
      },
    },
    jwtUtils: {
      // #282: consent redirects are authorization responses and echo the
      // RFC 9207 issuer sourced from here, the same as /oauth/authorize.
      getIssuer: () => ISSUER,
    },
    sessionService: sessions.service,
    redis: sessions.redis,
    // Only the pending-authorization stash (`pending-authz:` keys, #316
    // follow-up) that a redirect to /ui/login writes still goes through
    // `sessionUtils`; the browser session does not.
    sessionUtils: {
      setSession: vi.fn().mockResolvedValue(undefined),
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  return { fastify: fastify as FastifyInstance, ctx, sessions };
}

/** What {@link signIn} seeds besides the realm and the user. */
type SignInSeed = Omit<FakeSessionSeed, 'realmId' | 'userId'> & { side?: FakeSideRecordSeed };

/**
 * `user-1` signed in to {@link REALM} on this browser (#488): a live session
 * in the session service, its side record (the identifier `a@b.com` unless
 * `side` names another) and the cookie that names it.
 */
function signIn(sessions: BrowserSessionFixture, { side, ...seed }: SignInSeed) {
  return sessions.signIn({
    realmId: REALM.id,
    userId: 'user-1',
    ...seed,
    side: { identifier: 'a@b.com', ...side },
  });
}

const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'app-123',
  clientSecretHash: 'h',
  name: 'Test App',
  enabled: true,
  scopes: ['read:foo', 'email'],
  redirectUris: ['https://example.com/cb'],
  audience: null,
  dynamicRegisteredAt: null,
  // An operator-provisioned client: the only kind whose redirect URI receives
  // authorization errors by automatic redirect (ANT-2026-O8U3P920).
  provisionedByOperator: true,
  metadata: null,
};

const BASE_QUERY = {
  response_type: 'code' as const,
  client_id: 'app-123',
  redirect_uri: 'https://example.com/cb',
  code_challenge: 'A'.repeat(43),
  code_challenge_method: 'S256' as const,
  state: 'xyz',
  scope: 'email',
};

describe('UI /ui/consent GET — rendering', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('redirects to /ui/login when no session cookie present', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: '/ui/consent?...',
        headers: {},
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
  });

  it('renders consent HTML with CSRF token hidden input when session is valid', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { session, cookie } = await signIn(sessions, { sid: 'sid-g1' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: '/ui/consent?...',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const html = state.body as string;
    expect(typeof html).toBe('string');
    expect(html).toContain('Test App wants to access your account');
    expect(state.headers['Content-Type']).toContain('text/html');
    // Clickjacking/MIME/Referrer/CSP hardening moved to the global
    // security-headers plugin (#113) — covered in security-headers.test.ts.
    // The page stamps the per-request CSP nonce onto its inline <style>.
    expect(html).toContain('nonce="test-style-nonce"');
    // The render minted the CSRF token and bound the scopes and resources it
    // lists in the session's side record (#488), which the POST checks.
    const side = await sessions.sideRecord(session);
    expect(side.csrfToken).toEqual(expect.any(String));
    expect(html).toContain(`name="csrf_token" value="${side.csrfToken}"`);
    expect(side.consentScopes).toEqual({ 'app-123': ['email'] });
    expect(side.consentResources).toEqual({ 'app-123': [] });
  });

  it('shows the identifier the user signed in with (#230)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, {
      sid: 'sid-g-id',
      side: { identifier: 'alice@example.com' },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.get!(
      { query: BASE_QUERY, url: '/ui/consent?...', headers: { cookie }, ip: '127.0.0.1' },
      reply
    );

    expect(state.body as string).toContain('Signed in as alice@example.com');
  });

  it('shows the user id when the side record holds no identifier', async () => {
    // A sign-in without an identifier, or a side record lost from Redis: the
    // screen still names the account, by its stable subject id.
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await sessions.signIn({
      sid: 'sid-g-noid',
      realmId: REALM.id,
      userId: 'user-1',
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.get!(
      { query: BASE_QUERY, url: '/ui/consent?...', headers: { cookie }, ip: '127.0.0.1' },
      reply
    );

    expect(state.body as string).toContain('Signed in as user-1');
  });

  it('keeps the consent CSRF values out of the session service: they live in the side record only', async () => {
    // The token and the bindings change on every consent step; a Postgres
    // write for each would cost more than they are worth (#488). Rendering
    // the screen creates no session and puts nothing on the one it resolved.
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { session, cookie } = await signIn(sessions, { sid: 'sid-g-side' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, resource: ['https://api.example.com/v1'] },
        url: '/ui/consent?...',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(sessions.service.create).not.toHaveBeenCalled();
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    const stored = sessions.service.sessions.get(session.sid);
    expect(stored).toBeDefined();
    for (const field of ['csrfToken', 'apiCsrfToken', 'consentScopes', 'consentResources']) {
      expect(stored).not.toHaveProperty(field);
    }
    const side = await sessions.sideRecord(session);
    expect(side.csrfToken).toEqual(expect.any(String));
    expect(JSON.stringify(stored)).not.toContain(side.csrfToken);
    expect(JSON.stringify(stored)).not.toContain('https://api.example.com/v1');
    expect(side.consentScopes).toEqual({ 'app-123': ['email'] });
    expect(side.consentResources).toEqual({ 'app-123': ['https://api.example.com/v1'] });
  });

  it('renders RFC 8707 resource fields from the validated query, never from request.url', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-g2' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, resource: ['https://api.example.com/v1'] },
        // `?resource` to Fastify's parser (unknown key, stripped unvalidated),
        // `resource` to `URLSearchParams`. See oauth/authorize.ts.
        url: '/ui/consent??resource=system&resource=https%3A%2F%2Fapi.example.com%2Fv1',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const html = state.body as string;
    expect(html).toContain('name="resource" value="https://api.example.com/v1"');
    expect(html).not.toContain('value="system"');
  });

  it('names the requested RFC 8707 resource as the audience, over the client default', async () => {
    // The `resource` overrides `client.audience` in the token's `aud`
    // (`resolveAudience`), so the screen must name it: the grant the user
    // approves is for the resource server they were shown.
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { session, cookie } = await signIn(sessions, { sid: 'sid-g3' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      audience: ['https://default.example.com'],
    });

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, resource: ['https://api.example.com/v1'] },
        url: '/ui/consent?client_id=app-123&scope=email&resource=https%3A%2F%2Fapi.example.com%2Fv1',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const html = state.body as string;
    expect(html).toContain('Tokens will be valid for:</strong> https://api.example.com/v1');
    expect(html).not.toContain('https://default.example.com');
    // The rendered resources are bound to the session's side record, like the
    // scopes, so the POST records what the user saw rather than what the form
    // carries.
    expect((await sessions.sideRecord(session)).consentResources).toEqual({
      'app-123': ['https://api.example.com/v1'],
    });
  });

  it('keeps naming the client default audience when the request has no resource', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-g4' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      audience: ['https://default.example.com'],
    });

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: BASE_QUERY,
        url: '/ui/consent?client_id=app-123&scope=email',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.body as string).toContain(
      'Tokens will be valid for:</strong> https://default.example.com'
    );
  });
  it("rendering does not extend the session: the side record expires with the session's end", async () => {
    // The session lasts an hour (FAKE_SESSION_LIFETIME_MS) and is 45 minutes old.
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { session, cookie } = await signIn(sessions, {
      sid: 'sid-g5',
      authTime: Date.now() - 45 * 60 * 1000,
    });
    const end = session.expiresAt;
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const handler = ctx.get;
    if (!handler) throw new Error('Handler missing');
    const { reply } = createReply();
    await handler(
      {
        query: BASE_QUERY,
        url: '/ui/consent?...',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // The render wrote the token and the bindings, and set the record's
    // deadline to the session's absolute end: at most the 15 minutes left.
    expect((await sessions.sideRecord(session)).csrfToken).toEqual(expect.any(String));
    expect(sessions.redis.expiries.get(`browser-session-side:${REALM.id}:sid-g5`)).toBe(end);
    expect(end - Date.now()).toBeGreaterThan(0);
    expect(end - Date.now()).toBeLessThanOrEqual(15 * 60 * 1000);
  });
});

describe('UI /ui/consent POST — allow/deny', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('deny path redirects to redirect_uri with error=access_denied and preserves state', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-token-value-deny';
    const { session, cookie } = await signIn(sessions, { sid: 'sid-d', side: { csrfToken: csrf } });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'deny',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=access_denied');
    expect(state.redirected).toContain('state=xyz');
    // RFC 9207 §2 (#282): a user-denied request is still an authorization
    // response, so it identifies the AS exactly like a success does.
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error: 'access_denied' },
      { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' }
    );
    // A decided form cannot be submitted again: the token is burned on Deny too.
    expect((await sessions.sideRecord(session)).csrfToken).toBeUndefined();
  });

  it('rejects when CSRF token does not match', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, {
      sid: 'sid-bad',
      side: { csrfToken: 'expected-csrf-token' },
    });

    const { reply } = createReply();
    await expect(
      ctx.post!(
        {
          body: {
            decision: 'allow',
            csrf_token: 'attacker-guessed',
            client_id: 'app-123',
            redirect_uri: 'https://example.com/cb',
            code_challenge: 'A'.repeat(43),
            code_challenge_method: 'S256',
            response_type: 'code',
          },
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      )
    ).rejects.toBeInstanceOf(InvalidCsrfTokenError);
    // The posted client_id is not resolved before the check, so the event names no client.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:request.csrf_rejected:v1-rc.0',
      { form: 'consent' },
      { userId: 'user-1', actor: 'user' }
    );
  });

  it('allow + allow_forever persists consent and issues an authorization code', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-token-allow';
    const { session, cookie } = await signIn(sessions, {
      sid: 'sid-a',
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.oauthConsents.upsertGrant).toHaveBeenCalledWith(
      'user-1',
      'client-uuid-1',
      'realm-1',
      ['email'],
      []
    );
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(state.redirected).toContain('state=xyz');
    // #282: consent Allow is the authorization success response.
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    // The token is burned so the form cannot be replayed; the next render
    // mints a fresh one.
    expect((await sessions.sideRecord(session)).csrfToken).toBeUndefined();
  });

  it("resolves the client and records the grant in the request's realm (#487)", async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-token-realm';
    // The session lives in the realm the request carries: a session of
    // another realm is no sign-in here.
    const { cookie } = await sessions.signIn({
      sid: 'sid-r',
      realmId: 'realm-2',
      userId: 'user-1',
      side: { identifier: 'a@b.com', csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply } = createReply();
    await ctx.post!(
      {
        body: { ...BASE_QUERY, decision: 'allow', allow_forever: '1', csrf_token: csrf },
        headers: { cookie },
        ip: '127.0.0.1',
        realm: testRealm({ id: 'realm-2' }),
      },
      reply
    );

    expect(fastify.repositories.oauthClients.findByClientId).toHaveBeenCalledWith(
      'realm-2',
      'app-123'
    );
    expect(fastify.repositories.oauthConsents.upsertGrant).toHaveBeenCalledWith(
      'user-1',
      'client-uuid-1',
      'realm-2',
      ['email'],
      []
    );
  });

  it('persists RFC 8707 resource on the code when POST body carries resource field(s)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-res';
    const { cookie } = await signIn(sessions, {
      sid: 'sid-res',
      side: {
        csrfToken: csrf,
        consentScopes: { 'app-123': ['email'] },
        consentResources: { 'app-123': ['https://api.example.com/v1'] },
      },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
          // Hidden form inputs from the consent page — one or more values
          // (Fastify parses multi-value form bodies as an array).
          resource: ['https://api.example.com/v1'],
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.resource).toEqual(['https://api.example.com/v1']);
    // The remembered grant records the audience the user approved, so
    // /oauth/authorize can tell it from one they never saw.
    expect(fastify.repositories.oauthConsents.upsertGrant).toHaveBeenCalledWith(
      'user-1',
      'client-uuid-1',
      'realm-1',
      ['email'],
      ['https://api.example.com/v1']
    );
  });

  // The hidden `resource` fields are no more trustworthy than the hidden
  // `scope`: a page rendered for one resource stays submittable after a later
  // render rebinds the session to another (or a form is tampered with). What
  // the user is granting must be what the screen named.
  it.each([
    [
      'a resource the rendered page did not name',
      ['https://api.example.com/v1'],
      ['https://payroll.example.com/v1'],
    ],
    [
      'an extra resource',
      ['https://api.example.com/v1'],
      ['https://api.example.com/v1', 'https://payroll.example.com/v1'],
    ],
    ['a resource when the page named none', [], ['https://payroll.example.com/v1']],
    ['no resource when the page named one', ['https://api.example.com/v1'], undefined],
  ])('refuses %s with invalid_target', async (_label, bound, posted) => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-res-bind';
    const { cookie } = await signIn(sessions, {
      sid: 'sid-res-bind',
      side: {
        csrfToken: csrf,
        consentScopes: { 'app-123': ['email'] },
        consentResources: { 'app-123': bound },
      },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
          resource: posted,
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=invalid_target');
    expect(state.redirected).toContain('state=xyz');
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    // The resource URIs are not recorded: the reason says what diverged.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error: 'invalid_target', reason: 'consent_resource_mismatch' },
      expect.objectContaining({ userId: 'user-1', clientId: 'app-123', actor: 'user' })
    );
  });

  it.each<[string, SessionAssuranceLevel | null, string | null]>([
    ['a wallet session at high assurance', 'high', 'high'],
    // The password path stores no assurance level (`null`, ADR-003: `'low'`),
    // so the code records NULL and the ID token carries no `acr` — the
    // #237/#240 invariant, asserted on the consent-screen code-mint path too.
    ['a password session', null, null],
    // Neither the session service's type nor the `sessions` table's CHECK
    // admits `low`; the mint path collapses it to NULL all the same.
    ['a session that somehow carries low', 'low' as unknown as SessionAssuranceLevel, null],
  ])(
    'binds the assurance level of %s onto the authorization code (#237)',
    async (_label, sessionLevel, expected) => {
      const { fastify, ctx, sessions } = makeFastify();
      await consentRoute(fastify);
      const csrf = 'csrf-acr';
      const { cookie } = await signIn(sessions, {
        sid: 'sid-acr',
        assuranceLevel: sessionLevel,
        side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
      });
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
        CLIENT
      );

      const { reply } = createReply();
      await ctx.post!(
        {
          body: {
            decision: 'allow',
            allow_forever: '1',
            csrf_token: csrf,
            client_id: 'app-123',
            redirect_uri: 'https://example.com/cb',
            state: 'xyz',
            scope: 'email',
            code_challenge: 'A'.repeat(43),
            code_challenge_method: 'S256',
            response_type: 'code',
          },
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );

      const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
        .calls[0][0];
      expect(createArg.assuranceLevel).toBe(expected);
    }
  );

  it('allow without allow_forever issues code but does NOT persist consent', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-once';
    const { cookie } = await signIn(sessions, {
      sid: 'sid-once',
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('https://example.com/cb');
  });

  it('refuses to grant scopes the hidden field tampered beyond what was rendered (#150 binding)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-tamper';
    // The GET render bound only `email` (what the user saw). Both `email` and
    // `read:foo` are in the client allowlist, so a tampered `scope=email
    // read:foo` survives the allowlist filter — the binding check is what stops
    // the grant of the unseen `read:foo`.
    const { cookie } = await signIn(sessions, {
      sid: 'sid-tamper',
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          // Tampered: user only saw `email`.
          scope: 'email read:foo',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // No code minted, no grant persisted — redirected with invalid_scope.
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    // #282: consent-scope tamper refusal is an authorization error response.
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error: 'invalid_scope', reason: 'consent_scope_mismatch' },
      { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' }
    );
  });

  it('refuses a page rendered before the allowlist grew, even after a later render re-bound the session', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    // The side record keeps what the route writes, so the second GET below
    // really overwrites the per-client scope binding of the first.
    const { cookie } = await signIn(sessions, { sid: 'sid-stale-page' });

    const renderPage = async () => {
      const { reply, state } = createReply();
      await ctx.get!(
        {
          query: { ...BASE_QUERY, scope: 'email read:foo' },
          url: '/ui/consent?...',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      );
      return state.body as string;
    };
    const hidden = (page: string, name: string) =>
      new RegExp(`name="${name}" value="([^"]*)"`).exec(page)?.[1];

    // First page: the client may only ask for `email`, so that is all the
    // user is shown. `read:foo` is requested but NOT listed.
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      scopes: ['email'],
    });
    const firstPage = await renderPage();
    expect(firstPage).toContain('<code>email</code>');
    expect(firstPage).not.toContain('<code>read:foo</code>');
    // The form submits what the page LISTS, never the raw request.
    expect(hidden(firstPage, 'scope')).toBe('email');

    // The client's owner adds `read:foo` to the allowlist (PATCH
    // /api/clients/:id) and a second render (a cross-site top-level
    // navigation to /oauth/authorize) re-binds the slot to the wider set. The
    // CSRF token is reused across renders, so the first page stays submittable.
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    await renderPage();

    // The user presses Allow on the FIRST page, with its hidden fields as
    // rendered.
    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: hidden(firstPage, 'csrf_token'),
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: hidden(firstPage, 'scope'),
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // Nothing the approved page did not list may be granted.
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
  });
});

// ANT-2026-DR5XI3LV: an operator's suspension refuses the client on both
// halves of the consent screen, exactly as a disable does.
// Found while fixing the findings of scan qauth-20261015-005: a stored row may
// hold a scheme registration now refuses; the consent screen must not render
// for it, nor send a code there.
describe('UI /ui/consent — redirect URI scheme gate', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('GET refuses a registered javascript: redirect URI before rendering', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-js' });
    const uri = 'javascript:alert(document.domain)//';
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      redirectUris: [uri],
    });

    const { reply, state } = createReply();
    await expect(
      ctx.get!(
        {
          query: { ...BASE_QUERY, redirect_uri: uri },
          url: '/ui/consent?...',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      )
    ).rejects.toBeInstanceOf(InvalidRequestError);
    expect(state.body).toBeUndefined();
  });

  describe('REDIRECT_URI_CUSTOM_SCHEMES (#774)', () => {
    const cursorCallback = 'cursor://anysphere.cursor-mcp/oauth/callback';

    afterEach(() => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = [];
    });

    async function withCursorClient(sid: string, csrfToken: string) {
      const { fastify, ctx, sessions } = makeFastify();
      await consentRoute(fastify);
      const { cookie } = await signIn(sessions, {
        sid,
        side: {
          csrfToken,
          // The scopes the rendered screen presented, which the POST must match.
          consentScopes: { 'app-123': ['email'] },
        },
      });
      (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
        ...CLIENT,
        redirectUris: [cursorCallback],
      });
      return { fastify, ctx, cookie };
    }

    function allowBody(csrfToken: string) {
      return {
        decision: 'allow',
        csrf_token: csrfToken,
        client_id: 'app-123',
        redirect_uri: cursorCallback,
        state: 'xyz',
        scope: 'email',
        code_challenge: 'A'.repeat(43),
        code_challenge_method: 'S256',
        response_type: 'code',
      };
    }

    it('GET and POST refuse a registered bare scheme when the setting is empty', async () => {
      const { fastify, ctx, cookie } = await withCursorClient('sid-cursor-1', 'csrf-cursor-1');
      const { reply, state } = createReply();
      await expect(
        ctx.get!(
          {
            query: { ...BASE_QUERY, redirect_uri: cursorCallback },
            url: '/ui/consent?...',
            headers: { cookie },
            ip: '127.0.0.1',
          },
          reply
        )
      ).rejects.toBeInstanceOf(InvalidRequestError);
      expect(state.body).toBeUndefined();

      await expect(
        ctx.post!(
          { body: allowBody('csrf-cursor-1'), headers: { cookie }, ip: '127.0.0.1' },
          createReply().reply
        )
      ).rejects.toBeInstanceOf(InvalidRequestError);
      expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    });

    it('GET renders and POST issues a code to a bare scheme the deployment lists', async () => {
      env.REDIRECT_URI_CUSTOM_SCHEMES = ['cursor'];
      const { fastify, ctx, cookie } = await withCursorClient('sid-cursor-2', 'csrf-cursor-2');
      const rendered = createReply();
      await ctx.get!(
        {
          query: { ...BASE_QUERY, redirect_uri: cursorCallback },
          url: '/ui/consent?...',
          headers: { cookie },
          ip: '127.0.0.1',
        },
        rendered.reply
      );
      expect(rendered.state.body).toBeDefined();

      const { reply, state } = createReply();
      await ctx.post!(
        { body: allowBody('csrf-cursor-2'), headers: { cookie }, ip: '127.0.0.1' },
        reply
      );
      expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
      expect(state.redirected).toMatch(/^cursor:\/\/anysphere\.cursor-mcp\/oauth\/callback\?code=/);
    });
  });
});

describe('UI /ui/consent — operator-suspended client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const SUSPENDED = { ...CLIENT, enabled: true, suspended: true };

  it('GET refuses with unauthorized_client and renders nothing', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-susp-g' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      SUSPENDED
    );

    const { reply, state } = createReply();
    await expect(
      ctx.get!(
        { query: BASE_QUERY, url: '/ui/consent?...', headers: { cookie }, ip: '127.0.0.1' },
        reply
      )
    ).rejects.toBeInstanceOf(UnauthorizedClientError);
    expect(state.body).toBeUndefined();
  });

  it('POST allow refuses with unauthorized_client and mints no code', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-token-suspended';
    const { cookie } = await signIn(sessions, { sid: 'sid-susp-p', side: { csrfToken: csrf } });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      SUSPENDED
    );

    const { reply } = createReply();
    await expect(
      ctx.post!(
        {
          body: {
            decision: 'allow',
            csrf_token: csrf,
            client_id: 'app-123',
            redirect_uri: 'https://example.com/cb',
            scope: 'email',
            code_challenge: 'A'.repeat(43),
            code_challenge_method: 'S256',
            response_type: 'code',
          },
          headers: { cookie },
          ip: '127.0.0.1',
        },
        reply
      )
    ).rejects.toBeInstanceOf(UnauthorizedClientError);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });
});

// #513: a client_id that names no client and a malformed dpop_jkt are refused
// in place (RFC 6749 §4.1.2.1 forbids redirecting them), as `invalid_request`.
describe('UI /ui/consent — refusals answered in place as invalid_request (#513)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  /** A `dpop_jkt` of the shape a JWK thumbprint has. */
  const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';
  /** {@link JKT} without its last character: not the shape of a thumbprint. */
  const MALFORMED_JKT = JKT.slice(0, -1);

  async function setup(sid: string, { dpop = false }: { dpop?: boolean } = {}) {
    const { fastify, ctx, sessions } = makeFastify();
    if (dpop) {
      (fastify as unknown as { dpop: unknown }).dpop = {
        algorithms: ['ES256'],
        verifyRequest: vi.fn(),
      };
    }
    await consentRoute(fastify);
    const { get: getHandler, post: postHandler } = ctx;
    if (!getHandler || !postHandler) throw new Error('Handler missing');
    const csrf = `csrf-${sid}`;
    const { cookie } = await signIn(sessions, {
      sid,
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);
    const get = (query: Record<string, unknown>) => {
      const { reply, state } = createReply();
      return {
        state,
        result: getHandler(
          {
            query: { ...BASE_QUERY, ...query },
            url: '/ui/consent?...',
            headers: { cookie },
            ip: '127.0.0.1',
          },
          reply
        ),
      };
    };
    const post = (body: Record<string, unknown>) => {
      const { reply, state } = createReply();
      return {
        state,
        result: postHandler(
          {
            body: {
              decision: 'allow',
              csrf_token: csrf,
              client_id: 'app-123',
              redirect_uri: 'https://example.com/cb',
              state: 'xyz',
              scope: 'email',
              code_challenge: 'A'.repeat(43),
              code_challenge_method: 'S256',
              response_type: 'code',
              ...body,
            },
            headers: { cookie },
            ip: '127.0.0.1',
          },
          reply
        ),
      };
    };
    return { fastify, get, post };
  }

  it('GET and POST refuse a client_id that names no client of the realm', async () => {
    const { fastify, get, post } = await setup('sid-unknown');
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      undefined
    );

    const rendered = get({ client_id: 'no-such-client' });
    await expect(rendered.result).rejects.toBeInstanceOf(InvalidRequestError);
    expect(rendered.state.body).toBeUndefined();
    expect(rendered.state.redirected).toBeUndefined();

    const posted = post({ client_id: 'no-such-client' });
    await expect(posted.result).rejects.toBeInstanceOf(InvalidRequestError);
    expect(posted.state.redirected).toBeUndefined();
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('GET and POST refuse a malformed dpop_jkt while DPoP is on', async () => {
    const { fastify, get, post } = await setup('sid-jkt', { dpop: true });
    // The control: the same request with a well-formed key renders the screen.
    const control = get({ dpop_jkt: JKT });
    await control.result;
    expect(control.state.body as string).toContain(JKT);

    const rendered = get({ dpop_jkt: MALFORMED_JKT });
    await expect(rendered.result).rejects.toBeInstanceOf(InvalidRequestError);
    expect(rendered.state.body).toBeUndefined();

    const posted = post({ dpop_jkt: MALFORMED_JKT });
    await expect(posted.result).rejects.toBeInstanceOf(InvalidRequestError);
    expect(posted.state.redirected).toBeUndefined();
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });
});

describe('UI /ui/consent — loopback redirect on any port (RFC 8252 §7.3, #414)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const REGISTERED = 'http://127.0.0.1/callback';

  async function setup(registered: string[]) {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-loop';
    const { cookie } = await signIn(sessions, {
      sid: 'sid-loop',
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...CLIENT,
      redirectUris: registered,
    });
    const headers = { cookie };
    const { reply, state } = createReply();
    return {
      fastify,
      state,
      get: (redirectUri: string) =>
        ctx.get!(
          {
            query: { ...BASE_QUERY, redirect_uri: redirectUri },
            url: '/ui/consent?...',
            headers,
            ip: '127.0.0.1',
          },
          reply
        ),
      post: (redirectUri: string, decision: 'allow' | 'deny' = 'allow') =>
        ctx.post!(
          {
            body: {
              decision,
              csrf_token: csrf,
              client_id: 'app-123',
              redirect_uri: redirectUri,
              state: 'xyz',
              scope: 'email',
              code_challenge: 'A'.repeat(43),
              code_challenge_method: 'S256',
              response_type: 'code',
            },
            headers,
            ip: '127.0.0.1',
          },
          reply
        ),
    };
  }

  it.each([
    [REGISTERED, 'http://127.0.0.1:53817/callback'],
    ['http://[::1]/callback', 'http://[::1]:53817/callback'],
    ['http://localhost/callback', 'http://localhost:53817/callback'],
  ])('GET renders the consent screen for %s requested as %s', async (registered, requested) => {
    const { state, get } = await setup([registered]);
    await get(requested);

    const html = state.body as string;
    expect(html).toContain('Test App wants to access your account');
    // The form carries the requested URI forward to the POST, port included.
    expect(html).toContain(requested.replace(/&/g, '&amp;'));
  });

  it.each([
    [REGISTERED, 'http://127.0.0.1:53817/callback'],
    ['http://[::1]/callback', 'http://[::1]:53817/callback'],
    ['http://localhost/callback', 'http://localhost:53817/callback'],
  ])(
    'POST allow for %s requested as %s binds the code to the requested port',
    async (registered, requested) => {
      const { fastify, state, post } = await setup([registered]);
      await post(requested);

      expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledWith(
        expect.objectContaining({ redirectUri: requested })
      );
      expect(state.redirected!.startsWith(`${requested}?`)).toBe(true);
      expect(new URL(state.redirected!).searchParams.get('code')).toBeTruthy();
    }
  );

  it('POST deny redirects the error to the requested port', async () => {
    const { state, post } = await setup([REGISTERED]);
    await post('http://127.0.0.1:53817/callback', 'deny');

    expect(state.redirected!.startsWith('http://127.0.0.1:53817/callback?')).toBe(true);
    expect(state.redirected).toContain('error=access_denied');
  });

  const REJECTED: Array<[string, string, string]> = [
    ['a different path', REGISTERED, 'http://127.0.0.1:53817/other'],
    ['a different host', REGISTERED, 'http://127.0.0.2:53817/callback'],
    ['a different scheme', REGISTERED, 'https://127.0.0.1:53817/callback'],
    ['an added query', REGISTERED, 'http://127.0.0.1:53817/callback?x=1'],
    ['a different https port', 'https://example.com/cb', 'https://example.com:8443/cb'],
    [
      'a different custom-scheme port',
      'com.example.app://localhost/cb',
      'com.example.app://localhost:1234/cb',
    ],
  ];

  it.each(REJECTED)('GET rejects %s', async (_label, registered, requested) => {
    const { get } = await setup([registered]);
    await expect(get(requested)).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it.each(REJECTED)(
    'POST rejects %s without issuing a code',
    async (_label, registered, requested) => {
      const { fastify, state, post } = await setup([registered]);
      await expect(post(requested)).rejects.toBeInstanceOf(InvalidRequestError);
      expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
      expect(state.redirected).toBeUndefined();
    }
  );
});

describe('UI /ui/consent — agent scope-mode cap (ADR-007 §2, #184)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // An agent capped at `readonly` whose ALLOWLIST contains `agent:exec`. This
  // is the exact bypass the blocker described: the allowlist would permit
  // agent:exec, but the cap must refuse to mint a code for it on the consent
  // (code-issuing) path. `filterRequestedScopes` alone would have let it through.
  const READONLY_AGENT = {
    ...CLIENT,
    scopes: ['agent:readonly', 'agent:exec', 'email'],
    isAgent: true,
    maxAgentMode: 'readonly' as const,
  };

  function agentSignIn(sessions: BrowserSessionFixture, sid: string, csrf: string) {
    return signIn(sessions, {
      sid,
      side: {
        csrfToken: csrf,
        // The over-cap / non-agent tests reject at the agent-cap gate BEFORE the
        // scope-presentation binding check; the in-cap success test POSTs
        // `agent:readonly`, so bind that so its grant matches what was rendered.
        consentScopes: { 'app-123': ['agent:readonly'] },
      },
    });
  }

  it('POST rejects an over-cap scope with invalid_scope and issues NO code (blocker regression)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-cap-1';
    const { cookie } = await agentSignIn(sessions, 'sid-cap-1', csrf);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          allow_forever: '1',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          // Attacker-controlled hidden field — the allowlist permits it, the cap must not.
          scope: 'agent:exec',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    // #282: over-cap agent scope refused at consent still identifies the AS.
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
      expect.objectContaining({ userId: 'user-1', clientId: 'app-123', actor: 'user' })
    );
  });

  it('POST allows an in-cap scope and issues a code', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-cap-2';
    const { cookie } = await agentSignIn(sessions, 'sid-cap-2', csrf);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'agent:readonly',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    expect(state.redirected).toContain('code=');
    expect(state.redirected).not.toContain('error=');
  });

  it('POST rejects ANY agent scope for a non-agent client even if allowlisted (untrusted is_agent)', async () => {
    const nonAgent = { ...READONLY_AGENT, isAgent: false };
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-cap-3';
    const { cookie } = await agentSignIn(sessions, 'sid-cap-3', csrf);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      nonAgent
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: 'xyz',
          scope: 'agent:readonly',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=invalid_scope');
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
  });

  it('GET fails fast with invalid_scope for an over-cap scope (no consent screen rendered)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-cap-4' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      READONLY_AGENT
    );

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, scope: 'agent:exec' },
        url: '/ui/consent?scope=agent:exec',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('error=invalid_scope');
    expect(state.redirected).toContain('state=xyz');
    // #282: non-agent client agent-scope refusal.
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    // No HTML consent page was rendered.
    expect(state.body).toBeUndefined();
  });

  it('GET shows, rather than redirects, the invalid_scope of a self-registered client (RFC 9700 §4.11.2)', async () => {
    // This refusal fires before the user sees the consent screen (and the
    // destination host on it), so for a client that registered its own
    // redirect URI it must not be an automatic redirect off the issuer.
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signIn(sessions, { sid: 'sid-cap-5' });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue({
      ...READONLY_AGENT,
      provisionedByOperator: false,
      dynamicRegisteredAt: Date.now() - 400 * 24 * 60 * 60 * 1000,
      metadata: { registrationType: 'dynamic' },
    });

    const { reply, state } = createReply();
    await ctx.get!(
      {
        query: { ...BASE_QUERY, scope: 'agent:exec' },
        url: '/ui/consent?scope=agent:exec',
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toBeUndefined();
    expect(state.statusCode).toBe(400);
    expect(state.body as string).toContain('<code>invalid_scope</code>');
    expect(state.body as string).not.toContain('wants to access your account');
  });
});

describe('UI /ui/consent — step-up authentication (ADR-007 §2, #185)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Client whose allowlist includes a DANGEROUS scope (write:foo). Used to
  // prove the mint path forces a fresh authentication before a dangerous grant.
  const DANGEROUS_CLIENT = {
    ...CLIENT,
    scopes: ['read:foo', 'write:foo', 'email'],
  };

  const MINUTE = 60 * 1000;

  function postBody(overrides: Record<string, unknown> = {}) {
    return {
      decision: 'allow',
      allow_forever: '1',
      csrf_token: 'csrf-su',
      client_id: 'app-123',
      redirect_uri: 'https://example.com/cb',
      state: 'xyz',
      scope: 'write:foo',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
      ...overrides,
    };
  }

  // Scope-presentation binding (#150 hardening): the consent GET render binds the
  // visible scope set to the session's side record; the POST grants ONLY that
  // set. The bound set must equal what the test POSTs, so callers pass the scope
  // they submit (default `write:foo`, the dangerous scope these step-up tests
  // exercise).
  function signInAt(sessions: BrowserSessionFixture, authTime: number, boundScope = 'write:foo') {
    return signIn(sessions, {
      sid: 'sid-su',
      authTime,
      side: {
        csrfToken: 'csrf-su',
        consentScopes: { 'app-123': boundScope.split(/\s+/).filter((s) => s.length > 0) },
      },
    });
  }

  it('refuses to mint a code for a dangerous scope on a STALE session and bounces to /ui/login', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    // Session authenticated 10 minutes ago — outside the 2-minute fresh window.
    const { cookie } = await signInAt(sessions, Date.now() - 10 * MINUTE);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // Bounced to login (fresh-auth required); NO code, NO grant persisted.
    expect(state.redirected).toContain('/ui/login?return_to=');
    // #316 follow-up: the authorize URL is no longer nested in `return_to` —
    // `return_to` carries a short single-use handle and the URL itself is
    // parked server-side. The dangerous scope must still survive the round-trip,
    // so assert it on what was actually stashed.
    expect(state.redirected).toContain(encodeURIComponent('/ui/resume/'));
    const stashed = (fastify.sessionUtils.setSession as unknown as Mock).mock.calls
      .map((c) => c[1] as { authorizeUrl?: string })
      .find((d) => typeof d?.authorizeUrl === 'string');
    expect(stashed?.authorizeUrl).toContain('scope=write%3Afoo');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    expect(fastify.repositories.oauthConsents.upsertGrant).not.toHaveBeenCalled();
    // The step-up requirement is recorded.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:step_up.required:v1-rc.0',
      { reason: 'fresh_authentication_required', dangerousScopes: ['write:foo'] },
      { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' }
    );
  });

  it('mints a dangerous-scope code on a FRESH session and audits the elevation', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    // Authenticated 5 seconds ago — within the fresh-auth window.
    const { session, cookie } = await signInAt(sessions, Date.now() - 5000);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(issOf(state.redirected)).toBe(DISCOVERY_ISSUER);
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
    // The code and the elevation carry the session's authentication time
    // (OIDC `auth_time`), not the time of this consent.
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.authTime).toBe(session.authTime);
    // #552: the session's absolute end caps the refresh family the code starts.
    expect(createArg.sessionExpiresAt).toBe(session.expiresAt);
    expect(emittedTypes()).toEqual([
      'urn:qauth:event:step_up.elevated:v1-rc.0',
      'urn:qauth:event:consent.granted:v1-rc.0',
    ]);
    expect(emitted('urn:qauth:event:step_up.elevated:v1-rc.0')?.data).toMatchObject({
      authenticatedAt: new Date(session.authTime).toISOString(),
    });
    expect(emitted('urn:qauth:event:consent.granted:v1-rc.0')).toEqual({
      data: { scopes: ['write:foo'], remembered: true, dangerousScopes: ['write:foo'] },
      options: { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' },
    });
  });

  it('per-agent audit (#186): elevation by an agent client attributes actor + scope mode', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signInAt(sessions, Date.now() - 5000, 'agent:exec');
    // An EXEC-capped agent elevating to the dangerous `agent:exec` scope.
    const EXEC_AGENT = {
      ...DANGEROUS_CLIENT,
      isAgent: true,
      maxAgentMode: 'exec' as const,
      scopes: ['read:foo', 'agent:exec', 'email'],
    };
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      EXEC_AGENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'agent:exec' }),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('code=');
    const elevation = emitted('urn:qauth:event:step_up.elevated:v1-rc.0');
    // The user granted the elevation and is its actor; the agent is the
    // event's client, and the scope mode it was granted is recorded.
    expect(elevation).toEqual({
      data: {
        scopes: ['agent:exec'],
        dangerousScopes: ['agent:exec'],
        scopeMode: 'exec',
        authenticatedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/),
      },
      options: { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' },
    });
    // No-leak: the step-up elevation event must carry no session/CSRF secret,
    // no minted code, and no token material — only public identifiers.
    const serialized = JSON.stringify(elevation);
    expect(serialized).not.toContain('csrf-su');
    expect(serialized).not.toContain('sid-su');
    expect(serialized).not.toContain(cookie.slice(cookie.indexOf('=') + 1));
    expect(serialized).not.toContain('code=');
  });

  it('per-agent audit (#186): elevation by a NON-agent client records no agent attribution', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signInAt(sessions, Date.now() - 5000);
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(
      DANGEROUS_CLIENT
    );

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody(),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('code=');
    const elevation = emitted('urn:qauth:event:step_up.elevated:v1-rc.0');
    // Non-agent client: the elevation is still recorded, but with no scope mode.
    expect(elevation).toEqual({
      data: {
        scopes: ['write:foo'],
        dangerousScopes: ['write:foo'],
        authenticatedAt: expect.any(String),
      },
      options: { realmId: 'realm-1', userId: 'user-1', clientId: 'app-123', actor: 'user' },
    });
  });

  it('forces fresh auth for prompt=login on a stale session even with a non-dangerous scope', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signInAt(sessions, Date.now() - 10 * MINUTE, 'email');
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'email', prompt: 'login' }),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('/ui/login?return_to=');
    expect(fastify.repositories.authorizationCodes.create).not.toHaveBeenCalled();
    // No dangerous scope: the event carries the prompt that forced the step-up.
    expect(emitUserEventMock).toHaveBeenCalledExactlyOnceWith(
      expect.anything(),
      'urn:qauth:event:step_up.required:v1-rc.0',
      { reason: 'fresh_authentication_required', prompt: 'login' },
      expect.objectContaining({ userId: 'user-1', clientId: 'app-123' })
    );
  });

  it('mints a non-dangerous scope without step-up on a stale session (no over-gating)', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const { cookie } = await signInAt(sessions, Date.now() - 10 * MINUTE, 'email');
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: postBody({ scope: 'email' }),
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    expect(state.redirected).toContain('https://example.com/cb');
    expect(state.redirected).toContain('code=');
    expect(fastify.repositories.authorizationCodes.create).toHaveBeenCalledOnce();
  });
});

/**
 * Regression suite for qauth-labs/qauth#316 — long opaque `state` / `nonce`.
 *
 * This is site 2 of three. `/oauth/authorize` redirects here carrying the
 * client's `state`/`nonce`, the consent page re-emits them as hidden form
 * inputs, and this POST body schema re-validates them. It mirrored the
 * authorize query schema's 255 cap, so raising only the query cap moved the
 * 400 one step later in the SAME authorization_code flow — which is exactly
 * how the bug hid. See authorize.test.ts for site 1 and
 * libs/infra/db repositories.integration.test.ts for site 3 (the varchar(255)
 * columns, unobservable here because this harness mocks the repositories).
 */
describe('UI /ui/consent — long opaque state/nonce (#316)', () => {
  /**
   * A realistic Cursor-shaped `state`: base64url of a JSON blob carrying
   * workspace + attempt context. 282 chars — over the old 255 cap, under
   * OAUTH_OPAQUE_PARAM_MAX_LENGTH. Cursor's real payload only exceeds 255 when
   * a workspace is actually open, which made the failure intermittent.
   */
  const LONG_STATE = Buffer.from(
    JSON.stringify({
      id: 7,
      owner: { workspaceId: '9f2c1ab47de35608b1e4c7a09d5f3e21' },
      attemptId: '3f6c2b18-9d47-4e5a-b0c1-7e2f8a4d9b63',
      surface: 'mcp_process',
      redirect: 'cursor://anysphere.cursor-mcp/oauth/user-qauth/callback',
    })
  ).toString('base64url');

  const LONG_NONCE = 'n'.repeat(300);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  /** The POST body schema exactly as registered on the route. */
  async function bodySchema() {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    return ctx.postOpts.schema.body;
  }

  it('the fixture state is genuinely over the old 255-char cap', () => {
    expect(LONG_STATE.length).toBeGreaterThan(255);
    expect(LONG_STATE.length).toBeLessThan(OAUTH_OPAQUE_PARAM_MAX_LENGTH);
  });

  it('site 2: the consent form schema accepts a ~280-char state and 300-char nonce', async () => {
    const schema = await bodySchema();
    const parsed = schema.parse({
      decision: 'allow',
      csrf_token: 'csrf',
      client_id: 'app-123',
      redirect_uri: 'https://example.com/cb',
      state: LONG_STATE,
      nonce: LONG_NONCE,
      scope: 'email',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
    });
    expect(parsed.state).toBe(LONG_STATE);
    expect(parsed.nonce).toBe(LONG_NONCE);
  });

  it('site 2: the consent form schema still rejects over the DoS bound', async () => {
    const schema = await bodySchema();
    const base = {
      decision: 'allow',
      csrf_token: 'csrf',
      client_id: 'app-123',
      redirect_uri: 'https://example.com/cb',
      scope: 'email',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
    };
    const tooLong = 'x'.repeat(OAUTH_OPAQUE_PARAM_MAX_LENGTH + 1);
    expect(schema.safeParse({ ...base, state: tooLong }).success).toBe(false);
    expect(schema.safeParse({ ...base, nonce: tooLong }).success).toBe(false);
    // Exactly at the bound is still valid (off-by-one guard).
    expect(
      schema.safeParse({ ...base, state: 'x'.repeat(OAUTH_OPAQUE_PARAM_MAX_LENGTH) }).success
    ).toBe(true);
  });

  it('Allow mints a code with the FULL state/nonce and round-trips state verbatim', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-316';
    const { cookie } = await signIn(sessions, {
      sid: 'sid-316',
      side: { csrfToken: csrf, consentScopes: { 'app-123': ['email'] } },
    });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'allow',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: LONG_STATE,
          nonce: LONG_NONCE,
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    // Site 3 boundary: untruncated values reach the repository. The DDL that
    // used to reject them is asserted against real Postgres in infra-db.
    const createArg = (fastify.repositories.authorizationCodes.create as unknown as Mock).mock
      .calls[0][0];
    expect(createArg.state).toBe(LONG_STATE);
    expect(createArg.nonce).toBe(LONG_NONCE);

    // RFC 6749 §4.1.2: byte-for-byte round-trip to the client.
    const redirected = new URL(state.redirected as string);
    expect(redirected.searchParams.get('state')).toBe(LONG_STATE);
    expect(redirected.searchParams.get('code')).toBeTruthy();
  });

  it('Deny also round-trips the full state verbatim', async () => {
    const { fastify, ctx, sessions } = makeFastify();
    await consentRoute(fastify);
    const csrf = 'csrf-316d';
    const { cookie } = await signIn(sessions, { sid: 'sid-316d', side: { csrfToken: csrf } });
    (fastify.repositories.oauthClients.findByClientId as unknown as Mock).mockResolvedValue(CLIENT);

    const { reply, state } = createReply();
    await ctx.post!(
      {
        body: {
          decision: 'deny',
          csrf_token: csrf,
          client_id: 'app-123',
          redirect_uri: 'https://example.com/cb',
          state: LONG_STATE,
          scope: 'email',
          code_challenge: 'A'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'code',
        },
        headers: { cookie },
        ip: '127.0.0.1',
      },
      reply
    );

    const redirected = new URL(state.redirected as string);
    expect(redirected.searchParams.get('error')).toBe('access_denied');
    expect(redirected.searchParams.get('state')).toBe(LONG_STATE);
  });
});

describe('UI /ui/consent — redirect_uri reaches the handler as sent (exactUrl)', () => {
  it('the consent form schema refuses a tab or line break inside redirect_uri instead of stripping it', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const schema = ctx.postOpts.schema.body;
    const base = {
      decision: 'allow',
      csrf_token: 'csrf',
      client_id: 'app-123',
      scope: 'email',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
    };
    expect(schema.parse({ ...base, redirect_uri: 'https://example.com/cb' }).redirect_uri).toBe(
      'https://example.com/cb'
    );
    for (const redirect_uri of ['https://example.com/c\tb', 'https://exa\nmple.com/cb']) {
      expect(schema.safeParse({ ...base, redirect_uri }).success).toBe(false);
    }
  });
});

describe('UI /ui/consent — max_age is never converted from a non-scalar', () => {
  // `POST /ui/consent` validates its body before the session and CSRF checks,
  // and a JSON body puts any value in `max_age`. `Number()` of a deeply nested
  // array is seconds of event-loop time, so such a value must be refused by
  // type, unconverted.
  it('accepts a digit string and refuses an array without stringifying it', async () => {
    const { fastify, ctx } = makeFastify();
    await consentRoute(fastify);
    const schema = ctx.postOpts.schema.body;
    const base = {
      decision: 'allow',
      csrf_token: 'csrf',
      client_id: 'app-123',
      redirect_uri: 'https://example.com/cb',
      code_challenge: 'A'.repeat(43),
      code_challenge_method: 'S256',
      response_type: 'code',
    };
    expect(schema.parse({ ...base, max_age: '60' }).max_age).toBe(60);

    const toString = vi.fn(() => '60');
    let nested: unknown = [{ toString }];
    for (let i = 0; i < 100; i += 1) nested = [nested, 0];
    expect(schema.safeParse({ ...base, max_age: nested }).success).toBe(false);
    expect(schema.safeParse({ ...base, max_age: ['60'] }).success).toBe(false);
    expect(toString).not.toHaveBeenCalled();
  });
});
