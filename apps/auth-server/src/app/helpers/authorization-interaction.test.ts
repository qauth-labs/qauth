import { interactionStepView } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { InvalidRequestError } from '@qauth-labs/shared-errors';
import {
  ceremonyPagePath,
  INTERACTION_OPENAPI,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import {
  componentValidator,
  describeErrors,
} from '@qauth-labs/shared-interaction-contract/src/testing/schema-validator';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  checkAuthorizationRequest,
  decideAuthorization,
  liveBrowserSession,
  continueInteraction,
  emitUserEvent,
  mintAuthorizationCode,
  readSessionSideRecord,
} = vi.hoisted(() => ({
  checkAuthorizationRequest: vi.fn(),
  decideAuthorization: vi.fn(),
  liveBrowserSession: vi.fn(),
  continueInteraction: vi.fn(),
  emitUserEvent: vi.fn(),
  mintAuthorizationCode: vi.fn(),
  readSessionSideRecord: vi.fn(),
}));

vi.mock('../../config/env', () => ({ env: { DYNAMIC_CLIENT_BADGE_DAYS: 30 } }));
vi.mock('./authorization-request', () => ({ checkAuthorizationRequest, decideAuthorization }));
vi.mock('./authorization-code', () => ({ mintAuthorizationCode }));
vi.mock('./browser-session', () => ({ liveBrowserSession }));
vi.mock('./interaction', () => ({ continueInteraction }));
vi.mock('./session-side-record', () => ({ readSessionSideRecord }));
vi.mock('./user-events', () => ({ emitUserEvent }));

import { testRealm } from '../../testing/request-realm';
import { MINT_TRANSACTION, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../constants';
import {
  authorizationInteractionStart,
  cancelAuthorization,
  CONSENT_STEP,
  type ConsentAnswer,
  consentStep,
  type ConsentStepSubject,
  finishAuthorization,
  finishConsent,
  type FinishedAuthorization,
  identifierPrefill,
} from './authorization-interaction';
import type { InteractionRequest, InteractionStep } from './interaction-record';

/**
 * THE AUTHORIZATION REQUEST'S INTERACTIONS (#628): the first step of each,
 * and the finish, with the endpoint's checks and decision as stand-ins
 * (`authorize.test.ts` covers them, in both modes) and the interaction store
 * a stand-in (`interaction.test.ts`).
 */

const REALM = testRealm({ id: '22222222-2222-4222-8222-222222222222' });
const ISS = 'https://auth.example.com';
const NEXT_ID = 'n'.repeat(43);

const REQUEST: InteractionRequest = {
  response_type: 'code',
  client_id: 'notes-app',
  redirect_uri: 'https://notes.example.com/callback',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
  code_challenge_method: 'S256',
  state: 'af0ifjsldkj',
  scope: 'openid email',
} as InteractionRequest;

const SESSION = {
  realmId: REALM.id,
  sid: 'sid-1',
  userId: 'user-1',
  authTime: 1_700_000_000_000,
} as const;

/**
 * The client of the request, as `resolveClient` returns its row: an
 * operator-provisioned client with no verified domain, no agent, no
 * first-party profile.
 */
const CLIENT = {
  id: 'client-uuid-1',
  clientId: 'notes-app',
  name: 'Notes',
  enabled: true,
  scopes: ['openid', 'email', 'profile', 'write:notes'],
  redirectUris: ['https://notes.example.com/callback'],
  audience: null as string[] | null,
  metadata: null as Record<string, unknown> | null,
  dynamicRegisteredAt: null as number | null,
  provisionedByOperator: true,
  verifiedDomain: null as string | null,
  isAgent: false,
  maxAgentMode: null as string | null,
  firstPartyProfile: null as string | null,
  firstPartyPolicy: null as Record<string, unknown> | null,
  tokenEndpointAuthMethod: 'client_secret_basic',
  grantTypes: ['authorization_code', 'refresh_token'],
  developerId: null,
};

type TestClient = typeof CLIENT;

/** What the endpoint's checks found for a request of `client`. */
function targetOf(client: Partial<TestClient> = {}) {
  return {
    realm: REALM,
    iss: ISS,
    client: { ...CLIENT, ...client },
    policy: { agentStepUpEnforced: true },
    dpopJkt: null as string | null,
    clientEvent: { realmId: REALM.id, clientId: CLIENT.clientId, actor: 'client' },
  };
}

const TARGET = targetOf();

/** The display data `clientDisplay` computes for {@link CLIENT} and the request's redirect URI. */
const CLIENT_DISPLAY = {
  kind: 'unverified',
  redirect: { target: 'host', host: 'notes.example.com' },
  declaredName: 'Notes',
  newClient: false,
};

/** The request of a cancel or a consent answer, on the realm's host. */
const realmRequest = {
  realm: REALM,
  log: { warn: vi.fn(), info: vi.fn(), debug: vi.fn(), error: vi.fn() },
} as unknown as FastifyRequest;

/** The transaction the code, the grant and the events commit in (#549). */
const TX = { tx: true };
const upsertGrant = vi.fn();
const transaction = vi.fn<
  (cb: (tx: unknown) => Promise<unknown>, options?: unknown) => Promise<unknown>
>(async (cb) => cb(TX));
const fastify = {
  db: { transaction },
  repositories: { oauthConsents: { upsertGrant } },
} as unknown as FastifyInstance;
const request = {} as FastifyRequest;
const reply = {} as FastifyReply;

function finished(transaction: FinishedAuthorization['transaction']): FinishedAuthorization {
  return {
    request: REQUEST,
    transaction,
    continuation: { secrets: ['s'.repeat(43)], expiresAt: 1_700_000_900_000 },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  checkAuthorizationRequest.mockResolvedValue({ kind: 'checked', target: TARGET });
  liveBrowserSession.mockResolvedValue(SESSION);
  continueInteraction.mockResolvedValue({ id: NEXT_ID, expiresAt: 1_700_000_900_000 });
  readSessionSideRecord.mockResolvedValue({});
  mintAuthorizationCode.mockResolvedValue({ code: 'c0de' });
  upsertGrant.mockResolvedValue({});
});

/** A consent step's subject for a client that is no agent and has no audience. */
const SUBJECT: ConsentStepSubject = { clientAudience: null, agent: false, ssoMaxLifespan: null };

describe('identifierPrefill', () => {
  it('pre-fills the identifier with the hint', () => {
    expect(identifierPrefill('alice@example.com')).toEqual({ login_hint: 'alice@example.com' });
  });

  it('pre-fills nothing without a hint, or with one the screen must not show', () => {
    expect(identifierPrefill(undefined)).toEqual({});
    for (const hint of ['<b>alice</b>@example.com', ' alice@example.com', 'alice‮@x.com']) {
      expect(identifierPrefill(hint), hint).toEqual({});
    }
  });
});

describe('consentStep', () => {
  it('lists the scopes, marks the dangerous ones, and lists the resources', () => {
    expect(consentStep(['email', 'write:notes'], ['https://api.example.com/v1'], SUBJECT)).toEqual({
      name: CONSENT_STEP,
      params: {
        scopes: [
          { scope: 'email', text: 'View your email address', sensitive: false, dangerous: false },
          { scope: 'write:notes', sensitive: false, dangerous: true },
        ],
        resources: ['https://api.example.com/v1'],
        remember_default: true,
      },
      alternatives: [],
    });
  });

  it('shows a request that asks for no scope', () => {
    expect(consentStep([], [], SUBJECT)).toMatchObject({ params: { scopes: [], resources: [] } });
  });

  it('carries QAuth’s own text for the scopes it defines, and none for any other (#629)', () => {
    // No realm scope catalog yet: a scope QAuth does not define has no text,
    // and the screen shows the scope value. A scope named after an
    // Object.prototype member is no defined scope either.
    const step = consentStep(
      ['openid', 'profile', 'email', 'offline_access', 'read:notes', 'constructor', 'toString'],
      [],
      SUBJECT
    ) as InteractionStep;
    expect(step.params['scopes']).toEqual([
      { scope: 'openid', text: 'Verify your identity', sensitive: false, dangerous: false },
      {
        scope: 'profile',
        text: 'View your basic profile information',
        sensitive: false,
        dangerous: false,
      },
      { scope: 'email', text: 'View your email address', sensitive: false, dangerous: false },
      {
        scope: 'offline_access',
        text: 'Keep you signed in when you are not using the app',
        sensitive: false,
        dangerous: false,
      },
      { scope: 'read:notes', sensitive: false, dangerous: false },
      { scope: 'constructor', sensitive: false, dangerous: false },
      { scope: 'toString', sensitive: false, dangerous: false },
    ]);
  });

  it('names the client’s configured audience only when the request names no resource', () => {
    const audience = ['https://api.example.com/', 'urn:example:notes'];
    expect(consentStep(['email'], [], { ...SUBJECT, clientAudience: audience })).toMatchObject({
      params: { resources: [], audience },
    });
    // The resources are the tokens' audience then: the client's is not shown.
    expect(
      (
        consentStep(['email'], ['https://api.example.com/v1'], {
          ...SUBJECT,
          clientAudience: audience,
        }) as InteractionStep
      ).params
    ).not.toHaveProperty('audience');
    // A client with no audience, or an empty one, shows none.
    for (const clientAudience of [null, []]) {
      expect(
        (consentStep(['email'], [], { ...SUBJECT, clientAudience }) as InteractionStep).params,
        JSON.stringify(clientAudience)
      ).not.toHaveProperty('audience');
    }
  });

  it('is invalid_target for an audience the step cannot carry', () => {
    for (const clientAudience of [
      ['https://api.example.com/<script>'],
      ['urn:example:a b'],
      ['https://api.example.com/"x"'],
      [`https://api.example.com/${'a'.repeat(2048)}`],
      Array.from({ length: 17 }, (_, i) => `https://api${i}.example.com/`),
    ]) {
      expect(
        consentStep(['email'], [], { ...SUBJECT, clientAudience }),
        clientAudience.join(' ').slice(0, 80)
      ).toBe('invalid_target');
    }
  });

  it('names an AI agent client as one, with the realm’s maximum lifespan when it sets one', () => {
    expect(
      (consentStep(['email'], [], { ...SUBJECT, agent: true }) as InteractionStep).params['agent']
    ).toEqual({});
    expect(
      (
        consentStep(['email'], [], {
          ...SUBJECT,
          agent: true,
          ssoMaxLifespan: 86_400,
        }) as InteractionStep
      ).params['agent']
    ).toEqual({ max_lifespan: 86_400 });
    // Any other client: no agent member, whatever the realm sets.
    expect(
      (consentStep(['email'], [], { ...SUBJECT, ssoMaxLifespan: 86_400 }) as InteractionStep).params
    ).not.toHaveProperty('agent');
  });

  it('is invalid_scope for scopes the step cannot show', () => {
    expect(consentStep(['odd<scope'], [], SUBJECT)).toBe('invalid_scope');
    expect(consentStep(['s'.repeat(129)], [], SUBJECT)).toBe('invalid_scope');
    expect(
      consentStep(
        Array.from({ length: 65 }, (_, i) => `s${i}`),
        [],
        SUBJECT
      )
    ).toBe('invalid_scope');
  });

  it('is invalid_target for resources the step cannot show', () => {
    const resources = Array.from({ length: 17 }, (_, i) => `https://api${i}.example.com/`);
    expect(consentStep(['email'], resources, SUBJECT)).toBe('invalid_target');
  });
});

describe('authorizationInteractionStart', () => {
  it('starts a sign-in at the identifier step, the hint as its prefill, with no transaction and nothing carried in', async () => {
    expect(
      await authorizationInteractionStart(
        fastify,
        { kind: 'sign_in' },
        { ...REQUEST, login_hint: 'alice@example.com' },
        TARGET as never,
        null
      )
    ).toEqual({
      step: { name: stepUrn('identifier'), params: {}, alternatives: [] },
      personal: { login_hint: 'alice@example.com' },
    });
  });

  it('starts a sign-in asked for again over the session the browser holds, and records it as carried in (#964)', async () => {
    // `max_age`, `prompt=login` or a dangerous scope: the person signs in
    // again, as anyone, so the session is no subject of the transaction.
    expect(
      await authorizationInteractionStart(
        fastify,
        { kind: 'sign_in' },
        REQUEST,
        TARGET as never,
        SESSION as never
      )
    ).toEqual({
      step: { name: stepUrn('identifier'), params: {}, alternatives: [] },
      personal: {},
      carriedSession: { userId: 'user-1', sid: 'sid-1' },
    });
    expect(readSessionSideRecord).not.toHaveBeenCalled();
  });

  it('starts a consent for the session: its user, sid and authentication time, carried in (#964)', async () => {
    const start = await authorizationInteractionStart(
      fastify,
      { kind: 'consent', scopes: ['email'], resources: [] },
      REQUEST,
      TARGET as never,
      SESSION as never
    );
    expect(start).toMatchObject({
      step: { name: CONSENT_STEP },
      personal: {},
      transaction: { userId: 'user-1', sid: 'sid-1', authTime: SESSION.authTime, amr: [] },
      carriedSession: { userId: 'user-1', sid: 'sid-1' },
    });
  });

  it('starts a consent with the client’s display data, from its row and the request’s redirect URI (#593)', async () => {
    const start = await authorizationInteractionStart(
      fastify,
      { kind: 'consent', scopes: ['email'], resources: [] },
      REQUEST,
      TARGET as never,
      SESSION as never
    );
    expect(start).toMatchObject({ client: CLIENT_DISPLAY });
  });

  it('starts a consent with the identifier the user signed in with, from the session’s side record (#230)', async () => {
    readSessionSideRecord.mockResolvedValue({ identifier: 'alice@example.com', csrfToken: 'x' });
    const start = await authorizationInteractionStart(
      fastify,
      { kind: 'consent', scopes: ['email'], resources: [] },
      REQUEST,
      TARGET as never,
      SESSION as never
    );
    expect(readSessionSideRecord).toHaveBeenCalledWith(fastify, SESSION);
    // The identifier only: nothing else of the side record.
    expect(start).toMatchObject({ personal: { identifier: 'alice@example.com' } });
    expect((start as { personal: unknown }).personal).toEqual({ identifier: 'alice@example.com' });
    // Personal data, never in the step's params.
    expect(JSON.stringify((start as { step: unknown }).step)).not.toContain('alice');
  });

  it('starts a consent with no personal data when the side record holds no identifier, or one the step cannot show', async () => {
    for (const side of [
      {},
      { identifier: '<b>alice</b>@example.com' },
      { identifier: ' alice@example.com' },
      { identifier: 'alice\u202e@x.com' },
    ]) {
      readSessionSideRecord.mockResolvedValue(side);
      const start = await authorizationInteractionStart(
        fastify,
        { kind: 'consent', scopes: ['email'], resources: [] },
        REQUEST,
        TARGET as never,
        SESSION as never
      );
      expect((start as { personal: unknown }).personal, JSON.stringify(side)).toEqual({});
    }
  });

  it('refuses a consent whose redirect URI the step cannot show, as the consent page refuses to render', async () => {
    // Only a client registered before #593 can hold such a URI: an unverified
    // client's screen has nothing else the person can check.
    await expect(
      authorizationInteractionStart(
        fastify,
        { kind: 'consent', scopes: ['email'], resources: [] },
        { ...REQUEST, redirect_uri: 'https://under_score.example.com/callback' },
        TARGET as never,
        SESSION as never
      )
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it('answers the error, with state and iss, for a consent the step cannot show', async () => {
    expect(
      await authorizationInteractionStart(
        fastify,
        { kind: 'consent', scopes: ['odd<scope'], resources: [] },
        REQUEST,
        TARGET as never,
        SESSION as never
      )
    ).toEqual({
      error: expect.objectContaining({ error: 'invalid_scope', state: REQUEST.state, iss: ISS }),
    });
  });

  it('answers invalid_target for a client audience the step cannot carry', async () => {
    expect(
      await authorizationInteractionStart(
        fastify,
        { kind: 'consent', scopes: ['email'], resources: [] },
        REQUEST,
        targetOf({ audience: ['https://api.example.com/<x>'] }) as never,
        SESSION as never
      )
    ).toEqual({
      error: expect.objectContaining({ error: 'invalid_target', state: REQUEST.state, iss: ISS }),
    });
  });

  it('names an agent client as one, with the realm’s maximum lifespan', async () => {
    const start = await authorizationInteractionStart(
      fastify,
      { kind: 'consent', scopes: ['email'], resources: [] },
      REQUEST,
      {
        ...targetOf({ isAgent: true, maxAgentMode: 'readonly' }),
        realm: { ...REALM, ssoMaxLifespan: 3600 },
      } as never,
      SESSION as never
    );
    expect(start).toMatchObject({ step: { params: { agent: { max_lifespan: 3600 } } } });
  });
});

/**
 * ADR-019 Decision 6, #629 acceptance: "The step data never contains HTML or a
 * client-supplied URL". Everything a client supplied about itself is in its
 * row: its declared name and its metadata (registration, CIMD document).
 */
describe('the consent step’s data, for a hostile client (#629)', () => {
  /** Client-supplied URLs a metadata document or a registration can carry. */
  const CLIENT_URLS = {
    logo_uri: 'https://cdn.evil.example/logo.png',
    client_uri: 'https://evil.example/home',
    policy_uri: 'https://evil.example/policy',
    tos_uri: 'https://evil.example/tos',
    jwks_uri: 'https://evil.example/jwks.json',
    logoUri: 'https://cdn.evil.example/logo2.png',
    clientUri: 'https://evil.example/home2',
  };

  const HOSTILE_NAME =
    '<script>alert(1)</script><img src=x onerror=alert(2)>\u202eNotes\u2066 \u200b';

  const CIMD_ID = 'https://notes.example.com/oauth/client-metadata.json?v=2#frag';

  const HOSTILE_CLIENTS: readonly (readonly [string, Partial<TestClient>])[] = [
    ['an operator-provisioned client', { name: HOSTILE_NAME, metadata: { ...CLIENT_URLS } }],
    [
      'a CIMD client',
      {
        clientId: CIMD_ID,
        name: HOSTILE_NAME,
        provisionedByOperator: false,
        metadata: { registrationType: 'cimd', client_id_metadata_url: CIMD_ID, ...CLIENT_URLS },
      },
    ],
    [
      'a dynamically registered client in its badge window',
      {
        clientId: '01890f4e-7a3b-7c1d-8e2f-000000000001',
        name: '<a href="https://evil.example/">Notes</a>',
        provisionedByOperator: false,
        dynamicRegisteredAt: Date.now() - 60_000,
        metadata: { registrationType: 'dynamic', ...CLIENT_URLS },
      },
    ],
    [
      'an agent client with an audience',
      {
        name: HOSTILE_NAME,
        isAgent: true,
        maxAgentMode: 'readonly',
        audience: ['https://api.example.com/'],
        metadata: { ...CLIENT_URLS },
      },
    ],
  ];

  const validateInteraction = componentValidator(INTERACTION_OPENAPI).schema('Interaction');

  /** The step read as the Interaction API builds it (`stepRead`), and the personal read. */
  async function startOf(
    client: Partial<TestClient>,
    query: Partial<InteractionRequest>,
    resources: readonly string[]
  ) {
    readSessionSideRecord.mockResolvedValue({ identifier: 'alice@example.com' });
    const start = await authorizationInteractionStart(
      fastify,
      { kind: 'consent', scopes: ['openid', 'email', 'write:notes'], resources: [...resources] },
      { ...REQUEST, ...query },
      targetOf(client) as never,
      SESSION as never
    );
    if ('error' in start) throw new Error(`refused: ${start.error.error}`);
    const read = {
      ...interactionStepView(start.step),
      csrf: 'c'.repeat(43),
      ...(start.client === undefined ? {} : { client: start.client }),
      brand: { font: 'system', darkMode: 'enabled' },
      expiresAt: new Date(1_700_000_900_000).toISOString(),
    };
    return { read, personal: start.personal };
  }

  /** Every string in `value`, at any depth. */
  function stringsOf(value: unknown): string[] {
    if (typeof value === 'string') return [value];
    if (Array.isArray(value)) return value.flatMap(stringsOf);
    if (value !== null && typeof value === 'object') {
      return [...Object.keys(value), ...Object.values(value).flatMap(stringsOf)];
    }
    return [];
  }

  for (const [label, client] of HOSTILE_CLIENTS) {
    for (const [where, redirectUri] of [
      ['a web redirect', 'https://notes.example.com/callback?from=https%3A%2F%2Fevil.example'],
      ['a loopback redirect', 'http://127.0.0.1:53124/callback'],
      ['an app scheme', 'com.example.notes:/oauth/callback'],
    ] as const) {
      it(`carries no markup and no client URL: ${label}, ${where}`, async () => {
        const resources = client.audience === undefined ? ['https://api.example.com/v1'] : [];
        const { read, personal } = await startOf(client, { redirect_uri: redirectUri }, resources);
        const whole = JSON.stringify({ read, personal });

        expect(validateInteraction(read), describeErrors(validateInteraction)).toBe(true);
        expect(whole).not.toMatch(/[<>]/);
        expect(whole).not.toMatch(/[\u200b\u202a-\u202e\u2066-\u2069]/);
        for (const url of Object.values(CLIENT_URLS)) expect(whole).not.toContain(url);

        // The declared name is the one member a client writes: plain text,
        // which the contract marks as declared and a screen never links. Any
        // other member holds nothing the client supplied.
        const { declaredName, ...verified } = read.client ?? {};
        const rest = { read: { ...read, client: verified }, personal };
        const restJson = JSON.stringify(rest);
        // Nothing of the client's own URLs: a CIMD client id beyond its host,
        // the redirect URI beyond its host, port or scheme.
        expect(restJson).not.toContain('client-metadata.json');
        expect(restJson).not.toContain('frag');
        expect(restJson).not.toContain('callback');
        expect(restJson).not.toContain('53124');
        expect(restJson).not.toContain('evil.example');
        expect(typeof declaredName === 'string' ? declaredName : '').not.toMatch(/[<>]/);

        // The only URL-shaped values: the request's own resources, which the
        // step names as where the tokens may be used, and the client's
        // configured audience an operator set.
        const urls = stringsOf(rest).filter((value) => value.includes('://'));
        expect(urls.sort()).toEqual([...resources, ...(client.audience ?? [])].sort());
        // Where the code goes, as a host, "this device" or a scheme only.
        expect(read.client).toHaveProperty('redirect');
      });
    }
  }

  it('carries a declared name that looks like a URL as declared text only, with its markup removed', async () => {
    // #593: a declared name is stripped of markup, controls and format
    // characters, never of the characters a URL is made of. It reaches the
    // screen as text under the verified data, marked as declared; no other
    // member of the step carries anything of it.
    const { read } = await startOf(
      { name: '<a href="https://evil.example/login">https://evil.example/login</a>' },
      {},
      []
    );
    expect(read.client?.declaredName).toBe(
      'a href="https://evil.example/login"https://evil.example/login/a'
    );
    const verified = Object.entries(read.client ?? {}).filter(([key]) => key !== 'declaredName');
    expect(JSON.stringify({ ...read, client: verified })).not.toContain('evil.example');
  });

  it('shows a CIMD client by the host of its client id URL, and nothing else of it', async () => {
    const { read } = await startOf(HOSTILE_CLIENTS[1][1], {}, []);
    expect(read.client).toMatchObject({
      kind: 'cimd',
      verifiedDomain: { host: 'notes.example.com', registrableDomain: 'example.com' },
    });
  });

  it('shows the redirect as a host, "this device" or an app scheme', async () => {
    const targets = [];
    for (const redirectUri of [
      'https://notes.example.com/callback?x=1',
      'http://127.0.0.1:53124/callback',
      'http://[::1]:8080/cb',
      'com.example.notes:/oauth/callback',
    ]) {
      targets.push((await startOf({}, { redirect_uri: redirectUri }, [])).read.client?.redirect);
    }
    expect(targets).toEqual([
      { target: 'host', host: 'notes.example.com' },
      { target: 'this_device' },
      { target: 'this_device' },
      { target: 'app', scheme: 'com.example.notes' },
    ]);
  });

  it('marks a dynamically registered client in its badge window as new', async () => {
    const { read } = await startOf(HOSTILE_CLIENTS[2][1], {}, []);
    expect(read.client).toMatchObject({ kind: 'unverified', newClient: true });
  });
});

describe('finishAuthorization', () => {
  it('decides the request again for the live session the interaction holds, and redirects with the code', async () => {
    decideAuthorization.mockResolvedValue({
      kind: 'code',
      location: 'https://notes.example.com/callback?code=c0de&state=af0ifjsldkj&iss=x',
    });

    const location = await finishAuthorization(
      fastify,
      request,
      reply,
      finished({ userId: 'user-1', sid: 'sid-1', authTime: SESSION.authTime, amr: ['pwd'] })
    );

    expect(location).toBe('https://notes.example.com/callback?code=c0de&state=af0ifjsldkj&iss=x');
    // The request as the record holds it, checked as the endpoint checks it.
    expect(checkAuthorizationRequest).toHaveBeenCalledWith(fastify, request, REQUEST);
    expect(liveBrowserSession).toHaveBeenCalledWith(fastify, REALM.id, 'sid-1', 'user-1');
    expect(decideAuthorization).toHaveBeenCalledWith(fastify, request, TARGET, REQUEST, SESSION);
    expect(continueInteraction).not.toHaveBeenCalled();
  });

  it('decides with no session when nobody signed in, or the session is no longer live', async () => {
    decideAuthorization.mockResolvedValue({ kind: 'sign_in' });
    liveBrowserSession.mockResolvedValue(null);
    for (const transaction of [{ amr: [] }, { userId: 'user-1', sid: 'sid-1', amr: ['pwd'] }]) {
      decideAuthorization.mockClear();
      await finishAuthorization(fastify, request, reply, finished(transaction));
      expect(decideAuthorization).toHaveBeenCalledWith(fastify, request, TARGET, REQUEST, null);
    }
  });

  it('redirects to the client with the error, its state and iss', async () => {
    decideAuthorization.mockResolvedValue({
      kind: 'error',
      params: { error: 'invalid_scope', state: REQUEST.state, iss: ISS },
    });

    const location = new URL(
      await finishAuthorization(fastify, request, reply, finished({ amr: [] }))
    );

    expect(`${location.origin}${location.pathname}`).toBe(REQUEST.redirect_uri);
    expect(location.searchParams.get('error')).toBe('invalid_scope');
    expect(location.searchParams.get('state')).toBe(REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ISS);
    expect(location.searchParams.get('code')).toBeNull();
  });

  it('redirects with the error of a request the checks now refuse', async () => {
    checkAuthorizationRequest.mockResolvedValue({
      kind: 'refused',
      client: TARGET.client,
      params: { error: 'invalid_request', state: REQUEST.state, iss: ISS },
    });

    const location = new URL(
      await finishAuthorization(fastify, request, reply, finished({ amr: [] }))
    );

    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(decideAuthorization).not.toHaveBeenCalled();
  });

  it('throws what the checks throw: no redirect to a URI the client no longer holds', async () => {
    const refused = new Error('redirect_uri is no longer registered');
    checkAuthorizationRequest.mockRejectedValue(refused);

    await expect(finishAuthorization(fastify, request, reply, finished({ amr: [] }))).rejects.toBe(
      refused
    );
    expect(decideAuthorization).not.toHaveBeenCalled();
  });

  it('continues with a consent interaction, within the finished one’s lifetime and flow cookie', async () => {
    decideAuthorization.mockResolvedValue({ kind: 'consent', scopes: ['email'], resources: [] });
    const done = finished({ userId: 'user-1', sid: 'sid-1', amr: ['pwd'] });

    const location = await finishAuthorization(fastify, request, reply, done);

    expect(location).toBe(`${ISS}${ceremonyPagePath(NEXT_ID)}`);
    expect(continueInteraction).toHaveBeenCalledWith(request, reply, done.continuation, {
      request: REQUEST,
      step: expect.objectContaining({ name: CONSENT_STEP }),
      personal: {},
      transaction: { userId: 'user-1', sid: 'sid-1', authTime: SESSION.authTime, amr: [] },
      // Who the client is, computed when the consent starts (#629).
      client: CLIENT_DISPLAY,
      // The sign-in's session, which the consent is for: "Not you?" ends it (#964).
      carriedSession: { userId: 'user-1', sid: 'sid-1' },
    });
  });

  it('continues with a sign-in when the session ended meanwhile, carrying no session', async () => {
    decideAuthorization.mockResolvedValue({ kind: 'sign_in' });
    liveBrowserSession.mockResolvedValue(null);

    const location = await finishAuthorization(
      fastify,
      request,
      reply,
      finished({ userId: 'user-1', sid: 'sid-1', amr: ['pwd'] })
    );

    expect(location).toBe(`${ISS}${ceremonyPagePath(NEXT_ID)}`);
    expect(continueInteraction.mock.calls[0]?.[3]).toEqual({
      request: REQUEST,
      step: { name: stepUrn('identifier'), params: {}, alternatives: [] },
      personal: {},
    });
  });

  it('redirects with the error when the consent the request needs cannot be shown', async () => {
    decideAuthorization.mockResolvedValue({
      kind: 'consent',
      scopes: ['odd<scope'],
      resources: [],
    });

    const location = new URL(
      await finishAuthorization(
        fastify,
        request,
        reply,
        finished({ userId: 'user-1', sid: 'sid-1', amr: ['pwd'] })
      )
    );

    expect(location.searchParams.get('error')).toBe('invalid_scope');
    expect(continueInteraction).not.toHaveBeenCalled();
    expect(emitUserEvent).toHaveBeenCalledWith(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_scope', reason: 'consent_step_unshowable' },
      { realmId: REALM.id, userId: 'user-1', clientId: 'notes-app', actor: 'user' }
    );
  });
});

/**
 * The consent answer (#629): the POST scenarios of the consent page
 * (`routes/ui/consent.test.ts`), ported to the step. The endpoint's checks,
 * the decision, the session read, the code mint, the side record and the
 * next interaction are stand-ins; the scope, audience, agent-cap and step-up
 * rules are the real ones.
 */
describe('finishConsent', () => {
  const NOW_FRESH = () => Date.now() - 5_000;
  const STALE = () => Date.now() - STEP_UP_FRESH_AUTH_WINDOW_MS - 60_000;

  /** The live session the consent is for, signed in at `authTime`. */
  function liveSession(authTime: number) {
    return {
      realmId: REALM.id,
      sid: 'sid-1',
      userId: 'user-1',
      authTime,
      amr: ['pwd'],
      assuranceLevel: 'substantial',
      createdAt: authTime,
      lastSeenAt: authTime,
      expiresAt: authTime + 8 * 3600 * 1000,
      idleExpiresAt: null,
    };
  }

  /** The user, client and actor every event of a consent answer names. */
  const USER_EVENT = {
    realmId: REALM.id,
    userId: 'user-1',
    clientId: 'notes-app',
    actor: 'user',
  };

  /** The step the interaction held, for `scopes` at `resources`. */
  function stepFor(
    scopes: readonly string[],
    resources: readonly string[] = [],
    subject: Partial<ConsentStepSubject> = {}
  ): InteractionStep {
    const step = consentStep(scopes, resources, { ...SUBJECT, ...subject });
    if (typeof step === 'string') throw new Error(step);
    return step;
  }

  /** A consent interaction that finished with `answer`, for the request `query`. */
  function answered(
    options: {
      readonly query?: Partial<InteractionRequest>;
      readonly step?: InteractionStep;
      readonly answer?: Partial<ConsentAnswer>;
      readonly transaction?: FinishedAuthorization['transaction'];
    } = {}
  ) {
    return {
      request: { ...REQUEST, ...options.query } as InteractionRequest,
      transaction: options.transaction ?? {
        userId: 'user-1',
        sid: 'sid-1',
        authTime: SESSION.authTime,
        amr: [],
      },
      continuation: { secrets: ['s'.repeat(43)], expiresAt: 1_700_000_900_000 },
      step: options.step ?? stepFor(['openid', 'email']),
      answer: { decision: 'allow' as const, remember: true, ...options.answer },
    };
  }

  /** Decide `finished` for a request of `client`, on a session signed in at `authTime`. */
  async function decide(
    finished: ReturnType<typeof answered>,
    options: {
      readonly client?: Partial<TestClient>;
      readonly authTime?: number;
      readonly dpopJkt?: string | null;
    } = {}
  ) {
    const target = { ...targetOf(options.client), dpopJkt: options.dpopJkt ?? null };
    checkAuthorizationRequest.mockResolvedValue({ kind: 'checked', target });
    liveBrowserSession.mockResolvedValue(liveSession(options.authTime ?? NOW_FRESH()));
    const location = await finishConsent(fastify, realmRequest, reply, finished);
    return { location: new URL(location), raw: location, target };
  }

  /** The events the answer emitted, by type, with their data and options. */
  function emitted(type: string) {
    return emitUserEvent.mock.calls
      .filter(([, t]) => t === type)
      .map(([, , data, options]) => ({ data, options }));
  }

  function eventTypes(): string[] {
    return emitUserEvent.mock.calls.map(([, type]) => type as string);
  }

  /** A redirect to the client's `redirect_uri` with `error`, state and iss, and no code. */
  function expectClientError(location: URL, error: string, redirectUri = REQUEST.redirect_uri) {
    expect(`${location.origin}${location.pathname}`).toBe(redirectUri);
    expect(location.searchParams.get('error')).toBe(error);
    expect(location.searchParams.get('state')).toBe(REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(ISS);
    expect(location.searchParams.get('code')).toBeNull();
  }

  /** Nothing granted: no code, no remembered grant, no consent.granted. */
  function expectNothingGranted() {
    expect(mintAuthorizationCode).not.toHaveBeenCalled();
    expect(upsertGrant).not.toHaveBeenCalled();
    expect(eventTypes()).not.toContain('urn:qauth:event:consent.granted:v1-rc.0');
  }

  /** The request went on at a new sign-in interaction, the identifier step. */
  function expectSignInInteraction(raw: string, carried: boolean) {
    expect(raw).toBe(`${ISS}${ceremonyPagePath(NEXT_ID)}`);
    expect(continueInteraction).toHaveBeenCalledOnce();
    expect(continueInteraction.mock.calls[0]?.[3]).toEqual({
      request: expect.objectContaining({ client_id: REQUEST.client_id }),
      step: { name: stepUrn('identifier'), params: {}, alternatives: [] },
      personal: {},
      // The session, carried in, so "Not you?" can end it (#964).
      ...(carried ? { carriedSession: { userId: 'user-1', sid: 'sid-1' } } : {}),
    });
  }

  describe('deny', () => {
    it('records consent.denied and redirects with access_denied, its description, state and iss', async () => {
      const { location } = await decide(answered({ answer: { decision: 'deny' } }));

      expectClientError(location, 'access_denied');
      expect(location.searchParams.get('error_description')).toBe(
        'User denied the authorization request.'
      );
      expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toEqual([
        { data: { error: 'access_denied' }, options: USER_EVENT },
      ]);
      expectNothingGranted();
      // The request was checked again first: no redirect to a URI the client
      // no longer holds.
      expect(checkAuthorizationRequest).toHaveBeenCalledWith(
        fastify,
        realmRequest,
        expect.objectContaining({ client_id: REQUEST.client_id })
      );
    });

    it('stands when the checks now refuse the request: the decision still goes to the client', async () => {
      // A dpop_jkt that DPoP, switched on since, cannot read: the redirect
      // URI is still the client's.
      checkAuthorizationRequest.mockResolvedValue({
        kind: 'refused',
        client: CLIENT,
        params: { error: 'invalid_request', state: REQUEST.state, iss: ISS },
      });

      const location = new URL(
        await finishConsent(
          fastify,
          realmRequest,
          reply,
          answered({ answer: { decision: 'deny' } })
        )
      );

      expectClientError(location, 'access_denied');
      expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toHaveLength(1);
    });
  });

  it('redirects an allow the checks now refuse with their error, and mints nothing', async () => {
    checkAuthorizationRequest.mockResolvedValue({
      kind: 'refused',
      client: CLIENT,
      params: { error: 'invalid_request', state: REQUEST.state, iss: ISS },
    });

    const location = new URL(await finishConsent(fastify, realmRequest, reply, answered()));

    expectClientError(location, 'invalid_request');
    expectNothingGranted();
  });

  it('throws what the checks throw, and mints nothing', async () => {
    const refused = new Error('redirect_uri is no longer registered');
    checkAuthorizationRequest.mockRejectedValue(refused);

    await expect(finishConsent(fastify, realmRequest, reply, answered())).rejects.toBe(refused);
    expectNothingGranted();
    expect(emitUserEvent).not.toHaveBeenCalled();
  });

  it('throws for a transaction in which nobody signed in: a consent is always for a user', async () => {
    await expect(
      finishConsent(fastify, realmRequest, reply, answered({ transaction: { amr: [] } }))
    ).rejects.toThrow('a consent interaction is for a signed-in user');
    expect(checkAuthorizationRequest).not.toHaveBeenCalled();
    expectNothingGranted();
  });

  describe('allow', () => {
    it('mints the code for the scopes the step showed and remembers the grant, in one transaction', async () => {
      const authTime = NOW_FRESH();
      const session = liveSession(authTime);
      const finished = answered({
        query: {
          nonce: 'n-0S6_WzA2Mj',
          resource: ['https://api.example.com/v1'],
          // A scope the client's allowlist does not hold: the step never showed it.
          scope: 'openid email admin:all',
        },
        step: stepFor(['openid', 'email'], ['https://api.example.com/v1']),
      });

      const { location, target } = await decide(finished, { authTime, dpopJkt: 'j'.repeat(43) });

      expect(`${location.origin}${location.pathname}`).toBe(REQUEST.redirect_uri);
      expect(location.searchParams.get('code')).toBe('c0de');
      expect(location.searchParams.get('state')).toBe(REQUEST.state);
      expect(location.searchParams.get('iss')).toBe(ISS);
      expect(liveBrowserSession).toHaveBeenCalledWith(fastify, REALM.id, 'sid-1', 'user-1');
      expect(transaction).toHaveBeenCalledOnce();
      expect(transaction.mock.calls[0]?.[1]).toBe(MINT_TRANSACTION);
      expect(mintAuthorizationCode).toHaveBeenCalledOnce();
      expect(mintAuthorizationCode).toHaveBeenCalledWith(
        fastify,
        {
          oauthClientId: CLIENT.id,
          userId: 'user-1',
          redirectUri: REQUEST.redirect_uri,
          codeChallenge: REQUEST.code_challenge,
          codeChallengeMethod: 'S256',
          nonce: 'n-0S6_WzA2Mj',
          authTime,
          assuranceLevel: 'substantial',
          sessionExpiresAt: session.expiresAt,
          session: { realmId: REALM.id, sid: 'sid-1' },
          // The step's scope set, never the request's or an answer's.
          scopes: ['openid', 'email'],
          resource: ['https://api.example.com/v1'],
          state: REQUEST.state,
          dpopJkt: target.dpopJkt,
        },
        TX
      );
      expect(upsertGrant).toHaveBeenCalledOnce();
      expect(upsertGrant).toHaveBeenCalledWith(
        REALM.id,
        'user-1',
        CLIENT.id,
        ['openid', 'email'],
        ['https://api.example.com/v1'],
        TX
      );
      expect(emitted('urn:qauth:event:consent.granted:v1-rc.0')).toEqual([
        {
          data: { scopes: ['openid', 'email'], remembered: true },
          options: { ...USER_EVENT, tx: TX },
        },
      ]);
      expect(eventTypes()).not.toContain('urn:qauth:event:step_up.elevated:v1-rc.0');
      expect(continueInteraction).not.toHaveBeenCalled();
    });

    it('stores no grant when the person did not ask to remember it', async () => {
      const { location } = await decide(answered({ answer: { remember: false } }));

      expect(location.searchParams.get('code')).toBe('c0de');
      expect(upsertGrant).not.toHaveBeenCalled();
      expect(emitted('urn:qauth:event:consent.granted:v1-rc.0')).toEqual([
        {
          data: { scopes: ['openid', 'email'], remembered: false },
          options: { ...USER_EVENT, tx: TX },
        },
      ]);
    });

    it('mints with no nonce, no state and no DPoP key when the request had none', async () => {
      const { location } = await decide(answered({ query: { state: undefined } }));

      expect(location.searchParams.has('state')).toBe(false);
      expect(mintAuthorizationCode.mock.calls[0]?.[1]).toMatchObject({
        nonce: null,
        state: null,
        dpopJkt: null,
        resource: [],
      });
    });

    it('keeps the requested port of a loopback redirect (RFC 8252 §7.3)', async () => {
      const redirectUri = 'http://127.0.0.1:53124/callback';
      const { raw } = await decide(answered({ query: { redirect_uri: redirectUri } }));

      expect(raw.startsWith(`${redirectUri}?`)).toBe(true);
      expect(mintAuthorizationCode.mock.calls[0]?.[1]).toMatchObject({ redirectUri });
    });

    it('round-trips a state of the longest length, verbatim', async () => {
      const state = 'aZ09-._~+/=&%?#'.repeat(137).slice(0, 2048);
      const { location } = await decide(answered({ query: { state } }));

      expect(state).toHaveLength(2048);
      expect(location.searchParams.get('state')).toBe(state);
      expect(mintAuthorizationCode.mock.calls[0]?.[1]).toMatchObject({ state });
    });
  });

  describe('the step-up gate on the mint path (ADR-007 §2, #185)', () => {
    it('records the elevation of a dangerous scope on a fresh sign-in, with the grant, in the transaction', async () => {
      const authTime = NOW_FRESH();
      await decide(
        answered({
          query: { scope: 'openid write:notes' },
          step: stepFor(['openid', 'write:notes']),
        }),
        { authTime }
      );

      expect(mintAuthorizationCode).toHaveBeenCalledOnce();
      // No scope mode: the client is no agent.
      expect(emitted('urn:qauth:event:step_up.elevated:v1-rc.0')).toEqual([
        {
          data: {
            scopes: ['openid', 'write:notes'],
            dangerousScopes: ['write:notes'],
            authenticatedAt: new Date(authTime).toISOString(),
          },
          options: { ...USER_EVENT, tx: TX },
        },
      ]);
      expect(emitted('urn:qauth:event:consent.granted:v1-rc.0')).toEqual([
        {
          data: {
            scopes: ['openid', 'write:notes'],
            remembered: true,
            dangerousScopes: ['write:notes'],
          },
          options: { ...USER_EVENT, tx: TX },
        },
      ]);
      expect(eventTypes()).toEqual([
        'urn:qauth:event:step_up.elevated:v1-rc.0',
        'urn:qauth:event:consent.granted:v1-rc.0',
      ]);
    });

    it('records the agent’s scope mode in the elevation of an agent client (#186)', async () => {
      await decide(
        answered({
          query: { scope: 'agent:exec' },
          step: stepFor(['agent:exec'], [], { agent: true }),
        }),
        { client: { isAgent: true, maxAgentMode: 'exec', scopes: ['agent:exec', 'email'] } }
      );

      expect(mintAuthorizationCode).toHaveBeenCalledOnce();
      expect(emitted('urn:qauth:event:step_up.elevated:v1-rc.0')[0]?.data).toMatchObject({
        dangerousScopes: ['agent:exec'],
        scopeMode: 'exec',
      });
    });

    it('sends a dangerous scope on a stale sign-in to a fresh sign-in, before any code', async () => {
      const { raw } = await decide(
        answered({
          query: { scope: 'openid write:notes' },
          step: stepFor(['openid', 'write:notes']),
        }),
        { authTime: STALE() }
      );

      expect(emitted('urn:qauth:event:step_up.required:v1-rc.0')).toEqual([
        {
          data: { reason: 'fresh_authentication_required', dangerousScopes: ['write:notes'] },
          options: USER_EVENT,
        },
      ]);
      expectNothingGranted();
      expect(transaction).not.toHaveBeenCalled();
      expectSignInInteraction(raw, true);
    });

    it('sends prompt=login on a stale sign-in to a fresh sign-in, even for a harmless scope', async () => {
      const { raw } = await decide(answered({ query: { prompt: 'login' } }), {
        authTime: STALE(),
      });

      expect(emitted('urn:qauth:event:step_up.required:v1-rc.0')).toEqual([
        { data: { reason: 'fresh_authentication_required', prompt: 'login' }, options: USER_EVENT },
      ]);
      expectNothingGranted();
      expectSignInInteraction(raw, true);
    });

    it('mints a harmless scope on a stale sign-in: no over-gating', async () => {
      const { location } = await decide(answered(), { authTime: STALE() });

      expect(location.searchParams.get('code')).toBe('c0de');
      expect(eventTypes()).not.toContain('urn:qauth:event:step_up.required:v1-rc.0');
    });

    it('sends a sign-in older than max_age to a fresh sign-in, inside the freshness window too', async () => {
      // max_age is enforced exactly, not widened by the window.
      const { raw } = await decide(answered({ query: { max_age: 30 } }), {
        authTime: Date.now() - 90_000,
      });

      expect(emitted('urn:qauth:event:step_up.required:v1-rc.0')).toEqual([
        { data: { reason: 'fresh_authentication_required', maxAge: 30 }, options: USER_EVENT },
      ]);
      expectNothingGranted();
      expectSignInInteraction(raw, true);
    });

    it('mints within max_age', async () => {
      const { location } = await decide(answered({ query: { max_age: 300 } }), {
        authTime: Date.now() - 90_000,
      });

      expect(location.searchParams.get('code')).toBe('c0de');
    });

    describe('a native_backend client (ADR-017 Decision 9, #633)', () => {
      const NATIVE: Partial<TestClient> = {
        grantTypes: ['authorization_code', 'refresh_token'],
        tokenEndpointAuthMethod: 'private_key_jwt',
        firstPartyProfile: 'native_backend',
        firstPartyPolicy: { flows: ['login'] },
        isAgent: false,
        metadata: null,
      };

      it('sends a stale sign-in to a fresh sign-in, whatever prompt the request says', async () => {
        for (const prompt of [undefined, 'consent'] as const) {
          vi.clearAllMocks();
          continueInteraction.mockResolvedValue({ id: NEXT_ID, expiresAt: 1_700_000_900_000 });
          const { raw } = await decide(answered({ query: { prompt } }), {
            client: NATIVE,
            authTime: STALE(),
          });

          expect(
            emitted('urn:qauth:event:step_up.required:v1-rc.0')[0]?.data,
            String(prompt)
          ).toMatchObject({ reason: 'native_profile_login_required' });
          expectNothingGranted();
          expectSignInInteraction(raw, true);
        }
      });

      it('mints on a fresh sign-in', async () => {
        const { location } = await decide(answered(), { client: NATIVE });

        expect(location.searchParams.get('code')).toBe('c0de');
        expect(eventTypes()).not.toContain('urn:qauth:event:step_up.required:v1-rc.0');
      });
    });
  });

  describe('the agent scope-mode cap (ADR-007 §2, #184)', () => {
    it('refuses a scope over the agent’s cap with invalid_scope, though its allowlist holds it', async () => {
      const { location } = await decide(
        answered({
          query: { scope: 'agent:exec' },
          step: stepFor(['agent:exec'], [], { agent: true }),
        }),
        {
          client: {
            isAgent: true,
            maxAgentMode: 'readonly',
            scopes: ['agent:readonly', 'agent:exec', 'email'],
          },
        }
      );

      expectClientError(location, 'invalid_scope');
      expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toEqual([
        {
          data: { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
          options: USER_EVENT,
        },
      ]);
      expectNothingGranted();
    });

    it('refuses any agent scope for a client that is no agent, though its allowlist holds it', async () => {
      const { location } = await decide(
        answered({ query: { scope: 'agent:readonly' }, step: stepFor(['agent:readonly']) }),
        { client: { scopes: ['agent:readonly', 'email'] } }
      );

      expectClientError(location, 'invalid_scope');
      expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')[0]?.data).toEqual({
        error: 'invalid_scope',
        reason: 'agent_scope_mode_exceeded',
      });
      expectNothingGranted();
    });
  });

  it('refuses a QAuth API audience the client no longer lists with invalid_target (#509)', async () => {
    const audience = 'urn:qauth:aud:admin:v1-rc.0';
    const { location } = await decide(
      answered({ query: { resource: [audience] }, step: stepFor(['openid', 'email'], [audience]) })
    );

    expectClientError(location, 'invalid_target');
    expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toEqual([
      {
        data: { error: 'invalid_target', reason: 'reserved_audience_not_listed' },
        options: USER_EVENT,
      },
    ]);
    expectNothingGranted();
  });

  describe('a client that changed whether it is an agent since the step (ADR-014 §11, #845)', () => {
    it('grants an agent the step did not name as one nothing, and shows the step it needs now', async () => {
      decideAuthorization.mockResolvedValue({
        kind: 'consent',
        scopes: ['openid', 'email'],
        resources: [],
      });

      const { raw, target } = await decide(answered({ step: stepFor(['openid', 'email']) }), {
        client: { isAgent: true, maxAgentMode: 'readonly' },
      });

      expectNothingGranted();
      expect(decideAuthorization).toHaveBeenCalledWith(
        fastify,
        realmRequest,
        target,
        expect.objectContaining({ client_id: REQUEST.client_id }),
        expect.objectContaining({ sid: 'sid-1', userId: 'user-1' })
      );
      expect(raw).toBe(`${ISS}${ceremonyPagePath(NEXT_ID)}`);
      // The new consent step names the client as the agent it is now.
      expect(continueInteraction.mock.calls[0]?.[3]).toMatchObject({
        step: { name: CONSENT_STEP, params: { agent: {} } },
      });
      expect(realmRequest.log.warn).toHaveBeenCalled();
    });

    it('grants a client the step named as an agent, and is no longer, nothing, and goes where the decision says', async () => {
      decideAuthorization.mockResolvedValue({
        kind: 'code',
        location: 'https://notes.example.com/callback?code=n3w&state=af0ifjsldkj',
      });

      const { raw } = await decide(
        answered({ step: stepFor(['openid', 'email'], [], { agent: true }) })
      );

      expectNothingGranted();
      expect(decideAuthorization).toHaveBeenCalledOnce();
      expect(raw).toBe('https://notes.example.com/callback?code=n3w&state=af0ifjsldkj');
      expect(eventTypes()).not.toContain('urn:qauth:event:consent.denied:v1-rc.0');
    });
  });

  it('refuses a shown scope the client’s allowlist no longer holds with invalid_scope (#150)', async () => {
    // An owner removed `email` from the client since the step was shown.
    const { location } = await decide(answered(), { client: { scopes: ['openid'] } });

    expectClientError(location, 'invalid_scope');
    expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toEqual([
      { data: { error: 'invalid_scope', reason: 'consent_scope_mismatch' }, options: USER_EVENT },
    ]);
    expectNothingGranted();
  });

  it('refuses a step whose resources are not the request’s with invalid_target', async () => {
    const { location } = await decide(
      answered({ step: stepFor(['openid', 'email'], ['https://api.example.com/v1']) })
    );

    expectClientError(location, 'invalid_target');
    expect(emitted('urn:qauth:event:consent.denied:v1-rc.0')).toEqual([
      {
        data: { error: 'invalid_target', reason: 'consent_resource_mismatch' },
        options: USER_EVENT,
      },
    ]);
    expectNothingGranted();
  });

  it('sends the request to a sign-in when the account was disabled since, carrying no session', async () => {
    checkAuthorizationRequest.mockResolvedValue({ kind: 'checked', target: TARGET });
    liveBrowserSession.mockResolvedValue(null);

    const raw = await finishConsent(fastify, realmRequest, reply, answered());

    expectNothingGranted();
    expect(decideAuthorization).not.toHaveBeenCalled();
    expectSignInInteraction(raw, false);
  });

  it('grants nothing when the session ended under the request, and sends it to a sign-in', async () => {
    mintAuthorizationCode.mockResolvedValue('session_ended');

    const { raw } = await decide(answered());

    expect(mintAuthorizationCode).toHaveBeenCalledOnce();
    expect(upsertGrant).not.toHaveBeenCalled();
    expect(eventTypes()).toEqual(['urn:qauth:event:authorization.failed:v1-rc.0']);
    expect(emitted('urn:qauth:event:authorization.failed:v1-rc.0')).toEqual([
      {
        data: { error: 'login_required', reason: 'session_ended_during_authorization' },
        options: USER_EVENT,
      },
    ]);
    expectSignInInteraction(raw, false);
  });
});

describe('cancelAuthorization', () => {
  it('checks the request again, then redirects with access_denied, its state and iss', async () => {
    const location = new URL(await cancelAuthorization(fastify, realmRequest, REQUEST));

    expect(checkAuthorizationRequest).toHaveBeenCalledWith(fastify, realmRequest, REQUEST);
    expect(`${location.origin}${location.pathname}`).toBe(REQUEST.redirect_uri);
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe(REQUEST.state);
    expect(location.searchParams.get('iss')).toBe(REALM.issuer);
  });

  it('throws what the checks throw: no redirect for a client disabled since', async () => {
    const refused = new Error('client is disabled');
    checkAuthorizationRequest.mockRejectedValue(refused);

    await expect(cancelAuthorization(fastify, realmRequest, REQUEST)).rejects.toBe(refused);
  });
});
