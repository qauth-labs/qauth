import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { checkAuthorizationRequest, decideAuthorization, liveBrowserSession, continueInteraction } =
  vi.hoisted(() => ({
    checkAuthorizationRequest: vi.fn(),
    decideAuthorization: vi.fn(),
    liveBrowserSession: vi.fn(),
    continueInteraction: vi.fn(),
  }));

vi.mock('./authorization-request', () => ({ checkAuthorizationRequest, decideAuthorization }));
vi.mock('./browser-session', () => ({ liveBrowserSession }));
vi.mock('./interaction', () => ({ continueInteraction }));

import { testRealm } from '../../testing/request-realm';
import {
  authorizationInteractionStart,
  CONSENT_STEP,
  consentStep,
  type FinishedAuthorization,
  finishAuthorization,
  identifierPrefill,
} from './authorization-interaction';
import type { InteractionRequest } from './interaction-record';

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

const TARGET = { realm: REALM, iss: ISS, client: { clientId: 'notes-app' } };

const fastify = {} as FastifyInstance;
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
});

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
    expect(consentStep(['email', 'write:notes'], ['https://api.example.com/v1'])).toEqual({
      name: CONSENT_STEP,
      params: {
        scopes: [
          { scope: 'email', sensitive: false, dangerous: false },
          { scope: 'write:notes', sensitive: false, dangerous: true },
        ],
        resources: ['https://api.example.com/v1'],
        remember_default: true,
      },
      alternatives: [],
    });
  });

  it('shows a request that asks for no scope', () => {
    expect(consentStep([], [])).toMatchObject({ params: { scopes: [], resources: [] } });
  });

  it('is invalid_scope for scopes the step cannot show', () => {
    expect(consentStep(['odd<scope'], [])).toBe('invalid_scope');
    expect(consentStep(['s'.repeat(129)], [])).toBe('invalid_scope');
    expect(
      consentStep(
        Array.from({ length: 65 }, (_, i) => `s${i}`),
        []
      )
    ).toBe('invalid_scope');
  });

  it('is invalid_target for resources the step cannot show', () => {
    const resources = Array.from({ length: 17 }, (_, i) => `https://api${i}.example.com/`);
    expect(consentStep(['email'], resources)).toBe('invalid_target');
  });
});

describe('authorizationInteractionStart', () => {
  it('starts a sign-in at the identifier step, the hint as its prefill, with no transaction', () => {
    expect(
      authorizationInteractionStart(
        { kind: 'sign_in' },
        { ...REQUEST, login_hint: 'alice@example.com' },
        ISS,
        null
      )
    ).toEqual({
      step: { name: stepUrn('identifier'), params: {}, alternatives: [] },
      personal: { login_hint: 'alice@example.com' },
    });
  });

  it('starts a consent for the session: its user, sid and authentication time', () => {
    const start = authorizationInteractionStart(
      { kind: 'consent', scopes: ['email'], resources: [] },
      REQUEST,
      ISS,
      SESSION as never
    );
    expect(start).toMatchObject({
      step: { name: CONSENT_STEP },
      personal: {},
      transaction: { userId: 'user-1', sid: 'sid-1', authTime: SESSION.authTime, amr: [] },
    });
  });

  it('answers the error, with state and iss, for a consent the step cannot show', () => {
    expect(
      authorizationInteractionStart(
        { kind: 'consent', scopes: ['odd<scope'], resources: [] },
        REQUEST,
        ISS,
        SESSION as never
      )
    ).toEqual({
      error: expect.objectContaining({ error: 'invalid_scope', state: REQUEST.state, iss: ISS }),
    });
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
    });
  });

  it('continues with a sign-in when the session ended meanwhile', async () => {
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
  });
});
