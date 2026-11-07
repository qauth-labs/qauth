import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test', INTERACTION_TTL: 1800 } }));

import { testRealm } from '../../testing/request-realm';
import { accountPageUrl, accountRoundOf, engineClientIdOf } from './account-interaction';
import type { InteractionState } from './interaction';
import {
  ACCOUNT_PAGES_ENGINE_CLIENT_ID,
  eventClientIdOfEngineClient,
  IDENTIFIER_STEP,
  interactionRecordSchema,
} from './interaction-record';

/**
 * The account page's interactions (#844): what their engine rounds are bound
 * to and ask for, and where they finish.
 */

describe('the rounds of an account interaction', () => {
  it('always ask for a fresh sign-in, and bind the factor of an enrolment', () => {
    expect(accountRoundOf({ intent: 'sign_in', returnTo: '/ui/account' })).toEqual({
      freshSignIn: true,
    });
    expect(accountRoundOf({ intent: 'reauthenticate', returnTo: '/ui/account' })).toEqual({
      freshSignIn: true,
    });
    expect(accountRoundOf({ intent: 'passkey', returnTo: '/ui/account' })).toEqual({
      freshSignIn: true,
      enrol: 'passkey',
    });
    expect(accountRoundOf({ intent: 'totp', returnTo: '/ui/account' })).toEqual({
      freshSignIn: true,
      enrol: 'totp',
    });
    expect(accountRoundOf({ intent: 'link', returnTo: '/ui/account' })).toEqual({
      freshSignIn: true,
    });
  });

  it('are bound to the account pages’ engine client, which no event names', () => {
    const state = {
      purpose: 'account',
      request: { intent: 'sign_in', returnTo: '/ui/account' },
    } as unknown as Extract<InteractionState, { purpose: 'account' }>;
    expect(engineClientIdOf(state)).toBe(ACCOUNT_PAGES_ENGINE_CLIENT_ID);
    expect(eventClientIdOfEngineClient(ACCOUNT_PAGES_ENGINE_CLIENT_ID)).toBeNull();
    expect(eventClientIdOfEngineClient('notes-app')).toBe('notes-app');
    expect(eventClientIdOfEngineClient('x'.repeat(256))).toBeNull();
  });
});

describe('the record of an account interaction', () => {
  it('returns only to a page of the fixed list', () => {
    const record = (returnTo: string) =>
      interactionRecordSchema.safeParse({
        v: 2,
        ref: '0199fa20-0000-7000-8000-000000000001',
        realmId: '0199fa20-0000-7000-8000-00000000aaaa',
        purpose: 'account',
        request: { intent: 'reauthenticate', returnTo },
        step: { name: IDENTIFIER_STEP, params: {}, alternatives: [] },
        personal: {},
        transaction: { amr: [] },
        flowBinding: 'a'.repeat(43),
        csrfKey: 'b'.repeat(43),
        signInTransaction: null,
        revision: 0,
        createdAt: 1,
        expiresAt: 2,
      }).success;
    expect(record('/ui/account')).toBe(true);
    expect(record('/ui/account/password')).toBe(true);
    expect(record('https://evil.example/')).toBe(false);
    expect(record('/ui/account/../login')).toBe(false);
  });

  it('finishes at the page on the realm’s origin, with the notice', () => {
    const realm = testRealm({
      id: '0199fa20-0000-7000-8000-00000000aaaa',
      issuer: 'https://id.example.com',
    });
    expect(accountPageUrl(realm, '/ui/account', 'passkey')).toBe(
      'https://id.example.com/ui/account?notice=passkey'
    );
    expect(accountPageUrl(realm, '/ui/account/password')).toBe(
      'https://id.example.com/ui/account/password'
    );
  });
});
