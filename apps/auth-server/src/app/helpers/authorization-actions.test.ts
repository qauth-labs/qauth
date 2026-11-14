import { describe, expect, it } from 'vitest';

import { actionRefusal, actionRoundOf, asksForSetUp } from './authorization-actions';

/**
 * The set-ups an authorization request may ask for (#1108; ADR-020 §1):
 * `qauth_action=setup_passkey`, refused before any page unless it can run,
 * and a fresh sign-in that binds a passkey when it can.
 */
describe('qauth_action (#1108)', () => {
  const SET_UP = { qauth_action: 'setup_passkey' } as const;
  const ACCOUNT_CLIENT = { listsAccountAudience: true };
  const OTHER_CLIENT = { listsAccountAudience: false };

  it('lets a request that asks for no set-up through, whatever the client and the switches', () => {
    expect(actionRefusal({}, OTHER_CLIENT, false)).toBeNull();
    expect(
      actionRefusal({ prompt: 'create', qauth_link: 'oidc_corp' }, OTHER_CLIENT, false)
    ).toBeNull();
  });

  it('lets a client that lists the account API ask for one while it is offered', () => {
    expect(actionRefusal(SET_UP, ACCOUNT_CLIENT, true)).toBeNull();
    expect(actionRefusal({ ...SET_UP, prompt: 'login' }, ACCOUNT_CLIENT, true)).toBeNull();
  });

  it('refuses a client whose audience does not list the account API with unauthorized_client', () => {
    expect(actionRefusal(SET_UP, OTHER_CLIENT, true)).toMatchObject({
      error: 'unauthorized_client',
      reason: 'action_not_allowed_for_client',
    });
  });

  it('refuses a set-up the server does not offer with invalid_request', () => {
    expect(actionRefusal(SET_UP, ACCOUNT_CLIENT, false)).toMatchObject({
      error: 'invalid_request',
      reason: 'action_not_offered',
    });
  });

  it('refuses one beside prompt=create or qauth_link first, whatever the client', () => {
    expect(actionRefusal({ ...SET_UP, prompt: 'create' }, OTHER_CLIENT, false)).toMatchObject({
      error: 'invalid_request',
      reason: 'action_with_prompt_create',
    });
    expect(
      actionRefusal({ ...SET_UP, qauth_link: 'oidc_corp' }, OTHER_CLIENT, false)
    ).toMatchObject({
      error: 'invalid_request',
      reason: 'action_with_link',
    });
  });

  it('asks every round of a set-up for a fresh sign-in that binds a passkey, and nothing of another', () => {
    expect(asksForSetUp(SET_UP)).toBe(true);
    expect(asksForSetUp({})).toBe(false);
    expect(asksForSetUp(undefined)).toBe(false);
    expect(actionRoundOf(SET_UP)).toEqual({ freshSignIn: true, enrol: 'passkey' });
    expect(actionRoundOf({})).toEqual({});
    expect(actionRoundOf(undefined)).toEqual({});
  });
});
