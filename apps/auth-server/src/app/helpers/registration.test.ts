import { afterEach, describe, expect, it, vi } from 'vitest';

const { mockEnv } = vi.hoisted(() => ({ mockEnv: { INTERACTION_UI_ENABLED: true } }));
vi.mock('../../config/env', () => ({ env: mockEnv }));

import { createPromptRefusal, realmOffersRegistration, registrationAllowed } from './registration';

/** Who may register (#640; ADR-017 Decisions 3 and 8): the realm and the client, both. */

const OPEN_REALM = { registrationAllowed: true };
const CLOSED_REALM = { registrationAllowed: false };
const CLIENT = { enabled: true, hostedFlows: ['register'] };
const QUERY = { scope: 'openid email' };

afterEach(() => {
  mockEnv.INTERACTION_UI_ENABLED = true;
});

describe('realmOffersRegistration', () => {
  it("follows the realm's registration_allowed while the Interaction API is on", () => {
    expect(realmOffersRegistration(OPEN_REALM)).toBe(true);
    expect(realmOffersRegistration(CLOSED_REALM)).toBe(false);
  });

  it('offers nothing while the Interaction API is off', () => {
    mockEnv.INTERACTION_UI_ENABLED = false;
    expect(realmOffersRegistration(OPEN_REALM)).toBe(false);
  });
});

describe('registrationAllowed', () => {
  it('needs the realm and the client both', () => {
    expect(registrationAllowed(OPEN_REALM, CLIENT)).toBe(true);
    expect(registrationAllowed(CLOSED_REALM, CLIENT)).toBe(false);
    expect(registrationAllowed(OPEN_REALM, { ...CLIENT, hostedFlows: null })).toBe(false);
  });

  it('allows nothing for no client, a disabled client or a flow list that is not well formed', () => {
    expect(registrationAllowed(OPEN_REALM, null)).toBe(false);
    expect(registrationAllowed(OPEN_REALM, undefined)).toBe(false);
    expect(registrationAllowed(OPEN_REALM, { ...CLIENT, enabled: false })).toBe(false);
    expect(registrationAllowed(OPEN_REALM, { ...CLIENT, hostedFlows: 'register' })).toBe(false);
    expect(registrationAllowed(OPEN_REALM, { ...CLIENT, hostedFlows: [1] })).toBe(false);
  });
});

describe('createPromptRefusal', () => {
  it('starts a registration for an openid request the realm and the client allow', () => {
    expect(createPromptRefusal(OPEN_REALM, CLIENT, QUERY)).toBeNull();
  });

  it('refuses without openid first, whatever else holds', () => {
    for (const scope of [undefined, 'email', 'openidx email']) {
      expect(createPromptRefusal(CLOSED_REALM, {}, { scope })).toMatchObject({
        error: 'invalid_request',
        reason: 'create_without_openid',
      });
    }
  });

  it('refuses a realm that offers no sign-up with invalid_request, an unsupported value', () => {
    expect(createPromptRefusal(CLOSED_REALM, CLIENT, QUERY)).toMatchObject({
      error: 'invalid_request',
      reason: 'registration_not_offered',
    });
  });

  it('refuses a client whose flow list does not name register with unauthorized_client', () => {
    expect(createPromptRefusal(OPEN_REALM, { enabled: true }, QUERY)).toMatchObject({
      error: 'unauthorized_client',
      reason: 'registration_not_allowed_for_client',
    });
  });

  it('refuses max_age, which asks for a sign-in a registration never is', () => {
    expect(createPromptRefusal(OPEN_REALM, CLIENT, { ...QUERY, max_age: 0 })).toMatchObject({
      error: 'invalid_request',
      reason: 'create_with_max_age',
    });
  });
});
