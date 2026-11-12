import { defaultsFromEnv, realmSecretPaths } from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import {
  ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS,
  dynamicRegistrationScopesOf,
  POLICIES_READ_FROM_REALM_ROW,
  tokenLifetimesOf,
  withClientTokenLifetimes,
} from './realm-policy-readers';

/** A policy document's value at a dotted path, or `undefined`. */
function valueAt(document: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (node, segment) =>
        typeof node === 'object' && node !== null
          ? (node as Record<string, unknown>)[segment]
          : undefined,
      document
    );
}

describe('POLICIES_READ_FROM_REALM_ROW (#516)', () => {
  it('names fields of the realm policy document, none of them secret', () => {
    const document = defaultsFromEnv({});
    for (const path of POLICIES_READ_FROM_REALM_ROW) {
      expect(valueAt(document, path), path).not.toBeUndefined();
      expect(realmSecretPaths(), path).not.toContain(path);
    }
  });

  it('holds the two policies the server read from the row before #516, the token lifetimes (#527), the account policies (#528), the mail transport and sender (#529), CIMD (#534), the minimum password length (#634) and the bot challenge (#643)', () => {
    expect([...POLICIES_READ_FROM_REALM_ROW].sort()).toEqual([
      'accounts.requireVerifiedAccount',
      'botChallenge.difficulty',
      'botChallenge.requiredAtSignUp',
      'bruteForce.enabled',
      'bruteForce.lockoutSeconds',
      'bruteForce.maxAttempts',
      'bruteForce.windowSeconds',
      'mail.fromAddress',
      'mail.fromName',
      'mail.provider',
      'mail.smtp.host',
      'mail.smtp.port',
      'mail.smtp.secure',
      'mail.smtp.user',
      'password.minLength',
      'password.minScore',
      'posture.maxEnvironmentLaxity',
      'registration.cimd.enabled',
      'registration.cimd.trustPolicy',
      'registration.cimd.trustedDomains',
      'registration.dynamicRegistrationAllowedScopes',
      'tokens.accessTokenLifespanSeconds',
      'tokens.adminAccessTokenLifespanSeconds',
      'tokens.developmentAccessTokenLifespanSeconds',
      'tokens.refreshTokenLifespanSeconds',
    ]);
  });
});

describe('dynamicRegistrationScopesOf (#516)', () => {
  const FILL = Object.freeze(['openid', 'profile']);
  const policies = () => ({
    ofRealm: vi.fn(
      () =>
        ({
          policies: { registration: { dynamicRegistrationAllowedScopes: FILL } },
        }) as never
    ),
  });

  it("reads the row's list of a realm that has its policies, even an empty one", () => {
    const store = policies();
    const realm = testRealm({ id: 'r', dynamicRegistrationAllowedScopes: [], policiesVersion: 4 });

    expect(dynamicRegistrationScopesOf(store, realm)).toEqual([]);
    expect(store.ofRealm).not.toHaveBeenCalled();
  });

  it('reads the list of the fill of a realm with no policies yet, as a copy', () => {
    const store = policies();
    const realm = testRealm({ id: 'r', dynamicRegistrationAllowedScopes: [], policiesVersion: 0 });

    const scopes = dynamicRegistrationScopesOf(store, realm);

    expect(scopes).toEqual(FILL);
    expect(store.ofRealm).toHaveBeenCalledWith(realm);
    scopes.push('email');
    expect(FILL).toEqual(['openid', 'profile']);
  });
});

describe('tokenLifetimesOf (#527)', () => {
  /** A store whose snapshot holds `tokens`, and a JWT plugin configured with 900 s and a week. */
  function sources(tokens: Record<string, number>) {
    return {
      policyStore: { ofRealm: vi.fn(() => ({ policies: { tokens } }) as never) },
      jwtUtils: {
        getAccessTokenLifespan: vi.fn(() => 900),
        getRefreshTokenLifespan: vi.fn(() => 604_800),
      },
    };
  }
  const STORED = {
    accessTokenLifespanSeconds: 300,
    developmentAccessTokenLifespanSeconds: 7_200,
    refreshTokenLifespanSeconds: 86_400,
    adminAccessTokenLifespanSeconds: 600,
  };

  it('reads the four lifetimes from the policies of a realm that has them, from the row it is given', () => {
    const from = sources(STORED);
    const realm = testRealm({ id: 'r', policiesVersion: 3 });

    expect(tokenLifetimesOf(from, realm)).toEqual({
      accessTokenLifespanSeconds: 300,
      developmentAccessTokenLifespanSeconds: 7_200,
      refreshTokenLifespanSeconds: 86_400,
      adminAccessTokenLifespanSeconds: 600,
    });
    expect(from.policyStore.ofRealm).toHaveBeenCalledWith(realm);
    // The plugin's lifespans are only the fallback of a realm with no policies.
    expect(from.jwtUtils.getAccessTokenLifespan).not.toHaveBeenCalled();
    expect(from.jwtUtils.getRefreshTokenLifespan).not.toHaveBeenCalled();
  });

  it("reads a realm's own lifetimes, so two realms differ", () => {
    const short = tokenLifetimesOf(sources(STORED), testRealm({ id: 'a', policiesVersion: 1 }));
    const long = tokenLifetimesOf(
      sources({ ...STORED, accessTokenLifespanSeconds: 1_800 }),
      testRealm({ id: 'b', policiesVersion: 1 })
    );

    expect(short.accessTokenLifespanSeconds).toBe(300);
    expect(long.accessTokenLifespanSeconds).toBe(1_800);
  });

  it("runs a realm with no policies yet on the JWT plugin's lifespans and the development and admin lifetimes of its fill", () => {
    const from = sources(STORED);
    const realm = testRealm({ id: 'r', policiesVersion: 0 });

    expect(tokenLifetimesOf(from, realm)).toEqual({
      accessTokenLifespanSeconds: 900,
      developmentAccessTokenLifespanSeconds: 7_200,
      refreshTokenLifespanSeconds: 604_800,
      adminAccessTokenLifespanSeconds: 600,
    });
  });

  it('never lets an admin token live longer than 900 seconds, whatever the policy holds (#520)', () => {
    for (const policiesVersion of [0, 1]) {
      const lifetimes = tokenLifetimesOf(
        sources({ ...STORED, adminAccessTokenLifespanSeconds: 86_400 }),
        testRealm({ id: 'r', policiesVersion })
      );
      expect(lifetimes.adminAccessTokenLifespanSeconds).toBe(
        ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS
      );
    }
    expect(ADMIN_ACCESS_TOKEN_MAX_LIFESPAN_SECONDS).toBe(900);
  });

  it('hands out a frozen object', () => {
    const lifetimes = tokenLifetimesOf(sources(STORED), testRealm({ id: 'r', policiesVersion: 2 }));

    expect(Object.isFrozen(lifetimes)).toBe(true);
  });

  it('lets a store refusal of invalid stored policies through, rather than guess a lifetime', () => {
    const from = sources(STORED);
    from.policyStore.ofRealm.mockImplementation(() => {
      throw new Error('The stored policies are not valid');
    });

    expect(() => tokenLifetimesOf(from, testRealm({ id: 'r', policiesVersion: 2 }))).toThrow(
      'The stored policies are not valid'
    );
  });
});

describe('withClientTokenLifetimes (#632)', () => {
  const realm = Object.freeze({
    accessTokenLifespanSeconds: 900,
    developmentAccessTokenLifespanSeconds: 3600,
    refreshTokenLifespanSeconds: 604800,
    adminAccessTokenLifespanSeconds: 600,
  });

  it("keeps the realm's lifetimes for a client that sets none", () => {
    expect(
      withClientTokenLifetimes(realm, {
        accessTokenLifespanSeconds: null,
        refreshTokenLifespanSeconds: null,
      })
    ).toBe(realm);
  });

  it("caps every access tier, the admin one too, and the refresh lifetime, by the client's own", () => {
    expect(
      withClientTokenLifetimes(realm, {
        accessTokenLifespanSeconds: 300,
        refreshTokenLifespanSeconds: 86400,
      })
    ).toEqual({
      accessTokenLifespanSeconds: 300,
      developmentAccessTokenLifespanSeconds: 300,
      refreshTokenLifespanSeconds: 86400,
      adminAccessTokenLifespanSeconds: 300,
    });
  });

  it("never lengthens one: the realm's wins when it is the shorter", () => {
    expect(
      withClientTokenLifetimes(realm, {
        accessTokenLifespanSeconds: 1200,
        refreshTokenLifespanSeconds: null,
      })
    ).toEqual({ ...realm, developmentAccessTokenLifespanSeconds: 1200 });
  });
});

