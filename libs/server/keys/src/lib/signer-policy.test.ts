import { describe, expect, it } from 'vitest';

import { SIGNER_OPERATIONS } from './signer';
import {
  DELIVERY_SECRET_CONTEXT_PREFIX,
  isSignerCallAllowed,
  isSignerCaller,
  REALM_MAIL_SECRET_CONTEXT_PREFIX,
  SIGNER_CALLERS,
  SIGNER_POLICY,
  type SignerCaller,
  UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
} from './signer-policy';
import { JWS_SIGNING_PURPOSES } from './signer-typ';

/** Every grant as `operation` or `signJws:<purpose>`, for one role. */
function grantsOf(caller: SignerCaller): string[] {
  return SIGNER_OPERATIONS.flatMap((operation) =>
    operation === 'signJws'
      ? JWS_SIGNING_PURPOSES.filter((purpose) =>
          isSignerCallAllowed(caller, 'signJws', purpose)
        ).map((purpose) => `signJws:${purpose}`)
      : isSignerCallAllowed(caller, operation)
        ? [operation]
        : []
  );
}

describe('SIGNER_POLICY', () => {
  it('has one grant per role and nothing else', () => {
    expect(Object.keys(SIGNER_POLICY).sort()).toEqual([...SIGNER_CALLERS].sort());
  });

  it('pins what each role may call', () => {
    expect(Object.fromEntries(SIGNER_CALLERS.map((caller) => [caller, grantsOf(caller)]))).toEqual({
      local: [
        'signJws:token_signing',
        'signJws:event_signing',
        'signHybrid',
        'signWebhook',
        'signClientAssertion',
        'getCookieSecrets',
        'encrypt',
        'decrypt',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      web: ['getCookieSecrets', 'getVerificationKeys', 'getJwks', 'getUpstreamJwks'],
      api: [
        'signJws:token_signing',
        'signHybrid',
        'signClientAssertion',
        'encrypt',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      delivery: [
        'signJws:event_signing',
        'signWebhook',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      admin: ['getVerificationKeys', 'getJwks', 'getUpstreamJwks'],
    });
  });

  it('lets delivery sign webhooks and api sign client assertions, and no other role but local', () => {
    expect(SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'signWebhook'))).toEqual([
      'local',
      'delivery',
    ]);
    expect(
      SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'signClientAssertion'))
    ).toEqual(['local', 'api']);
  });

  it('lets local call every operation', () => {
    expect(grantsOf('local')).toHaveLength(
      SIGNER_OPERATIONS.length - 1 + JWS_SIGNING_PURPOSES.length
    );
  });

  it('never lets web sign', () => {
    expect(grantsOf('web').filter((grant) => grant.startsWith('sign'))).toEqual([]);
  });

  it('lets delivery decrypt only a delivery destination secret, and never encrypt', () => {
    expect(SIGNER_POLICY.delivery.decrypt).toEqual([DELIVERY_SECRET_CONTEXT_PREFIX]);
    expect(isSignerCallAllowed('delivery', 'decrypt', 'delivery:ssf_streams.x:1')).toBe(true);
    for (const context of [
      undefined,
      '',
      'oid4vp_request_states.key:1',
      'Delivery:x',
      'xdelivery:',
    ]) {
      expect(isSignerCallAllowed('delivery', 'decrypt', context), String(context)).toBe(false);
    }
    // A grant of `true` takes any context, or none.
    expect(isSignerCallAllowed('local', 'decrypt')).toBe(true);
    expect(isSignerCallAllowed('local', 'decrypt', 'anything')).toBe(true);
    expect(SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'encrypt'))).toEqual([
      'local',
      'api',
    ]);
  });

  it("lets api decrypt only a realm's mail secret and an upstream client secret (#529, #601)", () => {
    // Pinned as strings: server-realm-policy makes the mail contexts without
    // importing this library, and a changed prefix must fail here.
    expect(REALM_MAIL_SECRET_CONTEXT_PREFIX).toBe('realm_secrets:mail.');
    expect(UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX).toBe('upstream-oidc:client-secret:');
    expect(SIGNER_POLICY.api.decrypt).toEqual([
      REALM_MAIL_SECRET_CONTEXT_PREFIX,
      UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
    ]);
    // The contexts `realmSecretContext` of server-realm-policy and
    // `upstreamClientSecretContext` of server-upstream-oidc make.
    for (const context of [
      'realm_secrets:mail.smtp.password',
      'realm_secrets:mail.resend.apiKey',
      `upstream-oidc:client-secret:realm-1:oidc_corp:${'ab'.repeat(32)}`,
    ]) {
      expect(isSignerCallAllowed('api', 'decrypt', context), context).toBe(true);
    }
    for (const context of [
      undefined,
      '',
      'delivery:ssf_streams.x:1',
      'delivery:upstream-oidc:client-secret:realm-1:oidc_corp',
      'realm_secrets:admin.x',
      'realm_secrets:mailx',
      'upstream-oidc:client-secretx',
      'upstream-oidc:other:realm-1',
      'Upstream-oidc:client-secret:realm-1:oidc_corp',
      'oid4vp_request_states.key:1',
    ]) {
      expect(isSignerCallAllowed('api', 'decrypt', context), String(context)).toBe(false);
    }
    // Neither the browser-facing role nor delivery opens a provider's secret.
    for (const caller of ['web', 'delivery', 'admin'] as const) {
      expect(
        isSignerCallAllowed(caller, 'decrypt', 'upstream-oidc:client-secret:realm-1:oidc_corp'),
        caller
      ).toBe(false);
    }
  });

  it('gives the cookie secrets to web and local only', () => {
    expect(
      SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'getCookieSecrets'))
    ).toEqual(['local', 'web']);
  });

  it('is frozen', () => {
    expect(Object.isFrozen(SIGNER_POLICY)).toBe(true);
    for (const grant of Object.values(SIGNER_POLICY)) {
      expect(Object.isFrozen(grant)).toBe(true);
      expect(Object.isFrozen(grant.signJws)).toBe(true);
      if (Array.isArray(grant.decrypt)) expect(Object.isFrozen(grant.decrypt)).toBe(true);
    }
  });
});

describe('isSignerCallAllowed', () => {
  it.each(['signer', 'LOCAL', '', undefined, null, 1, { caller: 'local' }])(
    'refuses the unknown role %o',
    (caller) => {
      expect(isSignerCaller(caller)).toBe(false);
      for (const operation of SIGNER_OPERATIONS) {
        expect(isSignerCallAllowed(caller, operation, 'token_signing')).toBe(false);
      }
    }
  );

  it('refuses signJws without a purpose, or with one outside the grant', () => {
    expect(isSignerCallAllowed('local', 'signJws')).toBe(false);
    expect(isSignerCallAllowed('local', 'signJws', 'cookie_hmac')).toBe(false);
    expect(isSignerCallAllowed('api', 'signJws', 'event_signing')).toBe(false);
  });

  it('refuses an operation the table does not know', () => {
    expect(isSignerCallAllowed('local', 'exportKey' as never)).toBe(false);
    expect(isSignerCallAllowed('local', 'toString' as never)).toBe(false);
  });
});
