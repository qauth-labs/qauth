import { describe, expect, it } from 'vitest';

import { SIGNER_OPERATIONS } from './signer';
import {
  AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX,
  DELIVERY_SECRET_CONTEXT_PREFIX,
  isSignerCallAllowed,
  isSignerCaller,
  OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
  REALM_MAIL_SECRET_CONTEXT_PREFIX,
  SIGNER_CALLERS,
  SIGNER_POLICY,
  type SignerCaller,
  TOTP_SECRET_CONTEXT_PREFIX,
  UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
} from './signer-policy';
import { JWS_TYPS } from './signer-typ';

/** Every grant as `operation` or `signJws:<typ>`, for one role. */
function grantsOf(caller: SignerCaller): string[] {
  return SIGNER_OPERATIONS.flatMap((operation) =>
    operation === 'signJws'
      ? JWS_TYPS.filter((typ) => isSignerCallAllowed(caller, 'signJws', typ)).map(
          (typ) => `signJws:${typ}`
        )
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
        'signJws:at+jwt',
        'signJws:JWT',
        'signJws:oauth-id-jag+jwt',
        'signJws:logout+jwt',
        'signJws:secevent+jwt',
        'signHybrid',
        'signWebhook',
        'signClientAssertion',
        'signRequestObject',
        'getCookieSecrets',
        'encrypt',
        'decrypt',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      web: [
        'signRequestObject',
        'getCookieSecrets',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      api: [
        'signJws:at+jwt',
        'signJws:JWT',
        'signJws:oauth-id-jag+jwt',
        'signHybrid',
        'signClientAssertion',
        'encrypt',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      delivery: [
        'signJws:logout+jwt',
        'signJws:secevent+jwt',
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
    expect(grantsOf('local')).toHaveLength(SIGNER_OPERATIONS.length - 1 + JWS_TYPS.length);
  });

  it('lets web sign request objects and nothing else (#546)', () => {
    expect(grantsOf('web').filter((grant) => grant.startsWith('sign'))).toEqual([
      'signRequestObject',
    ]);
    expect(
      SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'signRequestObject'))
    ).toEqual(['local', 'web']);
  });

  it('lets web encrypt only an OID4VP response key, and api decrypt it (#546)', () => {
    // Pinned as a string: the auth server builds its contexts from it, and the
    // rows it seals name it.
    expect(OID4VP_RESPONSE_KEY_CONTEXT_PREFIX).toBe('oid4vp-response-key:');
    expect(SIGNER_POLICY.web.encrypt).toEqual([OID4VP_RESPONSE_KEY_CONTEXT_PREFIX]);
    expect(SIGNER_POLICY.web.decrypt).toBe(false);
    const context = 'oid4vp-response-key:ephemeral-kid';
    expect(isSignerCallAllowed('web', 'encrypt', context)).toBe(true);
    expect(isSignerCallAllowed('api', 'decrypt', context)).toBe(true);
    expect(isSignerCallAllowed('web', 'decrypt', context)).toBe(false);
    for (const other of [
      undefined,
      '',
      'oid4vp-response-keyx',
      'Oid4vp-response-key:x',
      'realm_secrets:mail.smtp.password',
      'delivery:ssf_streams.x:1',
      'upstream-oidc:client-secret:realm-1:oidc_corp',
      'auth-method-plugin:corp:@example/qauth-plugin-corp-sso:corp_sso:clientSecret',
    ]) {
      expect(isSignerCallAllowed('web', 'encrypt', other), String(other)).toBe(false);
    }
    for (const caller of ['delivery', 'admin'] as const) {
      expect(isSignerCallAllowed(caller, 'decrypt', context), caller).toBe(false);
      expect(isSignerCallAllowed(caller, 'encrypt', context), caller).toBe(false);
    }
    // A grant of `true` takes any context, or none.
    expect(isSignerCallAllowed('api', 'encrypt')).toBe(true);
    expect(isSignerCallAllowed('api', 'encrypt', context)).toBe(true);
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
    // Without a context, only a grant of `true` encrypts; web's is a list.
    expect(SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'encrypt'))).toEqual([
      'local',
      'api',
    ]);
  });

  it("lets api decrypt only a realm's mail secret, an upstream client secret, a plugin secret and an OID4VP response key (#529, #601, #600, #546)", () => {
    // Pinned as strings: server-realm-policy makes the mail contexts without
    // importing this library, and a changed prefix must fail here.
    expect(REALM_MAIL_SECRET_CONTEXT_PREFIX).toBe('realm_secrets:mail.');
    expect(UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX).toBe('upstream-oidc:client-secret:');
    expect(AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX).toBe('auth-method-plugin:');
    expect(TOTP_SECRET_CONTEXT_PREFIX).toBe('totp-secret:');
    expect(SIGNER_POLICY.api.decrypt).toEqual([
      REALM_MAIL_SECRET_CONTEXT_PREFIX,
      UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX,
      AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX,
      OID4VP_RESPONSE_KEY_CONTEXT_PREFIX,
      TOTP_SECRET_CONTEXT_PREFIX,
    ]);
    // The contexts `realmSecretContext` of server-realm-policy,
    // `upstreamClientSecretContext` of server-upstream-oidc and
    // `authMethodPluginSecretContext` of the auth server make.
    for (const context of [
      'realm_secrets:mail.smtp.password',
      'realm_secrets:mail.resend.apiKey',
      `upstream-oidc:client-secret:realm-1:oidc_corp:${'ab'.repeat(32)}`,
      'auth-method-plugin:corp:@example/qauth-plugin-corp-sso:corp_sso:clientSecret',
      'totp-secret:realm-1:user-1',
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
      'auth-method-pluginx:corp:clientSecret',
      'Auth-method-plugin:corp:clientSecret',
      'oid4vp_request_states.key:1',
      'totp-secretx:realm-1:user-1',
      'TOTP-secret:realm-1:user-1',
    ]) {
      expect(isSignerCallAllowed('api', 'decrypt', context), String(context)).toBe(false);
    }
    // Neither the browser-facing role nor delivery opens a provider's, a
    // plugin's or an account's TOTP secret, nor makes a TOTP ciphertext.
    for (const caller of ['web', 'delivery', 'admin'] as const) {
      expect(isSignerCallAllowed(caller, 'encrypt', 'totp-secret:realm-1:user-1'), caller).toBe(
        false
      );
      for (const context of [
        'upstream-oidc:client-secret:realm-1:oidc_corp',
        'auth-method-plugin:corp:@example/qauth-plugin-corp-sso:corp_sso:clientSecret',
        'totp-secret:realm-1:user-1',
      ]) {
        expect(isSignerCallAllowed(caller, 'decrypt', context), `${caller} ${context}`).toBe(false);
      }
    }
  });

  it("grants no role a decrypt prefix that is the start of another role's", () => {
    const granted = SIGNER_CALLERS.flatMap((caller) => {
      const { decrypt } = SIGNER_POLICY[caller];
      return Array.isArray(decrypt) ? decrypt.map((prefix: string) => ({ caller, prefix })) : [];
    });
    expect(granted.length).toBeGreaterThan(0);
    for (const one of granted) {
      expect(one.prefix, one.caller).not.toBe('');
      for (const other of granted) {
        if (other.caller === one.caller) continue;
        expect(
          other.prefix.startsWith(one.prefix),
          `${one.caller}'s ${one.prefix} starts ${other.caller}'s ${other.prefix}`
        ).toBe(false);
      }
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
      if (Array.isArray(grant.encrypt)) expect(Object.isFrozen(grant.encrypt)).toBe(true);
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
    // A purpose is not a type: no role is granted a key on its purpose alone
    // (#624). Delivery signs logout tokens with the token key, api none.
    expect(isSignerCallAllowed('local', 'signJws', 'token_signing')).toBe(false);
    expect(isSignerCallAllowed('delivery', 'signJws', 'token_signing')).toBe(false);
    expect(isSignerCallAllowed('delivery', 'signJws', 'logout+jwt')).toBe(true);
    expect(isSignerCallAllowed('api', 'signJws', 'logout+jwt')).toBe(false);
    expect(isSignerCallAllowed('delivery', 'signJws', 'JWT')).toBe(false);
    expect(isSignerCallAllowed('delivery', 'signJws', 'at+jwt')).toBe(false);
  });

  it('refuses an operation the table does not know', () => {
    expect(isSignerCallAllowed('local', 'exportKey' as never)).toBe(false);
    expect(isSignerCallAllowed('local', 'toString' as never)).toBe(false);
  });
});
