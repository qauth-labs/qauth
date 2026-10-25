import { describe, expect, it } from 'vitest';

import { SIGNER_OPERATIONS } from './signer';
import {
  isSignerCallAllowed,
  isSignerCaller,
  SIGNER_CALLERS,
  SIGNER_POLICY,
  type SignerCaller,
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
        'decrypt',
        'getVerificationKeys',
        'getJwks',
        'getUpstreamJwks',
      ],
      delivery: [
        'signJws:event_signing',
        'signWebhook',
        'decrypt',
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

  it('lets delivery decrypt but never encrypt: it reads secrets the api role stored', () => {
    expect(SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'decrypt'))).toEqual([
      'local',
      'api',
      'delivery',
    ]);
    expect(SIGNER_CALLERS.filter((caller) => isSignerCallAllowed(caller, 'encrypt'))).toEqual([
      'local',
      'api',
    ]);
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
