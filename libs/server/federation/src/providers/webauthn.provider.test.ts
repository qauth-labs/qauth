import { describe, expect, it } from 'vitest';

import { createInMemoryChallengeStore } from '../../testing/webauthn-challenge-store.fixture';
import {
  hexToBase64Url,
  W3C_VECTOR_ORIGIN,
  W3C_VECTOR_RP_ID,
  W3C_WEBAUTHN_VECTORS,
  w3cAuthenticationResponse,
  w3cRegistrationResponse,
  type W3cWebAuthnVector,
} from '../../testing/webauthn-w3c-vectors.fixture';
import { createSimpleWebAuthnVerifier } from '../webauthn/simplewebauthn-verifier';
import type { WebAuthnPurpose } from '../webauthn/webauthn.types';
import { WebAuthnRejection, type WebAuthnRejectionReason } from '../webauthn/webauthn-rejection';
import { createProviderRegistry } from './provider-registry';
import {
  createWebAuthnProvider,
  signCounterRegressed,
  WEBAUTHN_CEREMONY_TIMEOUT_MS,
  WEBAUTHN_PROVIDER_TYPE,
  webauthnCredentialDataAfterAssertion,
  type WebAuthnEnrolment,
  type WebAuthnRawClaims,
} from './webauthn.provider';
import { normalisePasskeyNickname, type WebAuthnCredentialData } from './webauthn-credential-data';

/**
 * The WebAuthn provider (issue #467) end to end over the WebAuthn Level 3 §16
 * vectors: options, a registration, an assertion, and the rules the provider
 * owns above the library: single-use challenges bound to their transaction, the
 * user-verification rule of sign-in, and the sign counter flag.
 *
 * The vectors fix their challenges, so the provider's random source is made to
 * return the vector's challenge bytes, in order.
 */

const USER_HANDLE = Buffer.from('user-handle-of-ada').toString('base64url');
const START = Date.UTC(2026, 9, 22, 12);

function setup(challengesHex: string[] = []) {
  const queue = [...challengesHex];
  let clock = START;
  const challenges = createInMemoryChallengeStore();
  const provider = createWebAuthnProvider({
    verifier: createSimpleWebAuthnVerifier(),
    challenges,
    now: () => clock,
    randomBytes: (size) => {
      const next = queue.shift();
      if (next === undefined) return new Uint8Array(size).fill(7);
      return Buffer.from(next, 'hex');
    },
  });
  return {
    provider,
    challenges,
    advance(ms: number) {
      clock += ms;
    },
  };
}

type Setup = ReturnType<typeof setup>;

async function enrol(
  { provider }: Setup,
  vector: W3cWebAuthnVector,
  purpose: WebAuthnPurpose,
  transactionId = 'enrol-1'
): Promise<WebAuthnEnrolment> {
  await provider.startRegistration({
    transactionId,
    purpose,
    rp: { id: W3C_VECTOR_RP_ID, name: 'Example' },
    origins: [W3C_VECTOR_ORIGIN],
    user: { handle: USER_HANDLE, name: 'ada@example.org', displayName: 'Ada' },
  });
  return provider.finishRegistration({
    transactionId,
    response: w3cRegistrationResponse(vector),
    nickname: 'Laptop',
  });
}

async function startSignIn(
  { provider }: Setup,
  vector: W3cWebAuthnVector,
  purpose: WebAuthnPurpose,
  transactionId = 'login-1',
  rpId = W3C_VECTOR_RP_ID
) {
  return provider.startAuthentication({
    transactionId,
    purpose,
    rpId,
    origins: [W3C_VECTOR_ORIGIN],
    allowCredentials: [{ id: hexToBase64Url(vector.credentialId) }],
  });
}

function verifyInput(
  vector: W3cWebAuthnVector,
  enrolment: WebAuthnEnrolment,
  transactionId = 'login-1',
  credentialData: WebAuthnCredentialData = enrolment.credentialData
) {
  return {
    transactionId,
    response: w3cAuthenticationResponse(vector),
    credential: { externalSub: enrolment.externalSub, credentialData },
  };
}

async function rejectionOf(promise: Promise<unknown>): Promise<WebAuthnRejectionReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught
  );
  expect(error).toBeInstanceOf(WebAuthnRejection);
  return (error as WebAuthnRejection).reason;
}

describe('createWebAuthnProvider', () => {
  it('registers in the provider registry under "webauthn"', () => {
    const { provider } = setup();
    const registry = createProviderRegistry([provider]);
    expect(provider.type).toBe(WEBAUTHN_PROVIDER_TYPE);
    expect(registry.resolve('webauthn')).toBe(provider);
  });

  describe('options', () => {
    it('asks for attestation "none", EdDSA, ES256 and RS256, and a verified discoverable passkey for sign-in', async () => {
      const { provider, challenges } = setup();
      const options = await provider.startRegistration({
        transactionId: 'tx',
        purpose: 'sign-in',
        rp: { id: 'auth.example.com', name: 'Example' },
        origins: ['https://auth.example.com'],
        user: { handle: USER_HANDLE, name: 'ada@example.com', displayName: 'Ada' },
        excludeCredentials: [{ id: 'AAAA', transports: ['internal'] }],
      });

      expect(options).toMatchObject({
        rp: { id: 'auth.example.com', name: 'Example' },
        user: { id: USER_HANDLE, name: 'ada@example.com', displayName: 'Ada' },
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: WEBAUTHN_CEREMONY_TIMEOUT_MS,
        excludeCredentials: [{ type: 'public-key', id: 'AAAA', transports: ['internal'] }],
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        },
        attestation: 'none',
      });
      expect(Buffer.from(options.challenge, 'base64url')).toHaveLength(32);
      expect(challenges.pending()).toEqual(['tx']);
    });

    it('prefers but does not require user verification for a second factor', async () => {
      const { provider } = setup();
      const registration = await provider.startRegistration({
        transactionId: 'tx-reg',
        purpose: 'second-factor',
        rp: { id: 'auth.example.com', name: 'Example' },
        origins: ['https://auth.example.com'],
        user: { handle: USER_HANDLE, name: 'ada', displayName: 'Ada' },
      });
      expect(registration.authenticatorSelection).toEqual({
        residentKey: 'discouraged',
        requireResidentKey: false,
        userVerification: 'preferred',
      });

      const authentication = await provider.startAuthentication({
        transactionId: 'tx-auth',
        purpose: 'second-factor',
        rpId: 'auth.example.com',
        origins: ['https://auth.example.com'],
        allowCredentials: [{ id: 'AAAA' }],
      });
      expect(authentication).toMatchObject({
        rpId: 'auth.example.com',
        userVerification: 'preferred',
      });
    });

    it('requires user verification for sign-in, and allows a passkey-first sign-in with no account named', async () => {
      const { provider } = setup();
      const options = await provider.startAuthentication({
        transactionId: 'tx',
        purpose: 'sign-in',
        rpId: 'auth.example.com',
        origins: ['https://auth.example.com'],
      });
      expect(options).toMatchObject({ userVerification: 'required', allowCredentials: [] });
    });

    it('refuses a second factor with no credential to allow', async () => {
      const { provider } = setup();
      await expect(
        provider.startAuthentication({
          transactionId: 'tx',
          purpose: 'second-factor',
          rpId: 'auth.example.com',
          origins: ['https://auth.example.com'],
        })
      ).rejects.toThrow("needs the account's credentials");
    });

    it('refuses an origin the RP ID does not cover, and accepts an Android app origin', async () => {
      const { provider } = setup();
      await expect(
        provider.startAuthentication({
          transactionId: 'tx-1',
          purpose: 'sign-in',
          rpId: 'auth.example.com',
          origins: ['https://app.example.com'],
        })
      ).rejects.toThrow('cannot run a ceremony for the RP ID "auth.example.com"');

      await expect(
        provider.startAuthentication({
          transactionId: 'tx-2',
          purpose: 'sign-in',
          rpId: 'auth.example.com',
          origins: [
            'https://auth.example.com',
            'android:apk-key-hash:sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE',
          ],
        })
      ).resolves.toBeDefined();
    });

    it('refuses a second ceremony on a transaction that has one waiting', async () => {
      const { provider } = setup();
      const start = () =>
        provider.startAuthentication({
          transactionId: 'tx',
          purpose: 'sign-in',
          rpId: 'auth.example.com',
          origins: ['https://auth.example.com'],
        });
      await start();
      await expect(start()).rejects.toThrow('already has a ceremony waiting');
    });
  });

  describe('registration and assertion over the recorded vectors', () => {
    it.each([
      ['ES256', 'packedEs256', 'sign-in', -7],
      ['RS256', 'packedRs256', 'second-factor', -257],
      ['EdDSA', 'packedEd25519', 'second-factor', -8],
    ] as const)(
      'enrols and then verifies an %s passkey (%s, %s)',
      async (_name, vectorName, purpose, algorithm) => {
        const vector = W3C_WEBAUTHN_VECTORS[vectorName];
        const context = setup([vector.registration.challenge, vector.authentication.challenge]);

        const enrolment = await enrol(context, vector, purpose);
        expect(enrolment).toMatchObject({
          externalSub: hexToBase64Url(vector.credentialId),
          rpId: W3C_VECTOR_RP_ID,
          purpose,
          attestationFormat: 'packed',
          credentialData: {
            algorithm,
            sign_count: 0,
            transports: ['internal'],
            rp_id: W3C_VECTOR_RP_ID,
            user_handle: USER_HANDLE,
            nickname: 'Laptop',
            created_at: START,
            last_used_at: null,
            sign_counter_regressed_at: null,
          },
        });

        await startSignIn(context, vector, purpose);
        const identity = await context.provider.verify(verifyInput(vector, enrolment));

        expect(identity).toEqual({
          externalSub: hexToBase64Url(vector.credentialId),
          assuranceLevel: 'low',
          rawClaims: expect.objectContaining({
            credential_id: hexToBase64Url(vector.credentialId),
            rp_id: W3C_VECTOR_RP_ID,
            origin: W3C_VECTOR_ORIGIN,
            purpose,
            sign_count: 0,
            sign_counter_regressed: false,
          }),
        });
        expect(context.provider.extractAttributes(identity)).toEqual([]);
      }
    );

    it('stores the backup flags of the registration', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedRs256;
      const enrolment = await enrol(
        setup([vector.registration.challenge]),
        vector,
        'second-factor'
      );
      expect(enrolment.credentialData).toMatchObject({ backup_eligible: true, backed_up: true });
    });
  });

  describe('the challenge', () => {
    it('is single use: a replayed assertion is refused', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');

      await expect(context.provider.verify(verifyInput(vector, enrolment))).resolves.toBeDefined();
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'challenge-unavailable'
      );
    });

    it('is burned by a failed answer too', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');

      const tampered = verifyInput(vector, enrolment);
      tampered.response.response.signature = hexToBase64Url('3045' + '00'.repeat(69));
      expect(await rejectionOf(context.provider.verify(tampered))).toBe('signature-invalid');
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'challenge-unavailable'
      );
    });

    it('is bound to its transaction: an answer under another transaction is refused', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      // The second transaction gets a different challenge.
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in', 'login-a');
      await startSignIn(context, vector, 'sign-in', 'login-b');

      expect(
        await rejectionOf(context.provider.verify(verifyInput(vector, enrolment, 'login-b')))
      ).toBe('challenge-mismatch');
      await expect(
        context.provider.verify(verifyInput(vector, enrolment, 'login-a'))
      ).resolves.toBeDefined();
    });

    it('expires with the ceremony timeout', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');
      context.advance(WEBAUTHN_CEREMONY_TIMEOUT_MS);

      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'challenge-unavailable'
      );
    });

    it('refuses an assertion answering a registration transaction', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await context.provider.startRegistration({
        transactionId: 'login-1',
        purpose: 'sign-in',
        rp: { id: W3C_VECTOR_RP_ID, name: 'Example' },
        origins: [W3C_VECTOR_ORIGIN],
        user: { handle: USER_HANDLE, name: 'ada', displayName: 'Ada' },
      });
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'ceremony-mismatch'
      );
    });
  });

  describe('refusals the acceptance criteria name', () => {
    it('refuses a wrong origin', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await context.provider.startAuthentication({
        transactionId: 'login-1',
        purpose: 'sign-in',
        rpId: W3C_VECTOR_RP_ID,
        origins: ['https://login.example.org'],
        allowCredentials: [{ id: enrolment.externalSub }],
      });
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'origin-mismatch'
      );
    });

    it('refuses a wrong RP ID hash', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      // `org` covers the vector's origin, so the ceremony starts; the vector was
      // signed for `example.org`, so its RP ID hash is not SHA-256("org").
      await startSignIn(context, vector, 'sign-in', 'login-1', 'org');
      expect(
        await rejectionOf(
          context.provider.verify(
            verifyInput(vector, enrolment, 'login-1', { ...enrolment.credentialData, rp_id: 'org' })
          )
        )
      ).toBe('rp-id-mismatch');
    });

    it('refuses a credential created under another RP ID before checking anything else', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');
      expect(
        await rejectionOf(
          context.provider.verify(
            verifyInput(vector, enrolment, 'login-1', {
              ...enrolment.credentialData,
              rp_id: 'other.example.org',
            })
          )
        )
      ).toBe('rp-id-mismatch');
    });

    it.each(['packedRs256', 'packedEd25519'] as const)(
      'refuses a sign-in whose assertion lacks the UV flag (%s)',
      async (vectorName) => {
        const vector = W3C_WEBAUTHN_VECTORS[vectorName];
        const context = setup([vector.registration.challenge, vector.authentication.challenge]);
        const enrolment = await enrol(context, vector, 'second-factor');
        await startSignIn(context, vector, 'sign-in');
        expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
          'user-not-verified'
        );
      }
    );

    it('refuses a sign-in enrolment whose registration lacks the UV flag', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEd25519;
      const context = setup([vector.registration.challenge]);
      expect(await rejectionOf(enrol(context, vector, 'sign-in'))).toBe('user-not-verified');
    });

    it('refuses a credential the transaction does not allow', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await context.provider.startAuthentication({
        transactionId: 'login-1',
        purpose: 'sign-in',
        rpId: W3C_VECTOR_RP_ID,
        origins: [W3C_VECTOR_ORIGIN],
        allowCredentials: [{ id: 'c29tZS1vdGhlci1jcmVkZW50aWFs' }],
      });
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'credential-mismatch'
      );
    });

    it('refuses a passkey-first sign-in whose answer carries no user handle', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await context.provider.startAuthentication({
        transactionId: 'login-1',
        purpose: 'sign-in',
        rpId: W3C_VECTOR_RP_ID,
        origins: [W3C_VECTOR_ORIGIN],
      });
      expect(await rejectionOf(context.provider.verify(verifyInput(vector, enrolment)))).toBe(
        'user-handle-mismatch'
      );
    });

    it('refuses a credential whose backup eligibility changed since registration', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');
      expect(
        await rejectionOf(
          context.provider.verify(
            verifyInput(vector, enrolment, 'login-1', {
              ...enrolment.credentialData,
              backup_eligible: false,
            })
          )
        )
      ).toBe('backup-eligibility-changed');
    });
  });

  describe('the sign counter', () => {
    it('flags a counter that goes backwards, and still answers who it is', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');
      await startSignIn(context, vector, 'sign-in');
      const stored = { ...enrolment.credentialData, sign_count: 7 };

      const identity = await context.provider.verify(
        verifyInput(vector, enrolment, 'login-1', stored)
      );

      const claims = identity.rawClaims as WebAuthnRawClaims;
      expect(claims).toMatchObject({ sign_count: 0, sign_counter_regressed: true });
      expect(webauthnCredentialDataAfterAssertion(stored, claims, START + 1)).toMatchObject({
        sign_count: 7,
        last_used_at: START + 1,
        sign_counter_regressed_at: START + 1,
      });
    });

    it('follows WebAuthn Level 3 §6.1.1: both zero is no counter, otherwise it must grow', () => {
      expect(signCounterRegressed(0, 0)).toBe(false);
      expect(signCounterRegressed(0, 1)).toBe(false);
      expect(signCounterRegressed(4, 5)).toBe(false);
      expect(signCounterRegressed(5, 5)).toBe(true);
      expect(signCounterRegressed(5, 0)).toBe(true);
      expect(signCounterRegressed(5, 4)).toBe(true);
    });

    it('records a growing counter and keeps an earlier regression mark', () => {
      const stored = {
        sign_count: 3,
        sign_counter_regressed_at: START - 10,
        backed_up: false,
      } as WebAuthnCredentialData;
      const claims = {
        sign_count: 9,
        sign_counter_regressed: false,
        backed_up: true,
      } as WebAuthnRawClaims;
      expect(webauthnCredentialDataAfterAssertion(stored, claims, START)).toMatchObject({
        sign_count: 9,
        backed_up: true,
        last_used_at: START,
        sign_counter_regressed_at: START - 10,
      });
    });
  });

  describe('verify input', () => {
    it('throws a plain error, not a rejection, on a malformed input or record', async () => {
      const vector = W3C_WEBAUTHN_VECTORS.packedEs256;
      const context = setup([vector.registration.challenge, vector.authentication.challenge]);
      const enrolment = await enrol(context, vector, 'sign-in');

      await expect(context.provider.verify({ transactionId: 'x' })).rejects.not.toBeInstanceOf(
        WebAuthnRejection
      );
      await startSignIn(context, vector, 'sign-in');
      await expect(
        context.provider.verify(
          verifyInput(vector, enrolment, 'login-1', { public_key: 'x' } as WebAuthnCredentialData)
        )
      ).rejects.toThrow('malformed credential_data');
    });
  });
});

describe('normalisePasskeyNickname', () => {
  it('trims, drops control characters, caps the length and turns empty into null', () => {
    expect(normalisePasskeyNickname('  Work laptop  ')).toBe('Work laptop');
    expect(normalisePasskeyNickname('Phone\u0000\u001b')).toBe('Phone');
    expect(normalisePasskeyNickname('   ')).toBeNull();
    expect(normalisePasskeyNickname(undefined)).toBeNull();
    expect(normalisePasskeyNickname('é'.repeat(80))).toHaveLength(64);
  });
});
