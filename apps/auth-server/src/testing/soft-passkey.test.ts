import {
  createPasskeyProvider,
  generateWebAuthnUserHandle,
  type WebAuthnCeremonyState,
  type WebAuthnChallengeStore,
  WebAuthnRejection,
} from '@qauth-labs/fastify-plugin-federation';
import { describe, expect, it } from 'vitest';

import { softPasskey } from './soft-passkey';

const RP_ID = 'auth.example.com';

/** The ceremony states, in memory. */
function memoryChallenges(): WebAuthnChallengeStore {
  const states = new Map<string, WebAuthnCeremonyState>();
  return {
    async begin(id, state) {
      states.set(id, state);
    },
    async take(id) {
      const state = states.get(id);
      states.delete(id);
      return state;
    },
  };
}

/**
 * The tests' software passkey answers a sign-in ceremony the way the
 * server's own provider and verifier accept, so the integration suite's
 * assertions are real ones.
 */
describe('softPasskey', () => {
  async function ceremony() {
    const provider = createPasskeyProvider(memoryChallenges());
    const passkey = softPasskey(RP_ID);
    const options = await provider.startAuthentication({
      transactionId: 'tx-1',
      purpose: 'sign-in',
      rpId: RP_ID,
      origins: [`https://${RP_ID}`],
    });
    const verify = (response: string) =>
      provider.verify({
        transactionId: 'tx-1',
        response: JSON.parse(response),
        credential: { externalSub: passkey.credentialId, credentialData: passkey.credentialData },
      });
    return { passkey, options, verify };
  }

  it('signs an assertion the verifier accepts, with the user verified', async () => {
    const { passkey, options, verify } = await ceremony();

    const verified = await verify(passkey.assert(options));

    expect(verified.externalSub).toBe(passkey.credentialId);
    expect(verified.rawClaims).toMatchObject({ user_verified: true, sign_count: 1 });
  });

  describe('a registration (#655)', () => {
    async function registration() {
      const provider = createPasskeyProvider(memoryChallenges());
      const options = await provider.startRegistration({
        transactionId: 'tx-2',
        purpose: 'sign-in',
        rp: { id: RP_ID, name: 'Example' },
        origins: [`https://${RP_ID}`],
        user: { handle: generateWebAuthnUserHandle(), name: 'account-x', displayName: 'account-x' },
        excludeCredentials: [],
      });
      const passkey = softPasskey(RP_ID, options.user.id);
      const finish = (response: string) =>
        provider.finishRegistration({ transactionId: 'tx-2', response: JSON.parse(response) });
      return { provider, options, passkey, finish };
    }

    it('creates a credential the verifier accepts, with a none attestation, that then signs in', async () => {
      const { provider, options, passkey, finish } = await registration();

      const enrolment = await finish(passkey.create(options));

      expect(enrolment.externalSub).toBe(passkey.credentialId);
      expect(enrolment.attestationFormat).toBe('none');
      expect(enrolment.credentialData).toMatchObject({
        algorithm: -7,
        sign_count: 0,
        rp_id: RP_ID,
        user_handle: passkey.userHandle,
      });

      // The stored credential verifies the passkey's assertions.
      const request = await provider.startAuthentication({
        transactionId: 'tx-3',
        purpose: 'sign-in',
        rpId: RP_ID,
        origins: [`https://${RP_ID}`],
      });
      const verified = await provider.verify({
        transactionId: 'tx-3',
        response: JSON.parse(passkey.assert(request)),
        credential: {
          externalSub: enrolment.externalSub,
          credentialData: enrolment.credentialData,
        },
      });
      expect(verified.externalSub).toBe(passkey.credentialId);
    });

    it('creates one without the user-verification flag when asked, which a sign-in refuses', async () => {
      const { options, passkey, finish } = await registration();

      const refused = await finish(passkey.create(options, { userVerified: false })).catch(
        (error: unknown) => error
      );

      expect(refused).toBeInstanceOf(WebAuthnRejection);
      expect((refused as WebAuthnRejection).reason).toBe('user-not-verified');
    });
  });

  it('signs one without the user-verification flag when asked, which a sign-in refuses', async () => {
    const { passkey, options, verify } = await ceremony();

    const refused = await verify(passkey.assert(options, { userVerified: false })).catch(
      (error: unknown) => error
    );

    expect(refused).toBeInstanceOf(WebAuthnRejection);
    expect((refused as WebAuthnRejection).reason).toBe('user-not-verified');
  });
});
