import {
  createPasskeyProvider,
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

  it('signs one without the user-verification flag when asked, which a sign-in refuses', async () => {
    const { passkey, options, verify } = await ceremony();

    const refused = await verify(passkey.assert(options, { userVerified: false })).catch(
      (error: unknown) => error
    );

    expect(refused).toBeInstanceOf(WebAuthnRejection);
    expect((refused as WebAuthnRejection).reason).toBe('user-not-verified');
  });
});
