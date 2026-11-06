import {
  createSimpleWebAuthnVerifier,
  createWebAuthnProvider,
  type WebAuthnChallengeStore,
  type WebAuthnProvider,
} from '@qauth-labs/server-federation';

/**
 * The deployment's WebAuthn provider (#467, #651): the provider's ceremony
 * rules over the library verifier QAuth ships, with ceremony state in
 * `challenges`. The app builds its passkey steps on it and never picks a
 * verifier of its own, so the rules of `webauthn.provider.ts` (algorithms,
 * user verification for a sign-in, the counter) hold on every path.
 */
export function createPasskeyProvider(challenges: WebAuthnChallengeStore): WebAuthnProvider {
  return createWebAuthnProvider({ verifier: createSimpleWebAuthnVerifier(), challenges });
}
