import type {
  WebAuthnCeremonyState,
  WebAuthnChallengeStore,
} from '../src/webauthn/webauthn-challenge-store';

/**
 * TEST SUPPORT — an in-memory {@link WebAuthnChallengeStore}.
 *
 * Single-process and synchronous underneath, so `take` is atomic by
 * construction: it deletes the entry in the same tick it reads it. That is the
 * property the port asks of the deployment store (Redis `GETDEL`), and the
 * provider tests rely on it to show that a challenge answers once. Expiry is
 * left to the state's own `expiresAt`, which the provider checks.
 */
export function createInMemoryChallengeStore(): WebAuthnChallengeStore & {
  /** Transactions with a ceremony waiting. */
  readonly pending: () => string[];
} {
  const entries = new Map<string, WebAuthnCeremonyState>();
  return {
    async begin(transactionId: string, state: WebAuthnCeremonyState): Promise<void> {
      if (entries.has(transactionId)) {
        throw new Error(`transaction ${transactionId} already has a ceremony waiting`);
      }
      entries.set(transactionId, structuredClone(state));
    },
    async take(transactionId: string): Promise<WebAuthnCeremonyState | undefined> {
      const state = entries.get(transactionId);
      entries.delete(transactionId);
      return state;
    },
    pending: () => [...entries.keys()],
  };
}
