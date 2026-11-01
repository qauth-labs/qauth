/**
 * A store the engine depends on failed: the MFA policy, the account
 * directory, the ladder, a limiter, the bot challenge, the password
 * verifier or the identifier key. The engine refuses the round before any
 * credential is checked, as ADR-017 Decision 7 asks ("fail closed"), and
 * never lets the failure become a different answer for some accounts.
 */
export class SignInStoreUnavailableError extends Error {
  /** Which port failed: logged, never answered. */
  readonly port: string;

  constructor(port: string, cause: unknown) {
    super(`sign-in engine: ${port} unavailable`, { cause });
    this.name = 'SignInStoreUnavailableError';
    this.port = port;
  }
}

/**
 * Call a port, and turn whatever it throws into a
 * {@link SignInStoreUnavailableError}. A step handler wraps every store it
 * calls in it, as the engine does.
 */
export async function fromStore<T>(port: string, call: () => Promise<T> | T): Promise<T> {
  try {
    return await call();
  } catch (error) {
    if (error instanceof SignInStoreUnavailableError) throw error;
    throw new SignInStoreUnavailableError(port, error);
  }
}
