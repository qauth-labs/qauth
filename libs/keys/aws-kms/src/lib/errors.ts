import {
  KekAccessDeniedError,
  KekUnavailableError,
  type KeyCustodyError,
  KeyDecryptionError,
} from '@qauth-labs/server-keys';

/**
 * How a failed KMS call maps onto the typed errors of key custody (ADR-019
 * Decision 9, #577).
 *
 * The KMS client retries throttling, timeouts and server faults itself, up to
 * its attempt limit (`kms-client.ts`), so an error that reaches this mapping is
 * final for the call. Errors are matched by `name`, the exception type KMS
 * returns, rather than by class, which a second copy of the SDK would not
 * share.
 *
 * - The ciphertext does not open under this key and encryption context:
 *   {@link KeyDecryptionError}. Never retried; another attempt gives the same
 *   answer.
 * - KMS or IAM refuses the call, or the key cannot be used: wrong or missing
 *   credentials, a policy that does not grant the action, a key that is
 *   disabled, pending deletion, missing or not an encryption key:
 *   {@link KekAccessDeniedError}. An operator has to act.
 * - Everything else, throttling and outages included, once the retries are
 *   spent: {@link KekUnavailableError}. The same call may succeed later.
 *
 * The KMS error is kept as the `cause`, for the signer's own log. Its message
 * can name the account, the role and the key, which are not secrets.
 */

/** The ciphertext, the key or the encryption context do not match. */
const DECRYPTION_FAILURES: ReadonlySet<string> = new Set([
  'IncorrectKeyException',
  'InvalidCiphertextException',
]);

/** The caller or the key is refused. */
const ACCESS_REFUSALS: ReadonlySet<string> = new Set([
  // IAM and request signing.
  'AccessDeniedException',
  'ExpiredTokenException',
  'IncompleteSignature',
  'InvalidClientTokenId',
  'InvalidSignatureException',
  'MissingAuthenticationToken',
  'UnrecognizedClientException',
  // The default credential chain found no credentials.
  'CredentialsProviderError',
  // The key itself.
  'DisabledException',
  'InvalidArnException',
  'InvalidKeyUsageException',
  'KMSInvalidStateException',
  'NotFoundException',
]);

/** The exception type of a KMS error, or `undefined` for a value that is not an error. */
export function kmsErrorName(error: unknown): string | undefined {
  return error instanceof Error ? error.name : undefined;
}

/** The key-custody error for a failed KMS call. */
export function toKeyCustodyError(error: unknown): KeyCustodyError {
  const name = kmsErrorName(error);
  if (name !== undefined && DECRYPTION_FAILURES.has(name)) {
    return new KeyDecryptionError({ detail: `KMS refused the ciphertext (${name})`, cause: error });
  }
  if (name !== undefined && ACCESS_REFUSALS.has(name)) {
    return new KekAccessDeniedError({ cause: error });
  }
  return new KekUnavailableError({ cause: error });
}
