/**
 * The typed errors of key custody (ADR-019 Decision 9).
 *
 * Every KEK provider, the default one and the adapters in optional packages,
 * reports a failure as one of these, so the signer can tell a key it must never
 * open from a backend that is briefly unreachable. A configuration fault is an
 * `InvalidConfigurationError` from `@qauth-labs/shared-errors` instead: it stops
 * the boot and is not a key-custody outcome.
 *
 * No message ever carries key material, a data key, the KEK or the bytes a
 * fingerprint was taken of. Each message is fixed text.
 */

/** What went wrong, as a stable value to branch on. */
export type KeyCustodyErrorCode =
  | 'KEY_DECRYPTION_FAILED'
  | 'KEK_UNKNOWN_REF'
  | 'KEK_UNAVAILABLE'
  | 'KEK_ACCESS_DENIED';

/**
 * The base of every key-custody error.
 *
 * Branch on {@link code}, or use {@link isKeyCustodyError}, rather than on
 * `instanceof`. An adapter package and the auth server can each hold their own
 * copy of this library (pnpm injects workspace packages as copies), and a class
 * from one copy is not the class from the other.
 */
export abstract class KeyCustodyError extends Error {
  /** A key-custody failure is a server fault. */
  readonly statusCode = 500;
  abstract readonly code: KeyCustodyErrorCode;

  protected constructor(message: string, options?: { cause?: unknown }) {
    super(message, options?.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, new.target);
    }
  }
}

/** The only message a {@link KeyDecryptionError} carries. */
export const KEY_DECRYPTION_ERROR_MESSAGE = 'Key material could not be decrypted';

/**
 * Wrapped key material did not authenticate: a wrong KEK, associated data that
 * differs from the data it was sealed with, or tampered bytes.
 *
 * The causes are not told apart in the message. A caller that could tell
 * "wrong associated data" from "tampered ciphertext" learns something about a
 * row it was not able to open. {@link detail} names the step for local logs.
 */
export class KeyDecryptionError extends KeyCustodyError {
  readonly code = 'KEY_DECRYPTION_FAILED';
  /** The step that failed, for local logs only. Never key material. */
  readonly detail?: string;

  constructor(options: { detail?: string; cause?: unknown } = {}) {
    super(KEY_DECRYPTION_ERROR_MESSAGE, options);
    this.detail = options.detail;
  }
}

/**
 * The provider holds no KEK with this `kekRef`. The provider never tries
 * another KEK instead.
 *
 * During a KEK rotation this means the previous KEK is not configured: for the
 * default provider, `KEK_PREVIOUS` or `KEK_PREVIOUS_PATH`.
 */
export class UnknownKekRefError extends KeyCustodyError {
  readonly code = 'KEK_UNKNOWN_REF';
  /** The reference that matched no KEK. A fingerprint, safe to log. */
  readonly kekRef: string;

  constructor(kekRef: string) {
    super('No configured KEK matches the key-encryption key reference');
    this.kekRef = kekRef;
  }
}

/**
 * The KEK backend did not answer: an outage, a timeout or throttling. The same
 * call may succeed later. Adapters raise it; the default provider never does.
 */
export class KekUnavailableError extends KeyCustodyError {
  readonly code = 'KEK_UNAVAILABLE';
  readonly retryable = true;

  constructor(options: { cause?: unknown } = {}) {
    super('The key-encryption key provider is unavailable', options);
  }
}

/**
 * The KEK backend refused the caller, for example a cloud KMS policy that does
 * not grant this role the wrap operation. Adapters raise it.
 */
export class KekAccessDeniedError extends KeyCustodyError {
  readonly code = 'KEK_ACCESS_DENIED';

  constructor(options: { cause?: unknown } = {}) {
    super('The key-encryption key provider denied access', options);
  }
}

const KEY_CUSTODY_ERROR_CODES: ReadonlySet<unknown> = new Set<KeyCustodyErrorCode>([
  'KEY_DECRYPTION_FAILED',
  'KEK_UNKNOWN_REF',
  'KEK_UNAVAILABLE',
  'KEK_ACCESS_DENIED',
]);

/**
 * Whether `error` is a key-custody error, optionally of one `code`.
 *
 * Checks the shape rather than the class, so it also recognises an error raised
 * by another copy of this library (see {@link KeyCustodyError}).
 */
export function isKeyCustodyError(
  error: unknown,
  code?: KeyCustodyErrorCode
): error is KeyCustodyError {
  if (!(error instanceof Error) || !('code' in error)) return false;
  const actual = (error as { code: unknown }).code;
  return code === undefined ? KEY_CUSTODY_ERROR_CODES.has(actual) : actual === code;
}
