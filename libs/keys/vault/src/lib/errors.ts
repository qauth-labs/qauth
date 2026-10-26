import {
  isKeyCustodyError,
  KekAccessDeniedError,
  KekUnavailableError,
  type KeyCustodyError,
  KeyDecryptionError,
  UnknownKekRefError,
} from '@qauth-labs/server-keys';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

/**
 * The Vault calls the provider makes, and how a failed one maps onto the typed
 * errors of key custody (ADR-019 Decision 9, #578).
 *
 * The Vault client retries connection failures, timeouts, throttling and
 * server faults itself, up to its attempt limit (`vault-client.ts`), and a
 * token Vault refuses is replaced once (`vault-token.ts`), so an error that
 * reaches this mapping is final for the call.
 *
 * - The ciphertext does not open under this key and context: Vault answers
 *   decrypt with 400 (`cipher: message authentication failed`, a malformed
 *   ciphertext): {@link KeyDecryptionError}. Never retried.
 * - The version `kekRef` names is not one Vault decrypts with: newer than the
 *   key's latest, or below its `min_decryption_version`:
 *   {@link UnknownKekRefError}, as for a KEK that is not configured.
 * - Vault refuses the caller or the key cannot be used: 403 (a token that is
 *   revoked, expired or lacks the policy), a failed AppRole login, a key that
 *   does not exist or is not a derived encryption key, a token or secret ID
 *   file that cannot be read: {@link KekAccessDeniedError}. An operator has
 *   to act.
 * - Everything else, a sealed or unreachable Vault, throttling and timeouts
 *   once the retries are spent, an answer that is not what Vault sends:
 *   {@link KekUnavailableError}. The same call may succeed later.
 *
 * The Vault error is kept as the `cause`, for the signer's own log. It holds
 * the HTTP status, the operation and Vault's error messages; never a token, a
 * secret ID or a data key.
 */

/** The Vault calls the provider makes. */
export type VaultOperation =
  | 'encrypt'
  | 'decrypt'
  | 'read-key'
  | 'approle-login'
  | 'token-lookup-self'
  | 'token-renew-self';

/** At most this many of Vault's error messages are kept, each cut to {@link MAX_ERROR_LENGTH}. */
const MAX_ERRORS = 5;
const MAX_ERROR_LENGTH = 200;

/** Vault's error messages from an answer body, as Vault sends them (`{"errors": [...]}`). */
export function vaultErrorsOf(body: unknown): readonly string[] {
  if (typeof body !== 'object' || body === null) return [];
  const errors = (body as { errors?: unknown }).errors;
  if (!Array.isArray(errors)) return [];
  return errors
    .filter((error): error is string => typeof error === 'string')
    .slice(0, MAX_ERRORS)
    .map((error) => error.replace(/\s+/g, ' ').trim().slice(0, MAX_ERROR_LENGTH));
}

/** Vault answered a call with a status other than 200 or 204. */
export class VaultHttpError extends Error {
  readonly operation: VaultOperation;
  readonly status: number;
  /** Vault's own error messages. */
  readonly errors: readonly string[];

  constructor(operation: VaultOperation, status: number, errors: readonly string[]) {
    super(
      `Vault answered ${status} to ${operation}${errors.length > 0 ? `: ${errors.join('; ')}` : ''}`
    );
    this.name = 'VaultHttpError';
    this.operation = operation;
    this.status = status;
    this.errors = errors;
  }
}

/** A call got no answer: the connection, TLS or the request timeout failed. */
export class VaultTransportError extends Error {
  readonly operation: VaultOperation;
  /** The Node error code, such as `ECONNREFUSED`, when there is one. */
  readonly code: string | undefined;

  constructor(operation: VaultOperation, cause: unknown) {
    const code = cause instanceof Error ? (cause as NodeJS.ErrnoException).code : undefined;
    super(`Vault could not be reached for ${operation}${code === undefined ? '' : ` (${code})`}`, {
      cause,
    });
    this.name = 'VaultTransportError';
    this.operation = operation;
    this.code = code;
  }
}

/** Vault answered 200, but not with what that call returns. */
export class VaultAnswerError extends Error {
  readonly operation: VaultOperation;

  constructor(operation: VaultOperation, what: string) {
    super(`Vault's answer to ${operation} ${what}`);
    this.name = 'VaultAnswerError';
    this.operation = operation;
  }
}

/** The Transit key exists but cannot be the KEK, for example a key that is not derived. */
export class VaultKeyRefusedError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = 'VaultKeyRefusedError';
  }
}

/** Statuses after which the same call may succeed: precondition (eventual consistency), throttling, server faults. */
export function isRetryableStatus(status: number): boolean {
  return status === 412 || status === 429 || (status >= 500 && status !== 501);
}

/** Vault's messages for a ciphertext version it does not decrypt with. */
const VERSION_REFUSALS = ['version is too new', 'disallowed by policy'];
/** Vault's message for a decrypt under a key that does not exist. */
const KEY_NOT_FOUND = 'encryption key not found';

function mentions(error: VaultHttpError, phrases: readonly string[]): boolean {
  return error.errors.some((message) => phrases.some((phrase) => message.includes(phrase)));
}

/** The key-custody error for a failed Vault call. `kekRef` is the reference a decrypt was for. */
export function toKeyCustodyError(error: unknown, kekRef?: string): KeyCustodyError {
  if (isKeyCustodyError(error)) return error;
  if (error instanceof VaultHttpError) {
    if (error.status === 403) return new KekAccessDeniedError({ cause: error });
    if (isRetryableStatus(error.status) || (error.status >= 300 && error.status < 400)) {
      return new KekUnavailableError({ cause: error });
    }
    if (error.operation === 'decrypt' && error.status === 400) {
      if (kekRef !== undefined && mentions(error, VERSION_REFUSALS)) {
        return new UnknownKekRefError(kekRef);
      }
      if (mentions(error, [KEY_NOT_FOUND])) return new KekAccessDeniedError({ cause: error });
      return new KeyDecryptionError({ detail: 'Vault refused the ciphertext', cause: error });
    }
    return new KekAccessDeniedError({ cause: error });
  }
  if (error instanceof VaultKeyRefusedError || error instanceof InvalidConfigurationError) {
    return new KekAccessDeniedError({ cause: error });
  }
  return new KekUnavailableError({ cause: error });
}

/** A short, secret-free account of a Vault failure: its status, or that Vault was not reached. */
export function describeVaultFailure(error: unknown): string | undefined {
  if (error instanceof VaultHttpError)
    return `Vault answered ${error.status} to ${error.operation}`;
  if (error instanceof VaultTransportError) return error.message;
  if (error instanceof VaultAnswerError || error instanceof VaultKeyRefusedError) {
    return error.message;
  }
  if (error instanceof InvalidConfigurationError) return error.message;
  return undefined;
}
