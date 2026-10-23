/**
 * The typed errors of the signer (issue #464).
 *
 * Messages name roles, operations, purposes, algorithms, realm ids and `kid`s,
 * all of which are public. They never carry key material, a claim value, a
 * plaintext or a ciphertext. When a key cannot be unwrapped, the signer passes
 * the key-custody error of `./errors` through unchanged.
 */

/** What went wrong, as a stable value to branch on. */
export type SignerErrorCode =
  | 'SIGNER_ACCESS_DENIED'
  | 'SIGNER_REQUEST_REFUSED'
  | 'SIGNER_ISSUER_NOT_FOUND'
  | 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND'
  | 'SIGNER_KEY_NOT_FOUND'
  | 'DATA_DECRYPTION_FAILED';

/**
 * The base of every signer error.
 *
 * Branch on {@link code}, or use {@link isSignerError}, rather than on
 * `instanceof`: the remote signer (#497) rebuilds these from a response, and a
 * copy of this library in another package has its own classes.
 */
export abstract class SignerError extends Error {
  abstract readonly code: SignerErrorCode;
  abstract readonly statusCode: number;

  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, new.target);
    }
  }
}

/**
 * The caller's role may not call the operation (`SIGNER_POLICY`), or the role
 * is unknown.
 */
export class SignerAccessDeniedError extends SignerError {
  readonly code = 'SIGNER_ACCESS_DENIED';
  readonly statusCode = 403;
  /** The role, when it is one of `SIGNER_CALLERS`; `undefined` for an unknown one. */
  readonly caller: string | undefined;
  readonly operation: string;
  /** The purpose, for `signJws`. */
  readonly purpose: string | undefined;

  constructor(caller: string | undefined, operation: string, purpose?: string) {
    // An unknown role is not echoed: it did not come from the policy table.
    const who = caller === undefined ? 'An unknown signer caller' : `Signer caller '${caller}'`;
    const what = purpose === undefined ? `'${operation}'` : `'${operation}' for '${purpose}'`;
    super(`${who} may not call ${what}`);
    this.caller = caller;
    this.operation = operation;
    this.purpose = purpose;
  }
}

/** Why a request was refused, as a stable value to branch on. */
export type SignerRefusalReason =
  /** The realm id is not a UUID. */
  | 'INVALID_REALM_ID'
  /** The purpose is not one `signJws` or `getVerificationKeys` serves. */
  | 'PURPOSE_NOT_ALLOWED'
  /** The purpose does not sign this `typ` (`JWS_TYP_BY_PURPOSE`). */
  | 'TYP_NOT_ALLOWED'
  /** The algorithm is not one of the purpose's JWS algorithms. */
  | 'ALGORITHM_NOT_ALLOWED'
  /** A scope id was given for an unscoped purpose. */
  | 'SCOPE_NOT_ALLOWED'
  /** A subscription or provider id is not a well-formed scope id (`MAX_SCOPE_ID_LENGTH`). */
  | 'INVALID_SCOPE_ID'
  /**
   * The claims set a claim the signer sets: `iss` from the realm row, or for a
   * client assertion `iss`, `sub` and `aud`.
   */
  | 'RESERVED_CLAIM'
  /** A client assertion's claims lack `exp` or `jti`, or carry one of the wrong type. */
  | 'MISSING_CLAIM'
  /** A client assertion's audience is not one non-empty string. */
  | 'INVALID_AUDIENCE'
  /** A webhook id is empty, too long, or holds a `.`, a space or a non-printable character. */
  | 'INVALID_WEBHOOK_ID'
  /** A webhook timestamp is not a whole, non-negative number of seconds. */
  | 'INVALID_TIMESTAMP'
  /** A webhook body is neither bytes nor well-formed text. */
  | 'INVALID_BODY'
  /** The request carries a field the operation does not take, such as `kid` or `iss`. */
  | 'UNEXPECTED_FIELD'
  /** The claims are not a JSON object. */
  | 'INVALID_CLAIMS'
  /** `HYBRID_SIGNING_ENABLED` is off. */
  | 'HYBRID_SIGNING_DISABLED'
  /** The plaintext is not bytes. */
  | 'INVALID_PLAINTEXT'
  /** The context is not a well-formed string of at most `MAX_DATA_CONTEXT_LENGTH` characters. */
  | 'INVALID_CONTEXT';

/** A request the signer does not run. Nothing was signed, encrypted or read. */
export class SignerRequestRefusedError extends SignerError {
  readonly code = 'SIGNER_REQUEST_REFUSED';
  readonly statusCode = 400;
  readonly reason: SignerRefusalReason;

  constructor(reason: SignerRefusalReason, message: string) {
    super(message);
    this.reason = reason;
  }
}

/**
 * The realm does not exist, or has no issuer yet (a realm that predates
 * migration 0025 until the boot step fills it, #484). The signer cannot set
 * `iss`, so it signs nothing.
 */
export class RealmIssuerNotFoundError extends SignerError {
  readonly code = 'SIGNER_ISSUER_NOT_FOUND';
  readonly statusCode = 500;
  readonly realmId: string;

  constructor(realmId: string) {
    super(`Realm '${realmId}' has no issuer`);
    this.realmId = realmId;
  }
}

/**
 * The realm has no configuration for the upstream provider a client assertion
 * names, so the signer has no client id to put in `iss` and `sub`. It signs
 * nothing.
 */
export class UpstreamClientNotFoundError extends SignerError {
  readonly code = 'SIGNER_UPSTREAM_CLIENT_NOT_FOUND';
  readonly statusCode = 500;
  readonly realmId: string;

  constructor(realmId: string) {
    // The provider id came from the caller; it is not echoed.
    super(`Realm '${realmId}' has no configuration for the upstream provider`);
    this.realmId = realmId;
  }
}

/**
 * The realm holds no key the operation can use: no active key of the purpose
 * and algorithm, no complete hybrid pair, or no usable key with the `kid` a
 * ciphertext names. The signer never creates a key in its place.
 */
export class SignerKeyNotFoundError extends SignerError {
  readonly code = 'SIGNER_KEY_NOT_FOUND';
  readonly statusCode = 500;
  readonly realmId: string;
  readonly purpose: string;
  /** The algorithm asked for, when the lookup was by algorithm. */
  readonly algorithm: string | undefined;
  /** The `kid` asked for, when the lookup was by `kid`. */
  readonly kid: string | undefined;

  constructor(
    realmId: string,
    purpose: string,
    options: { algorithm?: string; kid?: string; detail?: string } = {}
  ) {
    const which =
      options.kid !== undefined
        ? `key with kid '${options.kid}'`
        : `active '${options.algorithm ?? 'any'}' key`;
    super(
      `Realm '${realmId}' has no ${which} for purpose '${purpose}'` +
        (options.detail !== undefined ? ` (${options.detail})` : '')
    );
    this.realmId = realmId;
    this.purpose = purpose;
    this.algorithm = options.algorithm;
    this.kid = options.kid;
  }
}

/** The only message a {@link DataDecryptionError} carries. */
export const DATA_DECRYPTION_ERROR_MESSAGE = 'Data could not be decrypted';

/**
 * A `data_at_rest` ciphertext did not decrypt: it is malformed, was made for
 * another realm or context, or was changed. The causes are not told apart in
 * the message; {@link detail} names the step for local logs.
 */
export class DataDecryptionError extends SignerError {
  readonly code = 'DATA_DECRYPTION_FAILED';
  readonly statusCode = 500;
  /** The step that failed, for local logs only. Never data. */
  readonly detail: string | undefined;

  constructor(detail?: string) {
    super(DATA_DECRYPTION_ERROR_MESSAGE);
    this.detail = detail;
  }
}

const SIGNER_ERROR_CODES: ReadonlySet<unknown> = new Set<SignerErrorCode>([
  'SIGNER_ACCESS_DENIED',
  'SIGNER_REQUEST_REFUSED',
  'SIGNER_ISSUER_NOT_FOUND',
  'SIGNER_UPSTREAM_CLIENT_NOT_FOUND',
  'SIGNER_KEY_NOT_FOUND',
  'DATA_DECRYPTION_FAILED',
]);

/**
 * Whether `error` is a signer error, optionally of one `code`. Checks the
 * shape rather than the class (see {@link SignerError}).
 */
export function isSignerError(error: unknown, code?: SignerErrorCode): error is SignerError {
  if (!(error instanceof Error) || !('code' in error)) return false;
  const actual = (error as { code: unknown }).code;
  return code === undefined ? SIGNER_ERROR_CODES.has(actual) : actual === code;
}
