/**
 * The typed errors of key creation (issue #463).
 *
 * A refusal is decided before any key is generated or stored, so nothing is
 * left behind. Messages name purposes, algorithms and `kid`s, all of which are
 * public, and never key material.
 */

/** Why a key was refused, as a stable value to branch on. */
export type KeyCreationRefusalReason =
  /** The realm id is not a UUID. */
  | 'INVALID_REALM_ID'
  /** The purpose is not in `KEY_PURPOSES`. */
  | 'UNKNOWN_PURPOSE'
  /** The purpose belongs to a federation-operator deployment, and this is not one. */
  | 'FEDERATION_OPERATOR_ONLY'
  /** The purpose does not allow the algorithm. */
  | 'ALGORITHM_NOT_ALLOWED'
  /** The deployment's `SIGNING_ALGORITHM_MODE` does not enable the algorithm. */
  | 'ALGORITHM_NOT_ENABLED'
  /** The algorithm is created only as the second key of a hybrid pair. */
  | 'HYBRID_COMPANION_ONLY'
  /** A scoped purpose was given no scope id. */
  | 'SCOPE_REQUIRED'
  /** An unscoped purpose was given a scope id. */
  | 'SCOPE_NOT_ALLOWED'
  /** The scope id is empty, too long for `realm_keys.scope_id`, or not well-formed text. */
  | 'INVALID_SCOPE_ID'
  /**
   * With hybrid signing on, the realm holds only one active key of the pair,
   * so provisioning would have to create the other half alone.
   */
  | 'HYBRID_PAIR_INCOMPLETE';

/**
 * A key the deployment does not create: a malformed realm id, an unknown or
 * operator-only purpose, an algorithm the purpose or `SIGNING_ALGORITHM_MODE`
 * does not allow, a scope id that does not fit the purpose, or one half of a
 * hybrid pair. Branch on {@link reason}.
 */
export class KeyCreationRefusedError extends Error {
  readonly statusCode = 400;
  readonly code = 'KEY_CREATION_REFUSED';
  readonly reason: KeyCreationRefusalReason;

  constructor(reason: KeyCreationRefusalReason, message: string) {
    super(message);
    this.name = 'KeyCreationRefusedError';
    this.reason = reason;
    Object.setPrototypeOf(this, KeyCreationRefusedError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, KeyCreationRefusedError);
    }
  }
}

/**
 * A new `active` key would be the second active key of its realm, purpose,
 * scope and algorithm (`idx_realm_keys_one_active`). Raised before the insert.
 * A replacement is created as `next` and activated by a rotation.
 */
export class ActiveKeyConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'ACTIVE_KEY_CONFLICT';
  readonly purpose: string;
  readonly algorithm: string;

  constructor(purpose: string, algorithm: string) {
    super(`The realm already holds an active '${algorithm}' key for purpose '${purpose}'`);
    this.name = 'ActiveKeyConflictError';
    this.purpose = purpose;
    this.algorithm = algorithm;
    Object.setPrototypeOf(this, ActiveKeyConflictError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ActiveKeyConflictError);
    }
  }
}

/**
 * A new key's `kid` is already used by a key of the same realm. Raised before
 * the insert: a `kid` names exactly one key per realm, across every purpose
 * and status (`realm_keys_realm_id_kid_unique`).
 */
export class KeyIdConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'KEY_ID_CONFLICT';
  /** The `kid` already in use. Public, safe to log. */
  readonly kid: string;

  constructor(kid: string) {
    super(`The realm already holds a key with kid '${kid}'`);
    this.name = 'KeyIdConflictError';
    this.kid = kid;
    Object.setPrototypeOf(this, KeyIdConflictError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, KeyIdConflictError);
    }
  }
}
