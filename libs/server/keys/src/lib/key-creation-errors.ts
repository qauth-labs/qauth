/**
 * The typed errors of key creation (issue #463), and of the rotation and
 * deletion of scoped keys (issue #547).
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

/**
 * A new `next` key would be the second `next` key of its realm, purpose, scope
 * and algorithm. Raised before the insert. A rotation has one key waiting: a
 * webhook subscriber was shown that key's secret, and an upstream provider
 * may already hold its public half. Activate it, or delete the scope, first.
 */
export class NextKeyConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'NEXT_KEY_CONFLICT';
  readonly purpose: string;
  readonly algorithm: string;

  constructor(purpose: string, algorithm: string) {
    super(`The realm already holds a next '${algorithm}' key for purpose '${purpose}'`);
    this.name = 'NextKeyConflictError';
    this.purpose = purpose;
    this.algorithm = algorithm;
    Object.setPrototypeOf(this, NextKeyConflictError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NextKeyConflictError);
    }
  }
}

/** Why a change to stored keys was refused, as a stable value to branch on. */
export type KeyChangeRefusalReason =
  /** The realm id is not a UUID. */
  | 'INVALID_REALM_ID'
  /** The purpose is not in `KEY_PURPOSES`. */
  | 'UNKNOWN_PURPOSE'
  /** The purpose is not scoped. Only scoped keys rotate and are deleted this way. */
  | 'UNSCOPED_PURPOSE'
  /** The scope id is missing, empty, too long or not well-formed text. */
  | 'INVALID_SCOPE_ID'
  /** The purpose does not allow the algorithm. */
  | 'ALGORITHM_NOT_ALLOWED'
  /** The scope holds no `next` key of the algorithm to activate. */
  | 'NO_NEXT_KEY'
  /** The `next` key has not been published, or handed out, for the whole window yet. */
  | 'OVERLAP_NOT_ELAPSED'
  /** Another writer moved one of the keys while the rotation ran. Nothing changed. */
  | 'KEY_CHANGED';

/** The reasons that describe the stored keys rather than the request. */
const KEY_STATE_REASONS: readonly KeyChangeRefusalReason[] = [
  'NO_NEXT_KEY',
  'OVERLAP_NOT_ELAPSED',
  'KEY_CHANGED',
];

/**
 * A rotation step (`activateNextKey`) or a scope deletion (`deleteScopedKeys`)
 * the factory does not run. Nothing was changed. Branch on {@link reason}.
 */
export class KeyChangeRefusedError extends Error {
  readonly code = 'KEY_CHANGE_REFUSED';
  /** 409 when the stored keys are not ready, 400 when the request is malformed. */
  readonly statusCode: 400 | 409;
  readonly reason: KeyChangeRefusalReason;
  /** For `OVERLAP_NOT_ELAPSED`: the first moment, in epoch ms, the step may run. */
  readonly notBefore: number | undefined;

  constructor(reason: KeyChangeRefusalReason, message: string, notBefore?: number) {
    super(message);
    this.name = 'KeyChangeRefusedError';
    this.reason = reason;
    this.statusCode = KEY_STATE_REASONS.includes(reason) ? 409 : 400;
    this.notBefore = notBefore;
    Object.setPrototypeOf(this, KeyChangeRefusedError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, KeyChangeRefusedError);
    }
  }
}
