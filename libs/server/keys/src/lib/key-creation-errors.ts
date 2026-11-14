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
  | 'HYBRID_PAIR_INCOMPLETE'
  /** An import names a purpose that takes no imported key (`importable`). */
  | 'NOT_IMPORTABLE'
  /** An imported key's `kid` is empty, too long or holds a character other than printable ASCII. */
  | 'INVALID_KEY_ID'
  /** The imported text is no unencrypted private key in PEM. */
  | 'INVALID_KEY'
  /** The imported key is not a key of the algorithm it is imported for. */
  | 'KEY_ALGORITHM_MISMATCH'
  /**
   * The KEK is the published development KEK: a key from outside the
   * deployment wrapped with it would be as good as plaintext.
   */
  | 'DEVELOPMENT_KEK';

/**
 * A key the deployment does not create: a malformed realm id, an unknown or
 * operator-only purpose, an algorithm the purpose or `SIGNING_ALGORITHM_MODE`
 * does not allow, a scope id that does not fit the purpose, or one half of a
 * hybrid pair; for an import, also a purpose that takes no imported key, a
 * malformed `kid`, text that is no private key or a key of another algorithm,
 * and the development KEK. Branch on {@link reason}. A message never quotes
 * the imported text.
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
  /**
   * A manual rotation (#544) names a purpose the scheduled rotation does not
   * rotate (`AUTOMATIC_ROTATION_PURPOSES`): a scoped key, or one that rotates
   * only through its own operation, such as the federation keys. It has no
   * rotation to start early.
   */
  | 'NOT_A_ROTATING_PURPOSE'
  /** An unscoped purpose was given a scope id. */
  | 'SCOPE_NOT_ALLOWED'
  /** A manual rotation found no active key of the purpose to replace. Provisioning creates the first. */
  | 'NO_ACTIVE_KEY'
  /** The scope id is missing, empty, too long or not well-formed text. */
  | 'INVALID_SCOPE_ID'
  /** The purpose does not allow the algorithm. */
  | 'ALGORITHM_NOT_ALLOWED'
  /** The scope holds no `next` key of the algorithm to activate. */
  | 'NO_NEXT_KEY'
  /** The `next` key has not been published, or handed out, for the whole window yet. */
  | 'OVERLAP_NOT_ELAPSED'
  /** Another writer moved one of the keys while the rotation ran. Nothing changed. */
  | 'KEY_CHANGED'
  /**
   * The scheduled rotation (#542) found two `active` or two `next` keys of one
   * algorithm, which it cannot choose between. Nothing changed.
   */
  | 'AMBIGUOUS_KEYS'
  /**
   * Activating the `next` key would split a hybrid pair (ADR-005): with hybrid
   * signing on, the next EdDSA key has no ML-DSA-65 partner. Nothing changed.
   */
  | 'SPLIT_HYBRID_PAIR';

/** The reasons that describe the stored keys rather than the request. */
const KEY_STATE_REASONS: readonly KeyChangeRefusalReason[] = [
  'NO_ACTIVE_KEY',
  'NO_NEXT_KEY',
  'OVERLAP_NOT_ELAPSED',
  'KEY_CHANGED',
  'AMBIGUOUS_KEYS',
  'SPLIT_HYBRID_PAIR',
];

/**
 * A rotation step (`activateNextKey`, `rotateNow`) or a scope deletion
 * (`deleteScopedKeys`) the factory or the rotation does not run. Nothing was changed. Branch on {@link reason}.
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
