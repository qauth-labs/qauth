import { createHash, randomBytes } from 'node:crypto';

import { isKeyPurpose, type KeyPurpose } from './key-purposes';
import { isRealmId } from './realm-id';
import { isScopeId } from './scope-id';

/**
 * THE APPROVAL A KEY OPERATION RUNS UNDER (ADR-019 Decisions 7 and 9, issue
 * #544).
 *
 * A key operation such as a manual rotation is a security operation: it runs
 * only under a fresh approval bound to that exact operation. This module
 * defines what the key library needs of such an approval
 * ({@link ApprovedOperation}) and the canonical record an approval is bound
 * to. The approval itself (filing, the approver's passkey, the second admin
 * where a realm makes one mandatory, expiry) is the admin API's (#512, #521);
 * the break-glass CLI makes one of its own on a key-holding host.
 *
 * The binding: the operation builds its canonical record from its own
 * arguments, the requester and the approval's nonce
 * ({@link keyRotationOperation}), and hands the SHA-256 of the record's RFC
 * 8785 form ({@link operationDigest}) to {@link ApprovedOperation.consume},
 * inside the transaction that changes the keys. The approval consumes itself
 * only when that digest is the one it was filed for, which is the digest its
 * approver's passkey challenge was derived from. So an approval of one
 * realm, purpose, scope or requester approves no other, and is used once.
 *
 * Nothing here touches a KEK or key material: the admin API computes the
 * same digest when it files the approval, from this public entry point.
 */

/** The operation id of a manual key rotation, as the admin operation registry reserves it (#508). */
export const KEY_ROTATE_OPERATION = 'keys.rotate';

/** The operation id of a manual key rotation. */
export type KeyRotateOperation = typeof KEY_ROTATE_OPERATION;

/** The length of an approval's nonce, in bytes: the admin API's `APPROVAL_NONCE_BYTES`. */
export const OPERATION_NONCE_BYTES = 32;

/** The longest account id or operating-system user name an actor carries. */
const MAX_ACTOR_NAME_LENGTH = 255;

/** Who asks for a security operation. */
export type SecurityOperationActor =
  | {
      /**
       * An admin account: a human admin, whose own fresh step-up is the first
       * approval, or a service account, which files the request for human
       * admins to approve (ADR-019 Decision 7).
       */
      readonly kind: 'human' | 'service_account';
      /** The realm the account lives in. A UUID. */
      readonly realmId: string;
      readonly accountId: string;
    }
  | {
      /**
       * The break-glass CLI, on a host that holds the database credentials and
       * the KEK (ADR-019 Decision 7).
       */
      readonly kind: 'break_glass';
      /** The operating-system user that ran it, as the audit log records it. */
      readonly operatingSystemUser: string;
    };

/**
 * An approval of one security operation, as the operation it approves takes
 * it. The admin API's security-operation approval implements it (#512); so
 * does the break-glass CLI.
 *
 * `Op` is the operation's id, so an approval typed for another operation does
 * not compile where this one is asked for. `Tx` is the transaction of the
 * store the operation writes.
 */
export interface ApprovedOperation<Op extends string = string, Tx = unknown> {
  /** The approval's id, a UUID. The audit hook records it. */
  readonly id: string;
  /** The operation it approves, by its id in the admin operation registry. */
  readonly operation: Op;
  /** Who asked for the operation. Bound into the canonical record. */
  readonly requester: SecurityOperationActor;
  /**
   * The server's nonce the approval was filed with: {@link OPERATION_NONCE_BYTES}
   * random bytes, base64url without padding. Bound into the canonical record.
   */
  readonly nonce: string;
  /**
   * Use the approval up for the operation whose canonical record hashes to
   * `digest` ({@link operationDigest}), inside the operation's transaction
   * `tx`: the approval is open, approved by every approval its realm asks for,
   * not expired, filed for exactly that digest, and not used before. It
   * resolves once it has recorded the use in `tx`, so the use commits with
   * the operation or not at all. It rejects otherwise, and the operation then
   * rolls back with nothing changed.
   */
  consume(digest: Buffer, tx: Tx): Promise<void>;
}

/** Why an operation refused the approval it was given. */
export type OperationApprovalRefusal =
  /** No approval was given. */
  | 'missing'
  /** The approval is not one: a member is absent or malformed. */
  | 'malformed'
  /** The approval is for another operation. */
  | 'other_operation'
  /** The approval refused to be used for this operation ({@link ApprovedOperation.consume} rejected). */
  | 'refused';

/**
 * A security operation refused the approval it was given, and changed
 * nothing. Branch on {@link reason}. The message never carries the nonce.
 */
export class OperationApprovalError extends Error {
  readonly statusCode = 403;
  readonly code = 'OPERATION_APPROVAL_REFUSED';
  readonly reason: OperationApprovalRefusal;

  constructor(reason: OperationApprovalRefusal, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'OperationApprovalError';
    this.reason = reason;
    Object.setPrototypeOf(this, OperationApprovalError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, OperationApprovalError);
    }
  }
}

/** The canonical record of a manual key rotation: what its approval is bound to. */
export interface KeyRotationOperationRecord {
  readonly op: KeyRotateOperation;
  /** The realm whose keys rotate: its id, in lower case. */
  readonly realm: string;
  readonly purpose: KeyPurpose;
  /** The key's scope, `null` for a realm-wide key. */
  readonly scope: string | null;
  /** Who asked (ADR-019 Decision 7 binds the requester). */
  readonly requester: SecurityOperationActor;
  /** The approval's nonce. */
  readonly nonce: string;
}

/** What {@link keyRotationOperation} builds a record from. */
export interface KeyRotationOperationInput {
  readonly realmId: string;
  readonly purpose: KeyPurpose;
  /** Absent or `null` for a realm-wide key. */
  readonly scopeId?: string | null;
  readonly requester: SecurityOperationActor;
  readonly nonce: string;
}

/** A fresh nonce for an approval: {@link OPERATION_NONCE_BYTES} random bytes, base64url. */
export function newOperationNonce(): string {
  return randomBytes(OPERATION_NONCE_BYTES).toString('base64url');
}

/** Whether `value` is an approval nonce: {@link OPERATION_NONCE_BYTES} bytes in canonical base64url. */
export function isOperationNonce(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length === OPERATION_NONCE_BYTES && bytes.toString('base64url') === value;
}

/** Whether `value` holds no lone surrogate: it survives a round trip through UTF-8. */
function isWellFormed(value: string): boolean {
  return Buffer.from(value, 'utf8').toString('utf8') === value;
}

/** A name an actor carries: non-empty, at most 255 characters, well-formed, no control character. */
function isActorName(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > MAX_ACTOR_NAME_LENGTH ||
    !isWellFormed(value)
  ) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit < 0x20 || unit === 0x7f) return false;
  }
  return true;
}

/** Whether `value` is a {@link SecurityOperationActor}. */
export function isSecurityOperationActor(value: unknown): value is SecurityOperationActor {
  if (typeof value !== 'object' || value === null) return false;
  const actor = value as Record<string, unknown>;
  switch (actor['kind']) {
    case 'human':
    case 'service_account':
      return isRealmId(actor['realmId']) && isActorName(actor['accountId']);
    case 'break_glass':
      return isActorName(actor['operatingSystemUser']);
    default:
      return false;
  }
}

/** The actor's own members, and nothing else, with a realm id in lower case. */
function canonicalActor(actor: SecurityOperationActor): SecurityOperationActor {
  return actor.kind === 'break_glass'
    ? Object.freeze({ kind: actor.kind, operatingSystemUser: actor.operatingSystemUser })
    : Object.freeze({
        kind: actor.kind,
        realmId: actor.realmId.toLowerCase(),
        accountId: actor.accountId,
      });
}

/**
 * The canonical record of a manual rotation of the realm's `purpose` keys
 * (of `scopeId`, when the purpose is scoped), asked for by `requester` under
 * the approval whose nonce is `nonce`.
 *
 * @throws TypeError when the realm id is not a UUID, the purpose is unknown,
 *   the scope id could not be stored, the requester is not an actor, or the
 *   nonce is not one
 */
export function keyRotationOperation(input: KeyRotationOperationInput): KeyRotationOperationRecord {
  if (!isRealmId(input.realmId)) throw new TypeError('A realm id is a UUID');
  if (typeof input.purpose !== 'string' || !isKeyPurpose(input.purpose)) {
    throw new TypeError('An unknown key purpose');
  }
  const scope = input.scopeId ?? null;
  if (scope !== null && !isScopeId(scope)) throw new TypeError('A scope id is not well formed');
  if (!isSecurityOperationActor(input.requester)) {
    throw new TypeError('The requester is not a security operation actor');
  }
  if (!isOperationNonce(input.nonce)) {
    throw new TypeError(`A nonce is ${OPERATION_NONCE_BYTES} bytes in base64url`);
  }
  return Object.freeze({
    op: KEY_ROTATE_OPERATION,
    realm: input.realmId.toLowerCase(),
    purpose: input.purpose,
    scope,
    requester: canonicalActor(input.requester),
    nonce: input.nonce,
  });
}

/** A value of a canonical record: text, `null`, or an object of them. */
type RecordValue = string | null | { readonly [member: string]: RecordValue };

/**
 * The JSON Canonicalization Scheme (RFC 8785) for the values a record holds:
 * members sorted by their UTF-16 code units, no white space, and strings as
 * ECMAScript's `JSON.stringify` writes them (RFC 8785 §3.2.2.2). A number,
 * which needs RFC 8785's number form, is no value of a record.
 */
function canonicalJson(value: RecordValue): string {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    if (!isWellFormed(value)) throw new TypeError('A record holds a lone surrogate');
    return JSON.stringify(value);
  }
  const members = Object.keys(value).sort();
  return `{${members.map((name) => `${JSON.stringify(name)}:${canonicalJson(value[name])}`).join(',')}}`;
}

/**
 * The bytes of `record` the digest is taken over: its RFC 8785 form, in
 * UTF-8, built from the record's own members only. A golden test pins them.
 */
export function canonicalOperationBytes(record: KeyRotationOperationRecord): Buffer {
  if (record.op !== KEY_ROTATE_OPERATION) {
    throw new TypeError(`A key rotation record is for '${KEY_ROTATE_OPERATION}'`);
  }
  const built = keyRotationOperation({
    realmId: record.realm,
    purpose: record.purpose,
    scopeId: record.scope,
    requester: record.requester,
    nonce: record.nonce,
  });
  const value: RecordValue = {
    op: built.op,
    realm: built.realm,
    purpose: built.purpose,
    scope: built.scope,
    requester: { ...built.requester },
    nonce: built.nonce,
  };
  return Buffer.from(canonicalJson(value), 'utf8');
}

/**
 * The digest an approval of `record` is filed for and its approver's passkey
 * challenge is derived from: SHA-256 of {@link canonicalOperationBytes}.
 */
export function operationDigest(record: KeyRotationOperationRecord): Buffer {
  return createHash('sha256').update(canonicalOperationBytes(record)).digest();
}
