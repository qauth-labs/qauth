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
 * only for the digest of the record it rebuilds from what its approver
 * approved. The admin API's approval (#512) is filed for its own canonical
 * request of the operation, which holds the same realm, purpose, requester
 * and nonce, and its approver's passkey challenge is derived from that
 * request's hash; its `consume`, which the admin route that files a
 * `keys.rotate` approval implements, rebuilds this record from the request
 * filed. So the passkey that approved the request approved this rotation and
 * no other: an approval of one realm, purpose, scope or requester approves no
 * other, and is used once.
 *
 * The interface is structural: the type refuses no approval and an approval of
 * another operation, and the operation checks the members at run time, but it
 * cannot tell a real approval from an object shaped like one. The guarantee
 * lies in `consume`, which only the approvals module and the break-glass CLI
 * implement.
 *
 * A KEK rotation (#545) is bound the same way, to its own record
 * ({@link kekRotationOperation}): the KEK reference its keys move from, the
 * one they move to, the requester and the nonce. A KEK has no realm, so its
 * record names none.
 *
 * Nothing here touches a KEK or key material: the admin API computes the
 * same digest when it files the approval, from this public entry point.
 */

/** The operation id of a manual key rotation, as the admin operation registry reserves it (#508). */
export const KEY_ROTATE_OPERATION = 'keys.rotate';

/** The operation id of a manual key rotation. */
export type KeyRotateOperation = typeof KEY_ROTATE_OPERATION;

/**
 * The operation id of a KEK rotation, which re-wraps every stored key's data
 * key under a new KEK, as the admin operation registry reserves it (#508,
 * #545).
 */
export const KEK_ROTATE_OPERATION = 'kek.rotate';

/** The operation id of a KEK rotation. */
export type KekRotateOperation = typeof KEK_ROTATE_OPERATION;

/**
 * The longest KEK reference a record holds. A local KEK's is 16 hex
 * characters; a key service's names its key and version, such as a key ARN
 * and its key material ID.
 */
export const MAX_KEK_REF_LENGTH = 1024;

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
   * `tx`, which is a transaction of the database the approval lives in. It
   * resolves only when, read and written in `tx`:
   *
   * - `digest` is the digest of the record it rebuilds from what it was filed
   *   for (the realm, purpose, scope, requester and nonce its approver saw;
   *   for a KEK rotation, the two KEK references, the requester and the
   *   nonce), compared in constant time;
   * - the approval is open, not expired, and approved by every approver its
   *   realm asks for at that moment (a second admin, where the realm makes one
   *   mandatory for the operation);
   * - and it recorded the use with a conditional write that an approval used
   *   before matches nothing, so a second use, concurrent or not, fails.
   *
   * The use then commits with the operation, or not at all. To refuse, it
   * rejects with an {@link OperationApprovalError} (or another error whose
   * `code` is `OPERATION_APPROVAL_REFUSED`): the operation rolls back and
   * throws an `OperationApprovalError` of reason `refused`. Any other
   * rejection is a fault, which the operation passes on as it is after
   * rolling back.
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

/**
 * Whether `error` is a refusal of an approval: an {@link OperationApprovalError},
 * or an error of its code from another copy of this module.
 */
export function isOperationApprovalRefusal(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { readonly code?: unknown }).code === 'OPERATION_APPROVAL_REFUSED'
  );
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The approval members an operation reads, checked; a copy, so a getter
 * cannot change them later. Not on the package's entry points.
 */
export interface CheckedApproval<Tx> {
  readonly id: string;
  readonly requester: SecurityOperationActor;
  readonly nonce: string;
  consume(digest: Buffer, tx: Tx): Promise<void>;
}

/**
 * `approval`, when it is an approval of `operation`: an object with a UUID id,
 * that operation id, an actor, a nonce and a `consume` function. Its members
 * are read once. Not on the package's entry points: each operation checks
 * the approval it is handed with it, before it reads anything.
 *
 * @param missing - the message for an absent approval, such as "A manual
 *   rotation needs an approval"
 * @throws OperationApprovalError otherwise
 */
export function checkedApproval<Tx>(
  approval: unknown,
  operation: string,
  missing: string
): CheckedApproval<Tx> {
  if (approval === undefined || approval === null) {
    throw new OperationApprovalError('missing', missing);
  }
  if (typeof approval !== 'object') {
    throw new OperationApprovalError('malformed', 'The approval is not an approval');
  }
  const given = approval as Partial<ApprovedOperation<string, Tx>>;
  const { id, operation: approved, requester, nonce, consume } = given;
  if (approved !== operation) {
    throw new OperationApprovalError(
      typeof approved === 'string' ? 'other_operation' : 'malformed',
      `The approval is not for '${operation}'`
    );
  }
  if (typeof id !== 'string' || !UUID.test(id)) {
    throw new OperationApprovalError('malformed', 'An approval id is a UUID');
  }
  if (!isSecurityOperationActor(requester)) {
    throw new OperationApprovalError('malformed', "The approval's requester is not an actor");
  }
  if (!isOperationNonce(nonce)) {
    throw new OperationApprovalError('malformed', "The approval's nonce is not one");
  }
  if (typeof consume !== 'function') {
    throw new OperationApprovalError('malformed', 'The approval cannot be consumed');
  }
  return Object.freeze({
    id: id.toLowerCase(),
    requester: Object.freeze(
      requester.kind === 'break_glass'
        ? { kind: requester.kind, operatingSystemUser: requester.operatingSystemUser }
        : { kind: requester.kind, realmId: requester.realmId, accountId: requester.accountId }
    ),
    nonce,
    consume: (digest: Buffer, tx: Tx) => consume.call(approval, digest, tx),
  });
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

/** Text of 1 to `maxLength` characters, well-formed, with no control character. */
function isBoundedText(value: unknown, maxLength: number): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maxLength ||
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

/** A name an actor carries: non-empty, at most 255 characters, well-formed, no control character. */
function isActorName(value: unknown): value is string {
  return isBoundedText(value, MAX_ACTOR_NAME_LENGTH);
}

/**
 * Whether `value` can be a KEK reference (`realm_keys.kek_ref`): non-empty,
 * at most {@link MAX_KEK_REF_LENGTH} characters, well-formed, with no control
 * character. Which references a node holds a KEK for is its KEK provider's to
 * say.
 */
export function isKekRef(value: unknown): value is string {
  return isBoundedText(value, MAX_KEK_REF_LENGTH);
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

/** The canonical record of a KEK rotation (#545): what its approval is bound to. */
export interface KekRotationOperationRecord {
  readonly op: KekRotateOperation;
  /** The KEK reference the stored keys' data keys are re-wrapped from. */
  readonly from: string;
  /** The KEK reference they are re-wrapped to: the KEK the signer wraps under. */
  readonly to: string;
  /** Who asked (ADR-019 Decision 7 binds the requester). */
  readonly requester: SecurityOperationActor;
  /** The approval's nonce. */
  readonly nonce: string;
}

/** What {@link kekRotationOperation} builds a record from. */
export interface KekRotationOperationInput {
  readonly from: string;
  readonly to: string;
  readonly requester: SecurityOperationActor;
  readonly nonce: string;
}

/** The canonical record of any security operation the key library runs. */
export type SecurityOperationRecord = KeyRotationOperationRecord | KekRotationOperationRecord;

/**
 * The canonical record of a KEK rotation that re-wraps the stored keys' data
 * keys from the KEK reference `from` to `to`, asked for by `requester` under
 * the approval whose nonce is `nonce`. A KEK serves the whole deployment, so
 * the record names no realm.
 *
 * @throws TypeError when a KEK reference is not one ({@link isKekRef}), the
 *   two are the same, the requester is not an actor, or the nonce is not one
 */
export function kekRotationOperation(input: KekRotationOperationInput): KekRotationOperationRecord {
  if (!isKekRef(input.from)) throw new TypeError('The KEK reference to re-wrap from is not one');
  if (!isKekRef(input.to)) throw new TypeError('The KEK reference to re-wrap to is not one');
  if (input.from === input.to) {
    throw new TypeError('A KEK rotation moves keys to another KEK reference');
  }
  if (!isSecurityOperationActor(input.requester)) {
    throw new TypeError('The requester is not a security operation actor');
  }
  if (!isOperationNonce(input.nonce)) {
    throw new TypeError(`A nonce is ${OPERATION_NONCE_BYTES} bytes in base64url`);
  }
  return Object.freeze({
    op: KEK_ROTATE_OPERATION,
    from: input.from,
    to: input.to,
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
 *
 * @throws TypeError for a record of another operation, or one its own
 *   builder ({@link keyRotationOperation}, {@link kekRotationOperation})
 *   refuses
 */
export function canonicalOperationBytes(record: SecurityOperationRecord): Buffer {
  if (record.op === KEK_ROTATE_OPERATION) {
    const built = kekRotationOperation({
      from: record.from,
      to: record.to,
      requester: record.requester,
      nonce: record.nonce,
    });
    const value: RecordValue = {
      op: built.op,
      from: built.from,
      to: built.to,
      requester: { ...built.requester },
      nonce: built.nonce,
    };
    return Buffer.from(canonicalJson(value), 'utf8');
  }
  if (record.op !== KEY_ROTATE_OPERATION) {
    throw new TypeError(`A record is for '${KEY_ROTATE_OPERATION}' or '${KEK_ROTATE_OPERATION}'`);
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
export function operationDigest(record: SecurityOperationRecord): Buffer {
  return createHash('sha256').update(canonicalOperationBytes(record)).digest();
}
