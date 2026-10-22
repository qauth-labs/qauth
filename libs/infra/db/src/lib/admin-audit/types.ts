/**
 * The JSON shapes stored in `admin_audit_log` (ADR-019 Decision 7, issue #448).
 */

/** A JSON value, as `jsonb` stores it. */
export type JsonValue = string | number | boolean | null | JsonValue[] | JsonObject;

/** A JSON object. */
export type JsonObject = { [member: string]: JsonValue };

/**
 * The change an admin operation made to one resource: its state before and
 * after. `before` is `null` for a creation and `after` is `null` for a
 * deletion. Stored only after {@link maskSecrets} has replaced every secret
 * field.
 */
export interface AdminAuditDiff {
  before: JsonObject | null;
  after: JsonObject | null;
}

/** How a field of a resource is treated in a diff. */
export type FieldAnnotation = 'secret';

/**
 * Field annotations of a resource, keyed by the field's path inside the
 * resource: member names joined by `.`, where `*` matches any member or any
 * array element. For example `clientSecretHash`, `smtp.password` or
 * `webhooks.*.secret`. A secret field's whole value is masked, nested values
 * included.
 */
export type FieldAnnotations = Readonly<Record<string, FieldAnnotation>>;

/**
 * One approval of a security operation (ADR-019 Decision 7). Both approvals of
 * a two-admin operation are recorded, each with the passkey credential that
 * gave it.
 */
export interface AdminAuditApproval {
  /** Account id of the approving admin. */
  approverId: string;
  /** Id of the passkey credential the approval used. */
  credentialId: string;
  /**
   * Account id of whoever created the approver's account, or `null` when no
   * account did (a break-glass enrolment). The admin events show who created
   * each approver.
   */
  approverCreatedBy: string | null;
  /** When the approval was given, in epoch milliseconds. */
  approvedAt: number;
}

/**
 * An RFC 8693 §4.1 `act` claim as stored: the actor's identity claims and,
 * nested in `act`, the actor before it.
 */
export interface AdminAuditActClaim {
  sub: string;
  iss?: string;
  client_id?: string;
  act?: AdminAuditActClaim;
}

/**
 * The act chain of an operation performed for a user (ADR-019 Decision 7:
 * there is no impersonation, an admin acting for a user holds an act-chain
 * token). `sub` is the user acted for and `act` the token's full `act` claim,
 * nested as the token carried it; the outermost actor is the one that
 * performed the operation.
 */
export interface AdminAuditActChain {
  sub: string;
  act: AdminAuditActClaim;
}
