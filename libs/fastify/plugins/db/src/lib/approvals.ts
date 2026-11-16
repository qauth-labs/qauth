/**
 * What the auth server's approval engine (#512) takes from the database
 * library, which the app may not import itself: the RFC 8785 canonicalizer
 * the admin audit log hashes its rows with, so an approval's `op_hash` comes
 * from the same code, and the types of a stored approval.
 */
export type {
  AdminApproval,
  AdminApprovalClassification,
  AdminApprovalDisplay,
  AdminApprovalDisplayField,
  AdminApprovalEntry,
  AdminApprovalRequesterKind,
  AdminApprovalStatus,
  NewAdminApproval,
} from '@qauth-labs/infra-db';
export { canonicalizeJson } from '@qauth-labs/infra-db';
/** An act-chain token's row (#523), as the account API reads it. */
export type { AdminActSession, NewAdminActSession } from '@qauth-labs/infra-db';
