/**
 * What the auth server's approval engine (#512) takes from the database
 * library, which the app may not import itself: the RFC 8785 canonicalizer
 * the admin audit log hashes its rows with, so an approval's `request_hash`
 * and `op_hash` come from the same code, and the types of a stored approval.
 */
export type {
  AdminApproval,
  AdminApprovalClassification,
  AdminApprovalEntry,
  AdminApprovalRequesterKind,
  AdminApprovalStatus,
  NewAdminApproval,
} from '@qauth-labs/infra-db';
export { canonicalizeJson } from '@qauth-labs/infra-db';
