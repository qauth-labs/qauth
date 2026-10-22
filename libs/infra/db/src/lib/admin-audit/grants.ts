/**
 * Database grants for the admin audit log (ADR-019 Decision 7, issue #448).
 *
 * The roles that write the log hold only `INSERT` and `SELECT` on it, and only
 * `SELECT` on its checkpoints, which `admin_audit_log_prune` writes.
 * The prune function itself stays with the table owner; the retention job's
 * role (#536) is the only one ever granted `EXECUTE` on it.
 *
 * QAuth creates no database users: the operator does, and the per-role grants
 * script (#498) applies these entries to the users it is given. Until the
 * roles are split, the one database user owns the table: the triggers of
 * migration 0026 keep the log append-only against the application's own
 * statements, but an owner can disable a trigger.
 */

/** Privilege on a table, as `GRANT` spells it. */
export type TablePrivilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

/** What a role that writes the admin audit log holds, by table. */
export const ADMIN_AUDIT_LOG_WRITER_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    admin_audit_log: Object.freeze(['SELECT', 'INSERT'] as const),
    admin_audit_log_checkpoints: Object.freeze(['SELECT'] as const),
  });

/** Postgres truncates identifiers to 63 bytes (NAMEDATALEN - 1). */
const MAX_IDENTIFIER_BYTES = 63;

/**
 * Quote a role name as a Postgres identifier.
 *
 * @throws TypeError on an empty name, a NUL byte or a name over 63 bytes,
 *   which Postgres would truncate to some other role's name.
 */
function quoteRole(role: string): string {
  if (role === '' || role.includes('\0') || Buffer.byteLength(role) > MAX_IDENTIFIER_BYTES) {
    throw new TypeError('adminAuditLogWriterGrantStatements: not a valid role name');
  }
  return `"${role.replaceAll('"', '""')}"`;
}

/**
 * The statements that give `role` exactly {@link ADMIN_AUDIT_LOG_WRITER_GRANTS}:
 * they first revoke whatever else the role held on the two tables and on the
 * prune function, so running them again gives the same grants.
 *
 * @param role - An existing database role, as the operator named it.
 */
export function adminAuditLogWriterGrantStatements(role: string): string[] {
  const grantee = quoteRole(role);
  return [
    `REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM ${grantee}`,
    `REVOKE ALL ON FUNCTION "admin_audit_log_prune"(uuid, bigint) FROM ${grantee}`,
    ...Object.entries(ADMIN_AUDIT_LOG_WRITER_GRANTS).map(
      ([table, privileges]) => `GRANT ${privileges.join(', ')} ON TABLE "${table}" TO ${grantee}`
    ),
  ];
}
