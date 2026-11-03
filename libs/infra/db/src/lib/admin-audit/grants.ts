import { quoteRoleName, type TablePrivilege } from '../role-grants';

export type { TablePrivilege } from '../role-grants';

/**
 * Database grants for the admin audit log (ADR-019 Decision 7, issue #448).
 *
 * The roles that write the log hold only `INSERT` and `SELECT` on it, and only
 * `SELECT` on its checkpoints, which `admin_audit_log_prune` writes.
 * The prune function itself stays with the table owner; the retention job's
 * role (#536) is the only one ever granted `EXECUTE` on it.
 *
 * QAuth creates no database users: the operator does. The grants map of #498
 * (`database-users/grants-map.ts`) gives the `admin` role these entries, which
 * `db:grants` and the migration runner apply to its user. While every role
 * connects as one user, the one database user owns the table: the triggers of
 * migration 0026 keep the log append-only against the application's own
 * statements, but an owner can disable a trigger.
 */

/** What a role that writes the admin audit log holds, by table. */
export const ADMIN_AUDIT_LOG_WRITER_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    admin_audit_log: Object.freeze(['SELECT', 'INSERT'] as const),
    admin_audit_log_checkpoints: Object.freeze(['SELECT'] as const),
  });

/**
 * The statements that give `role` exactly {@link ADMIN_AUDIT_LOG_WRITER_GRANTS}:
 * they first revoke whatever else the role held on the two tables and on the
 * prune function, so running them again gives the same grants.
 *
 * @param role - An existing database role, as the operator named it.
 */
export function adminAuditLogWriterGrantStatements(role: string): string[] {
  const grantee = quoteRoleName(role, 'adminAuditLogWriterGrantStatements');
  return [
    `REVOKE ALL ON TABLE "admin_audit_log", "admin_audit_log_checkpoints" FROM ${grantee}`,
    `REVOKE ALL ON FUNCTION "admin_audit_log_prune"(uuid, bigint) FROM ${grantee}`,
    ...Object.entries(ADMIN_AUDIT_LOG_WRITER_GRANTS).map(
      ([table, privileges]) => `GRANT ${privileges.join(', ')} ON TABLE "${table}" TO ${grantee}`
    ),
  ];
}
