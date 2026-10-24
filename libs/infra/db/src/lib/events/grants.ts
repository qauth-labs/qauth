import { quoteRoleName, type TablePrivilege } from '../role-grants';

/**
 * Database grants for the event store (ADR-019 Decision 7, issue #459).
 *
 * A role that writes events holds only `INSERT` and `SELECT` on `events`:
 * `SELECT` because an admin event reads the realm's chain head and reads its
 * own row back to check its hash. No writer is granted `UPDATE` (a trigger
 * refuses it for every role anyway) or `DELETE`, which only the retention
 * job's role holds (#536). The identity column needs no sequence grant.
 *
 * QAuth creates no database users: the operator does, and the per-role grants
 * script (#498) applies these statements to the users it is given. Until the
 * roles are split, the one database user owns the table and can delete rows;
 * the hash chain shows a removed admin row.
 */

/** What a role that writes events holds, by table. */
export const EVENTS_WRITER_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    events: Object.freeze(['SELECT', 'INSERT'] as const),
  });

/**
 * The statements that give `role` exactly {@link EVENTS_WRITER_GRANTS}: they
 * first revoke whatever else the role held on `events`, so running them again
 * gives the same grants.
 *
 * @param role - An existing database role, as the operator named it.
 */
export function eventsWriterGrantStatements(role: string): string[] {
  const grantee = quoteRoleName(role, 'eventsWriterGrantStatements');
  return [
    `REVOKE ALL ON TABLE "events" FROM ${grantee}`,
    ...Object.entries(EVENTS_WRITER_GRANTS).map(
      ([table, privileges]) => `GRANT ${privileges.join(', ')} ON TABLE "${table}" TO ${grantee}`
    ),
  ];
}
