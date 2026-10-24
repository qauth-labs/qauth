import { quoteRoleName, type TablePrivilege } from '../role-grants';

/**
 * Database grants for the event store (ADR-019 Decision 7, issues #459 and
 * #827).
 *
 * A role that writes events holds `INSERT` on `events` and `EXECUTE` on the
 * two functions an admin event reads through (migration 0033):
 * `events_admin_chain_head`, the realm's chain head, and `events_own_row`,
 * the row its own transaction wrote, read back to check its hash. It holds
 * no `SELECT`: with it, a writer could read every realm's events, request
 * IPs, user agents and admin diffs included. No writer is granted `UPDATE`
 * (a trigger refuses it for every role anyway) or `DELETE`, which only the
 * retention job's role holds (#536). The identity column needs no sequence
 * grant.
 *
 * QAuth creates no database users: the operator does, and the per-role grants
 * script (#498) applies these statements to the users it is given. Until the
 * roles are split, the one database user owns the table and can delete rows;
 * the hash chain shows a removed admin row.
 */

/** What a role that writes events holds, by table. */
export const EVENTS_WRITER_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    events: Object.freeze(['INSERT'] as const),
  });

/** The functions a role that writes events may execute, by signature. */
export const EVENTS_WRITER_FUNCTIONS: readonly string[] = Object.freeze([
  '"events_admin_chain_head"(uuid)',
  '"events_own_row"(uuid)',
]);

/**
 * The statements that give `role` exactly {@link EVENTS_WRITER_GRANTS} and
 * {@link EVENTS_WRITER_FUNCTIONS}: they first revoke whatever else the role
 * held on `events`, so running them again gives the same grants.
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
    `GRANT EXECUTE ON FUNCTION ${EVENTS_WRITER_FUNCTIONS.join(', ')} TO ${grantee}`,
  ];
}
