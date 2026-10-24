import { quoteRoleName, type TablePrivilege } from '../role-grants';

/**
 * Database grants for the retention role (ADR-019 Decision 7, ADR-020 §3,
 * issue #536).
 *
 * The retention role is the only role granted `DELETE` on `events`: no
 * writer (`eventsWriterGrantStatements`) and not the delivery role
 * (`eventDeliveryGrantStatements`) holds it. It holds:
 *
 * - `events`: `SELECT` and `DELETE`, to find the oldest rows past their
 *   retention, check the admin rows it deletes against the chain, and
 *   delete them. A row's deliveries go with it through the foreign key's
 *   `ON DELETE CASCADE`, which Postgres runs as the owner of
 *   `event_deliveries`, so the role needs no grant to delete them.
 * - `event_chain_anchors`: `SELECT`, `INSERT` and `UPDATE`, to move a
 *   realm's anchor forward when it deletes admin rows.
 * - `event_deliveries` and `event_delivery_positions`: `SELECT`, to tell
 *   which events every enabled destination has finished.
 * - `realms`: `SELECT` on the id and the two retention columns only.
 *
 * QAuth creates no database users: the operator does, and the per-role
 * grants script (#498) applies these statements to the user the topology
 * area runs the retention job as. Until the roles are split, the one
 * database user owns the tables and can delete rows; the hash chain and its
 * anchor show a removed admin row.
 */
export const EVENT_RETENTION_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    events: Object.freeze(['SELECT', 'DELETE'] as const),
    event_chain_anchors: Object.freeze(['SELECT', 'INSERT', 'UPDATE'] as const),
    event_deliveries: Object.freeze(['SELECT'] as const),
    event_delivery_positions: Object.freeze(['SELECT'] as const),
  });

/** The columns of `realms` the retention role may read: a realm's retention. */
export const EVENT_RETENTION_REALM_COLUMNS: readonly string[] = Object.freeze([
  'id',
  'user_event_retention_days',
  'admin_event_retention_days',
]);

/**
 * The statements that give `role` exactly {@link EVENT_RETENTION_GRANTS} and
 * `SELECT` on {@link EVENT_RETENTION_REALM_COLUMNS}: they first revoke
 * whatever else the role held on those tables (a table's `REVOKE ALL` takes
 * its column privileges too), so running them again gives the same grants.
 *
 * @param role - An existing database role, as the operator named it.
 */
export function eventRetentionGrantStatements(role: string): string[] {
  const grantee = quoteRoleName(role, 'eventRetentionGrantStatements');
  const tables = Object.entries(EVENT_RETENTION_GRANTS);
  const columns = EVENT_RETENTION_REALM_COLUMNS.map((column) => `"${column}"`).join(', ');
  return [
    ...tables.map(([table]) => `REVOKE ALL ON TABLE "${table}" FROM ${grantee}`),
    `REVOKE ALL ON TABLE "realms" FROM ${grantee}`,
    ...tables.map(
      ([table, privileges]) => `GRANT ${privileges.join(', ')} ON TABLE "${table}" TO ${grantee}`
    ),
    `GRANT SELECT (${columns}) ON TABLE "realms" TO ${grantee}`,
  ];
}
