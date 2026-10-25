import { quoteRoleName, type TablePrivilege } from '../role-grants';

/**
 * Database grants for the delivery role (ADR-019 Decisions 7 and 8, issue
 * #460).
 *
 * The delivery role reads the event store and keeps its own queue:
 *
 * - `events`: `SELECT` only, to read each realm's stream and the event a
 *   delivery sends. It writes no event and deletes none.
 * - `event_deliveries`: `SELECT`, `INSERT` and `UPDATE`, to write the
 *   fan-out's rows and claim and finish them. A row is deleted only with its
 *   event, by the retention job (#536), through the foreign key.
 * - `event_delivery_positions`: every row privilege, since the fan-out
 *   forgets the position of a realm that has no destination of a kind left.
 * - `ssf_streams` and `ssf_stream_subjects`: `SELECT`, for the Shared
 *   Signals Framework route (#410) to list its streams and read the one it
 *   delivers to, the encrypted `authorization_header` included. The role asks
 *   the signer to decrypt that value; it holds no key.
 * - `realms` and `oauth_clients`: `SELECT` on the columns that say whether a
 *   stream may receive events (`EVENT_DELIVERY_COLUMNS`): the realm's SSF
 *   switch, and whether its receiver is enabled, not suspended and still
 *   holds the `ssf:stream` scope.
 *
 * Nothing else: no key table, no session or token table. The role holds no
 * private key (ADR-019 Decision 9); it asks the signer to sign.
 *
 * QAuth creates no database users: the operator does, and the per-role grants
 * script (#498) applies these statements to the user it is given.
 */
export const EVENT_DELIVERY_GRANTS: Readonly<Record<string, readonly TablePrivilege[]>> =
  Object.freeze({
    events: Object.freeze(['SELECT'] as const),
    event_deliveries: Object.freeze(['SELECT', 'INSERT', 'UPDATE'] as const),
    event_delivery_positions: Object.freeze(['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const),
    ssf_streams: Object.freeze(['SELECT'] as const),
    ssf_stream_subjects: Object.freeze(['SELECT'] as const),
  });

/** The columns the delivery role may read of tables it reads only in part, by table. */
export const EVENT_DELIVERY_COLUMNS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  realms: Object.freeze(['id', 'ssf_transmitter_enabled']),
  oauth_clients: Object.freeze(['id', 'enabled', 'suspended', 'scopes']),
});

/**
 * The statements that give `role` exactly {@link EVENT_DELIVERY_GRANTS} on
 * those tables and `SELECT` on {@link EVENT_DELIVERY_COLUMNS}: they first
 * revoke whatever else the role held on them (a table's `REVOKE ALL` takes
 * its column privileges too), so running them again gives the same grants.
 *
 * @param role - An existing database role, as the operator named it.
 */
export function eventDeliveryGrantStatements(role: string): string[] {
  const grantee = quoteRoleName(role, 'eventDeliveryGrantStatements');
  const tables = Object.entries(EVENT_DELIVERY_GRANTS);
  const columns = Object.entries(EVENT_DELIVERY_COLUMNS);
  return [
    ...[...tables, ...columns].map(([table]) => `REVOKE ALL ON TABLE "${table}" FROM ${grantee}`),
    ...tables.map(
      ([table, privileges]) => `GRANT ${privileges.join(', ')} ON TABLE "${table}" TO ${grantee}`
    ),
    ...columns.map(
      ([table, names]) =>
        `GRANT SELECT (${names.map((name) => `"${name}"`).join(', ')}) ON TABLE "${table}" TO ${grantee}`
    ),
  ];
}
