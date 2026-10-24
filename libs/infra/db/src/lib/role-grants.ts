/**
 * What the grant statement builders share: the privilege names and the
 * quoting of a role name.
 */

/** Privilege on a table, as `GRANT` spells it. */
export type TablePrivilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

/** Postgres truncates identifiers to 63 bytes (NAMEDATALEN - 1). */
const MAX_IDENTIFIER_BYTES = 63;

/**
 * Quote a role name as a Postgres identifier.
 *
 * @param role - The role, as the operator named it.
 * @param caller - The builder's name, for the error.
 * @throws TypeError on an empty name, a NUL byte or a name over 63 bytes,
 *   which Postgres would truncate to some other role's name.
 */
export function quoteRoleName(role: string, caller: string): string {
  if (role === '' || role.includes('\0') || Buffer.byteLength(role) > MAX_IDENTIFIER_BYTES) {
    throw new TypeError(`${caller}: not a valid role name`);
  }
  return `"${role.replaceAll('"', '""')}"`;
}
