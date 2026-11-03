import { MIGRATIONS_SCHEMA, MIGRATIONS_TABLE } from '../migrations/status';
import { quoteRoleName, type TablePrivilege } from '../role-grants';
import { DATABASE_GRANTS, type DatabaseGrantsMap } from './grants-map';
import { type DatabaseRole, type DatabaseUserAssignment, usersByRole } from './roles';

/**
 * The statements that give each role's database user exactly its grants
 * (issue #498): what {@link DATABASE_GRANTS} gives its roles, merged for a
 * user two roles share.
 */

/** The privileges in the order `GRANT` lists them here. */
const PRIVILEGE_ORDER: readonly TablePrivilege[] = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'];

/** What one database user holds once the grants are applied. */
export interface UserGrants {
  readonly user: string;
  /** The roles that connect as it. */
  readonly roles: readonly DatabaseRole[];
  /** Its privileges, by table, for the tables it holds any on. */
  readonly tables: ReadonlyMap<string, readonly TablePrivilege[]>;
  /**
   * The columns it may read, by table, of the tables it holds no table-wide
   * `SELECT` on.
   */
  readonly columns: ReadonlyMap<string, readonly string[]>;
  /** The functions it may execute, by signature. */
  readonly functions: readonly string[];
}

/** The grants of each distinct user of `users`, in role order. */
export function grantsOfUsers(
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): UserGrants[] {
  return [...usersByRole(users)].map(([user, roles]) => {
    const tables = new Map<string, readonly TablePrivilege[]>();
    for (const table of Object.keys(map.tables).sort()) {
      const held = new Set(roles.flatMap((role) => map.tables[table]?.[role] ?? []));
      if (held.size > 0) {
        tables.set(
          table,
          PRIVILEGE_ORDER.filter((privilege) => held.has(privilege))
        );
      }
    }
    const columns = new Map<string, readonly string[]>();
    for (const table of Object.keys(map.columns).sort()) {
      if (tables.get(table)?.includes('SELECT')) continue;
      const held = new Set(roles.flatMap((role) => map.columns[table]?.[role] ?? []));
      if (held.size > 0) columns.set(table, [...held].sort());
    }
    const functions = Object.keys(map.functions)
      .filter((signature) => roles.some((role) => map.functions[signature]?.includes(role)))
      .sort();
    return { user, roles, tables, columns, functions };
  });
}

function quoted(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

/** The migrations journal every role reads at boot (`awaitDatabaseMigrations`). */
const MIGRATIONS_JOURNAL = `${quoted(MIGRATIONS_SCHEMA)}.${quoted(MIGRATIONS_TABLE)}`;

/**
 * The statements that give each user of `users` exactly its grants. Each
 * user's first statements revoke everything it held on the schema's tables,
 * sequences and functions, so running them again gives the same grants, and
 * a grant the map no longer names goes.
 *
 * Run them as the owner of the tables, in one transaction. They do not touch
 * what `PUBLIC` holds, nor what a user inherits from a role it is a member
 * of: the check after them (`checkDatabaseUserGrants`) finds that.
 */
export function databaseUserGrantStatements(
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): string[] {
  const statements: string[] = [];
  for (const grants of grantsOfUsers(users, map)) {
    const grantee = quoteRoleName(grants.user, 'databaseUserGrantStatements');
    statements.push(
      `REVOKE ALL ON ALL TABLES IN SCHEMA "public" FROM ${grantee}`,
      `REVOKE ALL ON ALL SEQUENCES IN SCHEMA "public" FROM ${grantee}`,
      `REVOKE ALL ON ALL ROUTINES IN SCHEMA "public" FROM ${grantee}`,
      `REVOKE CREATE ON SCHEMA "public" FROM ${grantee}`,
      `REVOKE ALL ON ALL TABLES IN SCHEMA ${quoted(MIGRATIONS_SCHEMA)} FROM ${grantee}`,
      `REVOKE ALL ON SCHEMA ${quoted(MIGRATIONS_SCHEMA)} FROM ${grantee}`,
      `GRANT USAGE ON SCHEMA ${quoted(MIGRATIONS_SCHEMA)} TO ${grantee}`,
      `GRANT SELECT ON TABLE ${MIGRATIONS_JOURNAL} TO ${grantee}`
    );
    for (const [table, privileges] of grants.tables) {
      statements.push(`GRANT ${privileges.join(', ')} ON TABLE ${quoted(table)} TO ${grantee}`);
    }
    for (const [table, columns] of grants.columns) {
      statements.push(
        `GRANT SELECT (${columns.map(quoted).join(', ')}) ON TABLE ${quoted(table)} TO ${grantee}`
      );
    }
    if (grants.functions.length > 0) {
      statements.push(`GRANT EXECUTE ON FUNCTION ${grants.functions.join(', ')} TO ${grantee}`);
    }
  }
  return statements;
}
