import { quoteRoleName } from '../role-grants';

/**
 * The database users of the service roles (ADR-019 Decisions 8 and 9, issue
 * #498).
 *
 * Each service role connects to Postgres as a user of its own, with only the
 * grants it needs (`grants-map.ts`). The operator creates the users and sets
 * their passwords; QAuth only grants. The roles are the auth server's
 * `SERVICE_ROLES` (`SERVICE_ROLE_NAMES` in `@qauth-labs/server-config`, which
 * this layer cannot import; the auth server's tests check that the two lists
 * agree).
 */

/** The service roles that connect to the database, in the order the auth server lists them. */
export const DATABASE_ROLES = Object.freeze(['web', 'api', 'admin', 'signer', 'delivery'] as const);

/** A service role, as a holder of database grants. */
export type DatabaseRole = (typeof DATABASE_ROLES)[number];

/** The environment variable that names each role's database user. */
export const DATABASE_USER_ENV: Readonly<Record<DatabaseRole, string>> = Object.freeze({
  web: 'DB_USER_WEB',
  api: 'DB_USER_API',
  admin: 'DB_USER_ADMIN',
  signer: 'DB_USER_SIGNER',
  delivery: 'DB_USER_DELIVERY',
});

/**
 * Which database user each role connects as. Two roles that run in one
 * process share its `DATABASE_URL`, so they name the same user, which gets
 * the grants of both.
 */
export type DatabaseUserAssignment = Readonly<Record<DatabaseRole, string>>;

/** What {@link databaseUsersFromEnv} read. */
export type DatabaseUsersConfig =
  /**
   * No `DB_USER_*` variable is set: a single deployment, whose one database
   * user owns the tables and holds every privilege. There is nothing to grant.
   */
  | { readonly configured: false }
  | { readonly configured: true; readonly users: DatabaseUserAssignment }
  /** Some are set but not all, or one is not a usable role name. Nothing is granted. */
  | { readonly configured: 'invalid'; readonly problems: readonly string[] };

/**
 * Read the `DB_USER_*` variables. Every role needs a user once one has: a
 * role left out would connect as some other user, perhaps the owner, which
 * reads every table. A blank value counts as unset.
 */
export function databaseUsersFromEnv(
  env: Readonly<Record<string, string | undefined>>
): DatabaseUsersConfig {
  const named = DATABASE_ROLES.map((role) => {
    const value = env[DATABASE_USER_ENV[role]];
    return { role, value: value === undefined || value.trim() === '' ? undefined : value };
  });
  if (named.every(({ value }) => value === undefined)) return { configured: false };

  const problems: string[] = [];
  const missing = named.filter(({ value }) => value === undefined).map(({ role }) => role);
  if (missing.length > 0) {
    problems.push(
      `${missing.map((role) => DATABASE_USER_ENV[role]).join(', ')} ${missing.length === 1 ? 'is' : 'are'} not set: ` +
        'once one role has a database user of its own, every role needs one. Name the same ' +
        'user for the roles that run in one process.'
    );
  }
  for (const { role, value } of named) {
    if (value === undefined) continue;
    try {
      quoteRoleName(value, DATABASE_USER_ENV[role]);
    } catch {
      problems.push(
        `${DATABASE_USER_ENV[role]} is not a usable Postgres role name: it is empty, holds a NUL byte, or is longer than 63 bytes.`
      );
    }
  }
  if (problems.length > 0) return { configured: 'invalid', problems };

  const users = Object.fromEntries(named.map(({ role, value }) => [role, value as string]));
  return { configured: true, users: users as DatabaseUserAssignment };
}

/** The distinct users of an assignment, each with the roles it connects for, in role order. */
export function usersByRole(
  users: DatabaseUserAssignment
): ReadonlyMap<string, readonly DatabaseRole[]> {
  const byUser = new Map<string, DatabaseRole[]>();
  for (const role of DATABASE_ROLES) {
    const user = users[role];
    const roles = byUser.get(user);
    if (roles === undefined) byUser.set(user, [role]);
    else roles.push(role);
  }
  return byUser;
}
