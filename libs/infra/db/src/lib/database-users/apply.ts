import { Client } from 'pg';

import { MIGRATION_LOCK_NAME } from '../migrations/runner';
import { type MigrationQueryable, MIGRATIONS_SCHEMA, MIGRATIONS_TABLE } from '../migrations/status';
import { DATABASE_GRANTS, type DatabaseGrantsMap } from './grants-map';
import { type DatabaseUserAssignment } from './roles';
import { databaseUserGrantStatements, grantsOfUsers, type UserGrants } from './statements';

/**
 * Apply and check the grants of the roles' database users (issue #498).
 *
 * {@link applyDatabaseUserGrants} runs as the owner of the tables (the
 * migration runner's user), in one transaction under the migration lock:
 * it checks the users first, applies {@link databaseUserGrantStatements},
 * then reads back what each user can do and commits only when that is
 * exactly what the map gives it. What a user holds through `PUBLIC`, or
 * through any role it is a member of (whether it inherits that role's
 * privileges or can only `SET ROLE` to it), counts, so a user that can still
 * read `realm_keys` through some other grant fails the run instead of
 * passing it.
 */

/**
 * The predefined roles whose members read or write every table, or the
 * server's files and programs, whatever a table grants: a role user that is
 * a member of one is refused.
 */
const ALL_REACHING_ROLES = [
  'pg_read_all_data',
  'pg_write_all_data',
  'pg_read_server_files',
  'pg_write_server_files',
  'pg_execute_server_program',
] as const;

/**
 * The roles `$1` (a user's name) is a member of, itself included, with or
 * without inheriting their privileges: a member that does not inherit can
 * still `SET ROLE` to one and use them.
 */
const REACHABLE_ROLES = `SELECT oid FROM pg_roles WHERE pg_has_role($1, oid, 'MEMBER')`;

/** Every table privilege Postgres has, so a check sees the ones QAuth never grants too. */
const ALL_TABLE_PRIVILEGES = [
  'SELECT',
  'INSERT',
  'UPDATE',
  'DELETE',
  'TRUNCATE',
  'REFERENCES',
  'TRIGGER',
] as const;

/** The table privileges a column can hold as well. */
const COLUMN_PRIVILEGES: ReadonlySet<string> = new Set([
  'SELECT',
  'INSERT',
  'UPDATE',
  'REFERENCES',
]);

/** Where to connect: as the owner of the tables. */
export interface DatabaseUserGrantsTarget {
  /** A `postgresql://` URL. */
  readonly connectionString: string;
  /** How long to wait for a connection, in milliseconds. Ten seconds unless set. */
  readonly connectTimeoutMs?: number;
}

/** A run that changed nothing, and why: each problem in one line. */
export class DatabaseUserGrantsError extends Error {
  constructor(
    message: string,
    readonly problems: readonly string[]
  ) {
    super(`${message}\n${problems.map((problem) => `  - ${problem}`).join('\n')}`);
    this.name = 'DatabaseUserGrantsError';
  }
}

/** What a run granted. */
export interface DatabaseUserGrantsReport {
  /** Each distinct user, with its roles and its grants. */
  readonly users: readonly UserGrants[];
}

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

async function connect(target: DatabaseUserGrantsTarget): Promise<Client> {
  const client = new Client({
    connectionString: target.connectionString,
    connectionTimeoutMillis: target.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    application_name: 'qauth-db-grants',
  });
  // An idle connection that fails emits on the client; the next query fails instead.
  client.on('error', () => undefined);
  try {
    await client.connect();
  } catch (error) {
    await client.end().catch(() => undefined);
    throw error;
  }
  return client;
}

/**
 * Why the grants cannot be applied as the current user: a table or function
 * of the map the database lacks (migrations pending), a table the current
 * user does not own, and each named user that does not exist, is a
 * superuser, owns (or is a member of the owner of) a table, holds an
 * attribute or a predefined role that reaches past the table grants, or may
 * create schemas in the database. Empty when they can.
 */
export async function databaseUserGrantRefusals(
  db: MigrationQueryable,
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): Promise<string[]> {
  const problems: string[] = [];
  const tables = Object.keys(map.tables);
  const { rows: missingTables } = await db.query(
    `SELECT t.name FROM unnest($1::text[]) AS t(name)
      WHERE to_regclass(quote_ident('public') || '.' || quote_ident(t.name)) IS NULL
      ORDER BY t.name`,
    [[...new Set([...tables, ...Object.keys(map.columns)])]]
  );
  for (const row of missingTables) {
    problems.push(
      `The database has no table ${String(row['name'])}: run the migration runner of this release first.`
    );
  }
  const { rows: missingFunctions } = await db.query(
    `SELECT f.signature FROM unnest($1::text[]) AS f(signature)
      WHERE to_regprocedure(f.signature) IS NULL ORDER BY f.signature`,
    [Object.keys(map.functions)]
  );
  for (const row of missingFunctions) {
    problems.push(
      `The database has no function ${String(row['signature'])}: run the migration runner of this release first.`
    );
  }
  const { rows: journal } = await db.query(
    `SELECT to_regclass(quote_ident($1) || '.' || quote_ident($2)) IS NOT NULL AS present`,
    [MIGRATIONS_SCHEMA, MIGRATIONS_TABLE]
  );
  if (journal[0]?.['present'] !== true) {
    problems.push(
      'The database has no migrations journal: run the migration runner of this release first.'
    );
  }

  // The current user grants as the owner: on a table it does not own, GRANT
  // only warns and grants nothing.
  const { rows: notOwned } = await db.query(
    `SELECT c.relname AS name, pg_get_userbyid(c.relowner) AS owner
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ('public', $1) AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        AND NOT pg_has_role(current_user, c.relowner, 'USAGE')
      ORDER BY n.nspname, c.relname`,
    [MIGRATIONS_SCHEMA]
  );
  if (notOwned.length > 0) {
    const named = notOwned
      .slice(0, 5)
      .map((row) => `${String(row['name'])} (owned by ${String(row['owner'])})`)
      .join(', ');
    problems.push(
      `The current user does not own ${notOwned.length === 1 ? 'the table' : `${notOwned.length} tables, among them`} ${named}: ` +
        'apply the grants as the owner of the tables, the migration runner’s user.'
    );
  }

  const named = [...new Set(Object.values(users))];
  const { rows: found } = await db.query(
    `SELECT u.name, r.oid IS NOT NULL AS exists, coalesce(r.rolsuper, false) AS superuser,
            r.rolname = current_user AS is_current,
            EXISTS (
              SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname IN ('public', $2) AND pg_has_role(r.oid, c.relowner, 'MEMBER')
            ) OR EXISTS (
              SELECT 1 FROM pg_namespace n
               WHERE n.nspname IN ('public', $2) AND pg_has_role(r.oid, n.nspowner, 'MEMBER')
            ) AS owns,
            array_remove(ARRAY[
              CASE WHEN r.rolreplication THEN 'REPLICATION' END,
              CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END,
              CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END
            ], NULL) AS attributes,
            ARRAY(
              SELECT p.name FROM unnest($3::text[]) AS p(name)
               WHERE to_regrole(p.name) IS NOT NULL
                 AND pg_has_role(r.oid, to_regrole(p.name), 'MEMBER')
               ORDER BY p.name
            ) AS predefined,
            r.oid IS NOT NULL AND has_database_privilege(r.oid, current_database(), 'CREATE')
              AS creates_schemas
       FROM unnest($1::text[]) AS u(name) LEFT JOIN pg_roles r ON r.rolname = u.name`,
    [named, MIGRATIONS_SCHEMA, [...ALL_REACHING_ROLES]]
  );
  for (const row of found) {
    const user = JSON.stringify(String(row['name']));
    if (row['exists'] !== true) {
      problems.push(
        `The database user ${user} does not exist: create it first (CREATE ROLE … LOGIN PASSWORD …). ` +
          'QAuth creates no database user.'
      );
    } else if (row['superuser'] === true) {
      problems.push(`The database user ${user} is a superuser, which no grant can restrict.`);
    } else if (row['is_current'] === true || row['owns'] === true) {
      problems.push(
        `The database user ${user} owns the schema or its tables, or is a member of their owner: ` +
          'a role user must not be the migration runner’s user, which can change the schema.'
      );
    } else {
      const attributes = (row['attributes'] as string[] | null) ?? [];
      if (attributes.length > 0) {
        problems.push(
          `The database user ${user} has ${attributes.join(', ')}, which reaches past the table grants: ` +
            `ALTER ROLE ${user} ${attributes.map((attribute) => `NO${attribute}`).join(' ')}.`
        );
      }
      const predefined = (row['predefined'] as string[] | null) ?? [];
      if (predefined.length > 0) {
        problems.push(
          `The database user ${user} is a member of ${predefined.join(', ')}, which reads or writes ` +
            'past the table grants: revoke the membership.'
        );
      }
      if (row['creates_schemas'] === true) {
        problems.push(
          `The database user ${user} may create schemas in the database: REVOKE CREATE ON DATABASE … FROM ${user} (and from PUBLIC).`
        );
      }
    }
  }
  return problems;
}

/**
 * How each user's privileges differ from what the map gives its roles, read
 * from Postgres as it stands: what the user holds directly, through `PUBLIC`
 * and through every role it is a member of, one it can only `SET ROLE` to
 * included. Sequences count too: the map grants none. Empty when every user
 * holds exactly its grants. A function `PUBLIC` may execute is not counted
 * against a user, unless it runs as its owner (`SECURITY DEFINER`): that is
 * reported once, for every user.
 */
export async function databaseUserGrantDrift(
  db: MigrationQueryable,
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): Promise<string[]> {
  const problems: string[] = [];
  // A function that runs as its owner and that PUBLIC may execute gives every
  // role user its owner's reach. Each migration takes EXECUTE on one from
  // PUBLIC, and the map gives it to the roles that call it.
  const { rows: openDefiners } = await db.query(
    `SELECT p.oid::regprocedure::text AS signature
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public' AND p.prosecdef
        AND has_function_privilege('public', p.oid, 'EXECUTE')
      ORDER BY 1`
  );
  for (const row of openDefiners) {
    const signature = String(row['signature']);
    problems.push(
      `PUBLIC may execute ${signature}, which runs as its owner: REVOKE EXECUTE ON FUNCTION ${signature} FROM PUBLIC.`
    );
  }
  for (const grants of grantsOfUsers(users, map)) {
    const who = `${JSON.stringify(grants.user)} (${grants.roles.join(', ')})`;

    // `on_table` is what the user's own sessions use; `reachable` adds what a
    // role it is a member of holds, which `SET ROLE` reaches.
    const { rows: tablePrivileges } = await db.query(
      `WITH reach AS (${REACHABLE_ROLES})
       SELECT c.relname AS name, p.privilege,
              has_table_privilege($1, c.oid, p.privilege) AS on_table,
              EXISTS (SELECT 1 FROM reach WHERE has_table_privilege(reach.oid, c.oid, p.privilege))
                AS reachable,
              CASE WHEN p.privilege = ANY($3::text[])
                   THEN EXISTS (SELECT 1 FROM reach
                                 WHERE has_any_column_privilege(reach.oid, c.oid, p.privilege))
                   ELSE false END AS on_column
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN unnest($2::text[]) AS p(privilege)
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        ORDER BY c.relname, array_position($2::text[], p.privilege)`,
      [grants.user, [...ALL_TABLE_PRIVILEGES], [...COLUMN_PRIVILEGES]]
    );
    for (const row of tablePrivileges) {
      const table = String(row['name']);
      const privilege = String(row['privilege']);
      const expected = (grants.tables.get(table) as readonly string[] | undefined)?.includes(
        privilege
      );
      const onTable = row['on_table'] === true;
      if (expected === true && !onTable) {
        problems.push(`${who} lacks ${privilege} on ${table}, which the map gives it.`);
      } else if (expected !== true && row['reachable'] === true) {
        problems.push(
          `${who} holds ${privilege} on ${table}, which the map does not give it: directly, through PUBLIC or through a role it is a member of.`
        );
      } else if (
        expected !== true &&
        row['on_column'] === true &&
        !(privilege === 'SELECT' && grants.columns.has(table))
      ) {
        problems.push(
          `${who} holds ${privilege} on columns of ${table}, which the map does not give it.`
        );
      }
    }

    for (const [table, columns] of grants.columns) {
      const { rows } = await db.query(
        `WITH reach AS (${REACHABLE_ROLES})
         SELECT a.attname AS name, has_column_privilege($1, c.oid, a.attnum, 'SELECT') AS readable,
                EXISTS (SELECT 1 FROM reach
                         WHERE has_column_privilege(reach.oid, c.oid, a.attnum, 'SELECT'))
                  AS reachable
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
          WHERE n.nspname = 'public' AND c.relname = $2
          ORDER BY a.attnum`,
        [grants.user, table]
      );
      for (const row of rows) {
        const column = String(row['name']);
        const expected = columns.includes(column);
        if (expected && row['readable'] !== true) {
          problems.push(`${who} cannot read ${table}.${column}, which the map gives it.`);
        } else if (!expected && row['reachable'] === true) {
          problems.push(`${who} can read ${table}.${column}, which the map does not give it.`);
        }
      }
    }

    // A function PUBLIC may execute is anyone's, and not counted here,
    // unless it runs as its owner: that one is reported once, below.
    const { rows: functions } = await db.query(
      `WITH reach AS (${REACHABLE_ROLES})
       SELECT p.oid::regprocedure::text AS signature,
              has_function_privilege($1, p.oid, 'EXECUTE') AS executable,
              EXISTS (SELECT 1 FROM reach WHERE has_function_privilege(reach.oid, p.oid, 'EXECUTE'))
                AS reachable,
              p.oid = ANY (SELECT to_regprocedure(s)::oid FROM unnest($2::text[]) AS s) AS granted,
              has_function_privilege('public', p.oid, 'EXECUTE') AS public
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
        ORDER BY 1`,
      [grants.user, [...grants.functions]]
    );
    for (const row of functions) {
      const signature = String(row['signature']);
      if (row['granted'] === true && row['executable'] !== true) {
        problems.push(`${who} cannot execute ${signature}, which the map gives it.`);
      } else if (row['granted'] !== true && row['public'] !== true && row['reachable'] === true) {
        problems.push(`${who} can execute ${signature}, which the map does not give it.`);
      }
    }

    // The map gives no role a sequence: the identity columns need none.
    const { rows: sequences } = await db.query(
      `WITH reach AS (${REACHABLE_ROLES})
       SELECT c.relname AS name, p.privilege
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p(privilege)
        WHERE n.nspname = 'public' AND c.relkind = 'S'
          AND EXISTS (SELECT 1 FROM reach WHERE has_sequence_privilege(reach.oid, c.oid, p.privilege))
        ORDER BY c.relname, p.privilege`,
      [grants.user]
    );
    for (const row of sequences) {
      problems.push(
        `${who} holds ${String(row['privilege'])} on the sequence ${String(row['name'])}, which the map does not give it.`
      );
    }

    const { rows: schemas } = await db.query(
      `WITH reach AS (${REACHABLE_ROLES})
       SELECT has_schema_privilege($1, 'public', 'USAGE') AS public_usage,
              EXISTS (SELECT 1 FROM reach WHERE has_schema_privilege(reach.oid, 'public', 'CREATE'))
                AS public_create,
              has_schema_privilege($1, $2, 'USAGE') AS journal_usage,
              EXISTS (SELECT 1 FROM reach WHERE has_schema_privilege(reach.oid, $2, 'CREATE'))
                AS journal_create,
              has_table_privilege($1, quote_ident($2) || '.' || quote_ident($3), 'SELECT') AS journal_read,
              EXISTS (SELECT 1 FROM reach
                       WHERE has_table_privilege(reach.oid, quote_ident($2) || '.' || quote_ident($3),
                               'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'))
                AS journal_write`,
      [grants.user, MIGRATIONS_SCHEMA, MIGRATIONS_TABLE]
    );
    const schema = schemas[0] ?? {};
    if (schema['public_usage'] !== true) {
      problems.push(`${who} cannot use the schema public: grant it USAGE on it.`);
    }
    if (schema['public_create'] === true || schema['journal_create'] === true) {
      problems.push(
        `${who} can create objects in the schema ${schema['public_create'] === true ? 'public' : MIGRATIONS_SCHEMA}: ` +
          'revoke CREATE on it from the user and from PUBLIC (REVOKE CREATE ON SCHEMA public FROM PUBLIC).'
      );
    }
    if (schema['journal_usage'] !== true || schema['journal_read'] !== true) {
      problems.push(`${who} cannot read the migrations journal, which every role reads at boot.`);
    }
    if (schema['journal_write'] === true) {
      problems.push(`${who} can change the migrations journal.`);
    }
  }
  return problems;
}

/**
 * Give each user of `users` exactly the grants of its roles, as the owner of
 * the tables, in one transaction under the migration lock: a second run
 * waits, a migration run waits, and a failure changes nothing.
 *
 * @throws DatabaseUserGrantsError when a check refuses the run (a user that
 *   does not exist, owns the tables or is a superuser; pending migrations;
 *   a current user that is not the owner), or when a user still holds more
 *   or less than its grants once they are applied. Any other error is the
 *   database's.
 */
export async function applyDatabaseUserGrants(
  target: DatabaseUserGrantsTarget,
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): Promise<DatabaseUserGrantsReport> {
  const statements = databaseUserGrantStatements(users, map);
  const client = await connect(target);
  try {
    await client.query('BEGIN');
    try {
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [
        MIGRATION_LOCK_NAME,
      ]);
      const refusals = await databaseUserGrantRefusals(client, users, map);
      if (refusals.length > 0) {
        throw new DatabaseUserGrantsError('The grants were not applied:', refusals);
      }
      for (const statement of statements) await client.query(statement);
      const drift = await databaseUserGrantDrift(client, users, map);
      if (drift.length > 0) {
        throw new DatabaseUserGrantsError(
          'The grants were not applied: once granted, the users would hold other privileges than the map gives them.',
          drift
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    }
  } finally {
    await client.end().catch(() => undefined);
  }
  return { users: grantsOfUsers(users, map) };
}

/**
 * Check, changing nothing, that each user of `users` holds exactly the
 * grants of its roles. Returns the problems: why the grants could not be
 * applied, then how each user's privileges differ. Empty when current.
 */
export async function checkDatabaseUserGrants(
  target: DatabaseUserGrantsTarget,
  users: DatabaseUserAssignment,
  map: DatabaseGrantsMap = DATABASE_GRANTS
): Promise<string[]> {
  const client = await connect(target);
  try {
    const refusals = await databaseUserGrantRefusals(client, users, map);
    // Without the tables, every privilege on them would be reported missing.
    if (refusals.some((problem) => problem.startsWith('The database has no'))) return refusals;
    return [...refusals, ...(await databaseUserGrantDrift(client, users, map))];
  } finally {
    await client.end().catch(() => undefined);
  }
}

/** One line per user: who it is, for which roles, and how many grants it got. */
export function describeDatabaseUserGrants(report: DatabaseUserGrantsReport): string[] {
  return report.users.map(
    (grants) =>
      `${JSON.stringify(grants.user)} (${grants.roles.join(', ')}): ` +
      `${grants.tables.size} ${grants.tables.size === 1 ? 'table' : 'tables'}` +
      (grants.columns.size > 0 ? `, columns of ${[...grants.columns.keys()].join(', ')}` : '') +
      (grants.functions.length > 0
        ? `, ${grants.functions.length} ${grants.functions.length === 1 ? 'function' : 'functions'}`
        : '')
  );
}
