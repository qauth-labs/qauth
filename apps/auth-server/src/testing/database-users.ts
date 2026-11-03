import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

import type { ServiceRole } from '../app/service-roles';

/**
 * TEST SUPPORT — the service roles' own database users (#498).
 *
 * A suite that runs a role on a database user of its own creates the users
 * as an operator does ({@link createDatabaseUsers}), gives them their grants
 * with the operator's `db:grants` command ({@link grantDatabaseUsers}), and
 * boots each process on its user ({@link databaseUrlAs}). Database users are
 * cluster-wide, so a suite names its own or starts a Postgres server of its
 * own.
 *
 * `db:grants` runs as a child process, as an operator runs it: the auth
 * server's code may not import the database library's grant builder.
 */

/** The database library, whose `db:grants` command the suites run. */
const DB_LIB = path.resolve(__dirname, '..', '..', '..', '..', 'libs', 'infra', 'db');
const TSX_CLI = createRequire(path.join(DB_LIB, 'package.json')).resolve('tsx/cli');

/** `connectionString`, connecting as `user`, whose password is its own name. */
export function databaseUrlAs(connectionString: string, user: string): string {
  const url = new URL(connectionString);
  url.username = user;
  url.password = user;
  return url.toString();
}

/**
 * Create each of `users` as a login role whose password is its own name,
 * through `owner`, a pool that connects as a role allowed to create roles.
 */
export async function createDatabaseUsers(
  owner: { query(sql: string): Promise<unknown> },
  users: readonly string[]
): Promise<void> {
  for (const user of new Set(users)) {
    if (!/^[a-z_][a-z0-9_]*$/.test(user)) throw new Error(`not a plain role name: ${user}`);
    await owner.query(`CREATE ROLE ${user} LOGIN PASSWORD '${user}'`);
  }
}

/**
 * Run `db:grants` as an operator runs it, against `connectionString` (the
 * owner of the tables), naming `users` as the five roles' users. A user it
 * does not name keeps its grants, so two runs that name one user for two
 * roles give it both roles' grants and nothing else. Throws with the
 * command's output when it does not exit 0.
 */
export async function grantDatabaseUsers(
  connectionString: string,
  users: Readonly<Record<ServiceRole, string>>
): Promise<void> {
  const child = spawn(process.execPath, [TSX_CLI, 'src/scripts/grant-database-users.ts'], {
    cwd: DB_LIB,
    env: {
      PATH: process.env['PATH'] ?? '',
      DATABASE_URL: connectionString,
      DB_USER_WEB: users.web,
      DB_USER_API: users.api,
      DB_USER_ADMIN: users.admin,
      DB_USER_SIGNER: users.signer,
      DB_USER_DELIVERY: users.delivery,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
  child.stderr.on('data', (chunk: Buffer) => (output += chunk.toString('utf8')));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', resolve);
  });
  if (code !== 0) throw new Error(`db:grants exited ${String(code)}:\n${output}`);
}

/** What Postgres logs and answers when a user lacks a privilege. */
export const PERMISSION_ERROR = /permission denied|insufficient_privilege|"code":"42501"/;
