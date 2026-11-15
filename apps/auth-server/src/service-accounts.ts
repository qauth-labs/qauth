/**
 * `auth-server:service-accounts`: create a service account for the admin API,
 * list them, and disable or enable one (ADR-019 Decision 7, issue #522).
 *
 * Run it on a host that holds the database credentials, with `DATABASE_URL`
 * naming a role that may write users, OAuth clients, service accounts, admin
 * grants and the admin audit log: the owner's, not one service role's in a
 * split deployment.
 *
 * ```console
 * pnpm nx run auth-server:service-accounts -- create --name ci-realm-import \
 *   --client-id ci-realm-import --jwks-uri https://ci.example.com/jwks.json \
 *   --grant security-admin@*
 * # In the auth-server image, from /app:
 * tsx src/service-accounts.ts disable --name ci-realm-import
 * ```
 *
 * It records each creation, disable and enable, with the operating-system
 * user, in the operator realm's admin audit log. It makes no secret and prints none: the service
 * account's private key stays with the automation that signs with it.
 */
import { readFileSync } from 'node:fs';
import { userInfo } from 'node:os';

import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import Fastify from 'fastify';

import { ADMIN_ROLE_CATALOG } from './app/helpers/admin-roles';
import {
  parseServiceAccountsArguments,
  runServiceAccountsCommand,
  SERVICE_ACCOUNTS_USAGE,
  ServiceAccountsUsageError,
} from './app/helpers/service-accounts-command';

/** The user the command runs as, as the audit record names it. */
function operatingSystemUser(): string {
  try {
    return userInfo().username;
  } catch {
    return process.env['USER'] ?? 'unknown';
  }
}

async function main(): Promise<number> {
  // A usage error exits 2 before anything connects.
  let command;
  try {
    command = parseServiceAccountsArguments(process.argv.slice(2), (path) =>
      readFileSync(path, 'utf8')
    );
  } catch (error) {
    if (!(error instanceof ServiceAccountsUsageError)) throw error;
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
  if (command === 'help') {
    process.stdout.write(`${SERVICE_ACCOUNTS_USAGE}\n`);
    return 0;
  }
  const databaseUrl = process.env['DATABASE_URL'];
  if (!databaseUrl) {
    process.stderr.write('service-accounts: set DATABASE_URL in the environment.\n');
    return 2;
  }

  // Only the database: no route, no cache, no listening port.
  const server = Fastify({ logger: { level: 'warn' } });
  try {
    await server.register(databasePlugin, {
      config: { connectionString: databaseUrl, pool: { max: 2, min: 0 } },
      // The built-in admin roles a grant may name.
      adminRoleCatalog: ADMIN_ROLE_CATALOG,
      repositories: ['realms', 'serviceAccounts', 'adminGrants', 'adminAuditLog'],
    });
    await server.ready();
    return await runServiceAccountsCommand(command, {
      fastify: server,
      operatingSystemUser: operatingSystemUser(),
      out: (line) => process.stdout.write(`${line}\n`),
      err: (line) => process.stderr.write(`${line}\n`),
    });
  } finally {
    await server.close();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(
      `service-accounts: ${error instanceof Error ? error.message : String(error)}\n`
    );
    process.exitCode = 1;
  }
);
