/**
 * `auth-server:keys:rewrap`: rotate the KEK, re-wrapping every stored key's
 * data key from the old KEK to the new one (ADR-019 Decision 9, issue #545).
 *
 * Run it on a host that holds both KEKs, with the server's own environment:
 * the database, and the new KEK as `KEK` (or `KEK_PATH`) with the old one as
 * `KEK_PREVIOUS` (or `KEK_PREVIOUS_PATH`), or a key service adapter's
 * settings.
 *
 * ```console
 * pnpm nx run auth-server:keys:rewrap --status
 * pnpm nx run auth-server:keys:rewrap --from=<the old kek_ref>
 * # In the auth-server image, from /app:
 * tsx src/keys-rewrap.ts --from <the old kek_ref>
 * ```
 *
 * It records the run in the admin audit log of every realm that holds a key,
 * before any key moves, and prints the stored keys per `kek_ref` and whether
 * `KEK_PREVIOUS` may be removed. No key material, data key or KEK is ever
 * printed.
 */
import { userInfo } from 'node:os';

import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import {
  countKeysPerKek,
  listRealmIdsWithKeys,
  rotateKek,
} from '@qauth-labs/fastify-plugin-signer';
import Fastify from 'fastify';

import {
  describeKeysRewrapError,
  KeysRewrapUsageError,
  parseKeysRewrapArguments,
  recordHostKekRotation,
  runKeysRewrap,
} from './app/helpers/keys-rewrap';
import { env } from './config/env';

/** The user the command runs as, as the audit record names it. */
function operatingSystemUser(): string {
  try {
    return userInfo().username;
  } catch {
    return process.env['USER'] ?? 'unknown';
  }
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  // A usage error exits 2 before anything connects.
  try {
    parseKeysRewrapArguments(argv);
  } catch (error) {
    if (!(error instanceof KeysRewrapUsageError)) throw error;
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
  // Only the database: no route, no cache, no listening port.
  const server = Fastify({ logger: { level: 'warn' } });
  try {
    await server.register(databasePlugin, {
      config: { connectionString: env.DATABASE_URL, pool: { max: 2, min: 0 } },
    });
    await server.ready();
    const deps = {
      db: server.db,
      kekEnv: process.env,
      warn: ({ variable, message }: { variable: string; message: string }) =>
        server.log.warn({ variable }, message),
    };
    const { adminAuditLog } = server.repositories;
    return await runKeysRewrap(argv, {
      rotateKek: (input) => rotateKek(deps, input),
      recordRotation: (record, tx) =>
        recordHostKekRotation(
          {
            listRealmIds: (afterRealmId, limit, client) =>
              listRealmIdsWithKeys(client, afterRealmId, limit),
            appendAdminAudit: (client, entry) => adminAuditLog.appendAdminAudit(client, entry),
          },
          record,
          tx
        ),
      countKeysPerKek: () => countKeysPerKek(deps),
      operatingSystemUser,
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
    process.stderr.write(`keys:rewrap: ${describeKeysRewrapError(error)}\n`);
    process.exitCode = 1;
  }
);
