/**
 * `auth-server:keys:retire`: retire a token-signing key at once because it
 * may be compromised (ADR-019 Decisions 7 and 9, issue #551).
 *
 * Run it on a host that holds the database credentials and the KEK, with the
 * server's own environment: the database (a role that may write the keys, the
 * refresh tokens, the sessions and the audit log: the owner's, not one
 * process role's in a split deployment), Redis, and the KEK as `KEK` (or
 * `KEK_PATH`) or a key service adapter's settings.
 *
 * ```console
 * pnpm nx run auth-server:keys:retire --kid=<kid> --yes
 * # In the auth-server image, from /app:
 * tsx src/keys-retire.ts --kid <kid> --realm <name> --yes
 * ```
 *
 * It records the run, with the operating-system user, in the realm's admin
 * audit log, and announces it as a critical `key.emergency_retired` event.
 * No key material, data key or KEK is ever printed.
 */
import { userInfo } from 'node:os';

import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { sessionServicePlugin } from '@qauth-labs/fastify-plugin-sessions';
import Fastify from 'fastify';

import {
  describeKeysRetireError,
  keysRetireDependencies,
  KeysRetireUsageError,
  parseKeysRetireArguments,
  runKeysRetire,
} from './app/helpers/keys-retire';
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
    parseKeysRetireArguments(argv, env.DEFAULT_REALM_NAME);
  } catch (error) {
    if (!(error instanceof KeysRetireUsageError)) throw error;
    process.stderr.write(`${error.message}\n`);
    return 2;
  }
  // The database, Redis and the session service: no route, no listening port.
  const server = Fastify({ logger: { level: 'warn' } });
  try {
    await server.register(databasePlugin, {
      config: { connectionString: env.DATABASE_URL, pool: { max: 2, min: 0 } },
    });
    await server.register(cachePlugin, {
      config: {
        url: env.REDIS_URL,
        host: env.REDIS_HOST,
        port: env.REDIS_PORT,
        password: env.REDIS_PASSWORD,
        db: env.REDIS_DB,
        maxRetriesPerRequest: env.REDIS_MAX_RETRIES,
        connectTimeout: env.REDIS_CONNECTION_TIMEOUT,
        commandTimeout: env.REDIS_COMMAND_TIMEOUT,
        lazyConnect: true,
      },
    });
    await server.register(sessionServicePlugin, {
      settings: {
        defaultMaxLifespanSeconds: env.SESSION_COOKIE_TTL,
        lastSeenIntervalSeconds: env.SESSION_LAST_SEEN_INTERVAL,
      },
    });
    await server.ready();
    return await runKeysRetire(
      argv,
      env.DEFAULT_REALM_NAME,
      keysRetireDependencies(server, {
        kekEnv: process.env,
        enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        hybridSigning: env.HYBRID_SIGNING_ENABLED,
        operatingSystemUser,
        out: (line) => process.stdout.write(`${line}\n`),
        err: (line) => process.stderr.write(`${line}\n`),
      })
    );
  } finally {
    await server.close();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    process.stderr.write(`keys:retire: ${describeKeysRetireError(error)}\n`);
    process.exitCode = 1;
  }
);
