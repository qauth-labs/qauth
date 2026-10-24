/**
 * `auth-server:keys:create`: create one key for a realm, purpose and algorithm
 * (ADR-019 Decision 9, issue #485).
 *
 * Run it on a host that holds the KEK, with the server's own environment: the
 * database, the KEK settings, `SIGNING_ALGORITHM_MODE`, `HYBRID_SIGNING_ENABLED`
 * and `DEFAULT_REALM_NAME` are read from it.
 *
 * ```console
 * pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256
 * # In the auth-server image, from /app:
 * tsx src/keys-create.ts --purpose token_signing --algorithm RS256
 * ```
 *
 * It prints the stored key as one JSON line: realm, purpose, algorithm, `kid`,
 * status and the public JWK of a published purpose. No private material is
 * ever printed or returned.
 */
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { createRealmKey } from '@qauth-labs/fastify-plugin-signer';
import Fastify from 'fastify';

import { KeysCreateUsageError, parseKeysCreateArguments } from './app/helpers/keys-create';
import { env } from './config/env';

async function main(): Promise<void> {
  const input = parseKeysCreateArguments(process.argv.slice(2), env.DEFAULT_REALM_NAME);

  // Only the database: no route, no cache, no listening port.
  const server = Fastify({ logger: { level: 'warn' } });
  try {
    await server.register(databasePlugin, {
      config: { connectionString: env.DATABASE_URL, pool: { max: 2, min: 0 } },
    });
    await server.ready();

    const created = await createRealmKey(
      {
        db: server.db,
        kekEnv: process.env,
        warn: ({ variable, message }) => server.log.warn({ variable }, message),
        enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        hybridSigning: env.HYBRID_SIGNING_ENABLED,
      },
      input
    );
    for (const key of created) {
      process.stdout.write(
        `${JSON.stringify({
          realm: input.realmName,
          purpose: key.purpose,
          algorithm: key.algorithm,
          kid: key.kid,
          status: key.status,
          pairId: key.pairId,
          ...(key.publicJwk === undefined ? {} : { publicJwk: key.publicJwk }),
        })}\n`
      );
    }
  } finally {
    await server.close();
  }
}

main().catch((error: unknown) => {
  if (error instanceof KeysCreateUsageError) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  process.stderr.write(
    `keys:create: ${error instanceof Error ? `${error.name}: ${error.message}` : String(error)}\n`
  );
  process.exitCode = 1;
});
