/**
 * Exports the auth-server's OpenAPI 3.1 spec to `apps/docs-site/public/openapi.json`
 * (committed) — the source the docs site's API reference is built from, and
 * the artifact Task 3's endpoint-coverage guard checks against (#347).
 *
 * Run via `pnpm exec nx run auth-server:openapi-export` (see project.json).
 *
 * ## Why this exists instead of hitting the live server
 *
 * The real `main.ts` only writes the spec as a side effect of listening on a
 * port, which means "export the spec" would otherwise require a live
 * Postgres + Redis + a listening process. This script boots the SAME Fastify
 * app (`./app/app`) far enough to generate the spec and nothing further:
 *
 *   - No `server.listen()` — the process never accepts a connection.
 *   - No live Postgres/Redis required. `fastify-plugin-db` and
 *     `fastify-plugin-cache` each run a connection probe in an `onReady` hook
 *     that only WARNS on failure (`libs/fastify/plugins/db/src/lib/fastify-plugin-db.ts`,
 *     `libs/fastify/plugins/cache/src/lib/fastify-plugin-cache.ts`) — neither
 *     throws, so `await server.ready()` resolves even against the
 *     unreachable, ephemeral URLs set below. This script does not start a
 *     Docker container.
 *
 * ## Maximal flag surface (why, not just what)
 *
 * A default-flag boot omits `POST /oid4vp/response` entirely — that route is
 * registered only when `WALLET_FEDERATION_ENABLED` is on
 * (`apps/auth-server/src/app/routes/oid4vp/response.ts`), and it additionally
 * requires `OID4VP_VERIFIER_PROFILE` to be set or the app refuses to boot
 * (fail-closed, #299). Exporting under the defaults would leave Task 3's
 * endpoint-coverage guard checking a spec that never had that route to miss.
 * `oid4vp-1.0-base` is used because it is the profile that actually starts on
 * this deployment's crypto (EdDSA-only) — `haip-1.0` requires ES256 signing
 * and an unprovisioned certificate chain and refuses to boot; see
 * `deriveCryptoCapabilities` (`apps/auth-server/src/app/crypto-capabilities.ts`)
 * and `assertProfileWithinCryptoCapabilities`
 * (`libs/fastify/plugins/federation/src/lib/configured-providers.ts`).
 *
 * ## Ordering: env before import
 *
 * `apps/auth-server/src/config/env.ts` calls `parseEnv` (a
 * `schema.parse(process.env)`) at MODULE LOAD, not lazily. A static
 * `import './app/app'` at the top of this file would therefore evaluate the
 * env schema against an still-empty `process.env` before `main()` ever runs.
 * Every import that reaches `./config/env` is deferred behind a dynamic
 * `import()` inside `main()`, after `process.env` has been populated — the
 * "or spawn with the env set" alternative the brief allows, done by ordering
 * within one process instead.
 *
 * ## Key material
 *
 * All three private keys are generated fresh, in memory, for this run only —
 * NEVER written to disk and NEVER committed. `JWT_PRIVATE_KEY` /
 * `JWT_RS256_PRIVATE_KEY` must be PKCS#8 PEM (`jose`'s `importPKCS8` rejects
 * the PKCS#1 shape `openssl genrsa` produces by default), which is exactly
 * what `generateKeyPairSync(..., { format: 'pkcs8' })` emits. The ML-DSA seed
 * is a raw 32-byte value, base64url-encoded per `cryptoEnvSchema`'s format
 * check (`libs/server/config/src/lib/schemas/crypto.ts`).
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import type { ZodTypeProvider } from 'fastify-type-provider-zod';

/**
 * Output path: `apps/docs-site/public/openapi.json`, resolved from this
 * file's own location rather than `process.cwd()` so the script behaves the
 * same whether it is run via the Nx target (`cwd: apps/auth-server`) or
 * directly with `tsx` from any directory.
 */
const OUTPUT_PATH = resolve(__dirname, '..', '..', 'docs-site', 'public', 'openapi.json');

/**
 * Minimum number of OpenAPI paths the export must produce before it is
 * trusted enough to write (#347). A silently-empty or near-empty spec would
 * make Task 3's endpoint-coverage guard vacuous (nothing to compare against)
 * and the docs site's API reference blank.
 *
 * Chosen against the ACTUAL count observed at scaffold time (28 paths under
 * the full maximal-flag-surface environment, #347 Task 1) with headroom
 * UNDER it, not pinned to it: the threshold exists to catch "most routes
 * silently failed to register" (a dropped env flag, a plugin registration
 * that threw and was swallowed) — a catastrophic drop to a handful of paths
 * (`/health`, `/metrics`, the `.well-known` routes) — not to fail the build
 * on every future single-route addition or rename.
 */
const MIN_EXPECTED_PATHS = 20;

/**
 * Generate a fresh EdDSA (Ed25519) key pair (PKCS#8 private / SPKI public PEM).
 *
 * Both halves are generated and set explicitly (`JWT_PRIVATE_KEY` AND
 * `JWT_PUBLIC_KEY`) rather than leaning on `fastify-plugin-jwt`'s "derive the
 * public key from the private key" fallback: that fallback calls jose's
 * `exportSPKI` directly on the imported PRIVATE `KeyLike`
 * (`libs/server/jwt/src/lib/jose-utils.ts`), which jose rejects — it throws
 * `'Failed to derive public key from private key. Please provide
 * JWT_PUBLIC_KEY in environment variables.'` for every EdDSA key, not just an
 * edge case. Generating the pair up front sidesteps that path entirely.
 */
function generateEd25519KeyPairPem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/** Generate a fresh RS256-capable RSA private key (>=2048-bit), PKCS#8 PEM. */
function generateRsaPrivateKeyPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return privateKey;
}

/** Generate a fresh FIPS 204 ML-DSA-65 seed: 32 random bytes, base64url (unpadded). */
function generateMlDsaSeedBase64Url(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Populate `process.env` with the maximal flag surface + ephemeral key
 * material this export needs, BEFORE anything that reads `config/env.ts` is
 * imported (see the module doc comment).
 */
function setEphemeralEnv(): void {
  const ed25519 = generateEd25519KeyPairPem();

  Object.assign(process.env, {
    NODE_ENV: 'development',

    // Bogus, unroutable endpoints. `DB_POOL_CONNECTION_TIMEOUT` /
    // `REDIS_CONNECTION_TIMEOUT` are lowered so the onReady connection probes
    // (which only warn — see the module doc comment) fail fast on
    // ECONNREFUSED instead of waiting out the default multi-second timeouts.
    DATABASE_URL: 'postgresql://user:pass@127.0.0.1:1/db',
    DB_POOL_CONNECTION_TIMEOUT: '200',
    DB_POOL_MIN: '1',
    REDIS_URL: 'redis://127.0.0.1:1',
    REDIS_CONNECTION_TIMEOUT: '200',

    JWT_ISSUER: 'https://auth.qauth.dev',
    JWT_PRIVATE_KEY: ed25519.privateKeyPem,
    JWT_PUBLIC_KEY: ed25519.publicKeyPem,
    JWT_RS256_PRIVATE_KEY: generateRsaPrivateKeyPem(),
    JWT_MLDSA_PRIVATE_KEY: generateMlDsaSeedBase64Url(),

    EMAIL_PROVIDER: 'mock',
    EMAIL_FROM_ADDRESS: 'noreply@qauth.dev',
    EMAIL_BASE_URL: 'https://qauth.dev',

    RATE_LIMIT_ENABLED: 'false',

    // Wallet federation (ADR-004): both are required together, or the app
    // refuses to boot (#299 fail-closed). `POST /oid4vp/response` is
    // registered only when the flag is on — this is the whole reason the
    // export needs a non-default environment (see module doc comment).
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
  });
}

/** Minimal shape of `@fastify/swagger`'s generated document this script needs. */
interface OpenApiDocument {
  readonly paths?: Record<string, unknown>;
}

async function main(): Promise<void> {
  setEphemeralEnv();

  // Dynamic imports, not static ones: every one of these transitively
  // reaches `../config/env`, which validates `process.env` at import time.
  // Deferring them until after `setEphemeralEnv()` has run is what makes the
  // ordering in the module doc comment true.
  const [{ default: Fastify }, { default: swagger }, typeProviderZod, { app }] = await Promise.all([
    import('fastify'),
    import('@fastify/swagger'),
    import('fastify-type-provider-zod'),
    import('./app/app'),
  ]);
  const { createJsonSchemaTransform, serializerCompiler, validatorCompiler } = typeProviderZod;

  // No logger, no request-id/router options — this process never accepts a
  // request, so `main.ts`'s production Fastify constructor options do not
  // apply here. Only the swagger registration below is duplicated from
  // `main.ts`, per the brief.
  const server = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);

  // Duplicated from `apps/auth-server/src/main.ts` verbatim (same `openapi`
  // object, same `transform`). Kept in sync by hand for now — see the Task 1
  // report for why this was not extracted into a shared helper in this task.
  await server.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'QAuth Auth Server API',
        description:
          'OAuth 2.1 / OIDC authentication server API. Phase 1.7: userinfo and token introspection.',
        version: '1.0.0',
      },
      servers: [{ url: '/', description: 'Default' }],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Access token obtained from login, refresh, or OAuth token endpoint.',
          },
        },
      },
    },
    transform: createJsonSchemaTransform({
      zodToJsonConfig: { target: 'draft-2020-12' },
    }),
  });

  await server.register(app);
  await server.ready();

  const spec = server.swagger() as OpenApiDocument;
  const pathCount = Object.keys(spec.paths ?? {}).length;

  if (pathCount < MIN_EXPECTED_PATHS) {
    await server.close();
    console.error(
      `openapi-export: refusing to write a near-empty spec — got ${pathCount} path(s), ` +
        `expected at least ${MIN_EXPECTED_PATHS}. This usually means one of the maximal-surface ` +
        'env flags did not take effect (WALLET_FEDERATION_ENABLED / OID4VP_VERIFIER_PROFILE) or a ' +
        'route registration failed silently. Re-run with FASTIFY_DEBUG or inspect the app registration.'
    );
    process.exitCode = 1;
    return;
  }

  mkdirSync(dirname(OUTPUT_PATH), { recursive: true });
  writeFileSync(OUTPUT_PATH, `${JSON.stringify(spec, null, 2)}\n`);
  console.log(`openapi-export: wrote ${pathCount} path(s) to ${OUTPUT_PATH}`);

  await server.close();
}

main().catch((error) => {
  console.error('openapi-export: failed', error);
  process.exitCode = 1;
});
