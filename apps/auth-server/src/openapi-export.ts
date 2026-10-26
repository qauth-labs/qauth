/**
 * Exports the auth-server's OpenAPI 3.1 spec, under one of two flag surfaces:
 *
 *   - `--surface default` writes `stable-surface/openapi.json`: the app as a
 *     default deployment serves it, every feature switch at its default. This
 *     is the stable surface of ADR-018 §5. CI regenerates it, fails on drift,
 *     and compares it with the latest release tag (`scripts/stable-surface/`,
 *     #451).
 *   - `--surface maximal` writes `apps/docs-site/public/openapi.json`: every
 *     switch that registers a route turned on. The docs site's API reference is
 *     built from it, the endpoint-coverage guard checks against it (#347), and
 *     the stable-surface check requires every operation it adds over the
 *     default export to be tagged `x-qauth-stability: experimental`.
 *
 * Run both via `pnpm exec nx run auth-server:openapi-export` (see project.json).
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
 *     Docker container. The default realm's boot step, which does need the
 *     database, is turned off (`defaultRealmBoot: false`); it registers no
 *     route, so the spec is the same.
 *
 * ## Two flag surfaces (why, not just what)
 *
 * A default-flag boot omits `POST /oid4vp/response` entirely — that route is
 * registered only when `WALLET_FEDERATION_ENABLED` is on
 * (`apps/auth-server/src/app/routes/oid4vp/response.ts`), and it additionally
 * requires `OID4VP_VERIFIER_PROFILE` to be set or the app refuses to boot
 * (fail-closed, #299). Exporting only under the defaults would leave Task 3's
 * endpoint-coverage guard checking a spec that never had that route to miss;
 * exporting only under the maximal surface would publish switch-gated routes
 * as if a default deployment served them. Hence one process per surface: the
 * env is parsed once, at import (see "Ordering" below), so one process cannot
 * boot the app twice under different flags.
 *
 * Each surface sets every switch that decides whether a route registers
 * (`WALLET_FEDERATION_ENABLED`, `METRICS_ENABLED`, `SSF_TRANSMITTER_ENABLED`, and
 * the passkey app lists `WEBAUTHN_APPLE_APP_IDS` and `WEBAUTHN_ANDROID_APPS`)
 * explicitly, so a value in
 * the caller's shell cannot change which operations an export contains.
 * The maximal surface also turns on every built experimental item of the
 * registry (`@qauth-labs/shared-stability`), and the default surface none, or
 * the export refuses to write (ADR-018 §5, #477): an experimental item's
 * routes would otherwise be missing from both documents, and the
 * stable-surface check could not require their tag.
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

import { experimentalSurfaceProblem, type FlagSurface } from './openapi-export-surface';

const FLAG_SURFACES: readonly FlagSurface[] = ['default', 'maximal'];

/**
 * Output path per surface, resolved from this file's own location rather than
 * `process.cwd()` so the script behaves the same whether it is run via the Nx
 * target (`cwd: apps/auth-server`) or directly with `tsx` from any directory.
 * `stable-surface/surfaces.json` registers both paths.
 */
const OUTPUT_PATHS: Readonly<Record<FlagSurface, string>> = {
  default: resolve(__dirname, '..', '..', '..', 'stable-surface', 'openapi.json'),
  maximal: resolve(__dirname, '..', '..', 'docs-site', 'public', 'openapi.json'),
};

/** Read `--surface default|maximal` (or `--surface=…`) from the command line. */
function parseFlagSurface(argv: readonly string[]): FlagSurface {
  const index = argv.findIndex((arg) => arg === '--surface' || arg.startsWith('--surface='));
  const value =
    index === -1
      ? undefined
      : argv[index].includes('=')
        ? argv[index].slice('--surface='.length)
        : argv[index + 1];
  if (!FLAG_SURFACES.includes(value as FlagSurface)) {
    throw new Error(
      `openapi-export: pass --surface ${FLAG_SURFACES.join('|')} (got ${value ?? 'nothing'})`
    );
  }
  return value as FlagSurface;
}

/**
 * Minimum number of OpenAPI paths the export must produce before it is
 * trusted enough to write (#347). A silently-empty or near-empty spec would
 * make Task 3's endpoint-coverage guard vacuous (nothing to compare against)
 * and the docs site's API reference blank.
 *
 * Applies to both surfaces. Chosen against the ACTUAL count observed at
 * scaffold time (28 paths under the full maximal-flag-surface environment,
 * #347 Task 1; the default surface has had 29 since #451) with headroom
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
 * Populate `process.env` with the given flag surface + ephemeral key material
 * this export needs, BEFORE anything that reads `config/env.ts` is imported
 * (see the module doc comment).
 */
function setEphemeralEnv(surface: FlagSurface): void {
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

    // On by default; pinned so that a caller's `METRICS_ENABLED=false` cannot
    // drop `GET /metrics` from either export.
    METRICS_ENABLED: 'true',
  });

  if (surface === 'default') {
    Object.assign(process.env, {
      WALLET_FEDERATION_ENABLED: 'false',
      // No app identifiers, so neither association file is registered (#467).
      WEBAUTHN_APPLE_APP_IDS: '',
      WEBAUTHN_ANDROID_APPS: '',
      // No SSF transmitter, so none of its routes is registered (#410).
      SSF_TRANSMITTER_ENABLED: 'false',
    });
    return;
  }

  Object.assign(process.env, {
    // Wallet federation (ADR-004): all three are required together, or the app
    // refuses to boot (#299 and #379, both fail-closed). `POST /oid4vp/response`
    // is registered only when the flag is on — this is the whole reason the
    // export needs a non-default environment (see module doc comment).
    //
    // `OID4VP_SUBJECT_BINDING_CLAIMS` became load-bearing with #379's
    // subject-resolution boot gate: `oid4vp-1.0-base` defaults to
    // `asserted-lookup`, and `assertSubjectResolutionProvisioned` refuses to
    // start when that strategy has no binding claims, because an unchecked
    // asserted-lookup would let any valid credential authenticate any account
    // (ADR-009 §1). That gate landed without this script being updated, so the
    // export — and therefore any regeneration of `openapi.json` — has been
    // failing at boot ever since. The value is the EUDI PID mandatory attribute
    // set from `.env.example`; it affects no path in the emitted document, it
    // only has to be a configuration the app will start on.
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
    OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
    // The passkey association files (#467) are registered only when the
    // operator lists apps, and only while the RP ID is the realm host, which
    // it is with WEBAUTHN_RP_ID unset. Example identifiers in the documented
    // formats; they affect no path beyond the two routes.
    WEBAUTHN_RP_ID: '',
    WEBAUTHN_APPLE_APP_IDS: 'ABCDE12345.com.example.app',
    WEBAUTHN_ANDROID_APPS: JSON.stringify({
      'com.example.app': [
        'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C',
      ],
    }),
    // The Shared Signals Framework transmitter (#410): its metadata and its
    // stream management routes are registered only when it is on.
    SSF_TRANSMITTER_ENABLED: 'true',
  });
}

/** Minimal shape of `@fastify/swagger`'s generated document this script needs. */
interface OpenApiDocument {
  readonly paths?: Record<string, unknown>;
}

async function main(): Promise<void> {
  const surface = parseFlagSurface(process.argv.slice(2));
  const outputPath = OUTPUT_PATHS[surface];
  setEphemeralEnv(surface);

  // Dynamic imports, not static ones: every one of these transitively
  // reaches `../config/env`, which validates `process.env` at import time.
  // Deferring them until after `setEphemeralEnv()` has run is what makes the
  // ordering in the module doc comment true. `./app/openapi-options` itself
  // has no such dependency (it only imports `fastify-type-provider-zod`),
  // but it's grouped here anyway to keep every import in one place.
  const [
    { default: Fastify },
    { default: swagger },
    typeProviderZod,
    { app },
    { openapiOptions },
    { EXPERIMENTAL_SWITCHES, listEnabledExperimental },
  ] = await Promise.all([
    import('fastify'),
    import('@fastify/swagger'),
    import('fastify-type-provider-zod'),
    import('./app/app'),
    import('./app/openapi-options'),
    import('./config/experimental-features'),
  ]);
  const { serializerCompiler, validatorCompiler } = typeProviderZod;

  // `EXPERIMENTAL_SWITCHES` has one reader per built server item, so its keys
  // are the items the server can turn on.
  const experimentalProblem = experimentalSurfaceProblem(
    surface,
    listEnabledExperimental().map((item) => item.id),
    Object.keys(EXPERIMENTAL_SWITCHES)
  );
  if (experimentalProblem !== null) {
    throw new Error(`openapi-export: ${experimentalProblem}`);
  }

  // No logger, no request-id/router options — this process never accepts a
  // request, so `main.ts`'s production Fastify constructor options do not
  // apply here. Only the swagger registration below is shared with
  // `main.ts` (via `openapiOptions`), and deliberately so — see
  // `./app/openapi-options.ts`.
  const server = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);

  // Everything from here on MUST close `server` on every exit path, success
  // or failure. The cache plugin connects with `lazyConnect: true` and
  // ioredis's default retry strategy; if registration or `ready()` throws
  // after that connection attempt has started and nothing calls
  // `server.close()` (which runs the cache plugin's `onClose` hook →
  // `redis.quit()`), the live reconnect timers keep the event loop open and
  // the process hangs instead of exiting with the logged failure. This
  // script is meant to run unattended (Task 3's guard, CI), so a hang is the
  // worst available outcome — worse than the failure itself.
  try {
    // Same shared `openapiOptions` `main.ts` registers — see
    // `./app/openapi-options.ts` for why this is a single source of truth
    // rather than each file's own copy (#347 fix round 3).
    await server.register(swagger, openapiOptions);

    // No database behind this boot, so no default realm step (#484).
    await server.register(app, { defaultRealmBoot: false });
    await server.ready();

    const spec = server.swagger() as OpenApiDocument;
    const pathCount = Object.keys(spec.paths ?? {}).length;

    if (pathCount < MIN_EXPECTED_PATHS) {
      // Thrown, not just logged-and-returned, so this failure goes through
      // the SAME `finally` below as every other failure — one close path,
      // not two.
      throw new Error(
        `openapi-export: refusing to write a near-empty spec — got ${pathCount} path(s), ` +
          `expected at least ${MIN_EXPECTED_PATHS} for the ${surface} surface. This usually means ` +
          'one of the env flags did not take effect (WALLET_FEDERATION_ENABLED / ' +
          'OID4VP_VERIFIER_PROFILE) or a route registration failed silently. Re-run with ' +
          'FASTIFY_DEBUG or inspect the app registration.'
      );
    }

    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(spec, null, 2)}\n`);
    console.log(
      `openapi-export: wrote ${pathCount} path(s) for the ${surface} surface to ${outputPath}`
    );
  } finally {
    // A `finally` block that itself throws REPLACES whatever error was
    // already propagating — the original cause (a registration bug, a
    // fail-closed profile assertion) is the useful one, and a close-time
    // rejection must never win over it. Caught and logged here, deliberately
    // not rethrown, so the original error (if any) keeps propagating to the
    // `main().catch()` below unchanged.
    try {
      await server.close();
    } catch (closeError) {
      console.error(
        'openapi-export: also failed to close the Fastify instance during cleanup ' +
          '(the error above/below, if any, is the original failure and takes precedence)',
        closeError
      );
    }
  }
}

main().catch((error) => {
  console.error('openapi-export: failed', error);
  process.exitCode = 1;
});
