import * as path from 'node:path';

import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { emailPlugin, type EmailProviderConfig } from '@qauth-labs/fastify-plugin-email';
import {
  assertCredentialStatusConfigUsable,
  assertTrustedIssuersUsable,
  createConfiguredProviders,
  credentialStatusProvisioningOf,
  federationPlugin,
  type VerifierCryptoCapabilities,
} from '@qauth-labs/fastify-plugin-federation';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import { passwordPlugin } from '@qauth-labs/fastify-plugin-password';
import { pkcePlugin } from '@qauth-labs/fastify-plugin-pkce';
import { resolveStatusListTrustAnchorPems } from '@qauth-labs/server-config';
import type { FastifyInstance } from 'fastify';

import { env } from '../config/env';
import { deriveCryptoCapabilities } from './crypto-capabilities';
import { isJtiRevoked } from './helpers/token-revocation';
import errorHandler from './plugins/error-handler';
import { metricsPlugin } from './plugins/metrics';
import { rateLimitPlugin } from './plugins/rate-limit';
import { requestIdPlugin } from './plugins/request-id';
import { securityHeadersPlugin } from './plugins/security-headers';

/**
 * What this deployment's crypto layer can do, handed to the VerifierProfile gate
 * (#299) so a profile is checked against REALITY rather than against its own
 * declaration.
 *
 * Without this, `haip-1.0`'s `signingAlgs: ['ES256']` and
 * `responseEncryption: 'required'` (HAIP §7 / §5.1) were declared and enforced
 * nowhere: the only thing keeping that profile out was its missing certificate
 * chain, so the moment #233 provisioned one it would have booted on an
 * EdDSA-only stack and every EUDI wallet would have rejected every request.
 *
 * The answer is DERIVED from the deployment's provisioned key material rather
 * than written here, because the two questions "does the crypto library export
 * this algorithm" and "can this deployment sign with it" are not the same
 * question, and only the second one is what the gate is asking. See
 * `./crypto-capabilities` for which key material each entry is derived from and
 * why ES256 and the JWE stack are still answered `false` on a crypto layer that
 * implements both.
 */
const CRYPTO_CAPABILITIES: VerifierCryptoCapabilities = deriveCryptoCapabilities({
  rs256PrivateKey: env.JWT_RS256_PRIVATE_KEY,
});

export async function app(fastify: FastifyInstance, opts: object) {
  await fastify.register(databasePlugin, {
    config: {
      connectionString: env.DATABASE_URL,
      pool: {
        max: env.DB_POOL_MAX,
        min: env.DB_POOL_MIN,
        idleTimeoutMillis: env.DB_POOL_IDLE_TIMEOUT,
        connectionTimeoutMillis: env.DB_POOL_CONNECTION_TIMEOUT,
      },
    },
  });

  await fastify.register(cachePlugin, {
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

  await fastify.register(passwordPlugin, {
    hashConfig: {
      memoryCost: env.PASSWORD_MEMORY_COST,
      timeCost: env.PASSWORD_TIME_COST,
      parallelism: env.PASSWORD_PARALLELISM,
    },
    validationConfig: {
      minScore: env.PASSWORD_MIN_SCORE,
    },
  });

  await fastify.register(pkcePlugin);

  // Credential-provider registry (ADR-003, #228). The bootstrap remains the
  // single registration point, but WHICH providers exist is now a pure function
  // of config (`createConfiguredProviders`) so the decision is unit-testable
  // without booting this app. Adding an upstream still means extending that
  // list, never touching routes.
  //
  // WalletProvider (ADR-004, #232) joins the set only when
  // WALLET_FEDERATION_ENABLED is on — default OFF while epic #231 (#233–#238)
  // is incomplete, and inert even when on, because the skeleton's methods fail
  // closed and nothing resolves 'wallet' yet.
  //
  // Turning the flag on additionally requires a VerifierProfile (#299): the flag
  // decides WHETHER the wallet provider exists, the profile decides WHAT POSTURE
  // it runs with. An enabled deployment carrying no profile — one whose Client
  // Identifier Prefix needs unprovisioned X.509 material, or one whose declared
  // signing/encryption mandates exceed CRYPTO_CAPABILITIES above — throws here
  // and refuses to boot, rather than serving wallet flows with an unstated or
  // unmeetable posture.
  // Issuer trust (#236), the OTHER trust direction: which credential ISSUERS a
  // realm accepts credentials from. `OID4VP_TRUSTED_ISSUERS` is validated by
  // the env schema for SHAPE, but the runtime additionally canonicalizes every
  // entry, and a per-realm allowlist is all-or-nothing — so a single entry the
  // canonicalizer refuses (userinfo, a query string, a fragment) would make
  // that realm trust NOBODY, with no boot failure and no log, and every
  // Verifiable Presentation to it rejected. This runs the runtime's own
  // reduction at startup so that configuration fails the boot instead.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED: the typo is a typo whether or not
  // wallet flows are switched on today, and finding it at boot beats finding it
  // when the first presentation arrives.
  assertTrustedIssuersUsable(env.OID4VP_TRUSTED_ISSUERS);

  // Credential revocation (#297/#378), the same posture as the line above and
  // for the same reason. The two OID4VP_STATUS_LIST_* variables are validated by
  // the env schema for SHAPE, but the runtime additionally PARSES every anchor
  // certificate and COMPILES every URI prefix — and a deployment that configured
  // one half and not the other would build a checker that silently refuses every
  // credential carrying a `status` claim. Running the runtime's own compilation
  // at startup is what turns both into a boot failure instead of a 100%
  // login-failure rate nobody can explain.
  //
  // NOT gated on WALLET_FEDERATION_ENABLED or on the selected profile: a typo is
  // a typo whether or not wallet flows are switched on today.
  const statusListTrustAnchorPems = resolveStatusListTrustAnchorPems(env);
  assertCredentialStatusConfigUsable({
    trustAnchorPems: statusListTrustAnchorPems,
    uriAllowlist: env.OID4VP_STATUS_LIST_URI_ALLOWLIST,
  });

  await fastify.register(federationPlugin, {
    providers: createConfiguredProviders({
      walletFederationEnabled: env.WALLET_FEDERATION_ENABLED,
      verifierProfileId: env.OID4VP_VERIFIER_PROFILE,
      cryptoCapabilities: CRYPTO_CAPABILITIES,
      // What the operator provisioned for revocation checking (#297). A profile
      // declaring `requireCredentialStatus: true` — `haip-1.0` does — refuses to
      // start when either half is missing, naming which one. Threaded rather
      // than defaulted: the default is the refusing value, and a bootstrap that
      // HAS the answer must state it.
      credentialStatusProvisioned: credentialStatusProvisioningOf({
        trustAnchorPems: statusListTrustAnchorPems,
        uriAllowlist: env.OID4VP_STATUS_LIST_URI_ALLOWLIST,
      }),
      // `provisionedVerifierMaterial` is deliberately not passed: no certificate
      // configuration surface exists until #233, and the option's default is the
      // refusing one. Threading real material through here is that issue's job.
    }),
  });

  // Configure email provider from environment variables
  const emailProvider = env.EMAIL_PROVIDER;

  // Build provider-specific configuration
  let providerConfig: EmailProviderConfig | undefined;
  if (emailProvider === 'resend') {
    if (!env.RESEND_API_KEY) {
      throw new Error(
        'RESEND_API_KEY is required when EMAIL_PROVIDER is "resend". Please set it in your environment variables.'
      );
    }
    providerConfig = {
      apiKey: env.RESEND_API_KEY,
      fromAddress: env.EMAIL_FROM_ADDRESS,
    };
  } else if (emailProvider === 'smtp') {
    if (!env.SMTP_HOST || !env.SMTP_PORT || !env.SMTP_USER || !env.SMTP_PASSWORD) {
      throw new Error(
        'SMTP_HOST, SMTP_PORT, SMTP_USER, and SMTP_PASSWORD are required when EMAIL_PROVIDER is "smtp". Please set them in your environment variables.'
      );
    }
    providerConfig = {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASSWORD,
      },
      fromAddress: env.EMAIL_FROM_ADDRESS,
    };
  }
  // For 'mock' provider, providerConfig is undefined (no config needed)

  await fastify.register(emailPlugin, {
    provider: emailProvider,
    providerConfig,
    serviceConfig: {
      defaultFrom: env.EMAIL_FROM_ADDRESS,
      baseUrl: env.EMAIL_BASE_URL,
      // Same value the send routes use to compute `expiresAt`, so the copy in
      // the email cannot drift from the lifetime actually enforced (#334).
      verificationTokenExpiry: env.EMAIL_VERIFICATION_TOKEN_EXPIRY,
    },
  });

  await fastify.register(jwtPlugin, {
    privateKey: env.JWT_PRIVATE_KEY,
    publicKey: env.JWT_PUBLIC_KEY,
    issuer: env.JWT_ISSUER,
    accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
    refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
    // RS256 ID-token signing (#309), OPTIONAL and env-provisioned. When the
    // RS256 key is set, the plugin signs ID tokens with RS256 by default,
    // publishes the RSA public key in the JWKS, and discovery advertises
    // RS256 — unblocking OIDC Basic/Config OP certification (#286). Absent →
    // EdDSA-only, exactly as before. Access tokens always stay EdDSA. Spread
    // conditionally so unset keys never appear as `undefined` options.
    ...(env.JWT_RS256_PRIVATE_KEY
      ? {
          rs256PrivateKey: env.JWT_RS256_PRIVATE_KEY,
          ...(env.JWT_RS256_PUBLIC_KEY ? { rs256PublicKey: env.JWT_RS256_PUBLIC_KEY } : {}),
          ...(env.JWT_RS256_KID ? { rs256KeyId: env.JWT_RS256_KID } : {}),
        }
      : {}),
    // RFC 7009 revocation: the shared `requireJwt` preHandler consults this
    // Redis-backed denylist after verification so a revoked access token is
    // rejected everywhere it is used as a bearer credential. Resolved lazily
    // via the `fastify.redis` decorator (cache plugin registered above).
    isTokenRevoked: (jti) => isJtiRevoked(fastify, jti),
    // ADR-005: when hybrid signing is enabled, publish the ML-DSA public key as
    // an AKP JWK on /.well-known/jwks.json alongside the Ed25519 OKP key
    // (#246), AND mint live hybrid access tokens (#275). The config's fail-fast
    // coupling guarantees the seed is present when the flag is on; the plugin
    // additionally refuses to start if it is not. Default OFF.
    //
    // #248 F7/F11: the plugin resolves the ML-DSA backend through
    // `getSignatureBackend`, so it must see the operator's SIGNING_ALGORITHM_MODE
    // allowlist rather than a hardcoded literal.
    ...(env.HYBRID_SIGNING_ENABLED
      ? {
          mlDsaSeed: env.JWT_MLDSA_PRIVATE_KEY,
          mlDsaKeyId: env.JWT_MLDSA_KID,
          hybridSigningEnabled: true,
          // #248 F7/F11: honour the operator-enabled algorithm set at the live
          // call site instead of a hardcoded allowlist.
          enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        }
      : {}),
  });

  // Rate limiting (T3). This position IS load-bearing: it MUST stay ahead of
  // the routes AutoLoad below. @fastify/rate-limit applies both the global
  // ceiling and every per-route `config.rateLimit` override through an
  // `onRoute` hook, and `onRoute` is NOT retroactive — Fastify fires it as each
  // route is added, so routes already registered by the time this plugin loads
  // are simply never seen. Moving it after the AutoLoad would not throw, warn
  // or fail a boot check; it would silently drop every per-route limit,
  // including the brute-force ceiling on /auth/login and the
  // `config: { rateLimit: false }` scrape exemption on /metrics.
  await fastify.register(rateLimitPlugin);

  // Security headers (issue #113): every response — including the
  // server-rendered login/consent pages and error responses — carries the CSP,
  // HSTS, frame-options and related hardening headers.
  //
  // Unlike the rate limiter above, this position is NOT load-bearing (#365) —
  // but for a different reason than the symmetry suggests, and the distinction
  // is the whole point. The plugin installs an `onSend` hook, and `addHook`
  // for that class of hook recurses into already-created child scopes
  // (`this[kChildren].forEach(child => _addHook.call(child, name, fn))` in
  // Fastify's `_addHook`), so it does reach routes that loaded earlier.
  // `onRoute` is explicitly routed past that recursion — which is exactly why
  // the rate limiter above IS position-sensitive and this is not. Do not
  // generalise "hooks are retroactive" from this comment; it holds per hook
  // type, not per plugin.
  await fastify.register(securityHeadersPlugin);

  // Observability (T3): request-id propagation (#128) and the metrics registry
  // (#123/#126). Neither position is load-bearing either (#365): request-id is
  // another hook (`onRequest`), propagated into existing child scopes by the
  // same recursion described above, and metrics only `decorate()`s the
  // instance — its sole consumer, GET /metrics, dereferences `fastify.metrics`
  // inside the handler at request time, not while the route plugin is loading.
  await fastify.register(requestIdPlugin);
  await fastify.register(metricsPlugin);

  // Global error handler (#365). This MUST precede every route registration
  // below — it used to sit after both AutoLoads, under a comment claiming the
  // last position "catches all unhandled errors", and that is exactly
  // backwards. A route does not look its error handler up at request time:
  // Fastify snapshots it while closing the route's enclosing plugin
  // (`context.errorHandler = this[kErrorHandler]` in the `after()` callback of
  // `lib/route.js`). Since avvio runs queued plugins in registration order, a
  // `setErrorHandler` that runs later reaches NO route that already loaded —
  // the handler existed but was unreachable, and every error was answered by
  // Fastify's built-in `{statusCode, code, error, message}` envelope instead.
  //
  // What that silently reverted: the F-01 register-enumeration fix (PR #212),
  // which genericises `UniqueConstraintError` so the DB constraint name never
  // reaches the wire (the built-in envelope echoes `error.message`, which
  // embeds it); the RFC 6750 §3 `WWW-Authenticate: Bearer` challenge a
  // bearer-protected resource such as /oauth/userinfo MUST return on 401; the
  // RFC 6749 §5.2 OAuth error shapes; and the `error_description` sanitisation
  // that keeps that challenge header well-formed.
  //
  // It sits ahead of `cors` deliberately, not merely ahead of the AutoLoads:
  // @fastify/cors registers a route of its own — `fastify.options('*')` — so a
  // handler installed after it would leave that one route on the built-in
  // envelope. Cors answers most preflights from its `onRequest` hook before the
  // route body runs, but @fastify/rate-limit THROWS its 429 from an `onRequest`
  // hook registered earlier still, so a rate-limited OPTIONS request would
  // render the wrong shape. Registering here covers every route in this scope.
  //
  // Not covered, and never was: routes registered on the ROOT instance in
  // `main.ts` (Swagger's /docs, and the default 404 context) resolve the root's
  // error handler, not this one. Do not read this registration as "every
  // response now goes through error-handler.ts".
  await fastify.register(errorHandler);

  // CORS (F-06): fail-closed in production when CORS_ORIGIN is unset — the
  // auth-server's own browser flows (login/consent) are same-origin and do
  // not need CORS, and the JSON API is called by the same-origin developer
  // portal. Denying cross-origin by default is the safe posture; an operator
  // who needs cross-origin access sets CORS_ORIGIN explicitly. In
  // non-production the wildcard fallback is kept for local dev convenience.
  //
  // CORS_ORIGIN accepts a single origin or a comma-separated list (as the env
  // examples document). Split + trim it into an array so @fastify/cors matches
  // each origin; passing the raw comma string would be treated as one literal
  // origin and never match. Empty entries (e.g. a trailing comma) are dropped.
  const corsOrigins = env.CORS_ORIGIN
    ? env.CORS_ORIGIN.split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
    : [];
  await fastify.register(cors, {
    origin: corsOrigins.length > 0 ? corsOrigins : env.NODE_ENV === 'production' ? false : '*',
  });

  // RFC 6749 §3.2 (token endpoint) and RFC 7662 §2.1 (introspection)
  // both mandate `application/x-www-form-urlencoded` for request bodies.
  // Fastify ships with a JSON parser by default — without formbody,
  // every OAuth-spec-compliant client gets 415 Unsupported Media Type.
  // Register before routes so /oauth/* receives decoded form bodies.
  await fastify.register(formbody);

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'plugins'),
    options: { ...opts },
    ignorePattern:
      /(error-handler|rate-limit|security-headers|metrics|request-id)\.(ts|js)$|\.(test|spec)\.(ts|js)$/,
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
    ignorePattern: /\.(test|spec)\.(ts|js)$/,
  });
}
