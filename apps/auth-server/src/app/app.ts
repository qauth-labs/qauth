import * as path from 'node:path';

import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { emailPlugin, type EmailProviderConfig } from '@qauth-labs/fastify-plugin-email';
import { createPasswordProvider, federationPlugin } from '@qauth-labs/fastify-plugin-federation';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import { passwordPlugin } from '@qauth-labs/fastify-plugin-password';
import { pkcePlugin } from '@qauth-labs/fastify-plugin-pkce';
import type { FastifyInstance } from 'fastify';

import { env } from '../config/env';
import { isJtiRevoked } from './helpers/token-revocation';
import errorHandler from './plugins/error-handler';
import { metricsPlugin } from './plugins/metrics';
import { rateLimitPlugin } from './plugins/rate-limit';
import { requestIdPlugin } from './plugins/request-id';
import { securityHeadersPlugin } from './plugins/security-headers';

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

  // Credential-provider registry (ADR-003, #228). Providers are seeded here —
  // the bootstrap is the single registration point; adding an upstream (e.g.
  // WalletProvider, #231) means appending to this list, never touching routes.
  await fastify.register(federationPlugin, {
    providers: [createPasswordProvider()],
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
    },
  });

  await fastify.register(jwtPlugin, {
    privateKey: env.JWT_PRIVATE_KEY,
    publicKey: env.JWT_PUBLIC_KEY,
    issuer: env.JWT_ISSUER,
    accessTokenLifespan: env.ACCESS_TOKEN_LIFESPAN,
    refreshTokenLifespan: env.REFRESH_TOKEN_LIFESPAN,
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

  await fastify.register(rateLimitPlugin);

  // Security headers (issue #113): register before routes so every response —
  // including the server-rendered login/consent pages and error responses —
  // carries the CSP, HSTS, frame-options and related hardening headers.
  await fastify.register(securityHeadersPlugin);

  // Observability (T3): request-id propagation (#128) and the metrics registry
  // (#123/#126) must be available before routes are loaded.
  await fastify.register(requestIdPlugin);
  await fastify.register(metricsPlugin);

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

  // Register error handler last to catch all unhandled errors
  await fastify.register(errorHandler);
}
