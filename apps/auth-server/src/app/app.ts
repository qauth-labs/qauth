import * as path from 'node:path';

import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import formbody from '@fastify/formbody';
import { cachePlugin } from '@qauth-labs/fastify-plugin-cache';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { emailPlugin, type EmailProviderConfig } from '@qauth-labs/fastify-plugin-email';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import { passwordPlugin } from '@qauth-labs/fastify-plugin-password';
import { pkcePlugin } from '@qauth-labs/fastify-plugin-pkce';
import type { FastifyInstance } from 'fastify';

import { env } from '../config/env';
import errorHandler from './plugins/error-handler';
import { rateLimitPlugin } from './plugins/rate-limit';

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
  });

  await fastify.register(rateLimitPlugin);

  await fastify.register(cors, {
    origin: env.CORS_ORIGIN || '*',
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
    ignorePattern: /(error-handler|rate-limit)\.(ts|js)$|\.(test|spec)\.(ts|js)$/,
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
    ignorePattern: /\.(test|spec)\.(ts|js)$/,
  });

  // Register error handler last to catch all unhandled errors
  await fastify.register(errorHandler);
}
