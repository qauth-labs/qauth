import type { FastifyServerOptions } from 'fastify';

import type { env as Env } from './env';

/**
 * pino redaction paths. Any value at these paths is replaced with `[Redacted]`
 * in every log line, so secrets that ride along on the request/response (or are
 * accidentally logged inside an object) never reach the log sink (#122).
 *
 * Covers credentials, bearer/refresh tokens, client secrets, OAuth codes,
 * PKCE verifiers, `Authorization` headers, and cookies — across both request
 * (`req.*`) and response (`res.*`) serialised shapes that pino-http emits.
 */
export const LOG_REDACT_PATHS = [
  // Request/response headers carrying credentials.
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  // Common secret-bearing fields wherever they appear in a logged object.
  'password',
  '*.password',
  'newPassword',
  'currentPassword',
  'token',
  '*.token',
  'access_token',
  '*.access_token',
  'refresh_token',
  '*.refresh_token',
  'id_token',
  '*.id_token',
  'subject_token',
  'actor_token',
  'client_secret',
  '*.client_secret',
  'code',
  'code_verifier',
  'secret',
  '*.secret',
  'authorization',
] as const;

type ObservabilityEnvSubset = Pick<typeof Env, 'LOG_LEVEL' | 'LOG_PRETTY' | 'NODE_ENV'>;

/**
 * Build the pino logger options for the Fastify server.
 *
 * Honours `LOG_LEVEL`, always redacts secrets, and — only when `LOG_PRETTY` is
 * enabled and not running in production — routes output through `pino-pretty`
 * for human-readable local development. Production emits structured JSON for log
 * shippers.
 *
 * @param env - Validated environment configuration.
 * @returns A pino logger options object for `Fastify({ logger })`.
 */
export function buildLoggerOptions(env: ObservabilityEnvSubset): FastifyServerOptions['logger'] {
  const usePretty = env.LOG_PRETTY && env.NODE_ENV !== 'production';

  return {
    level: env.LOG_LEVEL,
    redact: {
      paths: [...LOG_REDACT_PATHS],
      censor: '[Redacted]',
    },
    ...(usePretty
      ? {
          transport: {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'SYS:standard',
              ignore: 'pid,hostname',
            },
          },
        }
      : {}),
  };
}
