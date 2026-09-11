import type { FastifyRequest, FastifyServerOptions } from 'fastify';

import type { env as Env } from './env';

/** What every redacted value is replaced with, on paths and in the URL alike. */
export const LOG_REDACT_CENSOR = '[Redacted]';

/**
 * pino redaction paths. Any value at these paths is replaced with `[Redacted]`
 * in every log line, so secrets that ride along on the request/response (or are
 * accidentally logged inside an object) never reach the log sink (#122).
 *
 * Covers credentials, bearer/refresh tokens, client secrets, OAuth codes,
 * PKCE verifiers, `Authorization` headers, and cookies — across both request
 * (`req.*`) and response (`res.*`) serialised shapes that pino-http emits.
 *
 * Path redaction cannot reach INSIDE a string, which is why the request `url`
 * has its own treatment in {@link LOG_REDACTED_QUERY_PARAMETERS}.
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

/**
 * Query parameters whose VALUE is censored inside the logged request `url`.
 *
 * Fastify's request log line carries `req.url` verbatim — path AND query
 * string — and pino's path-based `redact` works on object keys, so a bearer
 * secret that arrives as a query parameter would reach the sink in the clear
 * even though `LOG_REDACT_PATHS` names it. QAuth puts exactly one such secret
 * in a query string: the same-device Response Code the wallet's browser brings
 * back to `/ui/wallet-login/return?response_code=…` (OID4VP 1.0 §8.2 and
 * §14.2, #405, ADR-013). The code is single-use and short-lived, but a log
 * line outlives both, and a value that must "ensure only the receiver of the
 * redirect can fetch and process the Authorization Response" has no business
 * in a log shipper.
 *
 * Names are matched exactly and case-sensitively, as query parameter names
 * are; the value is censored up to the next `&`. Add to this list rather than
 * to `LOG_REDACT_PATHS` when the next bearer value has to ride in a URL.
 */
export const LOG_REDACTED_QUERY_PARAMETERS = ['response_code'] as const;

/**
 * One regular expression over {@link LOG_REDACTED_QUERY_PARAMETERS}, compiled
 * once: the separator, the name and the `=` captured (and kept), then
 * everything up to the next `&` (censored).
 *
 * Anchored on the `?` or `&` that precedes the name so `x_response_code=` is
 * left alone, and stopping at `&` so the parameters after the censored one
 * stay readable in the line.
 */
const REDACTED_QUERY_VALUE_PATTERN = new RegExp(
  `([?&](?:${LOG_REDACTED_QUERY_PARAMETERS.join('|')})=)[^&]*`,
  'g'
);

/**
 * Censor the value of every {@link LOG_REDACTED_QUERY_PARAMETERS} entry in a
 * request URL, leaving everything else byte-for-byte as it was.
 *
 * A string rewrite rather than `new URL(...)` round-tripping deliberately: the
 * logged URL is the request-target as the client sent it, and re-serialising it
 * would normalise percent-encoding and case on EVERY request just to redact one
 * parameter on one route.
 *
 * @param url - the raw request-target (`req.url`), path plus query string.
 */
export function redactLoggedUrl(url: string): string {
  return url.replace(REDACTED_QUERY_VALUE_PATTERN, `$1${LOG_REDACT_CENSOR}`);
}

/**
 * The pino `req` serializer: Fastify's default shape with the `url` passed
 * through {@link redactLoggedUrl}.
 *
 * Fastify does not export its default serializer, so the six fields it logs
 * (`method`, `url`, `version`, `host`, `remoteAddress`, `remotePort` — the
 * pino-http shape it inlined) are reproduced here verbatim, and NOTHING else is
 * added: the request log line carries exactly what it carried before #405,
 * minus the one query value. Written defensively against a partial object
 * because `app.log.info({ req })` reaches this serializer too, and a hand-built
 * `req` in a test (or a stray log call) must not throw inside the logger.
 *
 * @param req - the request being logged; a `FastifyRequest` on Fastify's own
 * request/response lines.
 */
export function serializeRequestForLog(req: FastifyRequest): {
  method: string | undefined;
  url: string | undefined;
  version: string | undefined;
  host: string | undefined;
  remoteAddress: string | undefined;
  remotePort: number | undefined;
} {
  const partial = req as Partial<FastifyRequest>;
  const acceptVersion = partial.headers?.['accept-version'];

  return {
    method: partial.method,
    url: typeof partial.url === 'string' ? redactLoggedUrl(partial.url) : partial.url,
    version: typeof acceptVersion === 'string' ? acceptVersion : undefined,
    host: partial.host,
    remoteAddress: partial.ip,
    remotePort: partial.socket?.remotePort,
  };
}

type ObservabilityEnvSubset = Pick<typeof Env, 'LOG_LEVEL' | 'LOG_PRETTY' | 'NODE_ENV'>;

/**
 * Build the pino logger options for the Fastify server.
 *
 * Honours `LOG_LEVEL`, always redacts secrets — by path through pino's
 * `redact`, and inside the request `url` through the `req` serializer — and,
 * only when `LOG_PRETTY` is enabled and not running in production, routes
 * output through `pino-pretty` for human-readable local development. Production
 * emits structured JSON for log shippers.
 *
 * Only `req` is overridden: Fastify merges these serializers OVER its defaults,
 * so `res` and `err` keep theirs.
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
      censor: LOG_REDACT_CENSOR,
    },
    serializers: {
      req: serializeRequestForLog,
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
