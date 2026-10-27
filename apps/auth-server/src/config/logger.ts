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
 * even though `LOG_REDACT_PATHS` names it. QAuth puts two such secrets in a
 * query string:
 *
 * - `response_code`: the same-device Response Code the wallet's browser brings
 *   back to `/ui/wallet-login/return?response_code=…` (OID4VP 1.0 §8.2 and
 *   §14.2, #405, ADR-013). The code is single-use and short-lived, but a log
 *   line outlives both, and a value that must "ensure only the receiver of the
 *   redirect can fetch and process the Authorization Response" has no
 *   business in a log shipper.
 * - `token`: the email verification token in the link a verification mail
 *   carries, `<issuer>/auth/verify?token=…` (#490). Opening the link sends a
 *   GET with the token in the query (`routes/auth/verify-page.ts`), logged by
 *   the request line; with the account's password it verifies the account
 *   until it is used or expires (a day by default). Censored on every path,
 *   so a link pasted onto a wrong path is censored too.
 *
 * Names are matched case-sensitively, as query parameter names are, and in
 * every spelling the route would accept: Fastify's querystring parser
 * percent-DECODES the key before the handler sees it, so a wallet or in-app
 * browser that re-encodes the `redirect_uri` QAuth issued into
 * `?response%5Fcode=…` (or `%5f`, or any other character of the name in its
 * `%XX` form) still lands on `request.query.response_code`, and the return
 * route burns and redeems that code exactly as it would the plain spelling.
 * The censor therefore tolerates a percent-encoded spelling of every character
 * of every listed name (see {@link percentEncodingTolerantPattern}); the plain
 * name is one of those spellings. The value is censored up to the next `&`.
 * Add to this list rather than to `LOG_REDACT_PATHS` when the next bearer
 * value has to ride in a URL.
 *
 * Every consumer of a request-target that reaches the log must go through
 * {@link redactLoggedUrl}: Fastify's own request/response lines do via the
 * `req` serializer below, and the global error handler
 * (`plugins/error-handler.ts`) does on the plain `url` key of its own lines —
 * a 429 from `@fastify/rate-limit` is thrown from an `onRequest` hook BEFORE the
 * return route runs, so on that line the code is not even spent yet. So does
 * the unknown-route line (`helpers/request-bounds.ts`).
 */
export const LOG_REDACTED_QUERY_PARAMETERS = ['response_code', 'token'] as const;

/**
 * Query parameter names this module knows how to spell tolerantly: the RFC
 * 3986 §2.3 unreserved set, which is every character a QAuth query parameter
 * name uses and every character a client may equally send plain or
 * percent-encoded (the two are equivalent by that section, and Fastify treats
 * them so). Kept narrow so the per-character pattern below never has to
 * reason about multi-byte UTF-8 sequences.
 */
const REDACTABLE_QUERY_PARAMETER_NAME = /^[A-Za-z0-9\-._~]+$/;

/**
 * A regular-expression source that matches `name` whether each of its
 * characters arrives plain or percent-encoded, in either hex case: for
 * `response_code`, the spellings `response_code`, `response%5Fcode`,
 * `response%5fcode` and `%72esponse_code` alike.
 *
 * Built character by character — `(?:_|%5[Ff])` for `_`, `(?:r|%72)` for `r` —
 * rather than by decoding the URL first, because the logged URL is kept as the
 * client sent it (see {@link redactLoggedUrl}) and a decoder run over the whole
 * line would rewrite every request to redact one parameter on one route.
 * Only `=` and `&` are NOT tolerated in encoded form, deliberately: the parser
 * splits on the literal separators before it decodes anything, so an encoded
 * `%3D` or `%26` never delimits the parameter it would have named.
 *
 * @param name - a query parameter name from the unreserved set; anything else
 * throws at module load, where a bad entry in
 * {@link LOG_REDACTED_QUERY_PARAMETERS} is found by every test rather than by
 * the first log line that should have been censored.
 */
export function percentEncodingTolerantPattern(name: string): string {
  if (!REDACTABLE_QUERY_PARAMETER_NAME.test(name)) {
    throw new TypeError(
      `Redacted query parameter name ${JSON.stringify(name)} must use only RFC 3986 unreserved characters`
    );
  }

  return [...name]
    .map((character) => {
      // `.` is the one unreserved character with a meaning inside a pattern.
      const literal = character === '.' ? '\\.' : character;
      const hex = character.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
      const encoded = [...hex]
        .map((digit) => (/[A-F]/.test(digit) ? `[${digit}${digit.toLowerCase()}]` : digit))
        .join('');

      return `(?:${literal}|%${encoded})`;
    })
    .join('');
}

/**
 * One regular expression over {@link LOG_REDACTED_QUERY_PARAMETERS}, compiled
 * once: the separator, the name (in any spelling
 * {@link percentEncodingTolerantPattern} admits) and the `=` captured (and
 * kept), then everything up to the next `&` (censored).
 *
 * Anchored on the `?` or `&` that precedes the name so `x_response_code=` is
 * left alone, and stopping at `&` so the parameters after the censored one
 * stay readable in the line.
 */
const REDACTED_QUERY_VALUE_PATTERN = new RegExp(
  `([?&](?:${LOG_REDACTED_QUERY_PARAMETERS.map(percentEncodingTolerantPattern).join('|')})=)[^&]*`,
  'g'
);

/**
 * Censor the value of every {@link LOG_REDACTED_QUERY_PARAMETERS} entry in a
 * request URL, leaving everything else byte-for-byte as it was — including the
 * spelling of the censored parameter's name, encoded or not.
 *
 * A string rewrite rather than `new URL(...)` round-tripping deliberately: the
 * logged URL is the request-target as the client sent it, and re-serialising it
 * would normalise percent-encoding and case on EVERY request just to redact one
 * parameter on one route.
 *
 * Used by the `req` serializer for Fastify's request/response lines AND by the
 * global error handler for the `url` it logs beside every error, so a thrown
 * 429 / 5xx / validation 400 on the return route carries no more than the
 * request line does.
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

/** What pino's own `err` serializer is willing to treat as an error. */
interface ErrorLike {
  message: string;
  name?: string;
  stack?: string;
  cause?: unknown;
}

function isErrorLike(value: unknown): value is ErrorLike {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as Partial<ErrorLike>).message === 'string'
  );
}

/**
 * drizzle-orm's `DrizzleQueryError`: the SQL that failed and the values bound
 * to its placeholders, which it ALSO spells out in its `message` — `Failed
 * query: <sql>\nparams: <values>` — and, through it, in its `stack`.
 */
interface FailedQueryErrorLike extends ErrorLike {
  query: string;
  params: unknown;
}

function isFailedQueryError(error: ErrorLike): error is FailedQueryErrorLike {
  return 'query' in error && typeof error.query === 'string' && 'params' in error;
}

/**
 * The `message` and `stack` of one link in a cause chain as they may be
 * logged: a failed query keeps its SQL and loses its bound parameters,
 * everything else is returned untouched.
 */
function loggableMessageAndStack(error: ErrorLike): { message: string; stack: string } {
  const stack = error.stack ?? '';
  if (!isFailedQueryError(error)) {
    return { message: error.message, stack };
  }
  const message = `Failed query: ${error.query}`;
  // The stack opens with the message, so the parameters sit there too. A
  // function replacement, because the SQL may contain `$1`-style sequences
  // that `String#replace` would otherwise interpret.
  return { message, stack: stack.replace(error.message, () => message) };
}

/** The shape Fastify declares for what an `err` serializer returns. */
interface SerializedErrorForLog {
  type: string;
  message: string;
  stack: string;
  [key: string]: unknown;
}

/**
 * The pino `err` serializer: what pino's own produces — `type`, `message` and
 * `stack` with the cause chain appended, the error's own enumerable fields —
 * minus the bound parameters of a failed database query.
 *
 * Every repository INSERT puts the row into the query parameters, and the
 * row is where the secrets live: `user_credentials.credential_data` carries
 * the Argon2id hash of the password just typed, `oauth_clients` the
 * `client_secret_hash`, `api_keys` the `key_hash`, beside the e-mail address
 * or client id the row is keyed by. drizzle-orm builds `DrizzleQueryError`'s
 * message from those parameters, the repositories keep it as the `cause` of
 * the `UniqueConstraintError` they throw (409), and an insert that fails for
 * any other reason reaches the error handler as the `DrizzleQueryError`
 * itself (500). Either way the global error handler logs `{ err }`, and
 * pino's default serializer flattens every message in the cause chain into
 * `err.message` and every stack into `err.stack`. `LOG_REDACT_PATHS` names
 * object keys and cannot reach inside those strings, for the same reason the
 * request `url` has {@link redactLoggedUrl}; `err.params` is dropped as well,
 * since on an unwrapped query error it is an own field and would be copied
 * verbatim.
 *
 * `err.rawPacket` is dropped for the same reason. Node's HTTP parser attaches
 * the bytes it could not parse to its client errors (`HPE_*`), and those
 * bytes are the request as sent: its `Cookie` and `Authorization` headers
 * included. Copied as an own field, a malformed request would put the
 * caller's session cookie or access token in the log.
 *
 * A duplicate registration was the everyday case: every second
 * `POST /auth/register` for an address fails inside the credential insert,
 * AFTER the password was hashed — and when it is the account holder retrying,
 * the hash in the log verifies against their real password. That route now
 * answers the duplicate itself (ANT-2026-SPEMY9GU) and logs neither the error
 * nor its cause, but any other insert that fails still reaches the handler.
 * The SQL text (with its `$n` placeholders) and the PostgreSQL message stay in
 * the line; an operator loses nothing they could not read from the schema.
 *
 * @param err - the value logged under `err`. Typed as Fastify types it, and
 * anything that is not error-like is passed through as pino's own serializer
 * does, so a stray `log.warn({ err: 'text' })` cannot throw inside the logger.
 */
export function serializeErrorForLog(err: Error): SerializedErrorForLog {
  if (!isErrorLike(err)) {
    return err as unknown as SerializedErrorForLog;
  }
  return serializeErrorLike(err, new Set<object>());
}

/**
 * {@link serializeErrorForLog} for one error. Mirrors pino-std-serializers'
 * `err`: it serializes `AggregateError#errors` into `aggregateErrors` and
 * error-valued fields recursively, so a failed query nested in either place
 * loses its parameters too, instead of being copied out raw. `visited`
 * (errors already serialized on this call) ends cycles, as pino's `seen` tag
 * does.
 */
function serializeErrorLike(err: ErrorLike, visited: Set<object>): SerializedErrorForLog {
  visited.add(err);

  const messages: string[] = [];
  const stacks: string[] = [];
  const chain = new Set<ErrorLike>();
  for (let link: unknown = err; isErrorLike(link) && !chain.has(link); link = link.cause) {
    chain.add(link);
    const { message, stack } = loggableMessageAndStack(link);
    messages.push(message);
    stacks.push(stack);
  }

  const errors = (err as { errors?: unknown }).errors;
  const fields: Record<string, unknown> = {};
  if (Array.isArray(errors)) {
    fields['aggregateErrors'] = errors.map((entry) =>
      isErrorLike(entry) && !visited.has(entry) ? serializeErrorLike(entry, visited) : entry
    );
  }
  for (const [key, value] of Object.entries(err)) {
    // `cause` is already folded into `message` and `stack`; `errors` into
    // `aggregateErrors`; a failed query's `params` are the secret, and so are
    // the raw request bytes a parser error carries in `rawPacket`.
    if (
      key === 'cause' ||
      key === 'rawPacket' ||
      (key === 'errors' && Array.isArray(errors)) ||
      (key === 'params' && isFailedQueryError(err))
    ) {
      continue;
    }
    if (isErrorLike(value)) {
      if (!visited.has(value)) {
        fields[key] = serializeErrorLike(value, visited);
      }
      continue;
    }
    fields[key] = value;
  }

  return {
    ...fields,
    type: typeof err.constructor === 'function' ? err.constructor.name : (err.name ?? 'Error'),
    message: messages.join(': '),
    stack: stacks.join('\ncaused by: '),
  };
}

type ObservabilityEnvSubset = Pick<typeof Env, 'LOG_LEVEL' | 'LOG_PRETTY' | 'NODE_ENV'>;

/**
 * Build the pino logger options for the Fastify server.
 *
 * Honours `LOG_LEVEL`, always redacts secrets — by path through pino's
 * `redact`, inside the request `url` through the `req` serializer, and inside
 * a failed query's message through the `err` serializer — and, only when
 * `LOG_PRETTY` is enabled and not running in production, routes output through
 * `pino-pretty` for human-readable local development. Production emits
 * structured JSON for log shippers.
 *
 * Only `req` and `err` are overridden: Fastify merges these serializers OVER
 * its defaults, so `res` keeps theirs.
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
      err: serializeErrorForLog,
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
