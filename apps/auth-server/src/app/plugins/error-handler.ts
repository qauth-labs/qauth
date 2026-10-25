import {
  InvalidClientError,
  InvalidDpopProofError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TemporarilyUnavailableError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { redactLoggedUrl } from '../../config/logger';
import { describeProblem, errorClassEntryOf } from '../api-conventions/error-classes';
import { apiFamilyOf } from '../api-conventions/families';
import {
  OAUTH_ERROR_CODES,
  type OAuthErrorBody,
  type OAuthErrorCode,
} from '../api-conventions/oauth-error';
import {
  codeForStatus,
  PROBLEM_CODES,
  PROBLEM_MEDIA_TYPE,
  type ProblemCode,
  problemCodeFor,
  type ProblemDocument,
} from '../api-conventions/problem';

/**
 * How a route answers an error (ADR-019 Decision 7, #506, #513):
 *
 *   - `problem`, the default: an RFC 9457 problem details document, sent as
 *     `application/problem+json`, with a stable `code` and a `trace_id`;
 *   - `oauth`: the error body of the specification the endpoint implements,
 *     `error` with an optional `error_description` (RFC 6749 §5.2), and no
 *     other member.
 *
 * The OAuth protocol endpoints set `oauth` in their route `config`: token,
 * authorization, introspection, revocation, dynamic registration, userinfo
 * and the wallet-facing OID4VP endpoints. Every other route answers `problem`
 * without saying so. Which class answers which code is set once, in
 * `api-conventions/error-classes.ts`.
 */
export type ErrorFormat = 'problem' | 'oauth';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The route's error format; see {@link ErrorFormat}. `problem` when unset. */
    errorFormat?: ErrorFormat;
  }
}

/** The error format of the route that failed; `problem` unless it says `oauth`. */
export function errorFormatOf(request: FastifyRequest): ErrorFormat {
  return request.routeOptions.config?.errorFormat ?? 'problem';
}

/**
 * Sanitize a message for an RFC 6749 `error_description`, in the body or in a
 * `WWW-Authenticate` header. The grammar permits only `%x20-21 / %x23-5B /
 * %x5D-7E` — no double-quote and no backslash — so anything outside that set
 * becomes a space: the body stays what the specification allows, and a
 * message cannot break out of the header's quoted value.
 */
function sanitizeDescription(message: string, maxLength: number): string {
  return message.replace(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/g, ' ').slice(0, maxLength);
}

/** The longest `error_description` inside a `WWW-Authenticate` challenge. */
const MAX_CHALLENGE_DESCRIPTION = 200;

/** The longest `error_description` in an OAuth error body. */
const MAX_BODY_DESCRIPTION = 500;

/**
 * The status this handler is about to answer with, decided BEFORE any branch
 * runs so the log line and the response can never disagree (#365).
 *
 * Both formats send `error.statusCode`, or a fixed status: a Fastify
 * validation failure is always 400, and anything with no usable `statusCode`
 * is always 500.
 *
 * `error.validation` is checked FIRST because Fastify's validation errors carry
 * a `statusCode` of their own and it agrees (400). A route's
 * `schemaErrorFormatter` may return a domain error, and Fastify attaches the
 * issues to it as `validation`: its status is still 400.
 */
function intendedStatusCode(error: FastifyError | Error): number {
  if (isValidationError(error)) return 400;

  const declared = (error as { statusCode?: unknown }).statusCode;

  return typeof declared === 'number' && declared >= 100 && declared <= 599 ? declared : 500;
}

/** Whether `error` is a schema validation failure Fastify raised. */
function isValidationError(error: FastifyError | Error): error is FastifyError {
  return 'validation' in error && Boolean(error.validation);
}

/**
 * One validation failure, reduced to what a CALLER may see (#365).
 *
 * The pre-#365 handler sent `error.validation` verbatim, and under
 * `fastify-type-provider-zod` that is the compiler's own issue objects. On
 * `POST /oauth/token` the emitted array carried, per issue, a `keyword`, an
 * `instancePath`, a `schemaPath` (`#/grant_type/invalid_union`) and a `params`
 * bag holding the discriminator name and the full option list — the internal
 * shape of the schema, handed to an unauthenticated caller.
 *
 * `pointer` and `message` are what a client needs to fix its request, and they
 * are all it needs: which field (an RFC 6901 JSON Pointer into the body, or
 * into the object of query or path parameters), and what is wrong with it.
 * Everything else describes how QAuth is BUILT rather than what it accepts.
 *
 * The `message` is kept INTACT, including the constraint it quotes (`must match
 * pattern "…"`, or the list of permitted discriminator values). Those are the
 * schemas, and the schemas are published in `openapi.json` — documentation
 * rather than disclosure. Genericising them would leave a caller a field path
 * and no way to learn what is wrong with it. The distinction that matters is
 * structural-vs-contractual, not verbose-vs-terse.
 */
interface ValidationDetail {
  pointer: string;
  message: string;
}

/**
 * Most validation issues returned or logged for one request.
 *
 * The request schemas bound how many issues a body can produce (`boundedArray`
 * in `schemas/common.ts`); this keeps the handler from depending on every
 * schema getting that right. An uncapped list multiplies whatever count a
 * caller reaches: each issue is ~190 bytes of answer and, logged whole, ~750
 * bytes of log. A caller fixing its request needs the first few.
 */
const MAX_VALIDATION_DETAILS = 20;

/** How many issues an OAuth `error_description` names: it is one line of text. */
const MAX_DESCRIBED_ISSUES = 5;

/**
 * Project the compiler's issues into {@link ValidationDetail}s.
 *
 * Tolerant by construction: the input is typed `unknown` by Fastify and its
 * shape depends on which validator compiler is installed, so an issue this
 * function cannot read degrades to an empty pointer and a generic message
 * rather than throwing out of the error handler — the one place a throw
 * becomes an unhandled rejection with no response at all.
 */
export function projectValidationDetails(validation: unknown): ValidationDetail[] {
  if (!Array.isArray(validation)) return [];

  return validation.slice(0, MAX_VALIDATION_DETAILS).map((issue: unknown) => {
    const record = (issue ?? {}) as Record<string, unknown>;
    const path = record['instancePath'];
    const message = record['message'];

    return {
      pointer: typeof path === 'string' ? path : '',
      message: typeof message === 'string' ? message : 'Invalid value',
    };
  });
}

/**
 * What the log line carries as `err`.
 *
 * A validation error holds every issue three times: in `validation`, in
 * `message` (Fastify joins every issue's message into it) and in `stack`, which
 * starts with that message. pino's `err` serializer writes all three. So a
 * validation error is logged as its issue count and the same bounded
 * projection the caller receives; any other error is logged as it is.
 */
function loggableError(error: FastifyError | Error): unknown {
  if (!isValidationError(error)) return error;

  return {
    type: 'ValidationError',
    validationContext: error.validationContext,
    issues: Array.isArray(error.validation) ? error.validation.length : undefined,
    details: projectValidationDetails(error.validation),
  };
}

/**
 * An error whose `message` is a registered OAuth `error` value and whose
 * human-readable detail lives on `errorDescription`: the OAuth error classes
 * of `@qauth-labs/shared-errors`.
 */
interface OAuthTokenError extends Error {
  readonly message: OAuthErrorCode;
  readonly errorDescription?: string;
}

function isOAuthTokenError(error: unknown): error is OAuthTokenError {
  return (
    error instanceof Error &&
    'errorDescription' in error &&
    Object.hasOwn(OAUTH_ERROR_CODES, error.message)
  );
}

/**
 * Whether the request presented its access token under the `DPoP` scheme
 * (RFC 9449 §7.1), matched exactly as `requireJwt` reads it.
 */
function usedDpopScheme(request: FastifyRequest): boolean {
  return (request.headers.authorization ?? '').startsWith('DPoP ');
}

/**
 * Whether the route that failed takes a bearer access token: it is a route of
 * an API family (ADR-019 Decision 7), or its schema declares the `bearerAuth`
 * security requirement, as the developer API at `/api/clients` does.
 */
function isBearerProtected(request: FastifyRequest): boolean {
  const url = request.routeOptions.url;
  if (url !== undefined && apiFamilyOf(url) !== undefined) return true;
  const security = (request.routeOptions.schema as { security?: unknown } | undefined)?.security;
  return (
    Array.isArray(security) &&
    security.some(
      (requirement) =>
        typeof requirement === 'object' &&
        requirement !== null &&
        Object.hasOwn(requirement, 'bearerAuth')
    )
  );
}

/** The problem code of `error` at `status`. */
function problemCodeOf(error: FastifyError | Error, status: number): ProblemCode {
  if (isValidationError(error)) return 'validation_error';
  const entry = errorClassEntryOf(error);
  if (entry !== undefined) {
    // A class thrown with a status its entry does not list (an
    // InvalidDpopProofError meant for a token request) gets the code of the
    // status, so a code is never sent with another status than its own.
    return PROBLEM_CODES[entry.code].status === status ? entry.code : codeForStatus(status);
  }
  // An error no entry lists: a framework error, the rate limiter's, a route's
  // own class. Its own code counts only when it is published for the status.
  return problemCodeFor((error as { code?: unknown }).code, status);
}

/**
 * The `detail` of a problem document: what a caller may read about this
 * failure, or nothing.
 *
 * A 5xx never carries one. The message of an unexpected error is ours, not the
 * caller's, and the `trace_id` already leads an operator to it. Nor does a
 * `UniqueConstraintError`, whose message embeds the constraint name: once an
 * enumeration oracle (a duplicate-email registration reached the wire with the
 * credentials index in it, PR #212). An OAuth error class carries its token as
 * the message, so its description is the detail.
 */
function problemDetail(error: FastifyError | Error, status: number): string | undefined {
  if (status >= 500) return undefined;
  if (isValidationError(error)) return 'The request is not valid.';
  if (error instanceof UniqueConstraintError) return undefined;
  if (isOAuthTokenError(error)) return error.errorDescription || undefined;
  return error.message || undefined;
}

/**
 * The request path without its query, as the document's `instance`.
 *
 * The query is left out because it can carry a secret: on
 * `/ui/wallet-login/return?response_code=…` it holds the same-device Response
 * Code (OID4VP 1.0 §14.2), which the request logger censors too.
 */
function instanceOf(request: FastifyRequest): string {
  const queryAt = request.url.indexOf('?');
  return queryAt === -1 ? request.url : request.url.slice(0, queryAt);
}

/**
 * Build the RFC 9457 document for `error` (#506, #513).
 *
 * `type`, `title` and `code` come from the registry: a class's entry, or the
 * code of the status for an error no entry lists. A framework code such as
 * `FST_ERR_VALIDATION` never reaches the wire. `trace_id` is the request id the
 * request logger carries as `reqId`, so an operator finds the log line by it.
 * A validation failure lists each field in `errors`, and a weak password lists
 * its feedback under `/password`.
 */
export function problemDocument(
  error: FastifyError | Error,
  request: FastifyRequest,
  status: number
): ProblemDocument {
  const { code, type, title } = describeProblem(problemCodeOf(error, status));
  const document: ProblemDocument = {
    type,
    title,
    status,
    instance: instanceOf(request),
    code,
    trace_id: request.id,
  };

  const detail = problemDetail(error, status);
  if (detail) document.detail = detail;

  const errors = isValidationError(error)
    ? projectValidationDetails(error.validation)
    : error instanceof WeakPasswordError
      ? (error.feedback ?? []).map((message) => ({ pointer: '/password', message }))
      : [];
  if (errors.length > 0) document.errors = errors;

  return document;
}

/**
 * The `error` an OAuth protocol endpoint answers for an error no registry
 * entry lists: a framework error (a body that is not JSON, an unsupported
 * media type), the rate limiter's 429, or an unexpected failure.
 */
function oauthErrorForStatus(status: number): OAuthErrorCode {
  if (status === 429 || status === 503) return 'temporarily_unavailable';
  if (status >= 500) return 'server_error';
  return 'invalid_request';
}

/** The fields a validation failure names, as one line for `error_description`. */
function describeValidation(validation: unknown): string {
  return projectValidationDetails(validation)
    .slice(0, MAX_DESCRIBED_ISSUES)
    .map(({ pointer, message }) => (pointer ? `${pointer}: ${message}` : message))
    .join('; ');
}

/**
 * Build the OAuth error body for `error` (RFC 6749 §5.2; #513): `error`, and an
 * `error_description` when there is one to give. No other member is sent.
 *
 * - An OAuth error class names its own token, and its description is its
 *   `errorDescription`. A route's `schemaErrorFormatter` may raise one for a
 *   body its schema refuses (`/oauth/register` answers `invalid_client_metadata`,
 *   RFC 7591 §3.2.2).
 * - Any other validation failure is `invalid_request`, and the description
 *   names the fields.
 * - Any other class answers the `oauthError` of its registry entry, with its
 *   message as the description; an error no entry lists answers by status.
 * - A 5xx and a `UniqueConstraintError` carry no description, for the reasons
 *   {@link problemDetail} gives, and nor does a `NotFoundError`.
 */
export function oauthErrorBody(error: FastifyError | Error, status: number): OAuthErrorBody {
  let code: OAuthErrorCode;
  let description: string | undefined;

  if (isOAuthTokenError(error)) {
    code = error.message;
    description = error.errorDescription;
  } else if (isValidationError(error)) {
    code = 'invalid_request';
    description = describeValidation(error.validation);
  } else {
    code = errorClassEntryOf(error)?.oauthError ?? oauthErrorForStatus(status);
    // A NotFoundError names the row it did not find (`User with id …`): on an
    // OAuth endpoint that is an internal id, such as the user an authorization
    // code was issued for, never one the caller sent.
    description =
      error instanceof UniqueConstraintError || error instanceof NotFoundError
        ? undefined
        : error.message;
  }

  if (status >= 500) description = undefined;
  // A message that only repeats the token says nothing more.
  if (description === code) description = undefined;
  return description
    ? { error: code, error_description: sanitizeDescription(description, MAX_BODY_DESCRIPTION) }
    : { error: code };
}

/**
 * The challenge for a 401 or 403 problem answer on a bearer-protected route
 * that no earlier branch gave one (RFC 6750 §3, RFC 9449 §7.1; #513).
 *
 * A request that presented no credentials gets a challenge with no error code,
 * as RFC 6750 §3.1 asks; a 401 for credentials that were presented says
 * `invalid_token`, and a 403 `insufficient_scope`. A request that used the
 * `DPoP` scheme while DPoP is on is answered in that scheme, with the proof
 * algorithms in `algs`.
 */
function bearerChallenge(request: FastifyRequest, status: number, dpopAlgs?: string): string {
  const presented = (request.headers.authorization ?? '') !== '';
  const error = status === 403 ? 'insufficient_scope' : presented ? 'invalid_token' : undefined;
  if (dpopAlgs !== undefined && usedDpopScheme(request)) {
    return `DPoP ${error === undefined ? '' : `error="${error}", `}algs="${dpopAlgs}"`;
  }
  return `Bearer realm="OAuth"${error === undefined ? '' : `, error="${error}"`}`;
}

/**
 * Global error handler plugin: turns every error a route throws into the
 * answer its error format defines.
 */
export default fp(async function (fastify: FastifyInstance) {
  fastify.setErrorHandler(
    (error: FastifyError | Error, request: FastifyRequest, reply: FastifyReply) => {
      const statusCode = intendedStatusCode(error);

      // Logged through the REQUEST logger, at a level that matches what the
      // caller is about to be told (#365).
      //
      // Two separate defects, both of which only started mattering when this
      // handler became reachable. `fastify.log` is the SERVER logger and
      // carries no `reqId`; `request.log` is the child logger Fastify binds the
      // request id to, which is the entire point of the request-id propagation
      // in `plugins/request-id.ts` (#128). Logging the error on the server
      // logger meant the one line an operator needs to correlate with a
      // caller's report was the one line that could not be correlated.
      //
      // And every error was `error` level, so a mistyped grant_type, an expired
      // token and a 404 all arrived at the same severity as an unhandled
      // exception. On an authentication server, whose 4xx rate is dominated by
      // ordinary client mistakes and by unauthenticated traffic anyone can
      // generate, that is not a noisy log — it is an `error` stream a stranger
      // controls the volume of, and a real 500 buried inside it.
      //
      // 5xx is ours and stays `error`. 4xx is the caller's and is `warn`, which
      // keeps it queryable without letting it drown the level that pages
      // someone. A request shed under load (`TemporarilyUnavailableError`, 503
      // with `Retry-After`, #751) is `warn` too: the server refused it as
      // configured, and a burst a stranger sends must not flood `error`.
      //
      // The `url` is a plain string key on THIS line, so neither pino's
      // path-based `redact` (which cannot reach inside a string) nor the `req`
      // serializer (which only Fastify's own request/response lines go through)
      // touches it. It is passed through the same censor the serializer uses,
      // because on `/ui/wallet-login/return?response_code=…` the request-target
      // carries the same-device Response Code (OID4VP 1.0 §14.2, #405, ADR-013)
      // and the errors that reach this handler are exactly the ones that arrive
      // with the code still redeemable: a 429 from `@fastify/rate-limit` is
      // thrown from an `onRequest` hook before the route has run, a store
      // failure inside the redemption is a 500 before the row was updated. The
      // request line censors it; the error line beside it must not undo that.
      const shed = error instanceof TemporarilyUnavailableError;
      request.log[statusCode >= 500 && !shed ? 'error' : 'warn'](
        {
          err: loggableError(error),
          url: redactLoggedUrl(request.url),
          method: request.method,
          statusCode,
        },
        'Error occurred'
      );

      // The offending constraint name can be an enumeration oracle (a
      // duplicate-email registration once reached the wire with the
      // credentials index in it), so it is logged for operators and never
      // returned: neither format sends the message of this class. `POST
      // /auth/register` no longer gets here at all: there the status alone
      // told a registered address from a free one, so the route answers a
      // duplicate with the same 202 as any address (ANT-2026-SPEMY9GU). The
      // `url` is censored for the reason given above.
      if (error instanceof UniqueConstraintError) {
        fastify.log.warn(
          { constraint: error.constraint, url: redactLoggedUrl(request.url) },
          'Unique constraint violation'
        );
      }

      // RFC 6750 §3: a bearer-protected resource (e.g. /oauth/userinfo) that
      // rejects an access token MUST answer with a `WWW-Authenticate: Bearer`
      // challenge carrying the `invalid_token` error code. This is scoped to the
      // JWT/access-token failures — thrown by `requireJwt` / access-token
      // verification on bearer-protected routes — and is DISTINCT from the
      // client-authentication Basic case below (`InvalidClientError`).
      // `InvalidTokenError` (email-verification tokens, etc.) is intentionally
      // NOT included: it is not a bearer resource failure. The header is set in
      // either error format.
      //
      // RFC 9449 §7.1 (#480): with DPoP on, a token refused under the `DPoP`
      // scheme gets a `DPoP` challenge instead, with the proof algorithms in
      // `algs`, and a refused proof gets `error="invalid_dpop_proof"`. While
      // DPoP is off (`fastify.dpop` null) the `DPoP` scheme is no credential and
      // every challenge stays the Bearer one above.
      const dpopAlgs = fastify.dpop ? fastify.dpop.algorithms.join(' ') : undefined;
      if (error instanceof JWTInvalidError || error instanceof JWTExpiredError) {
        const description = sanitizeDescription(error.message, MAX_CHALLENGE_DESCRIPTION);
        reply.header(
          'WWW-Authenticate',
          dpopAlgs !== undefined && usedDpopScheme(request)
            ? `DPoP error="invalid_token", error_description="${description}", algs="${dpopAlgs}"`
            : `Bearer realm="OAuth", error="invalid_token", error_description="${description}"`
        );
      }
      if (error instanceof InvalidDpopProofError && error.statusCode === 401) {
        reply.header(
          'WWW-Authenticate',
          `DPoP error="invalid_dpop_proof"${dpopAlgs === undefined ? '' : `, algs="${dpopAlgs}"`}`
        );
      }

      // RFC 6749 §5.2: if the client attempted Basic auth, the 401 response
      // MUST include a `WWW-Authenticate` header matching the scheme used.
      if (error instanceof InvalidClientError) {
        if (/^basic\s/i.test(request.headers.authorization ?? '')) {
          reply.header('WWW-Authenticate', 'Basic realm="OAuth"');
        }
      }

      // RFC 9110 §10.2.3: a request shed under load says when to try again, in
      // either error format (#751; RFC 7009 §2.2.1 for revocation).
      if (shed) {
        reply.header('Retry-After', String(error.retryAfterSeconds));
      }

      // The OAuth protocol endpoints answer the body their specification
      // defines (RFC 6749 §5.2), and nothing QAuth adds to it (#513).
      const status = statusCode >= 400 ? statusCode : 500;
      if (errorFormatOf(request) === 'oauth') {
        return reply.code(status).send(oauthErrorBody(error, status));
      }

      // Every other route answers an RFC 9457 problem document (ADR-019
      // Decision 7, #506, #513). A 401 or 403 on a bearer-protected route also
      // carries a challenge, when no branch above set one.
      if (
        (status === 401 || status === 403) &&
        !reply.hasHeader('WWW-Authenticate') &&
        isBearerProtected(request)
      ) {
        reply.header('WWW-Authenticate', bearerChallenge(request, status, dpopAlgs));
      }
      return reply
        .code(status)
        .type(PROBLEM_MEDIA_TYPE)
        .send(problemDocument(error, request, status));
    }
  );
});
