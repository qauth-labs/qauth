import {
  BadRequestError,
  EmailAlreadyVerifiedError,
  EmailNotVerifiedError,
  ForbiddenError,
  InvalidClientError,
  InvalidCredentialsError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TokenAlreadyUsedError,
  TokenExpiredError,
  TooManyRequestsError,
  UnauthorizedClientError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '../../config/env';
import { redactLoggedUrl } from '../../config/logger';
import { apiFamilyOf } from '../api-conventions/families';
import {
  DEFAULT_PROBLEM_TYPE,
  PROBLEM_MEDIA_TYPE,
  problemCodeFor,
  type ProblemDocument,
  statusTitle,
} from '../api-conventions/problem';

/**
 * How a route answers an error (ADR-019 Decision 7, #506):
 *
 *   - `problem`: an RFC 9457 problem details document, sent as
 *     `application/problem+json`, with a stable `code` and a `trace_id`;
 *   - `oauth`: the error shape of the specification the endpoint implements,
 *     such as RFC 6749 §5.2 on the token endpoint.
 *
 * A route under an API family prefix (`/admin/v1-rc.0`, `/account/v1-rc.0`,
 * `/developer/v1-rc.0`) answers `problem` unless it says otherwise. Every other
 * route keeps the body this handler sent before the API families existed,
 * until #513 makes `problem` the default and sets `oauth` on the OAuth
 * protocol endpoints.
 */
export type ErrorFormat = 'problem' | 'oauth';

declare module 'fastify' {
  interface FastifyContextConfig {
    /** The route's error format; see {@link ErrorFormat}. */
    errorFormat?: ErrorFormat;
  }
}

interface ErrorResponse {
  error: string;
  error_description?: string;
  code?: string;
  statusCode: number;
  feedback?: string[];
  retryAfter?: number;
}

/**
 * Sanitize a message for use as an RFC 6750 §3 `error_description` inside a
 * `WWW-Authenticate` header. That grammar's quoted-string permits only
 * `%x20-21 / %x23-5B / %x5D-7E` — i.e. no double-quote and no backslash — so we
 * strip anything outside that set to keep the header well-formed and prevent a
 * message from breaking out of the quoted value.
 */
function sanitizeChallengeDescription(message: string): string {
  return message.replace(/[^\x20-\x21\x23-\x5b\x5d-\x7e]/g, ' ').slice(0, 200);
}

/**
 * The status this handler is about to answer with, decided BEFORE any branch
 * runs so the log line and the response can never disagree (#365).
 *
 * Every branch below either sends `error.statusCode` or falls through to a
 * fixed status, so reading it once up front is exact rather than approximate.
 * The two fixed cases mirror the branches: a Fastify validation failure is
 * always 400, and anything with no usable `statusCode` is always 500.
 *
 * `error.validation` is checked FIRST because Fastify's validation errors carry
 * a `statusCode` of their own and it agrees (400) — but only the shape check
 * distinguishes them from a domain error that happens to be a 400, and the
 * ordering here has to match the ordering of the branches.
 */
function intendedStatusCode(error: FastifyError | Error): number {
  if ('validation' in error && error.validation) return 400;

  const declared = (error as { statusCode?: unknown }).statusCode;

  return typeof declared === 'number' && declared >= 100 && declared <= 599 ? declared : 500;
}

/**
 * One validation failure, reduced to what a CALLER may see (#365).
 *
 * The pre-#365 handler sent `error.validation` verbatim, and under
 * `fastify-type-provider-zod` that is the compiler's own issue objects. On
 * `POST /oauth/token` the emitted array carried, per issue, a `keyword`, an
 * `instancePath`, a `schemaPath` (`#/grant_type/invalid_union`) and a `params`
 * bag holding the discriminator name and the full option list — the internal
 * shape of the schema, handed to an unauthenticated caller. That was invisible
 * for as long as the handler was unreachable and became the wire contract the
 * moment it was not.
 *
 * `path` and `message` are what a client needs to fix its request, and they are
 * all it needs: which field, and what is wrong with it. Everything else
 * describes how QAuth is BUILT rather than what it accepts.
 *
 * The `message` is kept INTACT, including the constraint it quotes (`must match
 * pattern "…"`, or the list of permitted discriminator values). Those are the
 * schemas, and the schemas are published in `openapi.json` — documentation
 * rather than disclosure. Genericising them would leave a caller a field path
 * and no way to learn what is wrong with it, which is the failure mode of every
 * error message that has been sanitised past usefulness. The distinction that
 * matters is structural-vs-contractual, not verbose-vs-terse.
 */
interface ValidationDetail {
  path: string;
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

/**
 * Project the compiler's issues into {@link ValidationDetail}s.
 *
 * Tolerant by construction: the input is typed `unknown` by Fastify and its
 * shape depends on which validator compiler is installed, so an issue this
 * function cannot read degrades to an empty path and a generic message rather
 * than throwing out of the error handler — the one place a throw becomes an
 * unhandled rejection with no response at all.
 */
function projectValidationDetails(validation: unknown): ValidationDetail[] {
  if (!Array.isArray(validation)) return [];

  return validation.slice(0, MAX_VALIDATION_DETAILS).map((issue: unknown) => {
    const record = (issue ?? {}) as Record<string, unknown>;
    const path = record['instancePath'];
    const message = record['message'];

    return {
      path: typeof path === 'string' ? path : '',
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
  if (!('validation' in error) || !error.validation) return error;

  return {
    type: 'ValidationError',
    validationContext: (error as FastifyError).validationContext,
    issues: Array.isArray(error.validation) ? error.validation.length : undefined,
    details: projectValidationDetails(error.validation),
  };
}

/**
 * Whether the route that failed answers with a problem document: it says so in
 * `config.errorFormat`, or it sits under an API family prefix. A request that
 * matched no route has no `routeOptions.url` and keeps today's shape.
 */
function answersWithProblem(request: FastifyRequest): boolean {
  const declared = request.routeOptions.config?.errorFormat;
  if (declared !== undefined) return declared === 'problem';
  const url = request.routeOptions.url;
  return url !== undefined && apiFamilyOf(url) !== undefined;
}

/** The OAuth error classes whose `message` is the registered token, not prose. */
function isOAuthTokenError(
  error: unknown
): error is
  | InvalidScopeError
  | InvalidGrantError
  | InvalidRequestError
  | InvalidTargetError
  | InvalidClientError
  | UnauthorizedClientError {
  return (
    error instanceof InvalidScopeError ||
    error instanceof InvalidGrantError ||
    error instanceof InvalidRequestError ||
    error instanceof InvalidTargetError ||
    error instanceof InvalidClientError ||
    error instanceof UnauthorizedClientError
  );
}

/**
 * The `detail` of a problem document: what a caller may read about this
 * failure, or nothing.
 *
 * A 5xx never carries one. The message of an unexpected error is ours, not the
 * caller's, and the `trace_id` already leads an operator to it. Nor does a
 * `UniqueConstraintError`'s own message, which embeds the constraint name (the
 * enumeration oracle the legacy branch below guards against). An OAuth error
 * class carries its token as the message, so its description is the detail.
 */
function problemDetail(error: FastifyError | Error, status: number): string | undefined {
  if (status >= 500) return undefined;
  if ('validation' in error && error.validation) return 'The request is not valid.';
  if (error instanceof UniqueConstraintError) return 'Resource already exists';
  if (isOAuthTokenError(error)) return error.errorDescription || undefined;
  return error.message || undefined;
}

/**
 * Build the RFC 9457 document for `error` (#506).
 *
 * `type` is `about:blank` and `title` the status phrase (RFC 9457 §4.2.1);
 * `code` is one of the published codes (`api-conventions/problem.ts`), never a
 * framework code such as `FST_ERR_VALIDATION`; `trace_id` is the request id the
 * request logger carries as `reqId`, so an operator finds the log line by it. A
 * validation failure lists each field in `errors`, from the same projection
 * the legacy shape uses, and a weak password lists its feedback under
 * `/password`.
 */
function problemDocument(
  error: FastifyError | Error,
  request: FastifyRequest,
  status: number
): ProblemDocument {
  const isValidation = 'validation' in error && Boolean(error.validation);
  const document: ProblemDocument = {
    type: DEFAULT_PROBLEM_TYPE,
    title: statusTitle(status),
    status,
    code: isValidation
      ? 'validation_error'
      : problemCodeFor((error as { code?: unknown }).code, status),
    trace_id: request.id,
  };

  const detail = problemDetail(error, status);
  if (detail) document.detail = detail;

  const errors = isValidation
    ? projectValidationDetails((error as FastifyError).validation).map(({ path, message }) => ({
        pointer: path,
        message,
      }))
    : error instanceof WeakPasswordError
      ? (error.feedback ?? []).map((message) => ({ pointer: '/password', message }))
      : [];
  if (errors.length > 0) document.errors = errors;

  return document;
}

/** Simple errors that only need message and statusCode */
const SimpleErrorClasses = [
  BadRequestError,
  EmailAlreadyVerifiedError,
  EmailNotVerifiedError,
  ForbiddenError,
  InvalidCredentialsError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TokenAlreadyUsedError,
  TokenExpiredError,
  TooManyRequestsError,
] as const;

/**
 * Global error handler plugin
 * Handles all unhandled errors and converts them to appropriate HTTP responses
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
      // someone.
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
      request.log[statusCode >= 500 ? 'error' : 'warn'](
        {
          err: loggableError(error),
          url: redactLoggedUrl(request.url),
          method: request.method,
          statusCode,
        },
        'Error occurred'
      );

      // RFC 6750 §3: a bearer-protected resource (e.g. /oauth/userinfo) that
      // rejects an access token MUST answer with a `WWW-Authenticate: Bearer`
      // challenge carrying the `invalid_token` error code. This is scoped to the
      // JWT/access-token failures — thrown by `requireJwt` / access-token
      // verification on bearer-protected routes — and is DISTINCT from the
      // client-authentication Basic case below (`InvalidClientError`).
      // `InvalidTokenError` (email-verification tokens, etc.) is intentionally
      // NOT included: it is not a bearer resource failure. We only set the
      // header here and fall through so the normal body/status handling runs,
      // in either error format: an API family route is bearer-protected too.
      if (error instanceof JWTInvalidError || error instanceof JWTExpiredError) {
        reply.header(
          'WWW-Authenticate',
          `Bearer realm="OAuth", error="invalid_token", error_description="${sanitizeChallengeDescription(
            error.message
          )}"`
        );
      }

      // The API families, and any route that asks for it, answer with an RFC
      // 9457 problem document (ADR-019 Decision 7, #506). Every branch below is
      // the shape the other routes keep until #513 converts them.
      if (answersWithProblem(request)) {
        const status = statusCode >= 400 ? statusCode : 500;
        return reply
          .code(status)
          .type(PROBLEM_MEDIA_TYPE)
          .send(problemDocument(error, request, status));
      }

      // RFC 6749 §5.2: if the client attempted Basic auth, the 401 response
      // MUST include a `WWW-Authenticate` header matching the scheme used.
      // Set here and fallen through, so the body below is built in ONE place
      // for every §5.2 error rather than once per error class.
      if (error instanceof InvalidClientError) {
        if (/^basic\s/i.test(request.headers.authorization ?? '')) {
          reply.header('WWW-Authenticate', 'Basic realm="OAuth"');
        }
      }

      // OAuth errors, whose `message` IS the registered §5.2 token and whose
      // human-readable detail lives on `errorDescription` (RFC 6749 §5.2, RFC
      // 8707 §2.2 for `invalid_target`).
      //
      // `InvalidClientError` and `UnauthorizedClientError` joined this branch
      // with #365. They took prose as their MESSAGE, so a call site that
      // described the failure — `new InvalidClientError('CIMD document is not
      // valid JSON')` — put that sentence in `error`, where the specification
      // requires the bare token and where every OAuth client library looks for
      // one. The response shape therefore depended on which call site threw.
      if (isOAuthTokenError(error)) {
        const response: ErrorResponse = {
          error: error.message,
          statusCode: error.statusCode,
          code: error.code,
          ...(error.errorDescription ? { error_description: error.errorDescription } : {}),
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle simple error types (message + statusCode + optional code)
      for (const ErrorClass of SimpleErrorClasses) {
        if (error instanceof ErrorClass) {
          const response: ErrorResponse = {
            error: error.message,
            statusCode: error.statusCode,
            ...('code' in error && error.code ? { code: error.code } : {}),
          };
          return reply.code(error.statusCode).send(response);
        }
      }

      // Handle WeakPasswordError (includes feedback)
      if (error instanceof WeakPasswordError) {
        const response: ErrorResponse = {
          error: error.message,
          code: error.code,
          statusCode: error.statusCode,
          feedback: error.feedback,
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle UniqueConstraintError. The offending constraint name can be an
      // enumeration oracle (a duplicate-email registration once reached this
      // branch with the credentials index in it), so it is logged for
      // operators but NEVER returned to the caller. `POST /auth/register` no
      // longer gets here at all: there the status alone told a registered
      // address from a free one, so the route answers a duplicate with the
      // same 202 as any address (ANT-2026-SPEMY9GU). The wire `error`
      // message is genericised for the same reason — `error.message` embeds the
      // constraint name. `code` + `statusCode` are preserved so legitimate
      // clients can still branch on the conflict. The `url` is censored for the
      // same reason as on the line above: a plain key the `req` serializer
      // never sees.
      if (error instanceof UniqueConstraintError) {
        fastify.log.warn(
          { constraint: error.constraint, url: redactLoggedUrl(request.url) },
          'Unique constraint violation'
        );
        const response: ErrorResponse = {
          error: 'Resource already exists',
          code: error.code,
          statusCode: error.statusCode,
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle Fastify validation errors. `details` is PROJECTED, never
      // forwarded — see {@link projectValidationDetails} for what the raw
      // issues carried and why an unauthenticated caller must not receive it.
      if ('validation' in error && error.validation) {
        return reply.code(400).send({
          error: 'Validation error',
          code: 'VALIDATION_ERROR',
          statusCode: 400,
          details: projectValidationDetails(error.validation),
        });
      }

      // Handle HTTP errors with statusCode property
      if ('statusCode' in error && typeof error.statusCode === 'number') {
        const statusCode = error.statusCode;
        const response: ErrorResponse = {
          error: error.message || 'An error occurred',
          statusCode,
        };
        return reply.code(statusCode).send(response);
      }

      // Handle unknown errors. Use the validated `env.NODE_ENV` (not the raw
      // `process.env.NODE_ENV`) so a misconfigured environment can't silently
      // flip this branch — the schema defaults to `development` and rejects
      // anything outside the enum.
      const isDevelopment = env.NODE_ENV !== 'production';
      const response: ErrorResponse = {
        error: isDevelopment ? error.message : 'Internal server error',
        statusCode: 500,
      };

      // Include error details in development
      if (isDevelopment && error.stack) {
        return reply.code(500).send({
          ...response,
          stack: error.stack,
        });
      }

      return reply.code(500).send(response);
    }
  );
});
