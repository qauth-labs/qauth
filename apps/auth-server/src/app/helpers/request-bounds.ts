import { randomUUID } from 'node:crypto';
import { STATUS_CODES } from 'node:http';
import type { Socket } from 'node:net';

import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { redactLoggedUrl } from '../../config/logger';
import { describeProblem } from '../api-conventions/error-classes';
import {
  codeForStatus,
  PROBLEM_MEDIA_TYPE,
  type ProblemDocument,
} from '../api-conventions/problem';

/** Node's default `headersTimeout`: the deadline for a request's headers. */
const NODE_HEADERS_TIMEOUT_MS = 60_000;

/**
 * Server options that bound how long one incomplete request is held
 * (`REQUEST_TIMEOUT_MS`).
 *
 * Fastify's `requestTimeout` defaults to 0 and is copied onto the
 * `http.Server`, which switches off Node's own 300 s limit. A request whose
 * body stops one byte short of its `Content-Length` was then held for ever,
 * with everything buffered so far (up to the body limit), and the per-route
 * rate limits count a request when its headers arrive, so each window admitted
 * another batch on top of the ones still held.
 *
 * `headersTimeout` is kept no longer than the request deadline: when it is the
 * larger, Node swaps the two, so a request deadline under Node's 60 s headers
 * default would silently become 60 s. Node checks both on a sweep, every 30 s
 * by default, so a request can outlive the deadline by up to that much.
 */
export function requestDeadlineOptions(requestTimeoutMs: number) {
  return {
    requestTimeout: requestTimeoutMs,
    http: { headersTimeout: Math.min(NODE_HEADERS_TIMEOUT_MS, requestTimeoutMs) },
  };
}

/**
 * `onRequest` hook for the ROOT instance: answer a request for a route that
 * does not exist before its body is read.
 *
 * Fastify's default 404 handler belongs to the root instance, outside the
 * scope `app.ts` registers the rate limiter in (the limiter attaches to each
 * route through `onRoute`), yet Fastify still runs the body parser for it. Any
 * caller could therefore park unfinished 1 MiB bodies on unknown paths at any
 * rate, and about 2000 of them ran the process out of heap in seconds.
 *
 * The log line is the one Fastify's own handler writes, with the URL censored
 * as every other log line's is. The answer is the `not_found` problem document
 * every route that is not an OAuth protocol endpoint answers with (ADR-019
 * Decision 7, #513): a path no route serves is no protocol endpoint. Its
 * `instance` and `detail` leave out the query, which can carry a secret a
 * client sent to the wrong path.
 */
export async function answerUnknownRouteBeforeBody(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply | undefined> {
  if (!request.is404) return undefined;
  // Returning the reply is how an async hook tells Fastify it has answered.
  return answerRouteNotFound(request, reply);
}

/**
 * Answer as if no route served the request: the log line and the `not_found`
 * problem document of {@link answerUnknownRouteBeforeBody}.
 *
 * A route that must look absent sends this from its own `onRequest` hook,
 * before the body is read, as the SSF routes do for a realm that does not run
 * the transmitter. It is also the root instance's not-found handler, which
 * `reply.callNotFound()` reaches (`main.ts`): without it that is Fastify's
 * default handler, which answers its own `{ message, error, statusCode }`
 * envelope rather than the document an unknown path gets (#513).
 *
 * The request-target goes to the log through {@link redactLoggedUrl}: on
 * `/ui/wallet-login/return?response_code=…` the query holds a redeemable
 * Response Code, and a client may send one to a wrong path too.
 */
export function answerRouteNotFound(request: FastifyRequest, reply: FastifyReply): FastifyReply {
  const { method, url = '/' } = request.raw;
  request.log.info(`Route ${method}:${redactLoggedUrl(url)} not found`);
  echoRequestId(request, reply);
  const queryAt = url.indexOf('?');
  const path = queryAt === -1 ? url : url.slice(0, queryAt);
  const { code, type, title } = describeProblem('not_found');
  const document: ProblemDocument = {
    type,
    title,
    status: 404,
    detail: `No route serves ${method} ${path}.`,
    instance: path,
    code,
    trace_id: request.id,
  };
  return reply.code(404).type(PROBLEM_MEDIA_TYPE).send(document);
}

/**
 * Echo the request id in the header the server reads it from (`requestIdHeader`,
 * `REQUEST_ID_HEADER` in `main.ts`), as `plugins/request-id.ts` does for every
 * route. The root's own answers run outside that plugin's scope, and without
 * this their `trace_id` would be the one id the response does not carry.
 */
function echoRequestId(request: FastifyRequest, reply: FastifyReply): void {
  const header = requestIdHeaderOf(request.server);
  if (header !== undefined) reply.header(header, request.id);
}

/** An RFC 9110 §5.6.2 token: what a header name may be. */
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * The header the request id travels in, when the server names one that is a
 * valid header name: {@link answerClientError} writes it to the socket raw.
 */
function requestIdHeaderOf(server: FastifyInstance): string | undefined {
  const header = server.initialConfig.requestIdHeader;
  return typeof header === 'string' && HEADER_NAME.test(header) ? header : undefined;
}

/** What a caller is told about a request the router refused before any route. */
const FRAMEWORK_ERROR_DETAILS: Readonly<Record<string, string>> = {
  FST_ERR_BAD_URL: 'The request path is not a valid URL.',
  FST_ERR_MAX_PARAM_LENGTH: 'A segment of the request path is longer than the server accepts.',
};

/**
 * Fastify's `frameworkErrors` option: answer a request the router refuses
 * before any route runs, a path that is not valid percent-encoding
 * (`FST_ERR_BAD_URL`, 400) or a path parameter over the router's length
 * limit (`FST_ERR_MAX_PARAM_LENGTH`, 414), with the problem document of its
 * status (#513).
 *
 * Fastify's own answer was its `{ error, code, message, statusCode }`
 * envelope, with a framework code and the whole request-target, query
 * included, in `message`. The document carries neither: no `instance`, since
 * the path is not one, and a fixed `detail`. The request id is echoed, as on
 * every other answer, so the `trace_id` can be matched to the response.
 */
export function answerFrameworkError(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply
): void {
  const declared = error.statusCode;
  const status =
    typeof declared === 'number' && declared >= 400 && declared <= 599 ? declared : 500;
  request.log.info({ code: error.code, statusCode: status }, 'Request refused by the router');
  echoRequestId(request, reply);
  const { code, type, title } = describeProblem(codeForStatus(status));
  const detail = status < 500 ? FRAMEWORK_ERROR_DETAILS[error.code] : undefined;
  const document: ProblemDocument = {
    type,
    title,
    status,
    ...(detail === undefined ? {} : { detail }),
    code,
    trace_id: request.id,
  };
  void reply.code(status).type(PROBLEM_MEDIA_TYPE).send(document);
}

/** The status Node's HTTP parser error stands for, as Fastify's own handler reads it. */
function clientErrorStatus(error: Error & { code?: string }): 400 | 408 | 431 {
  if (error.code === 'ERR_HTTP_REQUEST_TIMEOUT') return 408;
  if (error.code === 'HPE_HEADER_OVERFLOW') return 431;
  return 400;
}

/**
 * Fastify's `clientErrorHandler` option: answer a connection whose request
 * could not be read at all, a malformed request line or header (400),
 * headers over the size limit (431) or a request that did not arrive whole
 * within `REQUEST_TIMEOUT_MS` (408), with a problem document (#513).
 *
 * Fastify's default writes its `{ error, message, statusCode }` envelope.
 * There is no request here, so no request id: the document's `trace_id` is
 * made for it, sent in the request-id header as every other answer's is, and
 * logged at `info` so an operator can find it. The log line carries the
 * parser's code, the trace id and the status, never the error itself: Node
 * attaches the bytes it could not parse as `rawPacket`, and those are the
 * request as sent, its `Cookie` and `Authorization` headers included. Written
 * raw to the socket, which Fastify then closes, as its own handler does.
 */
export function answerClientError(
  this: FastifyInstance,
  error: Error & { code?: string },
  socket: Socket
): void {
  if (error.code === 'ECONNRESET' || socket.destroyed) return;
  const status = clientErrorStatus(error);
  const traceId = randomUUID();
  this.log.info({ code: error.code, traceId, statusCode: status }, 'Client error');
  const { code, type, title } = describeProblem(codeForStatus(status));
  const body = JSON.stringify({ type, title, status, code, trace_id: traceId });
  const requestIdHeader = requestIdHeaderOf(this);
  const echoed = requestIdHeader === undefined ? '' : `${requestIdHeader}: ${traceId}\r\n`;
  if (socket.writable) {
    socket.write(
      `HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nContent-Type: ${PROBLEM_MEDIA_TYPE}\r\n${echoed}Connection: close\r\n\r\n${body}`
    );
  }
  socket.destroy(error);
}
