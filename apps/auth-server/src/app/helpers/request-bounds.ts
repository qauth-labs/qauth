import type { FastifyReply, FastifyRequest } from 'fastify';

import { describeProblem } from '../api-conventions/error-classes';
import { PROBLEM_MEDIA_TYPE, type ProblemDocument } from '../api-conventions/problem';

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
 * The log line is the one Fastify's own handler writes. The answer is the
 * `not_found` problem document every route that is not an OAuth protocol
 * endpoint answers with (ADR-019 Decision 7, #513): a path no route serves is
 * no protocol endpoint. Its `instance` and `detail` leave out the query, which
 * can carry a secret a client sent to the wrong path.
 */
export async function answerUnknownRouteBeforeBody(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply | undefined> {
  if (!request.is404) return undefined;
  const { method, url = '/' } = request.raw;
  request.log.info(`Route ${method}:${url} not found`);
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
  // Returning the reply is how an async hook tells Fastify it has answered.
  return reply.code(404).type(PROBLEM_MEDIA_TYPE).send(document);
}
