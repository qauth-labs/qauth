import type { FastifyReply, FastifyRequest } from 'fastify';

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
 * The answer is the one Fastify's own handler sends, with the same log line,
 * so 404 responses do not change.
 */
export async function answerUnknownRouteBeforeBody(
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply | undefined> {
  if (!request.is404) return undefined;
  const { method, url } = request.raw;
  const message = `Route ${method}:${url} not found`;
  request.log.info(message);
  // Returning the reply is how an async hook tells Fastify it has answered.
  return reply.code(404).send({ message, error: 'Not Found', statusCode: 404 });
}
