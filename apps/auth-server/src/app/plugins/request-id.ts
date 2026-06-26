import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import { env } from '../../config/env';

/**
 * Request-id propagation plugin (#128).
 *
 * Fastify already derives `request.id` from the inbound `REQUEST_ID_HEADER`
 * (configured as `requestIdHeader` on the server) and falls back to
 * `genReqId()` when the header is absent. That id is attached to the
 * request-scoped logger as `reqId`, so it appears on every log line for the
 * request automatically.
 *
 * This plugin closes the loop on the response side: it echoes the id back on
 * the outgoing `REQUEST_ID_HEADER` so a caller (and any downstream proxy or log
 * aggregator) can correlate the response — and its logs — with the request.
 */
export const requestIdPlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance) => {
    const headerName = env.REQUEST_ID_HEADER;

    fastify.addHook('onRequest', async (request, reply) => {
      // `request.id` is the propagated-or-generated id. Setting it early means
      // the header is present even on responses produced by error handlers.
      reply.header(headerName, request.id);
    });

    fastify.log.debug({ headerName }, 'Request-id plugin registered');
  },
  {
    name: '@qauth-labs/request-id',
  }
);

export default requestIdPlugin;
