import { INTERACTION_OPENAPI } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance } from 'fastify';

/**
 * The Interaction API's contract, served at a fixed path (#590): the OpenAPI
 * 3.1 document of `/interaction/v1-rc.0`, with every step's schema. It is the
 * same document the docs site publishes and the typed client is generated
 * from, so a ceremony app or a replacement UI can read the contract of the
 * server it talks to. The operations it describes arrive with the Interaction
 * API implementation; this route serves only the document.
 *
 * The path is written out, not taken from `INTERACTION_OPENAPI_PATH`, so the
 * docs site's endpoint-coverage guard sees it; `interaction-document.test.ts`
 * holds the two equal.
 */

/** Serialised once: the contract does not change while the server runs. */
const DOCUMENT = JSON.stringify(INTERACTION_OPENAPI);

/** A document about the server, like discovery: cacheable, and it changes only with a release. */
const DOCUMENT_CACHE_CONTROL = 'public, max-age=3600';

export default async function (fastify: FastifyInstance) {
  fastify.get(
    '/interaction/v1-rc.0/openapi.json',
    {
      schema: {
        description:
          'The OpenAPI 3.1 document of the Interaction API v1-rc.0, with one JSON Schema per step (ADR-019 Decision 6). The same document the docs site publishes. Unauthenticated, cacheable.',
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
      },
      config: { surface: 'meta' },
    },
    async (_request, reply) => {
      reply
        .header('Cache-Control', DOCUMENT_CACHE_CONTROL)
        .header('Content-Type', 'application/json; charset=utf-8');
      return reply.send(DOCUMENT);
    }
  );
}
