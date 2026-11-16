import type { FastifyInstance } from 'fastify';

import type { ScopedApiFamily } from '../api-conventions/families';
import {
  familyDocument,
  familyDocumentPath,
  type OpenApiDocument,
  serializeDocument,
} from '../api-conventions/family-documents';

/**
 * The OpenAPI documents of the account and developer APIs (#525, ADR-019
 * Decision 7), each at its family's `<prefix>/openapi.json` on the public
 * listener, beside the operations it describes. The admin API's is served on
 * the admin listener (`admin/listener.ts`).
 *
 * Each is cut from the server's own document (`familyDocument`), so it lists
 * exactly the family's operations this process registered: an operation whose
 * switch is off is not in it (ADR-018 §5). It is built once, on the first
 * call, after every route is registered. Unauthenticated and cacheable, like
 * the Interaction API's document: it describes routes and holds no realm
 * data, and the docs site publishes the same document, so it is served
 * whatever ENABLE_SWAGGER says (that flag gates only the Swagger UI). It is not an operation of the family it describes, so it is in no
 * document itself.
 *
 * A process that registered no OpenAPI collector (`@fastify/swagger`, which
 * `main.ts` always registers) has no document to cut, and answers 404.
 */

/** The families this listener serves a document for. */
const PUBLIC_FAMILIES: readonly ScopedApiFamily[] = ['account', 'developer'];

/** A document about the server, like discovery: cacheable, and it changes only with a release. */
const DOCUMENT_CACHE_CONTROL = 'public, max-age=3600';

export default async function (fastify: FastifyInstance) {
  for (const family of PUBLIC_FAMILIES) {
    let document: string | undefined;
    fastify.get(
      familyDocumentPath(family),
      { schema: { hide: true }, config: { surface: 'meta' } },
      async (_request, reply) => {
        if (typeof fastify.swagger !== 'function') return reply.callNotFound();
        document ??= serializeDocument(
          familyDocument(fastify.swagger() as OpenApiDocument, family)
        );
        reply
          .header('Cache-Control', DOCUMENT_CACHE_CONTROL)
          .header('Content-Type', 'application/json; charset=utf-8');
        return reply.send(document);
      }
    );
  }
}
