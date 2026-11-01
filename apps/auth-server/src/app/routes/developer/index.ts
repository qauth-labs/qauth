import type { FastifyInstance } from 'fastify';

import { MERGE_PATCH_MEDIA_TYPE } from '../../api-conventions/conditional-requests';
import { registerDeveloperApiKeyRoutes } from './api-keys';
import { registerDeveloperClientRoutes } from './clients';
import { registerDeveloperConsentRoutes } from './consents';

/**
 * THE DEVELOPER API, `/developer/v1-rc.0` (ADR-019 Decision 7, #524).
 *
 * A developer manages their OAuth clients, the clients' static API keys and,
 * until the account console takes them over (v0.3), their own consents. Every
 * route follows the API conventions (`reference/api-conventions.md`, #506):
 * RFC 3339 times, cursor paging on lists, `ETag` and `If-Match` on updates,
 * problem documents for errors.
 *
 * Every route is guarded by `requireFamilyToken('developer')` (#509): a token
 * whose only audience is `urn:qauth:aud:developer:v1-rc.0`, with no `act`
 * claim, whose subject is an enabled user of the request's realm (#869). The
 * developer portal's `/auth/login` token is one since #524. The guard runs
 * as the route's first `preValidation` hook, before the params, the query and
 * the body are validated, so a caller without such a token learns nothing of
 * a route's schemas. It does not run before anything: Fastify parses the body
 * before `preValidation`, so a body in a media type no parser here takes
 * answers 415, and one its parser cannot read answers 400, to a caller with
 * no token too. Those answers tell only which media types this module parses,
 * which the OpenAPI document publishes. Each route still looks its rows up in
 * `requestRealm(request)`.
 *
 * The domain logic is shared with the deprecated `/api/clients` and
 * `/api/consents`, which keep their old shapes: `helpers/developer-clients.ts`,
 * `helpers/developer-api-keys.ts` and `helpers/consent-management.ts`. A
 * client owned by another developer is 404, never 403 (ADR-012).
 */
export const autoPrefix = '/developer/v1-rc.0';

export default async function (fastify: FastifyInstance) {
  // A PATCH body here is a JSON Merge Patch (RFC 7396), parsed as JSON is.
  // Registered in this module only, so no route outside the families starts
  // taking the media type.
  fastify.addContentTypeParser(
    MERGE_PATCH_MEDIA_TYPE,
    { parseAs: 'string' },
    fastify.getDefaultJsonParser('error', 'error')
  );
  registerDeveloperClientRoutes(fastify);
  registerDeveloperApiKeyRoutes(fastify);
  registerDeveloperConsentRoutes(fastify);
}
