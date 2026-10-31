import type { FastifyInstance } from 'fastify';

import {
  type ConsentListRoute,
  type ConsentRevokeRoute,
  familyConsentRoutes,
} from '../../helpers/family-consents';

/**
 * The developer API's consents (#524): the active consents of the token's user,
 * and their revocation. The options and handlers are the account and
 * developer APIs' shared ones (`helpers/family-consents.ts`), behind this
 * family's own guard.
 *
 *   GET    /consents              — list, a page at a time
 *   DELETE /consents/{consentId}  — revoke one
 */
export function registerDeveloperConsentRoutes(fastify: FastifyInstance): void {
  const routes = familyConsentRoutes('developer');
  fastify.get<ConsentListRoute>('/consents', routes.list);
  fastify.delete<ConsentRevokeRoute>('/consents/:consentId', routes.revoke);
}
