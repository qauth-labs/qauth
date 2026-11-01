import type { FastifyInstance } from 'fastify';

import {
  type ConsentListRoute,
  type ConsentRevokeRoute,
  familyConsentRoutes,
} from '../../helpers/family-consents';

/**
 * The account API's consents (#524): the active consents of the token's user,
 * and their revocation. The options and handlers are the account and
 * developer APIs' shared ones (`helpers/family-consents.ts`), behind this
 * family's own guard.
 *
 *   GET    /consents              — list, a page at a time
 *   DELETE /consents/{consentId}  — revoke one
 */
export function registerAccountConsentRoutes(fastify: FastifyInstance): void {
  const routes = familyConsentRoutes('account');
  fastify.get<ConsentListRoute>('/consents', routes.list);
  fastify.delete<ConsentRevokeRoute>('/consents/:consentId', routes.revoke);
}
