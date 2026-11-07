import type { FastifyInstance } from 'fastify';

import { accountOperation } from '../../helpers/account-operation-guard';
import {
  type ConsentListRoute,
  type ConsentRevokeRoute,
  familyConsentRoutes,
} from '../../helpers/family-consents';

/**
 * The account API's consents (#524): the active consents of the token's user,
 * and their revocation. The options and handlers are the account and
 * developer APIs' shared ones (`helpers/family-consents.ts`), behind the
 * account API's operation guard (#663) with the rules the contract gives
 * them: neither asks for fresh authentication, and both take an act-chain
 * token.
 *
 *   GET    /consents              — list, a page at a time
 *   DELETE /consents/{consentId}  — revoke one
 */
export function registerAccountConsentRoutes(fastify: FastifyInstance): void {
  const routes = familyConsentRoutes('account');
  const list = accountOperation({
    operationId: 'account.consents.list',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  const revoke = accountOperation({
    operationId: 'account.consents.delete',
    freshAuthentication: 'none',
    actChain: 'accepted',
  });
  fastify.get<ConsentListRoute>('/consents', {
    ...routes.list,
    preValidation: list.guard,
    schema: { ...routes.list.schema, ...list.schema },
  });
  fastify.delete<ConsentRevokeRoute>('/consents/:consentId', {
    ...routes.revoke,
    preValidation: revoke.guard,
    schema: { ...routes.revoke.schema, ...revoke.schema },
  });
}
