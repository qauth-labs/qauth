import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type {
  FastifyRequest,
  RawReplyDefaultExpression,
  RawRequestDefaultExpression,
  RawServerDefault,
  RouteShorthandOptionsWithHandler,
} from 'fastify';
import { z } from 'zod';

import { type PageQuery, pageQuerySchema, pageSchema } from '../api-conventions/paging';
import { rfc3339 } from '../api-conventions/time';
import {
  consentParamsSchema,
  type FamilyConsent,
  familyConsentSchema,
} from '../schemas/family-consents';
import {
  type ConsentWithClient,
  pageConsentsForUser,
  revokeConsentForUser,
} from './consent-management';
import { requireFamilyToken } from './family-token';
import { requestRealm } from './request-realm';

/**
 * The consent routes of the account and developer APIs (#524): list the
 * active consents of the token's user, and revoke one. The two families serve
 * the same operations under their own prefix, each behind its own guard, so
 * a token for one family never reaches the other's.
 *
 * - The account API, `/account/v1-rc.0/consents`, is the account console's
 *   (v0.3), which calls it from its backend with a Bearer or DPoP token for
 *   the account audience.
 * - The developer API, `/developer/v1-rc.0/consents`, is the developer
 *   portal's until the consents page moves to the account console.
 *
 * Each family's route module registers the two routes with its own path
 * literals (`routes/account/consents.ts`, `routes/developer/consents.ts`), so
 * the docs site's endpoint check sees them; this module gives both the same
 * options and handlers.
 *
 * Ownership and the revocation's event are `helpers/consent-management.ts`',
 * shared with the deprecated `/api/consents` and `/consents`: a consent of
 * another user, or of another realm, is 404, as one that does not exist.
 *
 * The guard (`requireFamilyToken`) resolves the token's subject in the
 * request's realm (#869), and the routes look the consents up in
 * `requestRealm(request)` as well.
 */

/** A family that serves the consent routes. */
export type ConsentFamily = 'account' | 'developer';

/** The request of `GET /consents`. */
export interface ConsentListRoute {
  Querystring: PageQuery;
}

/** The request of `DELETE /consents/{consentId}`. */
export interface ConsentRevokeRoute {
  Params: { consentId: string };
}

/** Route options with their handler, for a route of the default server types. */
type RouteWithHandler<Route extends ConsentListRoute | ConsentRevokeRoute> =
  RouteShorthandOptionsWithHandler<
    RawServerDefault,
    RawRequestDefaultExpression,
    RawReplyDefaultExpression,
    Route
  >;

/**
 * The token's `sub`: a user of the request's realm once the guard passed. A
 * missing one is an invariant broken, refused as a bad token rather than
 * trusted.
 */
function requireTokenUserId(request: FastifyRequest): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError('Missing JWT payload');
  }
  return sub;
}

/** The representation of one consent. */
function toFamilyConsent(row: ConsentWithClient): FamilyConsent {
  return {
    id: row.id,
    client_id: row.clientClientId,
    client_name: row.clientName,
    scopes: row.scopes,
    grantedAt: rfc3339(row.grantedAt),
  };
}

/**
 * The options and handlers of `GET /consents` and `DELETE /consents/{consentId}`
 * for `family`, which its route module mounts under the family's prefix.
 */
export function familyConsentRoutes(family: ConsentFamily): {
  list: RouteWithHandler<ConsentListRoute>;
  revoke: RouteWithHandler<ConsentRevokeRoute>;
} {
  const guard = requireFamilyToken(family, { subjects: ['user'] });
  const tags = [family === 'account' ? 'Account API' : 'Developer API'];

  return {
    list: {
      // Before validation, so a caller without a token for this family learns
      // nothing about what the route accepts.
      preValidation: guard,
      schema: {
        operationId: `${family}.consents.list`,
        description:
          "List the active OAuth consents of the token's user, newest first, one page at a time.",
        tags,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'read',
        'x-qauth-permission': 'consents.read',
        'x-qauth-errors': [400, 401],
        querystring: pageQuerySchema,
        response: { 200: pageSchema(familyConsentSchema) },
      },
      config: { surface: 'api' },
      handler: async (request, reply) => {
        const userId = requireTokenUserId(request);
        const page = await pageConsentsForUser(request.server, requestRealm(request).id, userId, {
          list: `${family}.consents`,
          limit: request.query.limit,
          cursor: request.query.cursor,
          item: toFamilyConsent,
        });
        // Per-user data: keep it out of any shared or proxy cache.
        reply.header('Cache-Control', 'no-store');
        return reply.send(page);
      },
    },
    revoke: {
      preValidation: guard,
      schema: {
        operationId: `${family}.consents.delete`,
        description:
          "Revoke one of the token's user's OAuth consents, with every refresh token and unredeemed authorization code issued under it. A consent of another user is 404, as one that does not exist.",
        tags,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'consents.write',
        'x-qauth-errors': [400, 401, 404],
        params: consentParamsSchema,
        response: { 204: z.null() },
      },
      config: { surface: 'api' },
      handler: async (request, reply) => {
        const userId = requireTokenUserId(request);
        await revokeConsentForUser(
          request.server,
          request,
          requestRealm(request).id,
          userId,
          request.params.consentId
        );
        reply.code(204);
        return reply.send(null);
      },
    },
  };
}
