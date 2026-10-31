import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { API_FAMILY_AUDIENCES } from '../api-conventions/families';
import { accessTokenIssuedAt, accountCredentialRefusal } from './account-validity';
import { getOrCreateSystemClient } from './oauth-client';
import { type RealmRow, requestRealm } from './request-realm';
import { inactiveSubjectError } from './token-subject';

/** The claims of a verified access token that decide whether it is a management token. */
interface ManagementTokenClaims {
  sub?: string;
  clientId?: string;
  aud?: string | string[];
  act?: unknown;
  iat?: number;
}

/**
 * `users.id` is a uuid column: a non-UUID subject can never be a developer,
 * and refusing it here keeps it from reaching Postgres (22P02 → 500).
 */
const uuidSubjectSchema = z.uuid();

/**
 * Assert that a verified access token is a developer-management token: the
 * token `/auth/login` mints for the developer portal.
 *
 * `requireJwt` proves only that this server issued the token and that it is
 * not revoked. Every user access token passes that check — a token issued to
 * a third-party client, one bound to an RFC 8707 resource, a delegated RFC
 * 8693 token — because each carries the user's id as `sub`. The management
 * API (clients, API keys, consents, DCR attribution) must accept only the
 * portal's own token, so this pins all three claims that identify it:
 *
 * - `client_id` is the system client's id.
 * - `aud` holds exactly the developer API's audience,
 *   `urn:qauth:aud:developer:v1-rc.0`, the system client's since #524. The
 *   release of #509 accepted it and minted the system client's `client_id`;
 *   this one mints it and no longer accepts the `client_id` (expand, then
 *   contract: ADR-018 §5). So a portal token minted before the upgrade is
 *   refused here, expired or not, and its developer signs in again.
 *   `/auth/logout` relies on the same rule.
 * - No `act` claim: a delegated token acts for an agent, never the developer.
 * - `sub` names a user that still exists and is enabled. The token outlives
 *   the login that minted it by up to its lifetime, and an account disabled
 *   in between must not keep managing its clients — the same gate every
 *   token grant applies to the user it would mint for. Nor may a token minted
 *   before the account was last disabled, once it is enabled again (#748).
 * - The token belongs to `realm`, the realm of the request (#487). Its
 *   `client_id`, audience and issuer read the same in every realm (the system
 *   client is named by `SYSTEM_CLIENT_ID` in each), so the realm is its
 *   subject's: `sub` must name a user of this realm. A management token from
 *   realm A is refused at realm B, as a token naming no user is (#489).
 *
 * `requireActiveUser: false` skips the user lookup, for a caller that only
 * ends access (`/auth/logout`): a disabled user may still sign out. In that
 * mode this function checks no realm at all, so the caller MUST look the
 * subject up itself with a realm-scoped read (`users.findById(realm.id, sub)`,
 * as `/auth/logout` does) and refuse a subject that names no user of that
 * realm, an unknown one or another realm's, before acting on it.
 *
 * Throws `JWTInvalidError` (401) on any mismatch, as RFC 6750 §3.1 prescribes
 * for a token that is not valid for the resource.
 */
export async function assertManagementToken(
  fastify: FastifyInstance,
  realm: Pick<RealmRow, 'id'>,
  claims: ManagementTokenClaims | undefined,
  options: { requireActiveUser?: boolean } = {}
): Promise<void> {
  if (!claims) {
    throw new JWTInvalidError('Missing JWT payload');
  }

  const systemClient = await getOrCreateSystemClient(realm.id, fastify);

  if (claims.clientId !== systemClient.clientId) {
    throw new JWTInvalidError('Access token was not issued for the management API');
  }

  if (claims.act !== undefined && claims.act !== null) {
    throw new JWTInvalidError('A delegated access token cannot use the management API');
  }

  // Exactly the developer API's audience, as the developer family's guard
  // reads it (#524): one value. The system client's `client_id`, which a
  // portal token carried before #524, is no longer accepted.
  const presented = claims.aud === undefined ? [] : [claims.aud].flat();
  if (presented.length !== 1 || presented[0] !== API_FAMILY_AUDIENCES.developer) {
    throw new JWTInvalidError('Access token audience does not match the management API');
  }

  if (options.requireActiveUser === false) {
    return;
  }
  if (!claims.sub || !uuidSubjectSchema.safeParse(claims.sub).success) {
    throw inactiveSubjectError();
  }
  // Looked up in the request's realm (#489): a user of another realm is no
  // user here, refused exactly as an unknown or disabled subject is, so the
  // answer does not tell that the subject exists in another realm.
  const user = await fastify.repositories.users.findById(realm.id, claims.sub);
  if (!user || accountCredentialRefusal(user, accessTokenIssuedAt(claims)) !== null) {
    throw inactiveSubjectError();
  }
}

/**
 * Build the preHandler for developer-management routes: the shared
 * `requireJwt` verification (signature, `typ`, issuer, revocation) followed by
 * `assertManagementToken` against the request's realm.
 */
export function createRequireManagementJwt(
  fastify: FastifyInstance
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return async function requireManagementJwt(request, reply) {
    await fastify.requireJwt(request, reply);
    await assertManagementToken(fastify, requestRealm(request), request.jwtPayload);
  };
}
