import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { resolveAudience } from './client-auth';
import { getOrCreateSystemClient } from './oauth-client';
import { getOrCreateDefaultRealm } from './realm';

/** The claims of a verified access token that decide whether it is a management token. */
interface ManagementTokenClaims {
  sub?: string;
  clientId?: string;
  aud?: string | string[];
  act?: unknown;
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
 * - `aud` carries every audience the system client resolves to — the same
 *   binding the `/oauth/authorize` Bearer path already enforces.
 * - No `act` claim: a delegated token acts for an agent, never the developer.
 * - `sub` names a user that still exists and is enabled. The token outlives
 *   the login that minted it by up to its lifetime, and an account disabled
 *   in between must not keep managing its clients — the same gate every
 *   token grant applies to the user it would mint for.
 *
 * `requireActiveUser: false` skips that last check, for a caller that only
 * ends access (`/auth/logout`): a disabled user may still sign out.
 *
 * Throws `JWTInvalidError` (401) on any mismatch, as RFC 6750 §3.1 prescribes
 * for a token that is not valid for the resource.
 */
export async function assertManagementToken(
  fastify: FastifyInstance,
  claims: ManagementTokenClaims | undefined,
  options: { requireActiveUser?: boolean } = {}
): Promise<void> {
  if (!claims) {
    throw new JWTInvalidError('Missing JWT payload');
  }

  const realm = await getOrCreateDefaultRealm(fastify);
  const systemClient = await getOrCreateSystemClient(realm.id, fastify);

  if (claims.clientId !== systemClient.clientId) {
    throw new JWTInvalidError('Access token was not issued for the management API');
  }

  if (claims.act !== undefined && claims.act !== null) {
    throw new JWTInvalidError('A delegated access token cannot use the management API');
  }

  const expected = [resolveAudience(systemClient)].flat();
  const presented = claims.aud === undefined ? [] : [claims.aud].flat();
  if (!expected.every((audience) => presented.includes(audience))) {
    throw new JWTInvalidError('Access token audience does not match the management API');
  }

  if (options.requireActiveUser === false) {
    return;
  }
  if (!claims.sub || !uuidSubjectSchema.safeParse(claims.sub).success) {
    throw new JWTInvalidError('Access token subject is not a user');
  }
  const user = await fastify.repositories.users.findById(claims.sub);
  if (!user || !user.enabled) {
    throw new JWTInvalidError('Access token subject is not an active user');
  }
}

/**
 * Build the preHandler for developer-management routes: the shared
 * `requireJwt` verification (signature, `typ`, issuer, revocation) followed by
 * `assertManagementToken`.
 */
export function createRequireManagementJwt(
  fastify: FastifyInstance
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return async function requireManagementJwt(request, reply) {
    await fastify.requireJwt(request, reply);
    await assertManagementToken(fastify, request.jwtPayload);
  };
}
