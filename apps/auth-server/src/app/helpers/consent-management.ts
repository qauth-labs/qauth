import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

/**
 * Consent listing and revocation, shared by the two surfaces that expose it
 * (issue #150, issue #366).
 *
 * There are two, and they authenticate differently on purpose:
 *
 *   - `routes/consents` — the auth-server's OWN hosted UI. Authenticated by the
 *     `__Host-qauth_session` browser cookie, which is ambient credentials, so it
 *     carries a per-session CSRF token that `DELETE` must echo back.
 *   - `routes/consents-api` (`/api/consents`) — the developer portal, through
 *     its TanStack Start server functions. Authenticated by a developer Bearer
 *     access token, exactly like `/api/clients`. A Bearer token is not ambient,
 *     so there is no CSRF token to check and none is required.
 *
 * What must NOT differ between them is the authorization: a caller may only
 * ever see and revoke consents whose `user_id` is their own, and every
 * revocation is audited. That is why both halves live here rather than being
 * written twice — the ownership check below is the security boundary, and a
 * second copy of it is a second chance to get it wrong.
 */

/** One row as both surfaces render it. */
export interface ConsentView {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  grantedAt: number;
}

/**
 * The active consents belonging to `userId`, in the response shape both
 * surfaces publish.
 */
export async function listConsentsForUser(
  fastify: FastifyInstance,
  userId: string
): Promise<ConsentView[]> {
  const rows = await fastify.repositories.oauthConsents.listActiveForUserWithClient(userId);
  return rows.map((row) => ({
    id: row.id,
    clientId: row.clientClientId,
    clientName: row.clientName,
    scopes: row.scopes,
    grantedAt: row.grantedAt,
  }));
}

/**
 * Revoke one consent row on behalf of `userId`, with the ownership check and
 * the audit entry both surfaces owe.
 *
 * Throws `NotFoundError` when the row does not exist OR belongs to another
 * user — deliberately the same outcome, so the API never reveals that someone
 * else's consent id exists. Mirrors how `/api/clients` reports a client owned
 * by another developer as 404 rather than 403.
 *
 * A row that vanishes between the ownership check and the delete (a second tab
 * revoking the same grant) is treated as idempotent success: the caller's
 * intent — "this grant should not exist" — already holds.
 */
export async function revokeConsentForUser(
  fastify: FastifyInstance,
  request: FastifyRequest,
  userId: string,
  consentId: string
): Promise<void> {
  const rows = await fastify.repositories.oauthConsents.listActiveForUser(userId);
  const owned = rows.find((row) => row.id === consentId);
  if (!owned) {
    throw new NotFoundError('OAuthConsent', consentId);
  }

  try {
    await fastify.repositories.oauthConsents.revoke(consentId);
  } catch (err) {
    if (err instanceof NotFoundError) {
      // Raced with another tab — idempotent success, fall through to the audit
      // entry so the intent is still recorded.
    } else if (err instanceof BadRequestError) {
      throw err;
    } else {
      throw err;
    }
  }

  await fastify.repositories.auditLogs.create({
    userId,
    oauthClientId: owned.oauthClientId,
    event: 'oauth.consent.revoked',
    eventType: 'auth',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: { consentId },
  });
}
