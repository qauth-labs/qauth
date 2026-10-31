import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { readPage } from '../api-conventions/cursor';
import type { Page } from '../api-conventions/paging';
import { emitUserEvent } from './user-events';

/**
 * Consent listing and revocation, shared by the two surfaces that expose it
 * (issue #150, issue #366).
 *
 * There are four since #524, and they authenticate differently on purpose:
 *
 *   - `routes/consents` — the auth-server's OWN hosted UI. Authenticated by the
 *     `__Host-qauth_session` browser cookie, which is ambient credentials, so it
 *     carries a per-session CSRF token that `DELETE` must echo back.
 *   - `routes/consents-api` (`/api/consents`) — the developer portal, through
 *     its TanStack Start server functions. Authenticated by a developer Bearer
 *     access token, exactly like `/api/clients`. A Bearer token is not ambient,
 *     so there is no CSRF token to check and none is required.
 *   - `/developer/v1-rc.0/consents` and `/account/v1-rc.0/consents` (#524),
 *     which replace the two above: a token for the developer or the account
 *     API family, and the API conventions' representation and paging. The
 *     first two are deprecated aliases until their callers have moved.
 *
 * What must NOT differ between them is the authorization: a caller may only
 * ever see and revoke consents whose `user_id` is their own, and every
 * revocation is recorded as a `consent.revoked` event. That is why both
 * halves live here rather than being written twice — the ownership check
 * below is the security boundary, and a second copy of it is a second chance
 * to get it wrong.
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
 * The active consents belonging to `userId` in the request's realm, in the
 * response shape both surfaces publish.
 */
export async function listConsentsForUser(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<ConsentView[]> {
  const rows = await fastify.repositories.oauthConsents.listActiveForUserWithClient(
    realmId,
    userId
  );
  return rows.map((row) => ({
    id: row.id,
    clientId: row.clientClientId,
    clientName: row.clientName,
    scopes: row.scopes,
    grantedAt: row.grantedAt,
  }));
}

/** One active consent with its client, as the repository reads it. */
export type ConsentWithClient = Awaited<
  ReturnType<FastifyInstance['repositories']['oauthConsents']['listActiveForUserWithClient']>
>[number];

/**
 * One page of the active consents of `userId` in the realm, newest first
 * (#524), by `grantedAt` and then id. `list` names the list in its cursors,
 * so a cursor of another list is refused (`invalid_cursor`).
 */
export async function pageConsentsForUser<Item>(
  fastify: FastifyInstance,
  realmId: string,
  userId: string,
  page: {
    readonly list: string;
    readonly limit: number;
    readonly cursor: string | undefined;
    readonly item: (row: ConsentWithClient) => Item;
  }
): Promise<Page<Item>> {
  return readPage(
    {
      list: page.list,
      limit: page.limit,
      cursor: page.cursor,
      position: (row) => ({ at: row.grantedAt, id: row.id }),
      item: page.item,
    },
    (keyset) =>
      fastify.repositories.oauthConsents.pageActiveForUserWithClient(realmId, userId, keyset)
  );
}

/**
 * Revoke one consent row on behalf of `userId`, with the ownership check and
 * the event both surfaces owe. Every unredeemed authorization code and every
 * refresh token the user holds for that client is revoked in the same
 * transaction, and the `consent.revoked` event commits with them.
 *
 * Throws `NotFoundError` when the row does not exist, belongs to another
 * user OR to another realm (#489) — deliberately the same outcome, so the API
 * never reveals that someone else's consent id exists. Mirrors how
 * `/api/clients` reports a client owned by another developer as 404 rather
 * than 403.
 *
 * A row that vanishes between the ownership check and the delete (a second tab
 * revoking the same grant) is treated as idempotent success: the caller's
 * intent — "this grant should not exist" — already holds.
 */
export async function revokeConsentForUser(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realmId: string,
  userId: string,
  consentId: string
): Promise<void> {
  // Joined to the client in the same query: the event names the client by its
  // public `client_id`.
  const rows = await fastify.repositories.oauthConsents.listActiveForUserWithClient(
    realmId,
    userId
  );
  const owned = rows.find((row) => row.id === consentId);
  if (!owned) {
    throw new NotFoundError('OAuthConsent', consentId);
  }

  // Withdrawing a grant also ends the refresh tokens minted under it, in the
  // same transaction: otherwise the client keeps refreshing on a grant that no
  // longer exists, and a failure between the two steps could leave the
  // consent gone (so a retry 404s) with its refresh tokens still live.
  await fastify.db.transaction(async (tx) => {
    try {
      await fastify.repositories.oauthConsents.revoke(realmId, consentId, tx);
    } catch (err) {
      if (err instanceof NotFoundError) {
        // Raced with another tab — idempotent success. The refresh tokens are
        // still revoked below and the intent is still recorded.
      } else if (err instanceof BadRequestError) {
        throw err;
      } else {
        throw err;
      }
    }
    // Unredeemed codes for this client go first, as in logout: one redeemed
    // after the sweep would mint a refresh token the withdrawn grant no longer
    // covers, and a redemption in flight holds its code row locked until its
    // refresh token is committed, so the sweep below sees it.
    await fastify.repositories.authorizationCodes.invalidateForUserAndClient(
      userId,
      owned.oauthClientId,
      tx
    );
    const revokedRefreshCount = await fastify.repositories.refreshTokens.revokeAllForUserAndClient(
      userId,
      owned.oauthClientId,
      'consent_revoked',
      tx
    );

    // In the same transaction: the event commits with the revocation, or
    // neither does.
    await emitUserEvent(
      request,
      'urn:qauth:event:consent.revoked:v1-rc.0',
      { consentId, revokedRefreshCount },
      {
        tx,
        realmId: owned.realmId,
        userId,
        clientId: owned.clientClientId,
        actor: 'user',
      }
    );
  });
}
