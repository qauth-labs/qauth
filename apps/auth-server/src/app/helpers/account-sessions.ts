import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';
import { InvalidSessionCursorError } from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { InvalidCursorError } from './api-request-errors';
import { endBrowserSessions, revokeBrowserSession } from './browser-session';
import { emitUserEvent } from './user-events';

/**
 * THE ACCOUNT'S SESSIONS (#1110; ADR-017 Decision 8, ADR-019 Decision 3,
 * ADR-020 §3): the live browser sessions of an account, ending one, and
 * signing out everywhere, as the account API's `account.sessions.*`
 * operations and the hosted account page (#844) both make them. The page
 * calls with its browser session as the owner, the API with the token's
 * user; the rules are these functions', so the two never drift apart.
 *
 * - **The list** is the account's live sessions in its realm, most recently
 *   used first, through the session service (`listLiveForUser`): never an
 *   ended one, never another account's.
 * - **Ending one** revokes it through the service, which spends its
 *   unredeemed codes and queues a back-channel logout to every client it
 *   signed in to, in the revocation's transaction (#624), and drops its side
 *   record, so its cookie stops working; then the refresh-token families its
 *   sign-in opened end. A session of another account, or one that has ended,
 *   is `not_found`, untouched.
 * - **Signing out everywhere** ends every session of the account, the
 *   caller's own too unless it asks to keep it, each queuing its back-channel
 *   logouts; then every unredeemed code and every refresh-token family of the
 *   account end, as `POST /auth/logout` ends them (ADR-017 Decision 8).
 *
 * Each records `user.signed_out`: with the `sid` of the one session it
 * ended, and without one when every session of the account ended. A sign-out
 * everywhere that kept a session records one per session it ended instead, so
 * a Shared Signals receiver ends those sessions alone and not the one kept.
 */

/** Whose sessions a call reads or ends, and who asked. */
export interface AccountSessionOwner {
  readonly realmId: string;
  readonly userId: string;
  /**
   * The OAuth client the call came through: the account API's caller. The
   * hosted page is no client, so its events name none.
   */
  readonly clientId?: string | null;
  /**
   * The RFC 8693 `act` claim of a delegated call: the event's actor is the
   * acting client, with the whole chain (ADR-019 Decision 7).
   */
  readonly act?: ActClaim;
}

/** One live session of the account, as the page and the API show it. */
export interface AccountSession {
  readonly sid: string;
  /** Whether it is the caller's own: the page's browser session, or the token's `sid`. */
  readonly current: boolean;
  readonly createdAt: number;
  readonly lastSeenAt: number;
  readonly userAgent: string | null;
  readonly ipAddress: string | null;
  /** The names of the clients it signed in to, oldest first. */
  readonly clients: readonly string[];
}

/** One page of the account's live sessions, and the cursor of the next one. */
export interface AccountSessionPage {
  readonly items: readonly AccountSession[];
  readonly nextCursor: string | null;
}

/**
 * One page of the account's live sessions, most recently used first.
 * `currentSid` names the caller's own session, which the page marks.
 *
 * @throws {InvalidCursorError} for a cursor this list did not issue
 */
export async function pageAccountSessions(
  fastify: FastifyInstance,
  owner: Pick<AccountSessionOwner, 'realmId' | 'userId'>,
  page: {
    readonly limit: number;
    readonly cursor?: string;
    readonly currentSid?: string;
  }
): Promise<AccountSessionPage> {
  let listed: Awaited<ReturnType<FastifyInstance['sessionService']['listLiveForUser']>>;
  try {
    listed = await fastify.sessionService.listLiveForUser({
      realmId: owner.realmId,
      userId: owner.userId,
      page: {
        limit: page.limit,
        ...(page.cursor === undefined ? {} : { cursor: page.cursor }),
      },
    });
  } catch (error) {
    if (error instanceof InvalidSessionCursorError) throw new InvalidCursorError();
    throw error;
  }
  return {
    items: listed.items.map((item) => ({
      sid: item.sid,
      current: page.currentSid !== undefined && item.sid === page.currentSid,
      createdAt: item.createdAt,
      lastSeenAt: item.lastSeenAt,
      userAgent: item.userAgent,
      ipAddress: item.ipAddress,
      clients: item.clients.map((client) => client.name),
    })),
    nextCursor: listed.nextCursor,
  };
}

/** The `user.signed_out` event of a sign-out, as the owner's call records it. */
function recordSignedOut(
  request: FastifyRequest,
  owner: AccountSessionOwner,
  sid: string | undefined
): Promise<string> {
  return emitUserEvent(
    request,
    'urn:qauth:event:user.signed_out:v1-rc.0',
    sid === undefined ? {} : { sid },
    {
      realmId: owner.realmId,
      userId: owner.userId,
      clientId: owner.clientId ?? null,
      actor: 'user',
      ...(owner.act === undefined ? {} : { act: owner.act }),
    }
  );
}

/**
 * End one of the account's sessions (`account.sessions.delete`): its cookie
 * stops working, every client it signed in to is queued a back-channel
 * logout by the revocation itself (#624), and the refresh-token families its
 * sign-in opened end. Recorded as `user.signed_out` with its `sid`. A session
 * of another account, or one already ended, is `not_found`, untouched.
 */
export async function endAccountSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  owner: AccountSessionOwner,
  sid: string
): Promise<{ readonly kind: 'ended' | 'not_found' }> {
  const { realmId, userId } = owner;
  const result = await revokeBrowserSession(
    fastify,
    realmId,
    sid,
    'sign_out',
    { type: 'user', id: userId },
    userId
  );
  if (result.outcome !== 'ended') return { kind: 'not_found' };
  // A refresh family names no session: the families its sign-in opened carry
  // its `auth_time` (#662), as a removed new credential finds them (#1064).
  // The revocation spent the session's codes already, so none redeemed
  // after it opens a family this sweep misses.
  await fastify.repositories.refreshTokens.revokeFamiliesOfSignIns(
    userId,
    [result.session.authTime],
    'session_ended'
  );
  await recordSignedOut(request, owner, sid);
  return { kind: 'ended' };
}

/**
 * Sign out everywhere (`account.sessions.endAll`): every session of the
 * account ends but `keepSid`, when the caller asks to keep its own, each
 * client a session signed in to is queued a back-channel logout, and every
 * unredeemed code and refresh-token family of the account ends, as
 * `POST /auth/logout` ends them. Recorded as `user.signed_out` without a
 * `sid`, or, when a session was kept, once per session it ended, with its
 * `sid`.
 *
 * @returns the ids of the sessions it ended
 */
export async function endAllAccountSessions(
  fastify: FastifyInstance,
  request: FastifyRequest,
  owner: AccountSessionOwner,
  options: { readonly keepSid?: string } = {}
): Promise<readonly string[]> {
  const { realmId, userId } = owner;
  const ended = await endBrowserSessions(fastify, realmId, userId, {
    reason: 'sign_out_everywhere',
    ...(options.keepSid === undefined ? {} : { exceptSid: options.keepSid }),
  });
  // Codes first: one redeemed after the sweep below would mint a refresh
  // token that survives it.
  await fastify.repositories.authorizationCodes.invalidateForUser(userId);
  await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'logout');
  if (options.keepSid === undefined) {
    await recordSignedOut(request, owner, undefined);
  } else {
    for (const sid of ended) await recordSignedOut(request, owner, sid);
  }
  return ended;
}
