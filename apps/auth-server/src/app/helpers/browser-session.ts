import type {
  BrowserSession,
  SessionActor,
  SessionAssuranceLevel,
  SessionRevokedReason,
} from '@qauth-labs/fastify-plugin-sessions';
import { eventRequest } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { accountCredentialRefusal } from './account-validity';
import { requestRealm } from './request-realm';
import {
  clearSessionCookie,
  inspectSessionCookie,
  readCookie,
  SESSION_COOKIE_NAME,
} from './session-cookie';
import { deleteSessionSideRecord, writeSessionSideRecord } from './session-side-record';

/** What {@link createBrowserSession} stores for a successful sign-in. */
export interface BrowserSignIn {
  /** The realm the user signed in to: the user's own. */
  realmId: string;
  userId: string;
  /**
   * The identifier of the credential the user signed in with (its
   * `external_sub`), shown on the consent screen. Kept in the side record,
   * not in Postgres.
   */
  identifier?: string;
  /**
   * The eIDAS level of assurance the authentication established (#237);
   * `null` or absent when nothing above `low` was.
   */
  assuranceLevel?: SessionAssuranceLevel | null;
  /**
   * When the sign-in was issued: the time the caller took before it read the
   * account (#748). The session counts from it, so a disablement that commits
   * after that read finds the session issued before it.
   */
  issuedAt?: number;
}

/**
 * Sign the user in on this browser: a new session through the session service
 * (ADR-019 Decision 3, #488), with the request's address and `User-Agent`.
 * Always a new session with a new `sid`, whatever cookie the browser sent:
 * the session-fixation defence.
 *
 * The address and the `User-Agent` are stored as the sign-in event records
 * them (`eventRequest`): an address in its published form, the header cut to
 * 1024 characters, and neither when it does not qualify.
 *
 * The caller sets the cookie with the returned `sid`.
 */
export async function createBrowserSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  signIn: BrowserSignIn
): Promise<BrowserSession> {
  const userAgent = request.headers['user-agent'];
  const origin = eventRequest({
    ip: request.ip,
    userAgent: typeof userAgent === 'string' ? userAgent : undefined,
  });
  const session = await fastify.sessionService.create({
    realmId: signIn.realmId,
    userId: signIn.userId,
    authTime: Date.now(),
    assuranceLevel: signIn.assuranceLevel ?? null,
    ipAddress: origin?.ip ?? null,
    userAgent: origin?.userAgent ?? null,
    issuedAt: signIn.issuedAt,
  });
  if (signIn.identifier !== undefined) {
    await writeSessionSideRecord(fastify, session, { identifier: signIn.identifier });
  }
  return session;
}

/**
 * Resolve the currently authenticated browser user from the signed
 * `__Host-qauth_session` cookie, through the session service. Returns `null`
 * when:
 *   - the cookie is absent
 *   - the cookie does not verify with the request's realm's cookie keys
 *     (#493): tampered, signed by a key the realm no longer holds, signed for
 *     another realm, in the format of a release before the realm keys, or
 *     signed with a key this process has not read yet
 *   - the service holds no live session with that `sid` in the request's
 *     realm: never created, revoked, past its absolute end or the realm's idle
 *     limit, or a session of another realm (ADR-019 Decision 1)
 *   - the session's user no longer exists or has been disabled
 *   - the account was disabled after the session began, and enabled again
 *     since (#748): a session nobody used while the account was disabled does
 *     not come back with it
 *
 * The caller is responsible for deciding what to do with a null result —
 * e.g. redirect to the login page, or render an error. A cookie that does not
 * verify, or whose session is absent, is cleared as a side-effect so the
 * browser stops sending it; one that names a key this process has not read
 * yet, and may not read again yet, is left for the next request. A signer this
 * process cannot reach is not an invalid cookie: that throws, and the cookie
 * stays. A session whose user is
 * gone or disabled is revoked and its cookie cleared the same way: disabling
 * an account must end the sign-in it already holds, not only refuse the next
 * one (as `/ui/login` and every token grant already do).
 */
export async function resolveBrowserSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<BrowserSession | null> {
  const raw = readCookie(request, SESSION_COOKIE_NAME);
  if (raw === undefined) return null;
  const realmId = requestRealm(request).id;
  const cookie = await inspectSessionCookie(fastify, realmId, raw);
  if (cookie.contents === null) {
    // A cookie this realm did not sign names nothing: stop the browser
    // sending it. One that names a key this process has not read yet is left.
    if (cookie.clear) clearSessionCookie(reply);
    return null;
  }
  const sid = cookie.contents.activeSessionId;

  const session = await fastify.sessionService.get({ realmId, sid });
  if (!session) {
    // Signature was valid but the session is absent — stale cookie.
    clearSessionCookie(reply);
    return null;
  }

  const user = await fastify.repositories.users.findById(session.realmId, session.userId);
  if (!user || accountCredentialRefusal(user, session.createdAt) !== null) {
    // The account behind the session is gone or disabled, or was disabled
    // after the session began (#748) — end the session so the cookie cannot
    // keep using it, and treat it as no sign-in.
    await endBrowserSession(
      fastify,
      session.realmId,
      session.sid,
      'admin',
      SYSTEM_ACTOR,
      session.userId
    );
    clearSessionCookie(reply);
    return null;
  }
  return session;
}

/**
 * Who ends a session whose account is gone or disabled: QAuth itself, on the
 * request that found it so.
 */
const SYSTEM_ACTOR: SessionActor = Object.freeze({ type: 'system' });

/**
 * Revoke one session through the service and drop its side record.
 *
 * @param userId - the session's owner. Required for a `user` actor: the
 *   service ends only that user's session and answers another's as not found,
 *   whose side record is then left alone too.
 */
export async function endBrowserSession(
  fastify: FastifyInstance,
  realmId: string,
  sid: string,
  reason: SessionRevokedReason,
  actor: SessionActor,
  userId?: string
): Promise<void> {
  const result = await fastify.sessionService.revoke({
    realmId,
    sid,
    reason,
    actor,
    ...(userId === undefined ? {} : { userId }),
  });
  if (userId !== undefined && result.outcome === 'not_found') return;
  await deleteSessionSideRecord(fastify, realmId, sid);
}

/**
 * End every live browser session of `userId` in the realm: "sign out
 * everywhere" (`/auth/logout`). The sessions are found and ended in Postgres,
 * in one transaction, by the session service's `revokeAllForUser` (#550), so
 * `/oauth/authorize` shows the login page again on every node once the
 * cache's tombstones are written. Nothing in Redis decides which sessions
 * end: a per-user index of them in Redis, which this used to read, let the
 * sessions it no longer named (an eviction, a restart without persistence, a
 * failover) survive the sign-out (#912).
 *
 * Then, as a cache's tidying, it drops each ended session's side record. It
 * is never read for an ended session and expires with the session, so a Redis
 * failure there is logged and does not stop the logout's later steps (the
 * codes and refresh tokens).
 *
 * Only the sessions this call ends count. One that ended before (signed out,
 * revoked, lapsed) is neither ended again nor tidied, its side record expires
 * on its own, and a cookie that names it is cleared by the next page that
 * reads it.
 *
 * Returns the ids it ended, so the caller can clear the cookie of the request
 * it is handling when that is one of them; other browsers' cookies go stale
 * and are cleared on their next request.
 *
 * @param realmId - the user's realm: a session is only ever ended in it
 */
export async function endBrowserSessions(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<string[]> {
  const { sessions } = await fastify.sessionService.revokeAllForUser({
    realmId,
    userId,
    reason: 'sign_out_everywhere',
    // The user signs themselves out.
    actor: { type: 'user', id: userId },
  });
  const sids = sessions.map(({ session }) => session.id);
  const tidied = await Promise.allSettled(
    sids.map(async (sid) => deleteSessionSideRecord(fastify, realmId, sid))
  );
  const failed = tidied.filter(
    (result): result is PromiseRejectedResult => result.status === 'rejected'
  );
  if (failed.length > 0) {
    fastify.log.warn(
      { err: failed[0].reason, realmId, failed: failed.length },
      'The sessions are ended, but some of their side records could not be dropped; they expire with the sessions'
    );
  }
  return sids;
}
