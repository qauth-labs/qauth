import type {
  BrowserSession,
  SessionActor,
  SessionAssuranceLevel,
  SessionRevokedReason,
} from '@qauth-labs/fastify-plugin-sessions';
import { eventRequest } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { REDIS_KEYS } from '../constants/redis-keys';
import { accountCredentialRefusal } from './account-validity';
import { requestRealm } from './request-realm';
import {
  clearSessionCookie,
  readCookie,
  SESSION_COOKIE_NAME,
  verifySignedSessionId,
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
 * (ADR-019 Decision 3, #488), with the request's address and `User-Agent`,
 * recorded under the user for `/auth/logout`. Always a new session with a new
 * `sid`, whatever cookie the browser sent: the session-fixation defence.
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
  await trackBrowserSession(fastify, session);
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
 *   - the signature is invalid
 *   - the service holds no live session with that `sid` in the request's
 *     realm: never created, revoked, past its absolute end or the realm's idle
 *     limit, or a session of another realm (ADR-019 Decision 1)
 *   - the session's user no longer exists or has been disabled
 *   - the account was disabled after the session began, and enabled again
 *     since (#748): a session nobody used while the account was disabled does
 *     not come back with it
 *
 * The caller is responsible for deciding what to do with a null result —
 * e.g. redirect to the login page, or render an error. When the cookie
 * signature is valid but the session is absent, the stale cookie is cleared
 * as a side-effect so the browser stops sending it. A session whose user is
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
  const sid = verifySignedSessionId(raw);
  if (!sid) return null;

  const session = await fastify.sessionService.get({ realmId: requestRealm(request).id, sid });
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
 * Record a newly created browser session under its user, so
 * {@link endBrowserSessions} can end it (`/auth/logout`). The index lives as
 * long as the latest-ending session in it, which is not always the newest: a
 * realm whose lifetime shrank between two sign-ins gives the newer session an
 * earlier end. So the deadline is set on a new index (`NX`) and otherwise only
 * ever moved later (`GT`), never pulled in under a session still live
 * (Redis 7.0 or later).
 */
async function trackBrowserSession(
  fastify: FastifyInstance,
  session: BrowserSession
): Promise<void> {
  const key = REDIS_KEYS.USER_BROWSER_SESSIONS(session.userId);
  const results = await fastify.redis
    .multi()
    .sadd(key, session.sid)
    .pexpireat(key, session.expiresAt, 'NX')
    .pexpireat(key, session.expiresAt, 'GT')
    .exec();
  // A MULTI reports a failed command in its results, not by rejecting. An
  // untracked session would survive `/auth/logout`.
  const failed = results?.find(([error]) => error !== null);
  if (failed) throw failed[0];
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
 * End every browser session of `userId` recorded by `createBrowserSession`:
 * revoke each through the session service (so `/oauth/authorize` shows the
 * login page again on every node, after the cache's tombstone), drop its side
 * record, and drop the index. Returns the ids it ended, so the caller can
 * clear the cookie of the request it is handling when that is one of them;
 * other browsers' cookies go stale and are cleared on their next request.
 *
 * @param realmId - the user's realm: a session is only ever ended in it
 */
export async function endBrowserSessions(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<string[]> {
  const key = REDIS_KEYS.USER_BROWSER_SESSIONS(userId);
  const sids = await fastify.redis.smembers(key);
  // The user signs themselves out.
  const actor: SessionActor = { type: 'user', id: userId };
  for (const sid of sids) {
    await endBrowserSession(fastify, realmId, sid, 'sign_out_everywhere', actor, userId);
  }
  await fastify.redis.del(key);
  return sids;
}
