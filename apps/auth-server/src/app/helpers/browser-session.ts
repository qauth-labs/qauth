import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { REDIS_KEYS } from '../constants/redis-keys';
import {
  type BrowserSessionData,
  clearSessionCookie,
  readCookie,
  remainingSessionTtl,
  SESSION_COOKIE_NAME,
  verifySignedSessionId,
} from './session-cookie';

/**
 * Resolve the currently authenticated browser user from the signed
 * `__Host-qauth_session` cookie. Returns `null` when:
 *   - the cookie is absent
 *   - the signature is invalid
 *   - the referenced session has been evicted from Redis (TTL expired or
 *     logged out)
 *   - the session is older than `SESSION_COOKIE_TTL`, whatever expiry its
 *     Redis key carries (an absolute lifetime, counted from `createdAt`)
 *   - the session's user no longer exists or has been disabled
 *
 * The caller is responsible for deciding what to do with a null result —
 * e.g. redirect to the login page, or render an error. When the cookie
 * signature is valid but the session is gone, the stale cookie is cleared
 * as a side-effect so the browser stops sending it. A session whose user is
 * gone or disabled is deleted from Redis and its cookie cleared the same way:
 * disabling an account must end the sign-in it already holds, not only
 * refuse the next one (as `/ui/login` and every token grant already do).
 */
export async function resolveBrowserSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<BrowserSessionData | null> {
  const raw = readCookie(request, SESSION_COOKIE_NAME);
  const sessionId = verifySignedSessionId(raw);
  if (!sessionId) return null;

  const data = await fastify.sessionUtils.getSession<BrowserSessionData>(sessionId);
  if (!data) {
    // Signature was valid but Redis has no record — stale cookie.
    clearSessionCookie(reply);
    return null;
  }

  // Written as "not positive" so a record without `createdAt` (NaN) is refused.
  if (!(remainingSessionTtl(data) > 0)) {
    // Past its absolute lifetime: a record rewritten by a replayed cookie must
    // not outlive the lifetime the browser's own cookie was given at sign-in.
    await fastify.sessionUtils.deleteSession(sessionId);
    clearSessionCookie(reply);
    return null;
  }

  const user = await fastify.repositories.users.findById(data.userId);
  if (!user || !user.enabled) {
    // The account behind the session is gone or disabled — end the session
    // so the cookie cannot keep refreshing it, and treat it as no sign-in.
    await fastify.sessionUtils.deleteSession(sessionId);
    clearSessionCookie(reply);
    return null;
  }
  return data;
}

/**
 * Write back a session obtained from {@link resolveBrowserSession}, e.g. to
 * store a CSRF token on it.
 *
 * `setSession` is `SETEX`, which replaces the key's expiry, so the record is
 * stored for what is LEFT of its lifetime. Passing `SESSION_COOKIE_TTL` again
 * would restart the clock on every write and let a replayed cookie keep its
 * session alive indefinitely.
 */
export async function saveBrowserSession(
  fastify: FastifyInstance,
  session: BrowserSessionData
): Promise<void> {
  await fastify.sessionUtils.setSession<BrowserSessionData>(
    session.sessionId,
    session,
    // Redis rejects a TTL of 0, which a write on the last tick would compute.
    Math.max(1, remainingSessionTtl(session))
  );
}

/**
 * Record a newly minted browser session under its user, so
 * {@link endBrowserSessions} can end it (`/auth/logout`). Call it wherever a
 * session is created. The index expires `SESSION_COOKIE_TTL` after the newest
 * session in it was created: no session outlives that (see
 * {@link resolveBrowserSession}), and no rewrite extends one
 * ({@link saveBrowserSession}), so the index outlives every session it names.
 */
export async function trackBrowserSession(
  fastify: FastifyInstance,
  userId: string,
  sessionId: string
): Promise<void> {
  const key = REDIS_KEYS.USER_BROWSER_SESSIONS(userId);
  await fastify.redis.multi().sadd(key, sessionId).expire(key, env.SESSION_COOKIE_TTL).exec();
}

/**
 * End every browser session of `userId` recorded by
 * {@link trackBrowserSession}: delete each session record (which is what
 * {@link resolveBrowserSession} reads, so `/oauth/authorize` shows the login
 * page again) and drop the index. Returns the ids it ended, so the caller can
 * clear the cookie of the request it is handling when that is one of them;
 * other browsers' cookies go stale and are cleared on their next request.
 */
export async function endBrowserSessions(
  fastify: FastifyInstance,
  userId: string
): Promise<string[]> {
  const key = REDIS_KEYS.USER_BROWSER_SESSIONS(userId);
  const sessionIds = await fastify.redis.smembers(key);
  for (const sessionId of sessionIds) {
    await fastify.sessionUtils.deleteSession(sessionId);
  }
  await fastify.redis.del(key);
  return sessionIds;
}
