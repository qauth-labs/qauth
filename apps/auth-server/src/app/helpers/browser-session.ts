import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  type BrowserSessionData,
  clearSessionCookie,
  readCookie,
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
 *
 * The caller is responsible for deciding what to do with a null result —
 * e.g. redirect to the login page, or render an error. When the cookie
 * signature is valid but the session is gone, the stale cookie is cleared
 * as a side-effect so the browser stops sending it.
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
  return data;
}
