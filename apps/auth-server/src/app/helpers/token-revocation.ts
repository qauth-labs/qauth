import type { FastifyInstance } from 'fastify';

import { REDIS_KEYS } from '../constants/redis-keys';

/**
 * Access-token revocation denylist (RFC 7009).
 *
 * Access tokens are stateless EdDSA JWTs, so they cannot be invalidated by
 * deleting a row — they remain cryptographically valid until `exp`. To support
 * RFC 7009 revocation we keep a denylist of revoked `jti` values in Redis,
 * each with a TTL equal to the token's remaining lifetime. Once the token would
 * have expired anyway the key auto-evicts, so the denylist never grows
 * unbounded. The blast radius of an un-revoked token is therefore bounded by
 * the (short) access-token lifespan even before this denylist is consulted.
 *
 * This lives in the auth-server layer (not @qauth-labs/server-jwt) deliberately:
 * the JWT lib stays pure and side-effect free; the store dependency belongs to
 * the application. Both helpers fail SAFE — see the per-function notes.
 */

/**
 * Add an access token's `jti` to the revocation denylist.
 *
 * @param jti - The `jti` claim of the access token being revoked.
 * @param ttlSeconds - Remaining lifetime of the token (`exp - now`). The key is
 *   stored with this TTL so it self-evicts once the token expires. Values <= 0
 *   are a no-op: a token that has already expired is inert and never needs a
 *   denylist entry.
 */
export async function revokeJti(
  fastify: FastifyInstance,
  jti: string,
  ttlSeconds: number
): Promise<void> {
  if (!jti || ttlSeconds <= 0) return;
  // SET with EX (ioredis `setex`) — value is a marker; only key presence + TTL
  // matter. Rounded up so a sub-second remaining lifetime still denylists.
  await fastify.redis.setex(REDIS_KEYS.REVOKED_ACCESS_TOKEN(jti), Math.ceil(ttlSeconds), '1');
}

/**
 * Whether an access token's `jti` is on the revocation denylist.
 *
 * FAIL-SAFE: a token with no `jti` (legacy, minted before the claim existed)
 * cannot be individually revoked, so it is treated as NOT revoked — its bounded
 * lifespan is the compensating control. A Redis failure is propagated to the
 * caller rather than silently treated as "not revoked"; callers on security-
 * sensitive paths decide how to fail.
 */
export async function isJtiRevoked(
  fastify: FastifyInstance,
  jti: string | undefined
): Promise<boolean> {
  if (!jti) return false;
  const hit = await fastify.redis.exists(REDIS_KEYS.REVOKED_ACCESS_TOKEN(jti));
  return hit === 1;
}
