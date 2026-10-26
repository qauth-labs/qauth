import type { FastifyInstance } from 'fastify';

import { REDIS_KEYS } from '../constants/redis-keys';
import { revokeJti } from './token-revocation';

/**
 * THE ACCESS TOKENS A GRANT ISSUED (#627, ADR-017 Decision 10).
 *
 * A replayed authorization code or refresh token revokes the refresh family in
 * Postgres, but access tokens are self-contained JWTs: they are revoked only by
 * putting their `jti` on the denylist (`token-revocation.ts`), which userinfo,
 * introspection, token exchange and every `requireJwt` route consult. So each
 * access token is recorded, at issuance, against the grant it came from: the
 * authorization code that was redeemed, and the refresh family it belongs to.
 * A replay reads those records and denylists every token in them that has not
 * expired (OAuth 2.1 §4.1.3, RFC 6749 §4.1.2: "revoke (when possible) all
 * access tokens").
 *
 * A record is a Redis hash of `jti` to `exp`, so each token is denylisted for
 * exactly its remaining lifetime. The hash expires with the last token in it.
 *
 * Recording is best-effort: Redis being unavailable must not stop issuance, so
 * a failure is logged and the token is issued unrecorded (a replay cannot
 * revoke it; it expires on its own). Revocation reports what it did, and
 * `undefined` when it could not read or write the records, so a caller never
 * claims a revocation that did not happen.
 */

/** The grant an access token was issued from. */
export interface AccessTokenGrant {
  /** The authorization code whose redemption issued the token. */
  readonly authorizationCodeId?: string;
  /** The refresh family the token was issued in, at its start or a rotation. */
  readonly refreshFamilyId?: string | null;
}

/** The Redis hashes that hold the access tokens of `grant`. */
function recordKeys(grant: AccessTokenGrant): string[] {
  return [
    ...(grant.authorizationCodeId
      ? [REDIS_KEYS.CODE_ACCESS_TOKENS(grant.authorizationCodeId)]
      : []),
    ...(grant.refreshFamilyId
      ? [REDIS_KEYS.REFRESH_FAMILY_ACCESS_TOKENS(grant.refreshFamilyId)]
      : []),
  ];
}

/** The `[error, result]` pairs a Redis transaction answers; `null` when it was aborted. */
type ExecResult = [Error | null, unknown][] | null;

/**
 * Record a freshly signed access token against the grant it was issued from.
 *
 * Called inside the transaction that issues the token, before it commits: a
 * replay reads the record only after that transaction is over (a concurrent
 * redemption loses its compare-and-set only once the winner has committed; a
 * family revocation takes the user's lock only once every rotation in flight
 * has committed), so it always finds the token. A token whose transaction then
 * rolls back was never handed out, and its record is harmless.
 *
 * `jti` and `exp` are read with an unverified decode, safe here and only here:
 * this process signed the token a moment ago.
 *
 * Never throws: a failure is logged at `warn` and issuance goes on.
 */
export async function recordGrantAccessToken(
  fastify: FastifyInstance,
  accessToken: string,
  grant: AccessTokenGrant
): Promise<void> {
  const keys = recordKeys(grant);
  if (keys.length === 0) return;
  try {
    const { jti, exp } = fastify.jwtUtils.decodeTokenUnsafe(accessToken);
    if (typeof jti !== 'string' || jti.length === 0 || typeof exp !== 'number') {
      throw new Error('the access token has no jti or exp');
    }
    const ttlSeconds = Math.ceil(exp - Date.now() / 1000);
    if (ttlSeconds <= 0) return;
    const recording = fastify.redis.multi();
    for (const key of keys) {
      // NX gives a new hash its expiry; GT lengthens it for a later token and
      // never shortens it below an earlier one's.
      recording
        .hset(key, jti, String(exp))
        .expire(key, ttlSeconds, 'NX')
        .expire(key, ttlSeconds, 'GT');
    }
    const results = (await recording.exec()) as ExecResult;
    const failed = results === null ? new Error('aborted') : results.find(([error]) => error)?.[0];
    if (failed) throw failed;
  } catch (err) {
    fastify.log.warn(
      { err, ...grant },
      'Could not record an issued access token against its grant; a replay of the grant will not revoke it before it expires.'
    );
  }
}

/**
 * Put every unexpired access token recorded against `grant` on the
 * revocation denylist, each for its remaining lifetime.
 *
 * Called after the transaction that revoked the grant's refresh tokens has
 * committed: the denylist is in Redis, outside that transaction.
 *
 * @returns how many access tokens were denylisted; `undefined` when the
 *   records could not be read or the denylist written (logged at `error`): the
 *   caller must not report those tokens revoked.
 */
export async function revokeGrantAccessTokens(
  fastify: FastifyInstance,
  grant: AccessTokenGrant
): Promise<number | undefined> {
  const keys = recordKeys(grant);
  try {
    const live = new Map<string, number>();
    const nowSeconds = Date.now() / 1000;
    for (const key of keys) {
      const recorded = await fastify.redis.hgetall(key);
      for (const [jti, exp] of Object.entries(recorded)) {
        const remaining = Number(exp) - nowSeconds;
        if (Number.isFinite(remaining) && remaining > 0) live.set(jti, remaining);
      }
    }
    for (const [jti, remaining] of live) await revokeJti(fastify, jti, remaining);
    return live.size;
  } catch (err) {
    fastify.log.error(
      { err, ...grant },
      'Could not revoke the access tokens of a replayed grant; they stay valid until they expire.'
    );
    return undefined;
  }
}
