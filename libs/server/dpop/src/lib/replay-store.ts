/**
 * Where used DPoP proofs are remembered (RFC 9449 §11.1).
 *
 * The verifier records every proof it accepts, keyed by its key and `jti`,
 * for as long as the proof could still pass the `iat` check, and refuses a
 * proof that is already recorded. The check and the write are one atomic step
 * (Redis `SET … NX` in the deployment store), so of two requests racing with
 * one proof exactly one wins.
 *
 * Fail closed: when the store cannot answer, `record` rejects and the
 * verifier refuses the proof, because a replay can no longer be ruled out.
 */
export interface DpopReplayStore {
  /**
   * Record `key` as used for `ttlMs`, unless it is recorded already. Resolves
   * `true` when this call recorded it (the proof's first use), `false` when it
   * was there (a replay). Rejects when the store cannot answer.
   */
  record(key: string, ttlMs: number): Promise<boolean>;
}

/**
 * The one Redis command the replay store sends. An `ioredis` client fits; the
 * library does not depend on one.
 */
export interface DpopRedisClient {
  set(
    key: string,
    value: string,
    mode: 'PX',
    milliseconds: number,
    condition: 'NX'
  ): Promise<'OK' | null>;
}

/** Options for {@link createRedisDpopReplayStore}. */
export interface RedisDpopReplayStoreOptions {
  /** Prepended to every key. Default {@link DEFAULT_DPOP_REPLAY_KEY_PREFIX}. */
  readonly keyPrefix?: string;
}

/** The default key prefix of the Redis replay store. */
export const DEFAULT_DPOP_REPLAY_KEY_PREFIX = 'dpop-jti:';

/**
 * The replay store over Redis: one `SET <prefix><key> 1 PX <ttl> NX` per
 * proof. `OK` is a first use, a nil reply a replay, and anything else, or a
 * failed command, rejects, so the proof is refused.
 *
 * The verifier passes a hash, never the raw `jti`, so a client cannot choose
 * the Redis key or its length.
 */
export function createRedisDpopReplayStore(
  client: DpopRedisClient,
  options: RedisDpopReplayStoreOptions = {}
): DpopReplayStore {
  const prefix = options.keyPrefix ?? DEFAULT_DPOP_REPLAY_KEY_PREFIX;
  return {
    async record(key, ttlMs) {
      // Redis refuses a PX of 0; a positive fraction of a millisecond rounds up.
      const reply = await client.set(
        `${prefix}${key}`,
        '1',
        'PX',
        Math.max(1, Math.ceil(ttlMs)),
        'NX'
      );
      if (reply === 'OK') return true;
      if (reply === null) return false;
      throw new Error('The DPoP replay store sent a reply SET NX does not give');
    },
  };
}
