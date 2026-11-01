import { createHash, randomBytes } from 'node:crypto';

import {
  checkLadderPolicy,
  type FactorType,
  type IdentifierDigest,
  type LadderHook,
  type LadderPolicy,
  type LadderReservation,
  type LadderSettlement,
  type LadderVerdict,
  NOTHING_DUE,
  PASSWORD_LADDER_POLICY,
} from '@qauth-labs/server-sign-in-engine';

/**
 * THE PER-ACCOUNT FAILURE LADDER IN REDIS (PRO-12, #615; ADR-017 Decision 7,
 * NIST SP 800-63B-4 §3.2.2).
 *
 * Every counter that gates a verification is reserved before the verifier
 * runs, by one atomic store operation: a Redis script reads the counter's
 * wait, refuses an attempt that falls inside it (neither verified nor
 * counted), and otherwise counts the attempt as a failure and sets the next
 * wait. Parallel attempts against one account, each in its own transaction,
 * so meet the same ladder as attempts sent one at a time. The attempt is then
 * settled: a success of the authenticator clears its counter and no other, a
 * counter of failures alone takes the attempt back, and a failure stays
 * counted and says whether the hard action is due.
 *
 * Keys hold no address. A counter is keyed on the identifier's keyed HMAC
 * (realm and normalised identifier, whether or not an account holds it) and
 * the factor; the end-user IPs known to an account are kept as their own
 * keyed HMACs, never as addresses:
 *
 * - `sign-in-ladder:{<realm id>:<identifier HMAC>}:<factor>`: a hash of the
 *   run's consecutive counted failures (`n`), until when an attempt waits
 *   (`until`, epoch ms) and the run's id (`run`), kept `retentionMs` after the
 *   last counted failure;
 * - `sign-in-ladder:{<realm id>:<identifier HMAC>}:known-ips`: a sorted set of
 *   end-user IP HMACs, scored by their last successful sign-in.
 *
 * The braces are a Redis Cluster hash tag: both keys of an account sit in one
 * slot, so one script may read the one and write the other.
 *
 * Fail closed: every Redis call is bounded by `timeoutMs`, and any error or
 * timeout of a reservation rejects, which the engine and the legacy routes
 * turn into a refused round before any credential is checked.
 */

/** The prefix of every ladder key. */
export const LADDER_KEY_PREFIX = 'sign-in-ladder';

/** How long a Redis call of the ladder may take before the round is refused, in ms. */
export const LADDER_REDIS_TIMEOUT_MS = 2_000;

/** The most end-user IPs an account keeps known; the oldest goes first. */
export const LADDER_MAX_KNOWN_IPS = 16;

/** What the ladder needs of the Redis client (ioredis), by shape. */
export interface LadderRedis {
  evalsha(sha: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  hget(key: string, field: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
}

/** Options of {@link createRedisFailureLadder}. */
export interface RedisFailureLadderOptions {
  /**
   * The keyed HMAC an end-user IP is kept known under, in the realm: the
   * identifier HMAC's derivation under a label of its own, so a reader of
   * Redis learns no address.
   */
  readonly ipDigest: IdentifierDigest;
  /** The rules of each factor's ladder; a factor without one is refused (fail closed). */
  readonly policies?: Partial<Record<FactorType, LadderPolicy>>;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
  /** How long one Redis call may take. {@link LADDER_REDIS_TIMEOUT_MS} by default. */
  readonly timeoutMs?: number;
}

/** The ladder, and what the owner's reset (#642) needs of it. */
export interface RedisFailureLadder extends LadderHook {
  /** End the run of `factor` for the identifier: the owner's reset clears the password's (#642). */
  reset(input: {
    readonly realmId: string;
    readonly identifierHmac: string;
    readonly factor: FactorType;
  }): Promise<void>;
}

/**
 * Reserve an attempt. KEYS: the counter, the known-IP set. ARGV: now,
 * freeFailures, firstWaitMs, maxWaitMs, retentionMs, knownIpMs, the IP's HMAC
 * (empty for none), a new run id. Returns `{0, ms left}` for an attempt inside
 * the wait, `{1, n, run}` for a counted one.
 *
 * Redis runs scripts on Lua 5.1: numbers are doubles (an epoch in ms is exact
 * well past 2^50), a missing hash field reads as `false`, and a number a
 * script returns becomes an integer reply.
 */
export const RESERVE_SCRIPT = `
local now = tonumber(ARGV[1])
local free = tonumber(ARGV[2])
local first = tonumber(ARGV[3])
local longest = tonumber(ARGV[4])
local retention = tonumber(ARGV[5])
local knownMs = tonumber(ARGV[6])
local ip = ARGV[7]
local exempt = false
if knownMs > 0 and ip ~= '' then
  local seen = redis.call('ZSCORE', KEYS[2], ip)
  if seen and now - tonumber(seen) < knownMs then exempt = true end
end
local state = redis.call('HMGET', KEYS[1], 'n', 'until', 'run')
local n = tonumber(state[1]) or 0
local waitUntil = tonumber(state[2]) or 0
local run = state[3]
if not run then run = ARGV[8] end
if not exempt and waitUntil > now then
  return {0, waitUntil - now}
end
n = n + 1
local wait = 0
if n >= free then
  local doublings = n - free
  if doublings >= 40 then
    wait = longest
  else
    wait = math.min(first * 2 ^ doublings, longest)
  end
end
local nextUntil = now + wait
if nextUntil < waitUntil then nextUntil = waitUntil end
redis.call('HSET', KEYS[1], 'n', n, 'until', nextUntil, 'run', run)
redis.call('PEXPIRE', KEYS[1], retention)
return {1, n, run}
`;

/**
 * Settle a success. KEYS: the counter, the known-IP set. ARGV: now, the
 * policy's onSuccess (`clear` or `withdraw`), the reservation's run id,
 * knownIpMs, the IP's HMAC (empty for none), the most known IPs kept.
 * Both act on the reservation's own run only: `clear` ends it, `withdraw`
 * takes this attempt back from it. A run another success already ended, and
 * a run begun since, stay as they are, so a success that settles late never
 * wipes failures counted after it. The IP becomes known either way, the
 * stalest dropped past the cap.
 */
export const SETTLE_SUCCESS_SCRIPT = `
local now = tonumber(ARGV[1])
if redis.call('HGET', KEYS[1], 'run') == ARGV[3] then
  if ARGV[2] == 'clear' then
    redis.call('DEL', KEYS[1])
  else
    local n = redis.call('HINCRBY', KEYS[1], 'n', -1)
    if n <= 0 then redis.call('DEL', KEYS[1]) end
  end
end
local knownMs = tonumber(ARGV[4])
if knownMs > 0 and ARGV[5] ~= '' then
  redis.call('ZADD', KEYS[2], now, ARGV[5])
  redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - knownMs)
  local excess = redis.call('ZCARD', KEYS[2]) - tonumber(ARGV[6])
  if excess > 0 then redis.call('ZREMRANGEBYRANK', KEYS[2], 0, excess - 1) end
  redis.call('PEXPIRE', KEYS[2], knownMs)
end
return 1
`;

const sha1 = (script: string) => createHash('sha1').update(script).digest('hex');
export const RESERVE_SCRIPT_SHA = sha1(RESERVE_SCRIPT);
export const SETTLE_SUCCESS_SCRIPT_SHA = sha1(SETTLE_SUCCESS_SCRIPT);

/** The counter key of one factor of one identifier in one realm. */
export function ladderCounterKey(realmId: string, identifierHmac: string, factor: FactorType) {
  return `${LADDER_KEY_PREFIX}:{${realmId}:${identifierHmac}}:${factor}`;
}

/** The known-IP key of one identifier in one realm. */
export function ladderKnownIpsKey(realmId: string, identifierHmac: string) {
  return `${LADDER_KEY_PREFIX}:{${realmId}:${identifierHmac}}:known-ips`;
}

/** What a key part may hold: a realm id or an HMAC, so no caller can splice another key. */
const KEY_PART = /^[A-Za-z0-9_-]{1,64}$/;

/** A Redis call bounded by `ms`: a call that takes longer rejects, and its late answer is dropped. */
async function bounded<T>(call: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`sign-in ladder: ${what} timed out`)), ms);
  });
  call.catch(() => undefined);
  try {
    return await Promise.race([call, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** Whether a Redis error says the script is not cached on the server. */
function isNoScript(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith('NOSCRIPT');
}

/**
 * The failure ladder over Redis. Each reservation is one script call; a
 * failure of a factor with a hard ceiling makes one more read, once the run
 * has reached the ceiling.
 */
export function createRedisFailureLadder(
  redis: LadderRedis,
  options: RedisFailureLadderOptions
): RedisFailureLadder {
  const policies: Partial<Record<FactorType, LadderPolicy>> = Object.freeze({
    ...(options.policies ?? { password: PASSWORD_LADDER_POLICY }),
  });
  for (const policy of Object.values(policies)) if (policy !== undefined) checkLadderPolicy(policy);
  const now = options.now ?? (() => Date.now());
  const timeoutMs = options.timeoutMs ?? LADDER_REDIS_TIMEOUT_MS;

  const run = async (
    script: string,
    sha: string,
    keys: readonly string[],
    args: readonly (string | number)[],
    what: string
  ): Promise<unknown> =>
    bounded(
      (async () => {
        try {
          return await redis.evalsha(sha, keys.length, ...keys, ...args);
        } catch (error) {
          // A Redis restarted or flushed since: load the script with the call.
          if (!isNoScript(error)) throw error;
          return redis.eval(script, keys.length, ...keys, ...args);
        }
      })(),
      timeoutMs,
      what
    );

  const keyParts = (realmId: string, identifierHmac: string) => {
    if (!KEY_PART.test(realmId) || !KEY_PART.test(identifierHmac)) {
      throw new Error('sign-in ladder: a realm id or an identifier HMAC out of shape');
    }
  };

  async function reserve(input: {
    readonly realmId: string;
    readonly identifierHmac: string;
    readonly factor: FactorType;
    readonly endUserIp?: string;
  }): Promise<LadderVerdict> {
    const { realmId, identifierHmac, factor, endUserIp } = input;
    const policy = policies[factor];
    if (policy === undefined) throw new Error(`sign-in ladder: no ladder for ${factor}`);
    keyParts(realmId, identifierHmac);
    const counter = ladderCounterKey(realmId, identifierHmac, factor);
    const known = ladderKnownIpsKey(realmId, identifierHmac);
    const ip =
      policy.knownIpMs > 0 && endUserIp !== undefined && endUserIp !== ''
        ? await options.ipDigest({ realmId, identifier: endUserIp })
        : '';
    const newRun = randomBytes(12).toString('base64url');
    const reply = await run(
      RESERVE_SCRIPT,
      RESERVE_SCRIPT_SHA,
      [counter, known],
      [
        now(),
        policy.freeFailures,
        policy.firstWaitMs,
        policy.maxWaitMs,
        policy.retentionMs,
        policy.knownIpMs,
        ip,
        newRun,
      ],
      'reserve'
    );
    if (!Array.isArray(reply)) throw new Error('sign-in ladder: a reservation answered no list');
    const [kind, value, runId] = reply as unknown[];
    if (kind === 0 && typeof value === 'number' && value > 0) {
      return Object.freeze({ kind: 'wait', retryAfterSeconds: Math.ceil(value / 1000) });
    }
    if (kind !== 1 || typeof value !== 'number' || typeof runId !== 'string') {
      throw new Error('sign-in ladder: a reservation answered out of shape');
    }
    const failures = value;
    let settled = false;
    const reservation: LadderReservation = {
      kind: 'reserved',
      async settle(outcome): Promise<LadderSettlement> {
        if (settled) throw new Error('sign-in ladder: a reservation settled twice');
        settled = true;
        if (outcome === 'success') {
          await run(
            SETTLE_SUCCESS_SCRIPT,
            SETTLE_SUCCESS_SCRIPT_SHA,
            [counter, known],
            [now(), policy.onSuccess, runId, policy.knownIpMs, ip, LADDER_MAX_KNOWN_IPS],
            'settle'
          );
          return NOTHING_DUE;
        }
        // A failure stays counted. The hard action is due only when this
        // failure counted at the ceiling, in a run no success has ended since.
        if (policy.hardCeiling === null || failures < policy.hardCeiling) return NOTHING_DUE;
        const current = await bounded(redis.hget(counter, 'run'), timeoutMs, 'settle');
        return current === runId ? Object.freeze({ ceilingReached: true }) : NOTHING_DUE;
      },
    };
    return Object.freeze(reservation);
  }

  const ladder: RedisFailureLadder = {
    reserve,
    async reset({ realmId, identifierHmac, factor }) {
      keyParts(realmId, identifierHmac);
      await bounded(
        redis.del(ladderCounterKey(realmId, identifierHmac, factor)),
        timeoutMs,
        'reset'
      );
    },
  };
  return Object.freeze(ladder);
}
