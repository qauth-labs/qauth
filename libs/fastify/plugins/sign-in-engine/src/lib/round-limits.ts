import { createHash, randomBytes } from 'node:crypto';

import {
  type CredentialRoundKeys,
  type CredentialRoundOutcome,
  ROUND_LIMIT_ALERTS,
  ROUND_LIMIT_POLICY,
  ROUND_LIMITS,
  type RoundLimitAlert,
  type RoundLimitDecision,
  type RoundLimitKeys,
  type RoundLimitName,
  roundLimitPolicies,
  type RoundLimitPolicy,
  roundLimitPolicyFor,
  type RoundLimitStore,
} from '@qauth-labs/server-sign-in-engine';

/**
 * THE ROUND LIMITS IN REDIS (PRO-13, #636; ADR-017 Decision 7).
 *
 * One script per decision, so parallel rounds meet the same limits as rounds
 * sent one at a time: a credential round is reserved (counted as a failed
 * round of every row) before its credential is verified, and settled after.
 * Each count is a sliding log: a sorted set of times, pruned as its window
 * slides, so a `Retry-After` names the moment a slot frees.
 *
 * Keys hold no address, no identifier and no client id: an end-user IP and
 * its bucket are their keyed HMACs, an identifier its keyed HMAC, a client
 * and an account the SHA-256 of their ids. Every key of a realm carries the
 * realm's hash tag, `{<realm id>}`, so each script runs in one Redis Cluster
 * slot:
 *
 * - `round-limits:{<realm>}:ip:<ip>:failures`, `…:block`, `…:pace`: an end-user
 *   IP's failed (and reserved) credential rounds, until when its hard block
 *   and its delay hold (the delay of its own failures, or of its bucket's
 *   identifiers);
 * - `round-limits:{<realm>}:bucket:<bucket>:failures` (members
 *   `<identifier>:<reservation>`), `…:identifiers` (a hash of each
 *   identifier's live entries, so its length is the distinct count) and
 *   `…:alert`;
 * - `round-limits:{<realm>}:client:<client>:rounds` (every round, a minute),
 *   `…:credential` (its credential rounds: a reservation each, and one
 *   `a:<account>` per account that succeeded), `…:failures`, `…:pace` and
 *   `…:alert:<threshold>`;
 * - `round-limits:{<realm>}:registration:ip:<ip>` and `…:registration:client:<client>`.
 *
 * Every time a key holds is the store's clock, never Redis's, so the keys'
 * own expiry only drops what the clock has already let go.
 *
 * Fail closed: every Redis call is bounded by `timeoutMs`, and any error or
 * timeout rejects, which the engine turns into a refused round before any
 * credential is checked.
 */

/** The prefix of every round-limit key. */
export const ROUND_LIMITS_KEY_PREFIX = 'round-limits';

/** How long a Redis call of the round limits may take before the round is refused, in ms. */
export const ROUND_LIMITS_REDIS_TIMEOUT_MS = 2_000;

/** What the round limits need of the Redis client (ioredis), by shape. */
export interface RoundLimitsRedis {
  evalsha(sha: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
}

/** Options of {@link createRedisRoundLimits}. */
export interface RedisRoundLimitsOptions {
  /** The limits. {@link ROUND_LIMIT_POLICY} by default; `development` relaxes them. */
  readonly policy?: RoundLimitPolicy;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
  /** How long one Redis call may take. {@link ROUND_LIMITS_REDIS_TIMEOUT_MS} by default. */
  readonly timeoutMs?: number;
}

/** What every script opens with: the clock, number formatting and the marks. */
const PRELUDE = `
local now = tonumber(ARGV[1])
local flags = ARGV[2]
local function on(i) return string.sub(flags, i, i) == '1' end
local function num(i) return tonumber(ARGV[i]) end
local function ms(value) return string.format('%.0f', value) end
local function prune(key, window)
  redis.call('ZREMRANGEBYSCORE', key, '-inf', ms(now - window))
end
local function mark(key) return tonumber(redis.call('GET', key) or '0') or 0 end
local function extend(key, untilMs)
  if mark(key) < untilMs then
    redis.call('SET', key, ms(untilMs), 'PX', ms(math.max(1, untilMs - now)))
  end
end
local function claim(key, ttl)
  if mark(key) > now then return false end
  redis.call('SET', key, ms(now + ttl), 'PX', ms(ttl))
  return true
end
local function slot(key, window, limit)
  local n = redis.call('ZCARD', key)
  local oldest = redis.call('ZRANGE', key, n - limit, n - limit, 'WITHSCORES')
  local wait = tonumber(oldest[2]) + window - now
  if wait < 1 then wait = 1 end
  return wait
end
`;

/** Prune a bucket's log, keeping its identifiers' counts. KEYS 4 and 5 are the log and the hash. */
const PRUNE_BUCKET = `
local function pruneBucket(window)
  local gone = redis.call('ZRANGEBYSCORE', KEYS[4], '-inf', ms(now - window))
  for _, member in ipairs(gone) do
    local id = string.match(member, '^(.*):[^:]*$')
    if id then
      local left = redis.call('HINCRBY', KEYS[5], id, -1)
      if left <= 0 then redis.call('HDEL', KEYS[5], id) end
    end
  end
  redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', ms(now - window))
end
`;

/**
 * Admit a round (rule 3). KEYS: the IP's block, the client's rounds log, the
 * client's rounds alert, the bucket's failures and identifiers, the IP's
 * failures, the client's credential rounds and failures. ARGV: now, flags
 * (an IP, a client, a bucket), a member unique to the round, the client's
 * rounds a minute and its window, then the IP's window and soft failures,
 * the bucket's window and most identifiers, the client's window, ratio's
 * fewest rounds, ratio percentage and failure budget.
 *
 * An admitted round also says whether a soft threshold of its IP, its
 * bucket or its client holds, the thresholds that start a credential
 * round's delay: the round then owes the bot challenge (#643).
 * Returns `{'admitted'|'refused', limit, ms until it may come again, alert, soft}`.
 */
export const ADMIT_ROUND_SCRIPT = `${PRELUDE}${PRUNE_BUCKET}
local hasIp, hasClient, hasBucket = on(1), on(2), on(3)
local member = ARGV[3]
local maxRounds, window = num(4), num(5)
local ipWindow, ipSoft, bucketWindow, bucketMax = num(6), num(7), num(8), num(9)
local clientWindow, ratioMin, ratioPct, budget = num(10), num(11), num(12), num(13)
if hasIp then
  local block = mark(KEYS[1])
  if block > now then return {'refused', 'end_user_ip', block - now, '', ''} end
end
if hasClient then
  prune(KEYS[2], window)
  if redis.call('ZCARD', KEYS[2]) >= maxRounds then
    local wait = slot(KEYS[2], window, maxRounds)
    local alert = ''
    if claim(KEYS[3], window) then alert = 'client_rounds' end
    return {'refused', 'client_rounds', wait, alert, ''}
  end
  redis.call('ZADD', KEYS[2], ms(now), member)
  redis.call('PEXPIRE', KEYS[2], ms(window))
end
local soft = false
if hasIp then
  prune(KEYS[6], ipWindow)
  if redis.call('ZCARD', KEYS[6]) >= ipSoft then soft = true end
  if hasBucket then
    pruneBucket(bucketWindow)
    if redis.call('HLEN', KEYS[5]) > bucketMax then soft = true end
  end
end
if hasClient then
  prune(KEYS[7], clientWindow)
  prune(KEYS[8], clientWindow)
  local r = redis.call('ZCARD', KEYS[7])
  local f = redis.call('ZCARD', KEYS[8])
  if f > budget or (r >= ratioMin and f * 100 > ratioPct * r) then soft = true end
end
if soft then return {'admitted', '', 0, '', '1'} end
return {'admitted', '', 0, '', ''}
`;

/**
 * Reserve a credential round. KEYS: the IP's failures, block and pace; the
 * bucket's failures and identifiers; the client's credential rounds,
 * failures and pace. ARGV: now, flags (an IP, a bucket, an identifier, a
 * client), the reservation, the identifier HMAC, then the IP's window, soft
 * and hard failures and delay, the bucket's window, most identifiers and
 * delay, the client's window, ratio's fewest rounds, ratio percentage,
 * failure budget and delay.
 *
 * The order is the contract's: the IP's block, its hard limit, its delay
 * while the IP's or its bucket's soft threshold holds, the client's delay;
 * then, admitted, the round counts as a failed round of every row, and a
 * soft threshold that holds starts its delay. The bucket only counts: its
 * threshold paces each of its IPs, never the bucket as one. Returns
 * `{'admitted'|'refused', limit, ms until it may come again}`.
 */
export const RESERVE_CREDENTIAL_SCRIPT = `${PRELUDE}${PRUNE_BUCKET}
local hasIp, hasBucket, hasId, hasClient = on(1), on(2), on(3), on(4)
local res, identifier = ARGV[3], ARGV[4]
local ipWindow, ipSoft, ipHard, ipDelay = num(5), num(6), num(7), num(8)
local bucketWindow, bucketMax, bucketDelay = num(9), num(10), num(11)
local clientWindow, ratioMin, ratioPct, budget, clientDelay = num(12), num(13), num(14), num(15), num(16)
local ipIsSoft, bucketIsSoft, clientIsSoft = false, false, false
if hasIp then
  local block = mark(KEYS[2])
  if block > now then return {'refused', 'end_user_ip', block - now} end
  prune(KEYS[1], ipWindow)
  local n = redis.call('ZCARD', KEYS[1])
  if n >= ipHard then return {'refused', 'end_user_ip', slot(KEYS[1], ipWindow, ipHard)} end
  ipIsSoft = n >= ipSoft
  if hasBucket then
    pruneBucket(bucketWindow)
    bucketIsSoft = redis.call('HLEN', KEYS[5]) > bucketMax
  end
  local pace = mark(KEYS[3])
  if pace > now then
    if ipIsSoft then return {'refused', 'end_user_ip_delay', pace - now} end
    if bucketIsSoft then return {'refused', 'ip_bucket_delay', pace - now} end
  end
end
if hasClient then
  prune(KEYS[6], clientWindow)
  prune(KEYS[7], clientWindow)
  local r = redis.call('ZCARD', KEYS[6])
  local f = redis.call('ZCARD', KEYS[7])
  clientIsSoft = f > budget or (r >= ratioMin and f * 100 > ratioPct * r)
  local pace = mark(KEYS[8])
  if clientIsSoft and pace > now then return {'refused', 'client_delay', pace - now} end
end
if hasIp then
  redis.call('ZADD', KEYS[1], ms(now), res)
  redis.call('PEXPIRE', KEYS[1], ms(ipWindow))
  if ipIsSoft then extend(KEYS[3], now + ipDelay) end
  if bucketIsSoft then extend(KEYS[3], now + bucketDelay) end
  if hasBucket and hasId then
    redis.call('ZADD', KEYS[4], ms(now), identifier .. ':' .. res)
    redis.call('HINCRBY', KEYS[5], identifier, 1)
    redis.call('PEXPIRE', KEYS[4], ms(bucketWindow))
    redis.call('PEXPIRE', KEYS[5], ms(bucketWindow))
  end
end
if hasClient then
  redis.call('ZADD', KEYS[6], ms(now), res)
  redis.call('ZADD', KEYS[7], ms(now), res)
  redis.call('PEXPIRE', KEYS[6], ms(clientWindow))
  redis.call('PEXPIRE', KEYS[7], ms(clientWindow))
  if clientIsSoft then extend(KEYS[8], now + clientDelay) end
end
return {'admitted', '', 0}
`;

/**
 * Settle a credential round. KEYS: the IP's failures, block and pace; the
 * bucket's failures, identifiers and alert; the client's credential rounds,
 * failures, pace, ratio alert and budget alert. ARGV: now, flags (an IP, a
 * bucket, an identifier, a client, an account), the outcome, the
 * reservation, the identifier HMAC, the account's hash, then the IP's
 * window, soft and hard failures, block and delay, the bucket's window, most
 * identifiers and delay, the client's window, ratio's fewest rounds, ratio
 * percentage, failure budget and delay.
 *
 * A failure stays counted: at the IP's hard limit it blocks the IP (and
 * alerts, once per block); a soft threshold that holds starts the IP's (or
 * the client's) delay again, and the bucket's and the client's alert once
 * per window. A success or a withdrawal takes the round back from every
 * row; a success then counts once for its account on the client's
 * credential rounds. Returns the alerts.
 */
export const SETTLE_CREDENTIAL_SCRIPT = `${PRELUDE}${PRUNE_BUCKET}
local hasIp, hasBucket, hasId, hasClient, hasAccount = on(1), on(2), on(3), on(4), on(5)
local outcome, res, identifier, account = ARGV[3], ARGV[4], ARGV[5], ARGV[6]
local ipWindow, ipSoft, ipHard, ipBlock, ipDelay = num(7), num(8), num(9), num(10), num(11)
local bucketWindow, bucketMax, bucketDelay = num(12), num(13), num(14)
local clientWindow, ratioMin, ratioPct, budget, clientDelay = num(15), num(16), num(17), num(18), num(19)
local alerts = {}
if outcome == 'failure' then
  if hasIp then
    prune(KEYS[1], ipWindow)
    local n = redis.call('ZCARD', KEYS[1])
    if n >= ipHard and mark(KEYS[2]) <= now then
      redis.call('SET', KEYS[2], ms(now + ipBlock), 'PX', ms(ipBlock))
      table.insert(alerts, 'end_user_ip_blocked')
    end
    if n >= ipSoft then extend(KEYS[3], now + ipDelay) end
    if hasBucket then
      pruneBucket(bucketWindow)
      if redis.call('HLEN', KEYS[5]) > bucketMax then
        extend(KEYS[3], now + bucketDelay)
        if claim(KEYS[6], bucketWindow) then table.insert(alerts, 'ip_bucket_identifiers') end
      end
    end
  end
  if hasClient then
    prune(KEYS[7], clientWindow)
    prune(KEYS[8], clientWindow)
    local r = redis.call('ZCARD', KEYS[7])
    local f = redis.call('ZCARD', KEYS[8])
    local ratio = r >= ratioMin and f * 100 > ratioPct * r
    local overBudget = f > budget
    if ratio or overBudget then extend(KEYS[9], now + clientDelay) end
    if ratio and claim(KEYS[10], clientWindow) then
      table.insert(alerts, 'client_failure_ratio')
    end
    if overBudget and claim(KEYS[11], clientWindow) then
      table.insert(alerts, 'client_failure_budget')
    end
  end
  return alerts
end
if hasIp then
  redis.call('ZREM', KEYS[1], res)
  if hasBucket and hasId then
    if redis.call('ZREM', KEYS[4], identifier .. ':' .. res) == 1 then
      local left = redis.call('HINCRBY', KEYS[5], identifier, -1)
      if left <= 0 then redis.call('HDEL', KEYS[5], identifier) end
    end
  end
end
if hasClient then
  redis.call('ZREM', KEYS[8], res)
  if outcome == 'withdrawn' then
    redis.call('ZREM', KEYS[7], res)
  elseif hasAccount then
    redis.call('ZREM', KEYS[7], res)
    redis.call('ZADD', KEYS[7], ms(now), 'a:' .. account)
    redis.call('PEXPIRE', KEYS[7], ms(clientWindow))
  end
end
return alerts
`;

/**
 * Decide a registration start. KEYS: the IP's starts, the client's. ARGV:
 * now, flags (an IP, a client), a member unique to the start, the IP's
 * limit and window, the client's limit and window. Only an admitted start
 * counts. Returns `{'admitted'|'refused', limit, ms until a slot frees}`.
 */
export const REGISTRATION_START_SCRIPT = `${PRELUDE}
local hasIp, hasClient = on(1), on(2)
local member = ARGV[3]
local ipLimit, ipWindow, clientLimit, clientWindow = num(4), num(5), num(6), num(7)
if hasIp then
  prune(KEYS[1], ipWindow)
  if redis.call('ZCARD', KEYS[1]) >= ipLimit then
    return {'refused', 'registration_end_user_ip', slot(KEYS[1], ipWindow, ipLimit)}
  end
end
if hasClient then
  prune(KEYS[2], clientWindow)
  if redis.call('ZCARD', KEYS[2]) >= clientLimit then
    return {'refused', 'registration_client', slot(KEYS[2], clientWindow, clientLimit)}
  end
end
if hasIp then
  redis.call('ZADD', KEYS[1], ms(now), member)
  redis.call('PEXPIRE', KEYS[1], ms(ipWindow))
end
if hasClient then
  redis.call('ZADD', KEYS[2], ms(now), member)
  redis.call('PEXPIRE', KEYS[2], ms(clientWindow))
end
return {'admitted', '', 0}
`;

const sha1 = (script: string) => createHash('sha1').update(script).digest('hex');
export const ADMIT_ROUND_SCRIPT_SHA = sha1(ADMIT_ROUND_SCRIPT);
export const RESERVE_CREDENTIAL_SCRIPT_SHA = sha1(RESERVE_CREDENTIAL_SCRIPT);
export const SETTLE_CREDENTIAL_SCRIPT_SHA = sha1(SETTLE_CREDENTIAL_SCRIPT);
export const REGISTRATION_START_SCRIPT_SHA = sha1(REGISTRATION_START_SCRIPT);

/** What a key part may hold: a realm id, an HMAC or a reservation id, so no caller can splice another key. */
const KEY_PART = /^[A-Za-z0-9_-]{1,64}$/;

function part(value: string, what: string): string {
  if (!KEY_PART.test(value)) throw new Error(`round limits: ${what} out of shape`);
  return value;
}

/** A round-limit key of the realm, under the realm's hash tag. */
export function roundLimitKey(realmId: string, ...parts: string[]): string {
  return `${ROUND_LIMITS_KEY_PREFIX}:{${part(realmId, 'a realm id')}}:${parts.join(':')}`;
}

/** The key part of a client or an account: the SHA-256 of its id, base64url. */
function hashPart(id: string): string {
  return createHash('sha256').update(id).digest('base64url');
}

/** A Redis call bounded by `ms`: a call that takes longer rejects, and its late answer is dropped. */
async function bounded<T>(call: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`round limits: ${what} timed out`)), ms);
  });
  call.catch(() => undefined);
  try {
    return await Promise.race([call, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function isNoScript(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith('NOSCRIPT');
}

const flag = (on: boolean) => (on ? '1' : '0');

/** A log member no other round of the same millisecond takes. */
const uniqueMember = (at: number) => `${at}-${randomBytes(9).toString('base64url')}`;

/** An alert the script named, or none. */
function alertsOf(values: readonly unknown[]): RoundLimitAlert[] {
  return values.filter(
    (value): value is RoundLimitAlert =>
      typeof value === 'string' && (ROUND_LIMIT_ALERTS as readonly string[]).includes(value)
  );
}

/** Read a decision script's reply, refusing any shape it never returns. */
function decisionOf(reply: unknown): RoundLimitDecision {
  if (!Array.isArray(reply)) throw new Error('round limits: the script answered out of shape');
  const [kind, limit, wait, alert, soft] = reply as unknown[];
  const alerts = alertsOf([alert]);
  if (kind === 'admitted') {
    return soft === '1'
      ? { kind: 'admitted', alerts, softThreshold: true }
      : { kind: 'admitted', alerts };
  }
  if (
    kind === 'refused' &&
    typeof limit === 'string' &&
    (ROUND_LIMITS as readonly string[]).includes(limit) &&
    Number.isFinite(Number(wait))
  ) {
    return {
      kind: 'refused',
      limit: limit as RoundLimitName,
      retryAfterMs: Math.max(1, Number(wait)),
      alerts,
    };
  }
  throw new Error('round limits: the script answered out of shape');
}

/** The round limits over Redis: each decision is one script call. */
export function createRedisRoundLimits(
  redis: RoundLimitsRedis,
  options: RedisRoundLimitsOptions = {}
): RoundLimitStore {
  const policies = roundLimitPolicies(options.policy ?? ROUND_LIMIT_POLICY);
  const now = options.now ?? (() => Date.now());
  const timeoutMs = options.timeoutMs ?? ROUND_LIMITS_REDIS_TIMEOUT_MS;

  const run = (
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

  /** The keys of a round's rows, with what each holds; a row the round lacks keys a dummy name it never writes. */
  const rows = (keys: RoundLimitKeys) => {
    const realm = keys.realmId;
    const ip =
      keys.endUserIpHmac === undefined ? undefined : part(keys.endUserIpHmac, 'an IP HMAC');
    const bucket =
      ip === undefined || keys.ipBucketHmac === undefined
        ? undefined
        : part(keys.ipBucketHmac, 'a bucket HMAC');
    const client = keys.clientKey === undefined ? undefined : hashPart(keys.clientKey);
    const ipKey = (name: string) => roundLimitKey(realm, 'ip', ip ?? '-', name);
    const bucketKey = (name: string) => roundLimitKey(realm, 'bucket', bucket ?? '-', name);
    const clientKey = (...names: string[]) =>
      roundLimitKey(realm, 'client', client ?? '-', ...names);
    return { realm, ip, bucket, client, ipKey, bucketKey, clientKey };
  };

  const credentialArgs = (round: CredentialRoundKeys) => {
    const reservation = part(round.reservation, 'a reservation');
    const identifier =
      round.identifierHmac === undefined ? '' : part(round.identifierHmac, 'an identifier HMAC');
    return { reservation, identifier };
  };

  const store: RoundLimitStore = {
    async admitRound(keys) {
      const p = roundLimitPolicyFor(keys.environment, policies);
      const r = rows(keys);
      const at = now();
      const reply = await run(
        ADMIT_ROUND_SCRIPT,
        ADMIT_ROUND_SCRIPT_SHA,
        [
          r.ipKey('block'),
          r.clientKey('rounds'),
          r.clientKey('alert', 'rounds'),
          r.bucketKey('failures'),
          r.bucketKey('identifiers'),
          r.ipKey('failures'),
          r.clientKey('credential'),
          r.clientKey('failures'),
        ],
        [
          at,
          flag(r.ip !== undefined) + flag(r.client !== undefined) + flag(r.bucket !== undefined),
          uniqueMember(at),
          p.client.maxRounds,
          p.client.maxRoundsWindowMs,
          p.endUserIp.windowMs,
          p.endUserIp.softFailures,
          p.ipBucket.windowMs,
          p.ipBucket.maxIdentifiers,
          p.client.windowMs,
          p.client.ratioMinRounds,
          p.client.ratioPercent,
          p.client.failureBudget,
        ],
        'round'
      );
      return decisionOf(reply);
    },

    async reserveCredential(round) {
      const p = roundLimitPolicyFor(round.environment, policies);
      const r = rows(round);
      const { reservation, identifier } = credentialArgs(round);
      const reply = await run(
        RESERVE_CREDENTIAL_SCRIPT,
        RESERVE_CREDENTIAL_SCRIPT_SHA,
        [
          r.ipKey('failures'),
          r.ipKey('block'),
          r.ipKey('pace'),
          r.bucketKey('failures'),
          r.bucketKey('identifiers'),
          r.clientKey('credential'),
          r.clientKey('failures'),
          r.clientKey('pace'),
        ],
        [
          now(),
          flag(r.ip !== undefined) +
            flag(r.bucket !== undefined) +
            flag(identifier !== '') +
            flag(r.client !== undefined),
          reservation,
          identifier,
          p.endUserIp.windowMs,
          p.endUserIp.softFailures,
          p.endUserIp.hardFailures,
          p.endUserIp.delayMs,
          p.ipBucket.windowMs,
          p.ipBucket.maxIdentifiers,
          p.ipBucket.delayMs,
          p.client.windowMs,
          p.client.ratioMinRounds,
          p.client.ratioPercent,
          p.client.failureBudget,
          p.client.delayMs,
        ],
        'reserve'
      );
      return decisionOf(reply);
    },

    async settleCredential(round) {
      const p = roundLimitPolicyFor(round.environment, policies);
      const r = rows(round);
      const { reservation, identifier } = credentialArgs(round);
      const outcome: CredentialRoundOutcome = round.outcome;
      if (outcome !== 'success' && outcome !== 'failure' && outcome !== 'withdrawn') {
        throw new Error('round limits: not an outcome');
      }
      const account = round.accountKey === undefined ? '' : hashPart(round.accountKey);
      const reply = await run(
        SETTLE_CREDENTIAL_SCRIPT,
        SETTLE_CREDENTIAL_SCRIPT_SHA,
        [
          r.ipKey('failures'),
          r.ipKey('block'),
          r.ipKey('pace'),
          r.bucketKey('failures'),
          r.bucketKey('identifiers'),
          r.bucketKey('alert'),
          r.clientKey('credential'),
          r.clientKey('failures'),
          r.clientKey('pace'),
          r.clientKey('alert', 'ratio'),
          r.clientKey('alert', 'budget'),
        ],
        [
          now(),
          flag(r.ip !== undefined) +
            flag(r.bucket !== undefined) +
            flag(identifier !== '') +
            flag(r.client !== undefined) +
            flag(account !== ''),
          outcome,
          reservation,
          identifier,
          account,
          p.endUserIp.windowMs,
          p.endUserIp.softFailures,
          p.endUserIp.hardFailures,
          p.endUserIp.blockMs,
          p.endUserIp.delayMs,
          p.ipBucket.windowMs,
          p.ipBucket.maxIdentifiers,
          p.ipBucket.delayMs,
          p.client.windowMs,
          p.client.ratioMinRounds,
          p.client.ratioPercent,
          p.client.failureBudget,
          p.client.delayMs,
        ],
        'settle'
      );
      if (!Array.isArray(reply)) throw new Error('round limits: the script answered out of shape');
      return alertsOf(reply);
    },

    async reserveRegistrationStart(keys) {
      const p = roundLimitPolicyFor(keys.environment, policies).registrationStarts;
      const r = rows(keys);
      const at = now();
      const reply = await run(
        REGISTRATION_START_SCRIPT,
        REGISTRATION_START_SCRIPT_SHA,
        [
          roundLimitKey(r.realm, 'registration', 'ip', r.ip ?? '-'),
          roundLimitKey(r.realm, 'registration', 'client', r.client ?? '-'),
        ],
        [
          at,
          flag(r.ip !== undefined) + flag(r.client !== undefined),
          uniqueMember(at),
          p.endUserIp.limit,
          p.endUserIp.windowMs,
          p.client.limit,
          p.client.windowMs,
        ],
        'registration start'
      );
      return decisionOf(reply);
    },
  };
  return Object.freeze(store);
}
