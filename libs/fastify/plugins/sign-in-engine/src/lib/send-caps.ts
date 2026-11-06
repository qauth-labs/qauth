import { createHash, randomBytes } from 'node:crypto';

import {
  checkSendCapPolicy,
  type MailPassBinding,
  type MailPassFlow,
  type OnceANoticeKind,
  SEND_CAP_POLICY,
  SEND_CAP_REFUSING_TIERS,
  type SendCapDecision,
  type SendCapPolicy,
  type SendCapRefusingTier,
  type SendCapRequest,
  type SendCapStore,
} from '@qauth-labs/server-sign-in-engine';

/**
 * THE SEND CAPS IN REDIS (PRO-14, #637; ADR-017 Decision 5).
 *
 * One script decides a send and counts it on every tier that applies, so
 * parallel starts against one address meet the same caps as starts sent one
 * at a time, and a refused or quietly dropped send counts on no tier. Each
 * tier is a sliding log: a sorted set of send times, holding at most its
 * limit, pruned as the window slides, so a `Retry-After` names the moment
 * the oldest send of a full window leaves it.
 *
 * Keys hold no address, no IP and no client id: an address is its keyed
 * HMAC, an IP its keyed HMAC, a client the SHA-256 of its id. Every key of a
 * realm carries the realm's hash tag, `{<realm id>}`, so the one script that
 * reads the per-IP, per-client and per-address logs of a send runs in one
 * Redis Cluster slot:
 *
 * - `send-caps:{<realm>}:ip:<ip>` and `…:client:<client>`: the per-IP and
 *   per-client logs;
 * - `send-caps:{<realm>}:address-ip:<address>:<ip>`: the quiet tier's log,
 *   kept for its long window, its short window counted within it;
 * - `send-caps:{<realm>}:address-client:<address>:<client>`,
 *   `…:ceiling:<address>` and `…:after-first-factor:<address>`;
 * - `send-caps:{<realm>}:pass:<pass hash>`: a live pass, `<address>:<flow>:<expires at>`;
 * - `send-caps:{<realm>}:alert:<address>` and `…:notice:<kind>:<address>`:
 *   until when the operator's alert and each notice are spent.
 *
 * Every time a key holds is the store's clock, never Redis's, so the keys'
 * own expiry only drops what the clock has already let go.
 *
 * Fail closed: every Redis call is bounded by `timeoutMs`, and any error or
 * timeout rejects, which the caller turns into a refused round before any
 * mail is sent.
 */

/** The prefix of every send-cap key. */
export const SEND_CAPS_KEY_PREFIX = 'send-caps';

/** How long a Redis call of the send caps may take, in ms. */
export const SEND_CAPS_REDIS_TIMEOUT_MS = 2_000;

/** What the send caps need of the Redis client (ioredis), by shape. */
export interface SendCapsRedis {
  evalsha(sha: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode: 'PX', ms: number, condition: 'NX'): Promise<'OK' | null>;
}

/** Options of {@link createRedisSendCaps}. */
export interface RedisSendCapsOptions {
  /** The caps. {@link SEND_CAP_POLICY} by default. */
  readonly policy?: SendCapPolicy;
  /** The clock, in epoch ms. `Date.now` by default. */
  readonly now?: () => number;
  /** How long one Redis call may take. {@link SEND_CAPS_REDIS_TIMEOUT_MS} by default. */
  readonly timeoutMs?: number;
}

/**
 * Decide and count one send. KEYS: the per-IP log, the per-client log, the
 * address-and-IP log, the address-and-client log, the ceiling log, the
 * after-first-factor log, the pass, the alert mark. ARGV: now, a member
 * unique to this send, five flags (`1`/`0`: an IP, a client, a known IP,
 * after a first factor, a pass), then limit and window of the per-IP, the
 * per-client, the short and long address-and-IP, the address-and-client, the
 * ceiling and the after-first-factor tiers, the address HMAC, the alert's
 * interval.
 *
 * Returns `{'refused', tier, ms until a slot frees, alert}`, `{'quiet'}` or
 * `{'send', pass spent}`. The order is the contract's: the per-IP and
 * per-client caps, then the pass, then (unless a known IP or the pass
 * exempts the send) the ceiling or the after-first-factor cap, the
 * address-and-client cap and the quiet address-and-IP tier. Only a send
 * counts, and only then is the pass deleted.
 *
 * Redis runs scripts on Lua 5.1: numbers are doubles, exact for an epoch in
 * ms, and are written with `%.0f` so no score is ever in exponent form;
 * `until` is a keyword, so no variable bears that name.
 */
export const RESERVE_SEND_SCRIPT = `
local now = tonumber(ARGV[1])
local member = ARGV[2]
local flags = ARGV[3]
local function on(i) return string.sub(flags, i, i) == '1' end
local hasIp, hasClient, knownIp, after, hasPass = on(1), on(2), on(3), on(4), on(5)
local function num(i) return tonumber(ARGV[i]) end
local ipLimit, ipWindow = num(4), num(5)
local clientLimit, clientWindow = num(6), num(7)
local shortLimit, shortWindow = num(8), num(9)
local longLimit, longWindow = num(10), num(11)
local acLimit, acWindow = num(12), num(13)
local ceilLimit, ceilWindow = num(14), num(15)
local afterLimit, afterWindow = num(16), num(17)
local address = ARGV[18]
local alertTtl = num(19)

local function ms(value) return string.format('%.0f', value) end
local function since(window) return '(' .. ms(now - window) end
local function prune(key, window)
  redis.call('ZREMRANGEBYSCORE', key, '-inf', ms(now - window))
end
local function count(key, window)
  return redis.call('ZCOUNT', key, since(window), '+inf')
end
local function full(key, window, limit)
  prune(key, window)
  return count(key, window) >= limit
end
local function refused(tier, key, window, limit, alert)
  local n = count(key, window)
  local oldest = redis.call('ZRANGEBYSCORE', key, since(window), '+inf', 'WITHSCORES', 'LIMIT', n - limit, 1)
  local wait = tonumber(oldest[2]) + window - now
  if wait < 1 then wait = 1 end
  return {'refused', tier, wait, alert}
end

if hasIp and full(KEYS[1], ipWindow, ipLimit) then
  return refused('end_user_ip', KEYS[1], ipWindow, ipLimit, 0)
end
if hasClient and full(KEYS[2], clientWindow, clientLimit) then
  return refused('client', KEYS[2], clientWindow, clientLimit, 0)
end

local passOk = false
if hasPass then
  local bound = redis.call('GET', KEYS[7])
  if bound then
    local first = string.find(bound, ':', 1, true)
    local last = string.find(bound, ':[^:]*$')
    if first and last and string.sub(bound, 1, first - 1) == address
      and (tonumber(string.sub(bound, last + 1)) or 0) > now then
      passOk = true
    end
  end
end
local exempt = knownIp or passOk

if not exempt then
  if after then
    if full(KEYS[6], afterWindow, afterLimit) then
      return refused('after_first_factor', KEYS[6], afterWindow, afterLimit, 0)
    end
  elseif full(KEYS[5], ceilWindow, ceilLimit) then
    local alert = 0
    local marked = tonumber(redis.call('GET', KEYS[8]) or '0') or 0
    if marked <= now then
      redis.call('SET', KEYS[8], ms(now + alertTtl), 'PX', alertTtl)
      alert = 1
    end
    return refused('ceiling', KEYS[5], ceilWindow, ceilLimit, alert)
  end
  if hasClient and full(KEYS[4], acWindow, acLimit) then
    return refused('address_client', KEYS[4], acWindow, acLimit, 0)
  end
  if hasIp then
    prune(KEYS[3], longWindow)
    if count(KEYS[3], shortWindow) >= shortLimit or count(KEYS[3], longWindow) >= longLimit then
      return {'quiet'}
    end
  end
end

local function record(key, window)
  redis.call('ZADD', key, ms(now), member)
  redis.call('PEXPIRE', key, window)
end
if hasIp then record(KEYS[1], ipWindow) end
if hasClient then record(KEYS[2], clientWindow) end
if not exempt then
  if after then record(KEYS[6], afterWindow) else record(KEYS[5], ceilWindow) end
  if hasClient then record(KEYS[4], acWindow) end
  if hasIp then record(KEYS[3], longWindow) end
end
if passOk then
  redis.call('DEL', KEYS[7])
  return {'send', 1}
end
return {'send', 0}
`;

/**
 * Claim a once-an-interval mark. KEYS: the mark. ARGV: now, the interval.
 * Returns 1 for the first claim in the interval, 0 after it.
 */
export const CLAIM_MARK_SCRIPT = `
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local marked = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
if marked > now then return 0 end
redis.call('SET', KEYS[1], string.format('%.0f', now + ttl), 'PX', ttl)
return 1
`;

/** Give a mark back. KEYS: the mark. Returns the number of marks removed. */
export const RELEASE_MARK_SCRIPT = `
return redis.call('DEL', KEYS[1])
`;

const sha1 = (script: string) => createHash('sha1').update(script).digest('hex');
export const RESERVE_SEND_SCRIPT_SHA = sha1(RESERVE_SEND_SCRIPT);
export const CLAIM_MARK_SCRIPT_SHA = sha1(CLAIM_MARK_SCRIPT);
export const RELEASE_MARK_SCRIPT_SHA = sha1(RELEASE_MARK_SCRIPT);

/** What a key part may hold: a realm id or an HMAC, so no caller can splice another key. */
const KEY_PART = /^[A-Za-z0-9_-]{1,64}$/;

function part(value: string, what: string): string {
  if (!KEY_PART.test(value)) throw new Error(`send caps: ${what} out of shape`);
  return value;
}

/** A send-cap key of the realm, under the realm's hash tag. */
export function sendCapKey(realmId: string, ...parts: string[]): string {
  return `${SEND_CAPS_KEY_PREFIX}:{${part(realmId, 'a realm id')}}:${parts.join(':')}`;
}

/** An address's once-a-day notice of one kind. */
interface NoticeMark {
  readonly realmId: string;
  readonly addressHmac: string;
  readonly kind: OnceANoticeKind;
}

/** The key of a notice's mark. */
function noticeKey(input: NoticeMark): string {
  if (
    input.kind !== 'send_ceiling' &&
    input.kind !== 'password_disabled' &&
    input.kind !== 'recovery_codes_failed'
  ) {
    throw new Error('send caps: not a once-a-day notice');
  }
  return sendCapKey(
    input.realmId,
    'notice',
    input.kind,
    part(input.addressHmac, 'an address HMAC')
  );
}

/** The SHA-256 of a pass, base64url: what the store and an interaction keep in its place. */
export function mailPassHash(pass: string): string {
  return createHash('sha256').update(pass).digest('base64url');
}

/** The key part of a client: the SHA-256 of what names it, base64url. */
function clientPart(clientKey: string): string {
  return createHash('sha256').update(clientKey).digest('base64url');
}

/** A pass, as the link carries it. */
const PASS_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** A Redis call bounded by `ms`: a call that takes longer rejects, and its late answer is dropped. */
async function bounded<T>(call: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`send caps: ${what} timed out`)), ms);
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

/** Read the reserve script's reply, refusing any shape it never returns. */
function decisionOf(reply: unknown): SendCapDecision {
  if (!Array.isArray(reply)) throw new Error('send caps: the script answered out of shape');
  const [kind, ...rest] = reply as unknown[];
  if (kind === 'quiet') return { kind: 'quiet' };
  if (kind === 'send') return { kind: 'send', passSpent: Number(rest[0]) === 1 };
  if (kind === 'refused') {
    const [tier, wait, alert] = rest;
    if (
      typeof tier !== 'string' ||
      !(SEND_CAP_REFUSING_TIERS as readonly string[]).includes(tier) ||
      !Number.isFinite(Number(wait))
    ) {
      throw new Error('send caps: the script answered out of shape');
    }
    return {
      kind: 'refused',
      tier: tier as SendCapRefusingTier,
      retryAfterMs: Math.max(1, Number(wait)),
      alert: Number(alert) === 1,
    };
  }
  throw new Error('send caps: the script answered out of shape');
}

/** The send caps over Redis: each decision is one script call. */
export function createRedisSendCaps(
  redis: SendCapsRedis,
  options: RedisSendCapsOptions = {}
): SendCapStore {
  const policy = checkSendCapPolicy(options.policy ?? SEND_CAP_POLICY);
  const now = options.now ?? (() => Date.now());
  const timeoutMs = options.timeoutMs ?? SEND_CAPS_REDIS_TIMEOUT_MS;

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

  return Object.freeze({
    async reserve(request: SendCapRequest): Promise<SendCapDecision> {
      const { realmId } = request;
      const address = part(request.addressHmac, 'an address HMAC');
      const ip =
        request.endUserIpHmac === undefined ? undefined : part(request.endUserIpHmac, 'an IP HMAC');
      const client = request.clientKey === undefined ? undefined : clientPart(request.clientKey);
      const pass =
        request.passHash === undefined ? undefined : part(request.passHash, 'a pass hash');
      const unused = sendCapKey(realmId, 'unused');
      const keys = [
        ip === undefined ? unused : sendCapKey(realmId, 'ip', ip),
        client === undefined ? unused : sendCapKey(realmId, 'client', client),
        ip === undefined ? unused : sendCapKey(realmId, 'address-ip', address, ip),
        client === undefined ? unused : sendCapKey(realmId, 'address-client', address, client),
        sendCapKey(realmId, 'ceiling', address),
        sendCapKey(realmId, 'after-first-factor', address),
        pass === undefined ? unused : sendCapKey(realmId, 'pass', pass),
        sendCapKey(realmId, 'alert', address),
      ];
      const flags = [
        ip !== undefined,
        client !== undefined,
        request.knownIp,
        request.afterFirstFactor,
        pass !== undefined,
      ]
        .map((flag) => (flag ? '1' : '0'))
        .join('');
      const reply = await run(
        RESERVE_SEND_SCRIPT,
        RESERVE_SEND_SCRIPT_SHA,
        keys,
        [
          now(),
          randomBytes(12).toString('base64url'),
          flags,
          policy.endUserIp.limit,
          policy.endUserIp.windowMs,
          policy.client.limit,
          policy.client.windowMs,
          policy.addressIpShort.limit,
          policy.addressIpShort.windowMs,
          policy.addressIpLong.limit,
          policy.addressIpLong.windowMs,
          policy.addressClient.limit,
          policy.addressClient.windowMs,
          policy.ceiling.limit,
          policy.ceiling.windowMs,
          policy.afterFirstFactor.limit,
          policy.afterFirstFactor.windowMs,
          address,
          policy.noticeIntervalMs,
        ],
        'a send reservation'
      );
      return decisionOf(reply);
    },

    async mintPass(input: {
      readonly realmId: string;
      readonly addressHmac: string;
      readonly flow: MailPassFlow;
    }): Promise<string> {
      if (input.flow !== 'reset' && input.flow !== 'register') {
        throw new Error('send caps: a pass starts a reset or a registration');
      }
      const address = part(input.addressHmac, 'an address HMAC');
      const pass = randomBytes(32).toString('base64url');
      const expiresAt = now() + policy.passTtlMs;
      const stored = await bounded(
        redis.set(
          sendCapKey(input.realmId, 'pass', mailPassHash(pass)),
          `${address}:${input.flow}:${expiresAt}`,
          'PX',
          policy.passTtlMs,
          'NX'
        ),
        timeoutMs,
        'a pass'
      );
      if (stored !== 'OK') throw new Error('send caps: the pass was not stored');
      return pass;
    },

    async peekPass(realmId: string, pass: string): Promise<MailPassBinding | undefined> {
      if (!PASS_PATTERN.test(pass)) return undefined;
      const passHash = mailPassHash(pass);
      const bound = await bounded(
        redis.get(sendCapKey(realmId, 'pass', passHash)),
        timeoutMs,
        'a pass read'
      );
      if (bound === null) return undefined;
      const [addressHmac, flow, expiresAt] = bound.split(':');
      if (
        addressHmac === undefined ||
        !KEY_PART.test(addressHmac) ||
        (flow !== 'reset' && flow !== 'register') ||
        !(Number(expiresAt) > now())
      ) {
        return undefined;
      }
      return { passHash, addressHmac, flow };
    },

    async claimNotice(input: NoticeMark): Promise<boolean> {
      const reply = await run(
        CLAIM_MARK_SCRIPT,
        CLAIM_MARK_SCRIPT_SHA,
        [noticeKey(input)],
        [now(), policy.noticeIntervalMs],
        'a notice claim'
      );
      return Number(reply) === 1;
    },

    async releaseNotice(input: NoticeMark): Promise<void> {
      await run(
        RELEASE_MARK_SCRIPT,
        RELEASE_MARK_SCRIPT_SHA,
        [noticeKey(input)],
        [],
        'a notice release'
      );
    },
  });
}
