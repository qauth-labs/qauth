import {
  type CredentialRoundOutcome,
  ROUND_LIMIT_POLICY,
  type RoundLimitAlert,
  type RoundLimitDecision,
  type RoundLimitKeys,
  type RoundLimitName,
  roundLimitPolicies,
  type RoundLimitPolicy,
  roundLimitPolicyFor,
  type RoundLimitStore,
} from '../lib/round-limits';

/**
 * TEST SUPPORT — the round limits in memory, on a clock the test moves: the
 * rules of {@link RoundLimitPolicy} as the auth server's Redis script applies
 * them (`@qauth-labs/fastify-plugin-sign-in-engine`'s `round-limits.ts`). Not
 * for production: nothing is shared between processes.
 *
 * A log keeps an entry while its time is after `now − window`, as the Redis
 * script's `ZREMRANGEBYSCORE … -inf (now − window)` keeps it.
 */
export interface MemoryRoundLimits extends RoundLimitStore {
  /** Every decision of a reservation or a round, in order. */
  readonly decisions: RoundLimitDecision[];
}

/** Round limits in memory over `now`, with `policy` ({@link ROUND_LIMIT_POLICY} by default). */
export function createMemoryRoundLimits(
  now: () => number,
  policy: RoundLimitPolicy = ROUND_LIMIT_POLICY
): MemoryRoundLimits {
  const policies = roundLimitPolicies(policy);
  /** Each log's entries, by member, with their times. */
  const logs = new Map<string, Map<string, number>>();
  /** Until when each mark (a block, a delay, an alert) holds, in epoch ms. */
  const marks = new Map<string, number>();
  const decisions: RoundLimitDecision[] = [];

  const log = (key: string, windowMs: number, at: number): Map<string, number> => {
    const kept = new Map(
      [...(logs.get(key) ?? new Map<string, number>())].filter(([, time]) => time > at - windowMs)
    );
    logs.set(key, kept);
    return kept;
  };
  /** When the slot of a full log frees: its entry `limit` from the newest leaves the window. */
  const retry = (entries: Map<string, number>, limit: number, windowMs: number, at: number) => {
    const times = [...entries.values()].sort((a, b) => a - b);
    const leaving = times[times.length - limit] ?? at;
    return Math.max(1, leaving + windowMs - at);
  };
  const markUntil = (key: string) => marks.get(key) ?? 0;
  /** Push a mark to at least `until`. */
  const extend = (key: string, until: number) => {
    marks.set(key, Math.max(markUntil(key), until));
  };
  /** Claim an alert mark for `ttl`: `true` when none held. */
  const claim = (key: string, ttl: number, at: number) => {
    if (markUntil(key) > at) return false;
    marks.set(key, at + ttl);
    return true;
  };
  const refused = (
    limit: RoundLimitName,
    retryAfterMs: number,
    alerts: RoundLimitAlert[] = []
  ): RoundLimitDecision => {
    const decision: RoundLimitDecision = {
      kind: 'refused',
      limit,
      retryAfterMs: Math.max(1, retryAfterMs),
      alerts,
    };
    decisions.push(decision);
    return decision;
  };
  const admitted = (softThreshold = false): RoundLimitDecision => {
    const decision: RoundLimitDecision = softThreshold
      ? { kind: 'admitted', alerts: [], softThreshold: true }
      : { kind: 'admitted', alerts: [] };
    decisions.push(decision);
    return decision;
  };

  const k = (keys: RoundLimitKeys, ...parts: string[]) => [keys.realmId, ...parts].join(':');
  /** The distinct identifiers among a bucket log's members (`<identifier>:<reservation>`). */
  const distinct = (entries: Map<string, number>) =>
    new Set([...entries.keys()].map((member) => member.slice(0, member.lastIndexOf(':')))).size;

  const store: MemoryRoundLimits = {
    decisions,

    async admitRound(keys) {
      const at = now();
      const p = roundLimitPolicyFor(keys.environment, policies);
      if (keys.endUserIpHmac !== undefined) {
        const block = markUntil(k(keys, 'ip', keys.endUserIpHmac, 'block'));
        if (block > at) return refused('end_user_ip', block - at);
      }
      if (keys.clientKey !== undefined) {
        const key = k(keys, 'client', keys.clientKey, 'rounds');
        const rounds = log(key, p.client.maxRoundsWindowMs, at);
        if (rounds.size >= p.client.maxRounds) {
          const alert = claim(
            k(keys, 'client', keys.clientKey, 'alert', 'rounds'),
            p.client.maxRoundsWindowMs,
            at
          );
          return refused(
            'client_rounds',
            retry(rounds, p.client.maxRounds, p.client.maxRoundsWindowMs, at),
            alert ? ['client_rounds'] : []
          );
        }
        rounds.set(`${at}:${rounds.size}:${Math.random()}`, at);
      }
      // A soft threshold of any row asks for the bot challenge (#643): the
      // same thresholds that start a credential round's delay.
      let soft = false;
      if (keys.endUserIpHmac !== undefined) {
        const failures = log(
          k(keys, 'ip', keys.endUserIpHmac, 'failures'),
          p.endUserIp.windowMs,
          at
        );
        soft ||= failures.size >= p.endUserIp.softFailures;
        if (keys.ipBucketHmac !== undefined) {
          const entries = log(
            k(keys, 'bucket', keys.ipBucketHmac, 'failures'),
            p.ipBucket.windowMs,
            at
          );
          soft ||= distinct(entries) > p.ipBucket.maxIdentifiers;
        }
      }
      if (keys.clientKey !== undefined) {
        const client = keys.clientKey;
        const credential = log(k(keys, 'client', client, 'credential'), p.client.windowMs, at);
        const failures = log(k(keys, 'client', client, 'failures'), p.client.windowMs, at);
        soft ||=
          failures.size > p.client.failureBudget ||
          (credential.size >= p.client.ratioMinRounds &&
            failures.size * 100 > p.client.ratioPercent * credential.size);
      }
      return admitted(soft);
    },

    async reserveCredential(round) {
      const at = now();
      const p = roundLimitPolicyFor(round.environment, policies);
      let ipSoft = false;
      let bucketSoft = false;
      let clientSoft = false;
      if (round.endUserIpHmac !== undefined) {
        const ip = round.endUserIpHmac;
        const block = markUntil(k(round, 'ip', ip, 'block'));
        if (block > at) return refused('end_user_ip', block - at);
        const failures = log(k(round, 'ip', ip, 'failures'), p.endUserIp.windowMs, at);
        if (failures.size >= p.endUserIp.hardFailures) {
          return refused(
            'end_user_ip',
            retry(failures, p.endUserIp.hardFailures, p.endUserIp.windowMs, at)
          );
        }
        ipSoft = failures.size >= p.endUserIp.softFailures;
        if (round.ipBucketHmac !== undefined) {
          const entries = log(
            k(round, 'bucket', round.ipBucketHmac, 'failures'),
            p.ipBucket.windowMs,
            at
          );
          bucketSoft = distinct(entries) > p.ipBucket.maxIdentifiers;
        }
        // The row's delay is the IP's, whichever threshold holds: a bucket
        // past its identifiers paces each of its IPs, never the bucket as one.
        const pace = markUntil(k(round, 'ip', ip, 'pace'));
        if (ipSoft && pace > at) return refused('end_user_ip_delay', pace - at);
        if (bucketSoft && pace > at) return refused('ip_bucket_delay', pace - at);
      }
      if (round.clientKey !== undefined) {
        const client = round.clientKey;
        const credential = log(k(round, 'client', client, 'credential'), p.client.windowMs, at);
        const failures = log(k(round, 'client', client, 'failures'), p.client.windowMs, at);
        clientSoft =
          failures.size > p.client.failureBudget ||
          (credential.size >= p.client.ratioMinRounds &&
            failures.size * 100 > p.client.ratioPercent * credential.size);
        const pace = markUntil(k(round, 'client', client, 'pace'));
        if (clientSoft && pace > at) return refused('client_delay', pace - at);
      }
      // Admitted: counted as a failed round of every row until it settles.
      if (round.endUserIpHmac !== undefined) {
        const ip = round.endUserIpHmac;
        logs.get(k(round, 'ip', ip, 'failures'))?.set(round.reservation, at);
        if (ipSoft) extend(k(round, 'ip', ip, 'pace'), at + p.endUserIp.delayMs);
        if (bucketSoft) extend(k(round, 'ip', ip, 'pace'), at + p.ipBucket.delayMs);
        if (round.ipBucketHmac !== undefined && round.identifierHmac !== undefined) {
          logs
            .get(k(round, 'bucket', round.ipBucketHmac, 'failures'))
            ?.set(`${round.identifierHmac}:${round.reservation}`, at);
        }
      }
      if (round.clientKey !== undefined) {
        const client = round.clientKey;
        logs.get(k(round, 'client', client, 'credential'))?.set(round.reservation, at);
        logs.get(k(round, 'client', client, 'failures'))?.set(round.reservation, at);
        if (clientSoft) extend(k(round, 'client', client, 'pace'), at + p.client.delayMs);
      }
      return admitted();
    },

    async settleCredential(round) {
      const at = now();
      const p = roundLimitPolicyFor(round.environment, policies);
      const outcome: CredentialRoundOutcome = round.outcome;
      const alerts: RoundLimitAlert[] = [];
      const bucketMember =
        round.identifierHmac === undefined
          ? undefined
          : `${round.identifierHmac}:${round.reservation}`;
      if (outcome === 'failure') {
        if (round.endUserIpHmac !== undefined) {
          const ip = round.endUserIpHmac;
          const failures = log(k(round, 'ip', ip, 'failures'), p.endUserIp.windowMs, at);
          if (failures.size >= p.endUserIp.hardFailures) {
            const blockKey = k(round, 'ip', ip, 'block');
            if (markUntil(blockKey) <= at) {
              marks.set(blockKey, at + p.endUserIp.blockMs);
              alerts.push('end_user_ip_blocked');
            }
          }
          if (failures.size >= p.endUserIp.softFailures) {
            extend(k(round, 'ip', ip, 'pace'), at + p.endUserIp.delayMs);
          }
          if (round.ipBucketHmac !== undefined) {
            const bucket = round.ipBucketHmac;
            const entries = log(k(round, 'bucket', bucket, 'failures'), p.ipBucket.windowMs, at);
            if (distinct(entries) > p.ipBucket.maxIdentifiers) {
              extend(k(round, 'ip', ip, 'pace'), at + p.ipBucket.delayMs);
              if (claim(k(round, 'bucket', bucket, 'alert'), p.ipBucket.windowMs, at)) {
                alerts.push('ip_bucket_identifiers');
              }
            }
          }
        }
        if (round.clientKey !== undefined) {
          const client = round.clientKey;
          const credential = log(k(round, 'client', client, 'credential'), p.client.windowMs, at);
          const failures = log(k(round, 'client', client, 'failures'), p.client.windowMs, at);
          const ratio =
            credential.size >= p.client.ratioMinRounds &&
            failures.size * 100 > p.client.ratioPercent * credential.size;
          const budget = failures.size > p.client.failureBudget;
          if (ratio || budget) extend(k(round, 'client', client, 'pace'), at + p.client.delayMs);
          if (ratio && claim(k(round, 'client', client, 'alert', 'ratio'), p.client.windowMs, at)) {
            alerts.push('client_failure_ratio');
          }
          if (
            budget &&
            claim(k(round, 'client', client, 'alert', 'budget'), p.client.windowMs, at)
          ) {
            alerts.push('client_failure_budget');
          }
        }
        return alerts;
      }
      // A success or a withdrawal takes the failure back from every row.
      if (round.endUserIpHmac !== undefined) {
        logs.get(k(round, 'ip', round.endUserIpHmac, 'failures'))?.delete(round.reservation);
        if (round.ipBucketHmac !== undefined && bucketMember !== undefined) {
          logs.get(k(round, 'bucket', round.ipBucketHmac, 'failures'))?.delete(bucketMember);
        }
      }
      if (round.clientKey !== undefined) {
        const client = round.clientKey;
        logs.get(k(round, 'client', client, 'failures'))?.delete(round.reservation);
        const credential = logs.get(k(round, 'client', client, 'credential'));
        if (outcome === 'withdrawn') {
          credential?.delete(round.reservation);
        } else if (round.accountKey !== undefined && credential !== undefined) {
          // A success counts once per account in the window: its latest.
          credential.delete(round.reservation);
          credential.set(`a:${round.accountKey}`, at);
        }
      }
      return alerts;
    },

    async reserveRegistrationStart(keys) {
      const at = now();
      const p = roundLimitPolicyFor(keys.environment, policies).registrationStarts;
      const ipLog =
        keys.endUserIpHmac === undefined
          ? undefined
          : log(k(keys, 'registration', 'ip', keys.endUserIpHmac), p.endUserIp.windowMs, at);
      if (ipLog !== undefined && ipLog.size >= p.endUserIp.limit) {
        return refused(
          'registration_end_user_ip',
          retry(ipLog, p.endUserIp.limit, p.endUserIp.windowMs, at)
        );
      }
      const clientLog =
        keys.clientKey === undefined
          ? undefined
          : log(k(keys, 'registration', 'client', keys.clientKey), p.client.windowMs, at);
      if (clientLog !== undefined && clientLog.size >= p.client.limit) {
        return refused(
          'registration_client',
          retry(clientLog, p.client.limit, p.client.windowMs, at)
        );
      }
      const member = `${at}:${Math.random()}`;
      ipLog?.set(member, at);
      clientLog?.set(member, at);
      return admitted();
    },
  };
  return store;
}
