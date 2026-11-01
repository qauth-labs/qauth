import type { LadderHook, LadderReservation, LadderVerdict } from '../lib/hooks';
import {
  checkLadderPolicy,
  type LadderPolicy,
  ladderWaitMs,
  PASSWORD_LADDER_POLICY,
} from '../lib/ladder';
import type { FactorType } from '../lib/ports';

/**
 * TEST SUPPORT — the failure ladder in memory, on a clock the test moves: the
 * rules of {@link LadderPolicy} as the auth server's Redis script applies them
 * (`@qauth-labs/fastify-plugin-sign-in-engine`'s `failure-ladder.ts`). One
 * counter per (realm, identifier HMAC, factor), one known-IP list per (realm,
 * identifier HMAC). Not for production: nothing is shared between processes.
 */

/** One counter's state. */
export interface MemoryLadderRun {
  /** Consecutive counted failures of the run. */
  readonly failures: number;
  /** Until when an attempt waits, in epoch ms. */
  readonly waitUntil: number;
  /** The run's id: a success ends the run, and a later failure starts another. */
  readonly run: number;
}

export interface MemoryLadder extends LadderHook {
  /** The counter of `factor` for the identifier, or `undefined` when no run is counted. */
  counter(realmId: string, identifierHmac: string, factor: FactorType): MemoryLadderRun | undefined;
  /** The end-user IPs known to the identifier's account, with when each last signed in. */
  knownIps(realmId: string, identifierHmac: string): ReadonlyMap<string, number>;
  /** Every reservation, in order: what a test counts instead of verifications. */
  readonly reservations: { readonly factor: FactorType; readonly outcome: 'reserved' | 'wait' }[];
}

/** A ladder in memory over `now`, with `policy` for every factor (the password's by default). */
export function createMemoryLadder(
  now: () => number,
  policy: LadderPolicy = PASSWORD_LADDER_POLICY
): MemoryLadder {
  checkLadderPolicy(policy);
  const counters = new Map<string, MemoryLadderRun & { readonly lastAt: number }>();
  const known = new Map<string, Map<string, number>>();
  const reservations: MemoryLadder['reservations'] = [];
  let runs = 0;
  const counterKey = (realmId: string, hmac: string, factor: FactorType) =>
    `${realmId}\u0000${hmac}\u0000${factor}`;
  const knownKey = (realmId: string, hmac: string) => `${realmId}\u0000${hmac}`;
  const live = (key: string) => {
    const state = counters.get(key);
    if (state !== undefined && now() - state.lastAt >= policy.retentionMs) {
      counters.delete(key);
      return undefined;
    }
    return state;
  };

  return {
    reservations,
    counter: (realmId, hmac, factor) => {
      const state = live(counterKey(realmId, hmac, factor));
      return state === undefined
        ? undefined
        : { failures: state.failures, waitUntil: state.waitUntil, run: state.run };
    },
    knownIps: (realmId, hmac) => new Map(known.get(knownKey(realmId, hmac)) ?? []),
    async reserve({ realmId, identifierHmac, factor, endUserIp }): Promise<LadderVerdict> {
      const key = counterKey(realmId, identifierHmac, factor);
      const at = now();
      const seen =
        endUserIp === undefined
          ? undefined
          : known.get(knownKey(realmId, identifierHmac))?.get(endUserIp);
      const exempt = policy.knownIpMs > 0 && seen !== undefined && at - seen < policy.knownIpMs;
      const state = live(key);
      if (!exempt && state !== undefined && state.waitUntil > at) {
        reservations.push({ factor, outcome: 'wait' });
        return { kind: 'wait', retryAfterSeconds: Math.ceil((state.waitUntil - at) / 1000) };
      }
      const failures = (state?.failures ?? 0) + 1;
      const run = state?.run ?? (runs += 1);
      // An exempt attempt never shortens a wait already set.
      const waitUntil = Math.max(at + ladderWaitMs(failures, policy), state?.waitUntil ?? 0);
      counters.set(key, { failures, waitUntil, run, lastAt: at });
      reservations.push({ factor, outcome: 'reserved' });
      let settled = false;
      const reservation: LadderReservation = {
        kind: 'reserved',
        async settle(outcome) {
          if (settled) throw new Error('memory ladder: settled twice');
          settled = true;
          if (outcome === 'success') {
            counters.delete(key);
            if (endUserIp !== undefined && policy.knownIpMs > 0) {
              const ips = known.get(knownKey(realmId, identifierHmac)) ?? new Map<string, number>();
              ips.set(endUserIp, now());
              known.set(knownKey(realmId, identifierHmac), ips);
            }
            return { ceilingReached: false };
          }
          const current = live(key);
          return {
            ceilingReached:
              policy.hardCeiling !== null &&
              failures >= policy.hardCeiling &&
              current !== undefined &&
              current.run === run,
          };
        },
      };
      return reservation;
    },
  };
}
