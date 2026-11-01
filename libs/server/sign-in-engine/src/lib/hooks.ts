import type { StepName } from '@qauth-labs/server-step-grammar';

import type { FactorType } from './ports';
import type { SignInTransaction } from './transaction';

/**
 * THE HOOKS: the rules of ADR-017 Decision 4 that later issues fill. With no
 * hook registered, each lets the round through. A hook that throws refuses
 * the round as a store outage does (fail closed, ADR-017 Decision 7).
 *
 * | Hook           | Rule | Filled by                                   |
 * | -------------- | ---- | ------------------------------------------- |
 * | `limits`       | 3    | PRO-13 (#636): per client, per end-user IP  |
 * | `request`      | 4    | each transport's request checks (#628, #665)|
 * | `botChallenge` | 5    | PRO-19 (#643)                               |
 * | `ladder`       | 3, 7 | PRO-12 (#615): reserve before verify        |
 */

/** What a hook sees of a round: never an answer's fields, so never a password or a code. */
export interface HookRound {
  readonly realmId: string;
  readonly clientId: string;
  readonly transaction: SignInTransaction;
  /** The step the round's answer names, when the grammar knows it. */
  readonly answered?: StepName;
}

/** The answer of the limiters. */
export type LimitVerdict =
  | { readonly kind: 'continue' }
  | { readonly kind: 'throttled'; readonly retryAfterSeconds: number };

/** The answer of the transport's request checks. */
export type RequestVerdict =
  | { readonly kind: 'continue' }
  /** Refuse the round with the transport's own code, such as `unmet_authentication_requirements`. */
  | { readonly kind: 'refuse'; readonly code: string }
  /** Continue in a browser (`prompt=consent`, a dangerous scope at the FiPA endpoint). */
  | { readonly kind: 'redirect' };

/** The answer of the bot challenge. */
export type BotChallengeVerdict =
  | { readonly kind: 'not_due' }
  /**
   * A challenge is due. The engine offers the `captcha` step when a handler
   * for it is registered and the transport serves it; otherwise the round is
   * throttled for `retryAfterSeconds`, never redirected (ADR-017 Decision 7).
   */
  | { readonly kind: 'due'; readonly retryAfterSeconds: number };

/** What settling a reserved attempt found. */
export interface LadderSettlement {
  /**
   * Whether this failure counted at or past the ladder's hard ceiling, in a
   * run no success has ended since: the caller's hard action is due (it is
   * idempotent, so a later failure of the same run may say so again). Always
   * `false` for a success, and for a ladder with no hard ceiling.
   */
  readonly ceilingReached: boolean;
}

/** A settlement that fires nothing. */
export const NOTHING_DUE: LadderSettlement = Object.freeze({ ceilingReached: false });

/** One reserved attempt of the ladder, settled once the credential is checked. */
export interface LadderReservation {
  readonly kind: 'reserved';
  /**
   * `success` clears the counter of the factor it proved, and no other, and
   * makes the attempt's end-user IP known to the account; `failure` keeps the
   * attempt counted, and says whether the hard action is due. Settled once.
   */
  settle(outcome: 'success' | 'failure'): Promise<LadderSettlement>;
}

/** The ladder's answer to a reservation. */
export type LadderVerdict =
  | LadderReservation
  /** Inside a wait: the attempt is refused, neither verified nor counted. */
  | { readonly kind: 'wait'; readonly retryAfterSeconds: number };

/** The per-account failure ladder (PRO-12, #615). */
export interface LadderHook {
  /**
   * Reserve an attempt before its credential is verified: one atomic store
   * operation reads the wait, refuses an attempt inside it, and otherwise
   * counts the attempt as a failure until it settles. Keyed on the
   * identifier's HMAC, whether or not an account holds it.
   */
  reserve(input: {
    readonly realmId: string;
    readonly identifierHmac: string;
    readonly factor: FactorType;
    /**
     * The end-user IP, as the limiters key it (an IPv6 address by its /64):
     * one with a successful sign-in to the account in the ladder's known-IP
     * window skips the wait and still counts. Absent: no exemption.
     */
    readonly endUserIp?: string;
  }): Promise<LadderVerdict>;
}

export interface SignInHooks {
  readonly limits?: (round: HookRound) => Promise<LimitVerdict>;
  readonly request?: (round: HookRound) => Promise<RequestVerdict>;
  readonly botChallenge?: (round: HookRound) => Promise<BotChallengeVerdict>;
  readonly ladder?: LadderHook;
}

/**
 * The engine's default ladder, which counts nothing: every attempt is
 * reserved and settling does nothing. For tests only: the plugin of
 * `@qauth-labs/fastify-plugin-sign-in-engine` refuses a production engine
 * without a real one (#615).
 */
export const NO_LADDER: LadderHook = Object.freeze({
  reserve: async () =>
    Object.freeze({
      kind: 'reserved' as const,
      settle: async () => NOTHING_DUE,
    }) as LadderReservation,
});
