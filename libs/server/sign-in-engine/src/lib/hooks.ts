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

/** One reserved attempt of the ladder, settled once the credential is checked. */
export interface LadderReservation {
  readonly kind: 'reserved';
  /** `success` clears the counter of the factor it proved; `failure` keeps the attempt counted. */
  settle(outcome: 'success' | 'failure'): Promise<void>;
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
  }): Promise<LadderVerdict>;
}

export interface SignInHooks {
  readonly limits?: (round: HookRound) => Promise<LimitVerdict>;
  readonly request?: (round: HookRound) => Promise<RequestVerdict>;
  readonly botChallenge?: (round: HookRound) => Promise<BotChallengeVerdict>;
  readonly ladder?: LadderHook;
}

/** The ladder while #615 is not built: every attempt is reserved, and settling does nothing. */
export const NO_LADDER: LadderHook = Object.freeze({
  reserve: async () =>
    Object.freeze({
      kind: 'reserved' as const,
      settle: async () => undefined,
    }) as LadderReservation,
});
