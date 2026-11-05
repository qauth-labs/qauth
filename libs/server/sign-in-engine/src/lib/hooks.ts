import type { StepName } from '@qauth-labs/server-step-grammar';

import type { LadderCounter } from './ports';
import type { RegistrationStartRound, RoundEnvironment } from './round-limits';
import type { SignInTransaction } from './transaction';

/**
 * THE HOOKS: the rules of ADR-017 Decision 4 that later issues fill. With no
 * hook registered, each lets the round through. A hook that throws refuses
 * the round as a store outage does (fail closed, ADR-017 Decision 7).
 *
 * | Hook           | Rule | Filled by                                   |
 * | -------------- | ---- | ------------------------------------------- |
 * | `limits`       | 3, 7 | PRO-13 (#636): per client, per end-user IP  |
 * | `request`      | 4    | each transport's request checks (#628, #665)|
 * | `botChallenge` | 5    | a deployment's own reason for a challenge   |
 * | `ladder`       | 3, 7 | PRO-12 (#615): reserve before verify        |
 *
 * The bot challenge itself (PRO-19, #643) is the engine's rule 5: the
 * `limits` hook and the `ladder` hook say when a soft threshold holds, the
 * registration port when a sign-up requires one, and the `captcha` step
 * handler (`createCaptchaStep`) offers and checks it. `botChallenge` only
 * adds a reason of the deployment's own.
 */

/** What a hook sees of a round: never an answer's fields, so never a password or a code. */
export interface HookRound {
  readonly realmId: string;
  readonly clientId: string;
  readonly transaction: SignInTransaction;
  /** The step the round's answer names, when the grammar knows it. */
  readonly answered?: StepName;
  /**
   * The round's end-user IP, as the limiters key it (`RoundContext.endUserIp`);
   * absent when the round carries no address.
   */
  readonly endUserIp?: string;
  /**
   * The client's effective environment (ADR-008 §7), `production` unless the
   * transport said otherwise: `development` relaxes the limiters (ADR-008 §5).
   */
  readonly environment: RoundEnvironment;
}

/** The answer of the limiters. */
export type LimitVerdict =
  | {
      readonly kind: 'continue';
      /**
       * A soft threshold of a row holds for this round (PRO-13, ADR-017
       * Decision 7: the end-user IP's failures, its bucket's identifiers, the
       * client's ratio or budget): a bot challenge is due (#643), on top of
       * the delay the row's reservations keep.
       */
      readonly softThreshold?: boolean;
    }
  | { readonly kind: 'throttled'; readonly retryAfterSeconds: number };

/** A credential round the limiters reserve before its credential is verified (#636). */
export interface CredentialRound {
  readonly realmId: string;
  readonly clientId: string;
  /** The end-user IP, as the limiters key it; absent: no per-IP row applies. */
  readonly endUserIp?: string;
  readonly environment: RoundEnvironment;
  /**
   * The keyed HMAC of the identifier the round is for, for the IP bucket's
   * count of distinct identifiers; absent before any identifier (a
   * discoverable passkey).
   */
  readonly identifierHmac?: string;
}

/** A reserved credential round, settled once its credential is checked. */
export interface CredentialRoundReservation {
  readonly kind: 'reserved';
  /**
   * `success`: the credential was right, and `userId` the account it proved,
   * whose success counts once per window toward the client's failure ratio;
   * `failure`: it was wrong, and stays counted; `withdrawn`: it was never
   * verified (the account's ladder refused it inside a wait), and is taken
   * back. Settled once.
   */
  settle(
    outcome: 'success' | 'failure' | 'withdrawn',
    options?: { readonly userId?: string }
  ): Promise<void>;
}

/** The limiters' answer to a credential round. */
export type CredentialLimitVerdict =
  | CredentialRoundReservation
  /** Inside a delay or past a hard limit: the round is refused, neither verified nor counted. */
  | { readonly kind: 'throttled'; readonly retryAfterSeconds: number };

/**
 * The limiters around the per-account ladder (PRO-13, #636; ADR-017
 * Decision 7): per end-user IP, per IP bucket and, at the FiPA endpoint, per
 * authenticated client. `round` answers every round at rule 3; `reserve`
 * holds a credential round (a password, an `otp`, a recovery code, a
 * WebAuthn response) before its credential is verified, as the ladder does.
 */
export interface LimitsHook {
  round(round: HookRound): Promise<LimitVerdict>;
  reserve(round: CredentialRound): Promise<CredentialLimitVerdict>;
  /**
   * Count a registration start (#640; ADR-017 Decision 7, "Registration
   * starts"): the first code a registration mails, new address or not.
   * Absent, no start is capped.
   */
  reserveRegistrationStart?(round: RegistrationStartRound): Promise<LimitVerdict>;
}

/** The answer of the transport's request checks. */
export type RequestVerdict =
  | { readonly kind: 'continue' }
  /** Refuse the round with the transport's own code, such as `unmet_authentication_requirements`. */
  | { readonly kind: 'refuse'; readonly code: string }
  /** Continue in a browser (`prompt=consent`, a dangerous scope at the FiPA endpoint). */
  | { readonly kind: 'redirect' };

/**
 * The answer of the `botChallenge` hook: a reason of the deployment's own to
 * ask for a challenge, beside the engine's (a soft threshold, a sign-up that
 * requires one). A due challenge is met as the engine's are (rule 5, #643):
 * the `captcha` step for a transport that serves it, once per credential
 * round; the delay and the hard 429 alone for one that does not.
 */
export type BotChallengeVerdict = { readonly kind: 'not_due' } | { readonly kind: 'due' };

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

/** How a success settles: whether it makes the attempt's end-user IP known to the account. */
export interface LadderSuccessOptions {
  /**
   * `false` clears the counter and records no IP: the right password of an
   * account whose address is not proved yet (#638), which has no owner whose
   * IPs a later attempt may count as known. `true` by default.
   */
  readonly rememberIp?: boolean;
}

/** One reserved attempt of the ladder, settled once the credential is checked. */
export interface LadderReservation {
  readonly kind: 'reserved';
  /**
   * `success` clears the counter of the factor it proved (or of the email
   * codes, for a right code), and no other, and makes the attempt's end-user
   * IP known to the account unless `options.rememberIp` is `false`;
   * `failure` keeps the attempt counted, and says whether the hard action is
   * due. Settled once.
   */
  settle(outcome: 'success' | 'failure', options?: LadderSuccessOptions): Promise<LadderSettlement>;
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
    /**
     * The counter: a factor's, or `email_code`, the wrong email codes'
     * (#638), a separate counter under the same key that is never a factor.
     */
    readonly factor: LadderCounter;
    /**
     * The end-user IP, as the limiters key it (an IPv6 address by its /64):
     * one with a successful sign-in to the account in the ladder's known-IP
     * window skips the wait and still counts. Absent: no exemption.
     */
    readonly endUserIp?: string;
  }): Promise<LadderVerdict>;
  /**
   * Whether any of `counters` of the identifier has reached its soft
   * threshold: a run of at least the ladder's `freeFailures` consecutive
   * counted failures, the point from which every attempt waits (ADR-017
   * Decision 7: "bot challenge from F1b"). A bot challenge is then due (#643).
   * It reads and writes nothing else. Absent: the ladder never asks for one.
   */
  softThreshold?(input: {
    readonly realmId: string;
    readonly identifierHmac: string;
    readonly counters: readonly LadderCounter[];
  }): Promise<boolean>;
}

export interface SignInHooks {
  readonly limits?: LimitsHook;
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
