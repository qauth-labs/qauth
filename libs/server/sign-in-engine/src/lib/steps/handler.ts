import type {
  StepAnswer,
  StepErrorCode,
  StepName,
  StepParams,
} from '@qauth-labs/server-step-grammar';

import type { FactorType, SignInAccount, SignInAuditReason, SignInCandidate } from '../ports';
import type { SignInTransaction } from '../transaction';

/**
 * THE STEP-HANDLER INTERFACE: how a step joins the engine. The identifier
 * and password steps are the engine's own handlers; passkeys (#651), TOTP
 * (#653), the email code (#638) and the bot challenge (#643) are added the
 * same way, through `createSignInEngine({ steps })`.
 *
 * A handler says where its step sits in ADR-017 Decision 4's order (its
 * role), what it is offered with, and how an answer to it is verified. The
 * engine decides when it is offered and whether an answer reaches it: a
 * handler is asked to verify only an answer to a step the engine expects
 * next, already read by the step grammar's `readAnswer` against the params it
 * was offered with.
 */

/**
 * Where a step sits in the rule order of ADR-017 Decision 4:
 *
 * - `challenge`: rule 5, the bot challenge; offered alone, and the pending
 *   step resumes after it;
 * - `identifier`: rule 6;
 * - `first_factor`: rule 7, offered to every account alike until a factor
 *   succeeds; after one, offered again only to meet the downgrade rule;
 * - `second_factor`: rule 8, offered only after a first factor, to meet the
 *   MFA policy.
 */
export const STEP_ROLES = ['challenge', 'identifier', 'first_factor', 'second_factor'] as const;
export type StepRole = (typeof STEP_ROLES)[number];

/** What a handler sees of the round. It never sees the transport, the request or another step's answer. */
export interface StepRound {
  readonly realmId: string;
  readonly clientId: string;
  /** The transaction as it stands before this step's answer. */
  readonly transaction: SignInTransaction;
  /** The transaction's identifier, once it holds one. */
  readonly identifier?: string;
  /** The round's end-user IP, for the ladder's known-IP exemption (`RoundContext.endUserIp`). */
  readonly endUserIp?: string;
  /**
   * The identifier's keyed HMAC, computed at most once a round. Throws
   * `SignInStoreUnavailableError` when the key cannot be read.
   */
  identifierHmac(): Promise<string>;
}

/**
 * Why a verdict refused. The engine names the person in the audit record
 * itself: by the identifier's HMAC until the transaction's subject is fixed,
 * never by a user a refused answer happened to resolve.
 */
export interface VerdictAudit {
  readonly reason: SignInAuditReason;
}

/** The account a factor proved, as far as the engine checks it before fixing the subject. */
export type ProvedAccount = Pick<SignInCandidate, 'userId' | 'enabled' | 'verified'>;

/** What a handler made of an answer. */
export type StepVerdict =
  /** The identifier step: who the transaction is for, checked and normalised. */
  | { readonly kind: 'identified'; readonly identifier: string }
  /**
   * A factor proved the account: its user becomes, or must be, the
   * transaction's subject. A handler refuses a disabled account, and an
   * unverified one under `REQUIRE_VERIFIED_ACCOUNT`, itself (settling its
   * ladder as a failure); the engine refuses any it still proves, with the
   * step's `invalid_credentials`, and never fixes the subject.
   */
  | { readonly kind: 'proved'; readonly account: ProvedAccount }
  /** The bot challenge was solved. */
  | { readonly kind: 'passed' }
  /** The answer was refused: the step is offered again with `error`, from the step's closed set. */
  | { readonly kind: 'refused'; readonly error: StepErrorCode; readonly audit: VerdictAudit }
  /** The answer was neither verified nor counted: a wait of the ladder applies. */
  | {
      readonly kind: 'throttled';
      readonly retryAfterSeconds: number;
      readonly audit: VerdictAudit;
    };

/** A step the engine can offer and verify. */
export interface StepHandler<N extends StepName = StepName> {
  readonly step: N;
  readonly role: StepRole;
  /** For a factor: the authenticator type it proves, which ranks it for the downgrade rule. */
  readonly factor?: FactorType;
  /**
   * For a first factor: whether it names the account by itself (a
   * discoverable passkey, #651), so it can be offered before any identifier.
   * Before the identifier it is preferred, with the identifier step and the
   * other first factors as alternatives; once the transaction holds an
   * identifier it is offered after them (ADR-017 Decision 4).
   */
  readonly discoverable?: boolean;
  /**
   * Whether `account` can answer this step now: the authenticator is bound
   * and usable. Asked only after a first factor succeeded, never before, so
   * it cannot change what an account is offered while that must be the same
   * for every account.
   */
  usableBy?(account: SignInAccount): boolean;
  /** The params this step is offered with this round. They must not depend on any account. */
  params(round: StepRound): StepParams<N> | Promise<StepParams<N>>;
  /** The personal data of the step's screen: who is signing in, at most. */
  personal?(round: StepRound): Readonly<Record<string, unknown>>;
  /** Verify an answer to this step, offered with `params`. */
  verify(
    round: StepRound,
    read: { readonly params: StepParams<N>; readonly answer: StepAnswer<N> }
  ): Promise<StepVerdict>;
}

/** Any handler, whatever its step. */
export type AnyStepHandler = { [N in StepName]: StepHandler<N> }[StepName];
