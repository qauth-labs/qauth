import type {
  AmrValue,
  AnswerEncoding,
  StepName,
  StepOffer,
} from '@qauth-labs/server-step-grammar';

import type { EmailCodePurpose } from './email-code';
import type { AuditSink, UpstreamProviderEntry } from './ports';
import type { RoundEnvironment } from './round-limits';
import type { ProvedAccount } from './steps/handler';
import type { SignInTransaction } from './transaction';

/** The answer a round carries, as the transport received it. */
export interface RoundAnswer {
  /** The step it answers: the step URN on the wire (`urn:qauth:ia:password:v1-rc.0`). */
  readonly step: string;
  /** The body or the form, whole: the engine takes only the answered step's own members. */
  readonly fields: unknown;
  /** How it arrived: a form post (the default) or a JSON body. */
  readonly encoding?: AnswerEncoding;
}

/** What the capped sender decided about a code (#637): send it, or refuse with a 429. */
export type EmailCodeSendOutcome =
  /** The code goes out, or is quietly dropped at a quiet tier: the engine cannot tell, and does not try. */
  | { readonly kind: 'accepted' }
  /** A tier that answers 429 is full, whatever the address: nothing is mailed. */
  | { readonly kind: 'capped'; readonly retryAfterSeconds: number };

/**
 * The transport's capped sender of email codes (PRO-14, #637), bound to the
 * round's request: it counts the code on every send cap that applies and,
 * unless a tier stops it, dispatches the mail after the answer is built. The
 * code is handed over only to be mailed; the engine keeps its HMAC alone. A
 * throw is an outage of the caps, which refuses the round: fail closed.
 */
export type EmailCodeSender = (mail: {
  readonly realmId: string;
  /** The normalised address: the transaction's identifier. */
  readonly address: string;
  readonly purpose: EmailCodePurpose;
  readonly code: string;
  /** How long the code is valid, in seconds: what the mail says. */
  readonly expiresInSeconds: number;
  /** The code follows a correct first factor in the same transaction: it skips the per-address ceiling. */
  readonly afterFirstFactor: boolean;
  /**
   * A registration's code (#640; ADR-017 Decision 8): what the address is,
   * which only the mail may tell. The step looks the same for all three.
   *
   * - `new_address`: no account holds it; the mail carries the code.
   * - `account_exists`: an account holds it; the mail carries the code and
   *   an "account exists" notice.
   * - `withheld`: a disabled user holds it. Nothing is mailed, as at a quiet
   *   send tier, and the code is counted on every cap all the same.
   *
   * Absent for every code of a sign-in.
   */
  readonly registration?: RegistrationMail;
}) => Promise<EmailCodeSendOutcome>;

/** What a registration's code mail says about its address (#640). */
export type RegistrationMail = 'new_address' | 'account_exists' | 'withheld';

/** What starting an upstream identity provider found (#639). */
export type UpstreamStartOutcome =
  /** The provider's transaction is kept: the browser goes to `redirectTo`. */
  | { readonly kind: 'started'; readonly redirectTo: string }
  /** The provider could not be started (its discovery document cannot be read): nothing is kept. */
  | { readonly kind: 'unavailable' };

/**
 * The transport's start of an upstream identity provider (#639), bound to the
 * round's request: it calls the provider's AuthMethod `start()`, keeps the
 * transaction it answers server-side, bound to the sign-in and to the
 * browser's flow cookie, and answers where the browser goes. A throw is an
 * outage of the transport's store, which refuses the round.
 */
export type UpstreamStarter = (provider: UpstreamProviderEntry) => Promise<UpstreamStartOutcome>;

/**
 * What an upstream provider's callback proved (#639), for
 * `SignInEngine.completeUpstream`: the transport found the account by the
 * provider's subject (never by an attribute), or created it.
 */
export interface UpstreamProof {
  /** The provider the sign-in went out through, as the step listed it or the request routed to it. */
  readonly provider: UpstreamProviderEntry;
  /** The account that holds the provider's identity. */
  readonly account: ProvedAccount;
  /**
   * The address the provider gave, normalised: what rule 8 verifies with an
   * emailed code when the account is not verified. Absent when it gave none.
   */
  readonly address?: string;
}

/** What a round is for: the transport's view of the request, already checked by its own rules 1 and 2. */
export interface RoundContext {
  readonly realm: { readonly id: string };
  /** The authenticated client the transaction is for. */
  readonly client: { readonly id: string };
  /**
   * The authorization request's `login_hint`, frozen at round 0. One that is
   * not a valid identifier is ignored here; a transport that must refuse it
   * does so in its own checks.
   */
  readonly loginHint?: string;
  /**
   * The steps the transport can serve this round: the Interaction API serves
   * every step; the FiPA endpoint the ones the client listed. Absent means
   * every step.
   */
  readonly serves?: readonly StepName[];
  /** When the request arrived, in epoch milliseconds: the timing floor counts from it. Absent means now. */
  readonly receivedAt?: number;
  /**
   * The end-user IP, as the limiters key it (an IPv6 address by its /64): the
   * request's address on the Interaction API, the signed `qauth_end_user_ip`
   * claim at the FiPA endpoint (ADR-017 Decision 7). The ladder's known-IP
   * exemption reads it; absent, no attempt is exempt.
   */
  readonly endUserIp?: string;
  /**
   * The client's effective environment (ADR-008 §7: the stricter of the
   * client's and its realm's ceiling). `development` relaxes the limiters
   * (ADR-008 §5); `staging`, `production` and absent keep production values.
   */
  readonly environment?: RoundEnvironment;
  /** Where the round's audit records go. */
  readonly audit: AuditSink;
  /**
   * The capped sender of email codes, bound to this round's request. An
   * engine built with `emailCodes` needs it on every round that may mail a
   * code: the inline verification of an account after its password (#638).
   */
  readonly sendCode?: EmailCodeSender;
  /**
   * The start of an upstream identity provider, bound to this round's request
   * (#639). Without it the `upstream` step is never offered.
   */
  readonly startUpstream?: UpstreamStarter;
  /**
   * The provider the authorization request routes to (`qauth_upstream`,
   * #639), which the transport checked the realm has enabled, hidden or not.
   * At round 0, while nobody is named, the engine starts it at once instead
   * of offering the first step.
   */
  readonly upstreamRoute?: UpstreamProviderEntry;
  /**
   * The flow the request asked for, frozen at round 0: `register` for
   * `prompt=create` (#640; ADR-017 Decision 8), absent for a sign-in. A
   * round of another flow than its transaction's ends the transaction.
   */
  readonly flow?: SignInFlow;
}

/** A flow other than a sign-in: registration (#640). */
export type SignInFlow = 'register';

/**
 * A completed sign-in or registration: what the transport mints a session or
 * a code from.
 */
export type CompletedSignIn = SignedIn | Registered;

/** A completed sign-in. */
export interface SignedIn {
  /** The user id. */
  readonly subject: string;
  /**
   * The identifier the person signed in with, normalised. Absent when a
   * discoverable factor named the account before any identifier (#651).
   */
  readonly identifier?: string;
  /** The RFC 8176 values, from the step grammar's `transactionAmr`. */
  readonly amr: readonly AmrValue[];
  /** When the last authenticator succeeded, in epoch milliseconds. */
  readonly authTime: number;
  readonly registered?: undefined;
}

/**
 * A completed registration (#640; ADR-017 Decisions 8 and 10): the account
 * was created after its mailbox was proved and its password passed the
 * policy. No authenticator was presented, so it carries no `amr` and no
 * `auth_time`, and the transport starts no session that could satisfy
 * `max_age` or `prompt=login`.
 */
export interface Registered {
  /** The new account's user id. */
  readonly subject: string;
  /** The address it was registered with, normalised. */
  readonly identifier: string;
  readonly registered: true;
  readonly amr?: undefined;
  readonly authTime?: undefined;
}

/** Why a round was refused. */
export type RefusalReason =
  /** The transaction ended: the transport discards it (FiPA: `invalid_session`). */
  | 'transaction_ended'
  /** A limiter, the ladder's wait or a due bot challenge the transport cannot serve: 429 with `Retry-After`. */
  | 'throttled'
  /** A store the round needs is down, or the MFA policy cannot be read: fail closed (503). */
  | 'unavailable'
  /** The answer is malformed: a fault of the request (FiPA: `invalid_request`). */
  | 'invalid_answer'
  /**
   * The transport's request checks refused the round, with their own code;
   * or the registration gate did, with `registration_not_allowed` (#640).
   */
  | 'request_refused';

/** What the engine answers a round. */
export type RoundResult =
  /** The next step, or the same step again with its error. */
  | {
      readonly kind: 'step';
      readonly transaction: SignInTransaction;
      readonly offer: StepOffer;
      /** The current step's personal data: at most the identifier the person gave. */
      readonly personal: Readonly<Record<string, unknown>>;
    }
  /**
   * Send the browser to an upstream identity provider (#639): the person
   * picked one, or the request routed to one. `offer` is the step the person
   * picked it from, which stays the current step: the way back from the
   * provider. The provider's callback completes the step
   * (`SignInEngine.completeUpstream`).
   */
  | {
      readonly kind: 'upstream';
      readonly transaction: SignInTransaction;
      readonly offer: StepOffer;
      readonly personal: Readonly<Record<string, unknown>>;
      /** The provider's type. */
      readonly provider: string;
      /** Where the browser goes: the provider's authorization request. */
      readonly redirectTo: string;
    }
  /**
   * The sign-in is complete: the transport mints the session or the code,
   * once. The transaction ends with it, so no later round can complete it
   * again.
   */
  | {
      readonly kind: 'complete';
      readonly transaction: null;
      readonly signIn: CompletedSignIn;
    }
  /**
   * Continue elsewhere (FiPA: `redirect_to_web`): a step the sign-in needs is
   * not built yet or not served by the transport (`step_not_available`), or the
   * request checks asked for a browser (`request`). The transaction ends.
   */
  | {
      readonly kind: 'redirect';
      readonly transaction: null;
      readonly reason: 'step_not_available' | 'request';
    }
  | { readonly kind: 'refused'; readonly reason: 'transaction_ended'; readonly transaction: null }
  | {
      readonly kind: 'refused';
      readonly reason: 'throttled';
      readonly retryAfterSeconds: number;
      /** The transaction as far as the round took it before the refusal: nothing it refused is in it. */
      readonly transaction: SignInTransaction;
    }
  | {
      readonly kind: 'refused';
      readonly reason: 'unavailable' | 'invalid_answer';
      readonly transaction: SignInTransaction;
    }
  | {
      readonly kind: 'refused';
      readonly reason: 'request_refused';
      readonly code: string;
      readonly transaction: SignInTransaction;
    };
