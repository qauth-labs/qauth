import type {
  AmrValue,
  AnswerEncoding,
  StepName,
  StepOffer,
} from '@qauth-labs/server-step-grammar';

import type { EmailCodePurpose } from './email-code';
import type { AuditSink, SignInAuditReason, UpstreamProviderEntry } from './ports';
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
  /**
   * A reset's code (#642; ADR-017 Decision 8): whether it may be mailed. The
   * step looks the same either way.
   *
   * - `account`: an enabled account holds the address with a password; the
   *   mail carries the code.
   * - `withheld`: any other address (no account, no password, a disabled
   *   user). Nothing is mailed, as at a quiet send tier, and the code is
   *   counted on every cap all the same.
   *
   * Absent for every code that is not a reset's.
   */
  readonly reset?: ResetMail;
}) => Promise<EmailCodeSendOutcome>;

/** What a registration's code mail says about its address (#640). */
export type RegistrationMail = 'new_address' | 'account_exists' | 'withheld';

/** Whether a reset's code may be mailed to its address (#642). */
export type ResetMail = 'account' | 'withheld';

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
   * An upstream provider the `upstream` step must not list (#1080; ADR-020
   * §3): the one whose identity a sign-in to join an upstream identity to an
   * account (#670) links, by its type. The realm's other providers are
   * listed as on any first step; with none left, the step is not offered. An
   * answer that names this provider is refused as any provider the step did
   * not list.
   */
  readonly withheldUpstream?: string;
  /**
   * The flow the request asked for, frozen at round 0: `register` for
   * `prompt=create` (#640; ADR-017 Decision 8), `reset` for a transport that
   * starts a reset on its own (the FiPA endpoint's `password_reset` start,
   * #642), absent for a sign-in. A round of another flow than its
   * transaction's ends the transaction, with two exceptions: a sign-in that
   * turned into a reset at its password step (#642) goes on as a reset on
   * the rounds of a sign-in; and with {@link RoundContext.switchFlows} the
   * transaction's own flow is the round's, `flow` only the one a new
   * transaction begins with.
   */
  readonly flow?: SignInFlow;
  /**
   * The transport lets the person switch between a sign-in and a
   * registration within one transaction's interaction (#1079; ADR-017
   * Decision 8): the Interaction API, for an authorization request, never
   * for a sign-in to join an upstream identity to an account (#670) nor for
   * the account page's (#844). A sign-in's first step then offers `register`
   * beside it, before anyone is named, while the registration gate holds,
   * the transport serves a registration's steps and the request asks for no
   * fresh sign-in; and a registration's address step offers `sign_in`, the
   * way back. Answering either starts a new transaction of the other flow,
   * at its first round, in the same round. A marker the transaction may no
   * longer take is refused as an invalid answer. Ignored on a reset's start.
   */
  readonly switchFlows?: boolean;
  /**
   * The request asks for a fresh sign-in: `max_age` or `prompt=login`. A
   * reset proves no authenticator, so it can never satisfy one (ADR-017
   * Decision 8): it is never offered, and a reset transaction is answered
   * with a redirect (#642).
   */
  readonly freshSignIn?: boolean;
  /**
   * An enrolment the person asked for (#844): the hosted account page's "Add
   * a passkey" or "Set up an authenticator app", passed on every round of the
   * transaction. Rule 8 binds the factor it names after every factor the
   * sign-in needs and the forced update, before the recovery codes: a passkey
   * for any account, not only a password-only one as the optional offer
   * after a sign-in, and an authenticator app for an account that holds
   * none. Each binding keeps its own rules: a factor proved at most five
   * minutes before, and the mailbox of a password-only account's first one
   * (ADR-017 Decision 8). One the transport cannot serve, or the account
   * cannot take (it holds an authenticator app already), is skipped, and the
   * sign-in completes without it. A registration never takes one.
   */
  readonly enrol?: EnrolmentRequest;
}

/** A factor a sign-in binds because the person asked for it (#844). */
export type EnrolmentRequest = 'passkey' | 'totp';

/** A flow other than a sign-in: registration (#640), or the owner's password reset (#642). */
export type SignInFlow = 'register' | 'reset';

/**
 * A completed sign-in, registration or reset: what the transport mints a
 * session or a code from.
 */
export type CompletedSignIn = SignedIn | Registered | Recovered;

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
  /**
   * The sign-in took a recovery code in place of a lost factor (#649, #663;
   * ADR-017 Decision 8). A code adds no `amr` value, so this is the one place
   * the transport learns it: it records it on the browser session, and the
   * account API lets such a session rebind a factor. Absent otherwise.
   */
  readonly recoveryCode?: true;
  /**
   * The account's new credentials (#1064) the sign-in bound or proved: a
   * passkey or an authenticator app inside the window that follows a
   * binding after a password-only sign-in. The transport records them on the
   * browser session, so removing one while it is new ends the session, and a
   * fresh sign-in that proved a factor only through one of them is not the
   * account's strongest factor. Absent when there are none.
   */
  readonly newCredentials?: readonly string[];
  readonly registered?: undefined;
  readonly recovered?: undefined;
}

/**
 * A completed registration (#640; ADR-017 Decisions 8 and 10): the account
 * was created after its mailbox was proved and its password passed the
 * policy, or, for an account whose primary identity is a passkey (#655),
 * after its registration ceremony and the confirmation of its recovery
 * codes. No sign-in completed, so it carries no `amr` and no `auth_time`,
 * and the transport starts no session that could satisfy `max_age` or
 * `prompt=login`.
 */
export interface Registered {
  /** The new account's user id. */
  readonly subject: string;
  /** The address it was registered with, normalised; none for a passkey-only account (#655). */
  readonly identifier?: string;
  readonly registered: true;
  readonly recovered?: undefined;
  readonly amr?: undefined;
  readonly authTime?: undefined;
}

/**
 * A completed password reset (#642; ADR-017 Decisions 8 and 10): the
 * account's mailbox, and every other authenticator it holds, were proved,
 * and its password replaced. A reset proves the mailbox, not an
 * authenticator, so it carries no `amr` and no `auth_time`, and the
 * transport starts no session that could satisfy `max_age` or
 * `prompt=login`: for a password-only account it is an email-recovery
 * sign-in at mailbox assurance.
 */
export interface Recovered {
  /** The account's user id. */
  readonly subject: string;
  /** The address the reset proved, normalised. */
  readonly identifier: string;
  readonly recovered: true;
  /**
   * The session epoch the reset advanced the account to. A later reset of
   * the account ends what this one finished: the transport keeps it with
   * the authorization request the reset completed.
   */
  readonly epoch: number;
  readonly registered?: undefined;
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
   * or the registration gate did, with `registration_not_allowed` (#640); or
   * the reset gate, with `reset_not_allowed` (#642).
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
  /**
   * The transaction ended: the transport discards it, and may start a new
   * one. `cause` is the reason the engine audited the end under (a burned
   * code, another account, its age), for a transport that tells the person
   * why the sign-in starts again (#1081). Before a factor succeeded it is the
   * same for every identifier, as the round's answer is (ADR-017 Decision 4).
   */
  | {
      readonly kind: 'refused';
      readonly reason: 'transaction_ended';
      readonly transaction: null;
      readonly cause: SignInAuditReason;
    }
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
