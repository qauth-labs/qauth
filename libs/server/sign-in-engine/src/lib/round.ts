import type {
  AmrValue,
  AnswerEncoding,
  StepName,
  StepOffer,
} from '@qauth-labs/server-step-grammar';

import type { AuditSink } from './ports';
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
  /** Where the round's audit records go. */
  readonly audit: AuditSink;
}

/** A completed sign-in: what the transport mints a session or a code from. */
export interface CompletedSignIn {
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
  /** The transport's request checks refused the round, with their own code. */
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
