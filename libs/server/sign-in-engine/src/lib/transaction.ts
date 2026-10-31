import { grammarStep, isStepName, type OfferedStep } from '@qauth-labs/server-step-grammar';
import { z } from 'zod';

/**
 * THE SIGN-IN TRANSACTION: what the engine keeps between the rounds of one
 * sign-in. The transport stores it (the interaction record of the
 * Interaction API, the `auth_session` state of the FiPA endpoint) and hands
 * it back on the next round; the engine never stores anything itself.
 *
 * It holds no policy (the MFA policy is read on every round, ADR-017
 * Decision 4), no answer, no password and no account state: only who the
 * transaction is for, and what it proved.
 */

/** The transaction format. A transaction of another version is refused, which ends it. */
export const SIGN_IN_TRANSACTION_VERSION = 1;

/** The most verified steps one transaction holds; a sign-in proves a handful. */
const MAX_VERIFIED_STEPS = 16;

export interface SignInTransaction {
  readonly v: typeof SIGN_IN_TRANSACTION_VERSION;
  /**
   * The identifier, checked and normalised: the first one the transaction
   * was given. It never changes; a different one ends the transaction, and so
   * does any one brought after a discoverable factor fixed the subject
   * without one.
   */
  readonly identifier?: string;
  /** The user the first factor proved. It never changes; another user's proof ends the transaction. */
  readonly subject?: string;
  /**
   * Every step whose answer the engine accepted, in order, with the params
   * it was offered with: the input of the step grammar's `transactionAmr`.
   */
  readonly verified: readonly OfferedStep[];
  /** When the last authenticator succeeded, in epoch milliseconds: the `auth_time` of a completed sign-in. */
  readonly authTime?: number;
}

/** A transaction that holds nothing yet: the state before round 0. */
export function newSignInTransaction(): SignInTransaction {
  return Object.freeze({ v: SIGN_IN_TRANSACTION_VERSION, verified: Object.freeze([]) });
}

const verifiedStepSchema = z
  .strictObject({ step: z.string().max(64), params: z.unknown() })
  .superRefine((value, context) => {
    if (!isStepName(value.step)) {
      context.addIssue({ code: 'custom', message: 'not a step of the grammar' });
      return;
    }
    if (!grammarStep(value.step).params.safeParse(value.params).success) {
      context.addIssue({ code: 'custom', message: 'params outside the step’s schema' });
    }
  })
  .transform((value) => value as OfferedStep);

/**
 * The stored form of a transaction, for the transport to check what it
 * reads back. The engine parses every transaction it is given with it, and a
 * transaction it refuses ends.
 */
export const signInTransactionSchema = z.strictObject({
  v: z.literal(SIGN_IN_TRANSACTION_VERSION),
  identifier: z.string().min(3).max(254).optional(),
  subject: z.string().min(1).max(64).optional(),
  verified: z.array(verifiedStepSchema).max(MAX_VERIFIED_STEPS),
  authTime: z.int().positive().optional(),
});

/** Parse a stored transaction; `null` when it is not one the engine wrote. */
export function readSignInTransaction(value: unknown): SignInTransaction | null {
  const parsed = signInTransactionSchema.safeParse(value);
  if (!parsed.success) return null;
  const { identifier, subject, verified, authTime } = parsed.data;
  // An auth_time without a subject, or a subject without one, is no state the
  // engine writes. (A subject without an identifier is: a discoverable factor
  // names the account by itself.)
  if ((authTime === undefined) !== (subject === undefined)) return null;
  return freezeTransaction({
    v: SIGN_IN_TRANSACTION_VERSION,
    ...(identifier === undefined ? {} : { identifier }),
    ...(subject === undefined ? {} : { subject }),
    verified,
    ...(authTime === undefined ? {} : { authTime }),
  });
}

/** A frozen copy, so no caller can change the state it was handed. */
export function freezeTransaction(transaction: SignInTransaction): SignInTransaction {
  return Object.freeze({
    ...transaction,
    verified: Object.freeze(transaction.verified.map((step) => Object.freeze({ ...step }))),
  });
}
