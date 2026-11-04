import {
  EMAIL_CODE_PURPOSES,
  grammarStep,
  isStepName,
  type OfferedStep,
} from '@qauth-labs/server-step-grammar';
import { z } from 'zod';

import {
  EMAIL_CODE_HMAC_PATTERN,
  EMAIL_CODE_MAX_WRONG_ANSWERS,
  EMAIL_CODE_SALT_PATTERN,
  emailCodeLength,
  type HeldEmailCode,
} from './email-code';

/**
 * THE SIGN-IN TRANSACTION: what the engine keeps between the rounds of one
 * sign-in. The transport stores it (the interaction record of the
 * Interaction API, the `auth_session` state of the FiPA endpoint) and hands
 * it back on the next round; the engine never stores anything itself.
 *
 * It holds no policy (the MFA policy is read on every round, ADR-017
 * Decision 4), no answer, no password, no code and no account state: only the
 * realm and the client it is for, when it began, who it is for, what it
 * proved, the HMAC of an email code it mailed (#638), and whether the password
 * it proved was on the realm's breach list (#635).
 *
 * It is not sealed: whoever can write it can claim any subject and any
 * verified step. The transport must keep it server-side, under an
 * unguessable handle bound to the realm and the client, and never hand it to
 * the client to bring back. The engine checks only that it is well formed,
 * of the round's realm and client, and no older than
 * {@link SIGN_IN_TRANSACTION_MAX_AGE_MS}.
 */

/** The transaction format. A transaction of another version is refused, which ends it. */
export const SIGN_IN_TRANSACTION_VERSION = 1;

/**
 * The longest a transaction lives, from round 0, in milliseconds: two hours,
 * the longest `INTERACTION_TTL` allows. An older one ends. A transport ends
 * its transactions sooner by its own rules (the FiPA `auth_session` lives ten
 * minutes); this bound is the engine's backstop.
 */
export const SIGN_IN_TRANSACTION_MAX_AGE_MS = 2 * 60 * 60 * 1000;

/**
 * How far in the future a transaction's start may lie, in milliseconds: the
 * clocks of two nodes of one deployment differ by a little. One further ahead
 * is no transaction the engine wrote.
 */
export const SIGN_IN_TRANSACTION_CLOCK_SKEW_MS = 60 * 1000;

/** The most verified steps one transaction holds; a sign-in proves a handful. */
const MAX_VERIFIED_STEPS = 16;

export interface SignInTransaction {
  readonly v: typeof SIGN_IN_TRANSACTION_VERSION;
  /** The realm the transaction is for: a round of another realm ends it. */
  readonly realmId: string;
  /** The client the transaction is for: a round of another client ends it. */
  readonly clientId: string;
  /** When round 0 began, in epoch milliseconds: the transaction's age counts from it. */
  readonly createdAt: number;
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
  /**
   * The email code this transaction mailed and still waits for (#638): its
   * salt and keyed HMAC, never the code, when it was issued, and the wrong
   * answers the transaction counted, which a new code keeps. Gone once the
   * code is answered right; a code answered right is no factor, so it moves
   * no `authTime`.
   */
  readonly emailCode?: HeldEmailCode;
  /**
   * The password this transaction proved is on the realm's breach list
   * (#635): the sign-in completes only once a new password is set (the
   * `new_password` step with `update_required` among the verified steps). Set
   * by the password step, since QAuth keeps only the hash and can check a
   * password only when the person types it.
   */
  readonly breachedPassword?: true;
}

/** What binds a transaction to its sign-in: its realm, its client, and when it began. */
export interface SignInTransactionBinding {
  readonly realmId: string;
  readonly clientId: string;
  readonly createdAt: number;
}

/** A transaction that holds nothing yet: the state before round 0. */
export function newSignInTransaction(binding: SignInTransactionBinding): SignInTransaction {
  return Object.freeze({
    v: SIGN_IN_TRANSACTION_VERSION,
    realmId: binding.realmId,
    clientId: binding.clientId,
    createdAt: binding.createdAt,
    verified: Object.freeze([]),
  });
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
 * The longest `client_id` a transaction holds: the authorization request's
 * bound, which leaves room for a Client ID Metadata Document URL. A shorter
 * bound would end every sign-in of a client whose URL id is longer, at its
 * second round.
 */
const SIGN_IN_CLIENT_ID_MAX_LENGTH = 2048;

/** A held email code as the transaction stores it: a length its purpose takes, a count below the burn. */
const heldEmailCodeSchema = z
  .strictObject({
    purpose: z.enum(EMAIL_CODE_PURPOSES),
    length: z.union([z.literal(6), z.literal(8)]),
    salt: z.string().regex(EMAIL_CODE_SALT_PATTERN),
    hmac: z.string().regex(EMAIL_CODE_HMAC_PATTERN),
    issuedAt: z.int().nonnegative(),
    wrongAnswers: z
      .int()
      .min(0)
      .max(EMAIL_CODE_MAX_WRONG_ANSWERS - 1),
  })
  .refine(
    (held) =>
      held.length === emailCodeLength(held.purpose, { afterPassword: true }) ||
      held.length === emailCodeLength(held.purpose, { afterPassword: false }),
    { message: 'a length its purpose does not take' }
  );

/**
 * The stored form of a transaction, for the transport to check what it
 * reads back. The engine parses every transaction it is given with it, and a
 * transaction it refuses ends.
 */
export const signInTransactionSchema = z.strictObject({
  v: z.literal(SIGN_IN_TRANSACTION_VERSION),
  realmId: z.string().min(1).max(255),
  clientId: z.string().min(1).max(SIGN_IN_CLIENT_ID_MAX_LENGTH),
  createdAt: z.int().nonnegative(),
  identifier: z.string().min(3).max(254).optional(),
  subject: z.string().min(1).max(64).optional(),
  verified: z.array(verifiedStepSchema).max(MAX_VERIFIED_STEPS),
  authTime: z.int().positive().optional(),
  emailCode: heldEmailCodeSchema.optional(),
  breachedPassword: z.literal(true).optional(),
});

/**
 * Parse a stored transaction; `null` when it is not well formed. A well-formed
 * one is not thereby one the engine wrote: see the module doc.
 */
export function readSignInTransaction(value: unknown): SignInTransaction | null {
  const parsed = signInTransactionSchema.safeParse(value);
  if (!parsed.success) return null;
  const {
    realmId,
    clientId,
    createdAt,
    identifier,
    subject,
    verified,
    authTime,
    emailCode,
    breachedPassword,
  } = parsed.data;
  // An auth_time without a subject, or a subject without one, is no state the
  // engine writes. (A subject without an identifier is: a discoverable factor
  // names the account by itself.)
  if ((authTime === undefined) !== (subject === undefined)) return null;
  // Only a password that proved the subject is checked against a breach list.
  if (breachedPassword === true && subject === undefined) return null;
  return freezeTransaction({
    v: SIGN_IN_TRANSACTION_VERSION,
    realmId,
    clientId,
    createdAt,
    ...(identifier === undefined ? {} : { identifier }),
    ...(subject === undefined ? {} : { subject }),
    verified,
    ...(authTime === undefined ? {} : { authTime }),
    ...(emailCode === undefined ? {} : { emailCode }),
    ...(breachedPassword === undefined ? {} : { breachedPassword }),
  });
}

/**
 * A frozen copy, so no caller can change the state it was handed. A member set
 * to `undefined` (an email code consumed) is left out, so the stored form has
 * no key the schema refuses.
 */
export function freezeTransaction(transaction: SignInTransaction): SignInTransaction {
  const { emailCode, ...rest } = transaction;
  return Object.freeze({
    ...rest,
    verified: Object.freeze(transaction.verified.map((step) => Object.freeze({ ...step }))),
    ...(emailCode === undefined ? {} : { emailCode: Object.freeze({ ...emailCode }) }),
  });
}
