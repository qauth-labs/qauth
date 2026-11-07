import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import { FIRST_RELEASE } from './fields';

/** Refusals of a request as a whole, before its own handling starts. */

export const CSRF_FORMS = [
  'sign_in',
  'wallet_sign_in',
  'wallet_link',
  'consent',
  'consent_revocation',
  /** An answer or a cancel at the Interaction API (#616). */
  'interaction',
] as const;

export const requestCsrfRejected = defineEventType({
  name: 'request.csrf_rejected',
  version: 1,
  rc: 0,
  description:
    'A form post was refused because its CSRF check failed: the token was missing or did not match.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    form: extensibleEnum(CSRF_FORMS).describe(
      'The form that was posted. The set may grow in a minor release.'
    ),
  }),
});

/**
 * Why the account API's operation guard refused a call (#663):
 *
 * - `delegated_token`: an act-chain token (RFC 8693 `act`) at an operation
 *   that takes none (ADR-019 Decision 7);
 * - `authentication_too_old`: the sign-in behind the token is more than five
 *   minutes old, or the token says nothing of when it happened;
 * - `strongest_factor_missing`: the sign-in is recent, but its `amr` lacks the
 *   account's strongest bound factor, and no recovery code stood in for it
 *   where the operation takes one (ADR-017 Decision 8);
 * - `lookup_failed`: what the guard reads to decide, the account's bound
 *   factors or the token's browser session, could not be read.
 */
export const ACCOUNT_OPERATION_REFUSAL_REASONS = [
  'delegated_token',
  'authentication_too_old',
  'strongest_factor_missing',
  'lookup_failed',
] as const;

/**
 * The RFC 8176 `amr` value of an account's strongest bound factor: `pop` for a
 * passkey, `otp` for an authenticator app, `pwd` for a password alone.
 */
export const ACCOUNT_FACTORS = ['pop', 'otp', 'pwd'] as const;

export const requestAccountOperationRefused = defineEventType({
  name: 'request.account_operation_refused',
  version: 1,
  rc: 0,
  description:
    'An account API call was refused before its operation ran: the token was an act-chain token the operation does not take, or the sign-in behind it was too old or lacked the account’s strongest bound factor (ADR-017 Decision 8).',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    operation: z
      .string()
      .min(1)
      .max(64)
      .regex(/^account(?:\.[a-z][A-Za-z]*)+$/)
      .describe(
        'The refused operation: its `operationId` in the account API contract, such as `account.password.change`.'
      ),
    reason: extensibleEnum(ACCOUNT_OPERATION_REFUSAL_REASONS).describe(
      '`delegated_token`: an act-chain token at an operation that takes none. `authentication_too_old`: the sign-in is more than five minutes old. `strongest_factor_missing`: the sign-in lacks the account’s strongest bound factor. `lookup_failed`: the bound factors or the session could not be read. The set may grow in a minor release.'
    ),
    requiredFactor: extensibleEnum(ACCOUNT_FACTORS)
      .optional()
      .describe(
        'With `strongest_factor_missing`: the RFC 8176 `amr` value the sign-in needed, the account’s strongest bound factor. The set may grow in a minor release.'
      ),
    maxAge: z
      .int()
      .min(0)
      .optional()
      .describe('The `max_age` of the step-up challenge the call was answered with, in seconds.'),
  }),
});

export const REQUEST_EVENT_TYPES = [requestCsrfRejected, requestAccountOperationRefused] as const;
