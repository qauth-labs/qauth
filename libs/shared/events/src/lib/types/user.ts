import { z } from 'zod';

import { defineEventType } from '../definition';
import { CAEP_SESSION_REVOKED, RISC_ACCOUNT_DISABLED, RISC_ACCOUNT_ENABLED } from '../ssf-mapping';
import {
  FIRST_RELEASE,
  identifierHmac,
  reason,
  signInMethod,
  stepName,
  verifierProfile,
} from './fields';

/**
 * A person's own account activity: sign-in, sign-out and registration; and an
 * operator's switch of the account.
 */

export const userSignedIn = defineEventType({
  name: 'user.signed_in',
  version: 1,
  rc: 0,
  description:
    'A person signed in: the credential checked out and QAuth started a browser session or issued tokens.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
    verifierProfile: verifierProfile().optional(),
  }),
});

export const userSignInFailed = defineEventType({
  name: 'user.sign_in_failed',
  version: 1,
  rc: 0,
  description:
    'A sign-in was refused: an unknown identifier, a wrong credential, a locked or disabled account.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
    reason: reason(),
    identifierHmac: identifierHmac().optional(),
    verifierProfile: verifierProfile().optional(),
  }),
});

/**
 * One accepted step of a sign-in, from the sign-in engine (#614): every
 * transport that runs the engine records it, the Interaction API and the
 * FiPA endpoint alike. A refused or ended step is `user.sign_in_failed`.
 */
export const userSignInStepPassed = defineEventType({
  name: 'user.sign_in_step_passed',
  version: 1,
  rc: 0,
  description:
    'The sign-in engine accepted an answer to one step of a sign-in: the identifier, or a factor that proved who the person is. A refused answer is user.sign_in_failed; the session or the tokens the sign-in leads to are user.signed_in.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    step: stepName('The step whose answer was accepted.'),
    identifierHmac: identifierHmac().optional(),
  }),
});

export const userSignedOut = defineEventType({
  name: 'user.signed_out',
  version: 1,
  rc: 0,
  description: 'A person signed out, and QAuth ended their sessions.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: { event: CAEP_SESSION_REVOKED },
});

export const userSignOutFailed = defineEventType({
  name: 'user.sign_out_failed',
  version: 1,
  rc: 0,
  description: 'A sign-out request was refused or could not complete.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    reason: reason(),
  }),
});

export const userRegistered = defineEventType({
  name: 'user.registered',
  version: 1,
  rc: 0,
  description: 'A person created an account.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
  }),
});

export const userRegistrationFailed = defineEventType({
  name: 'user.registration_failed',
  version: 1,
  rc: 0,
  description: 'An account could not be created, for example because the address is in use.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  data: z.strictObject({
    reason: reason(),
    identifierHmac: identifierHmac().optional(),
  }),
});

/**
 * An operator's switch of an account (#748). Until the admin API has user
 * operations (#681), the `db:disable-user` operator tool is the one path that
 * emits these, in the transaction of the change.
 */

export const userDisabled = defineEventType({
  name: 'user.disabled',
  version: 1,
  rc: 0,
  description:
    'An operator disabled an account: it can no longer sign in or obtain tokens, and every browser session and token issued to it before now stays refused, also after it is enabled again.',
  category: 'admin',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: { event: RISC_ACCOUNT_DISABLED },
  ssfNote:
    'Sent without `reason`: RISC 1.0 names only `hijacking` and `bulk-account`, and QAuth records no reason for the switch.',
});

export const userEnabled = defineEventType({
  name: 'user.enabled',
  version: 1,
  rc: 0,
  description:
    'An operator enabled a disabled account again. The person signs in again: what was issued before the account was disabled stays refused.',
  category: 'admin',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: { event: RISC_ACCOUNT_ENABLED },
});

export const USER_EVENT_TYPES = [
  userSignedIn,
  userSignInFailed,
  userSignInStepPassed,
  userSignedOut,
  userSignOutFailed,
  userRegistered,
  userRegistrationFailed,
  userDisabled,
  userEnabled,
] as const;
