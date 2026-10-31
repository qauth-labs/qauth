import { z } from 'zod';

import { defineEventType } from '../definition';
import { CAEP_SESSION_REVOKED } from '../ssf-mapping';
import { FIRST_RELEASE, identifierHmac, reason, signInMethod, verifierProfile } from './fields';

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
});

export const USER_EVENT_TYPES = [
  userSignedIn,
  userSignInFailed,
  userSignedOut,
  userSignOutFailed,
  userRegistered,
  userRegistrationFailed,
  userDisabled,
  userEnabled,
] as const;
