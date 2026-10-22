import { z } from 'zod';

import { defineEventType } from '../definition';
import { FIRST_RELEASE, identifierHmac, reason, signInMethod, verifierProfile } from './fields';

/** A person's own account activity: sign-in, sign-out and registration. */

export const userSignedIn = defineEventType({
  name: 'user.signed_in',
  version: 1,
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
  description: 'A person signed out, and QAuth ended their sessions.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
});

export const userSignOutFailed = defineEventType({
  name: 'user.sign_out_failed',
  version: 1,
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
  description: 'An account could not be created, for example because the address is in use.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  data: z.strictObject({
    reason: reason(),
    identifierHmac: identifierHmac().optional(),
  }),
});

export const USER_EVENT_TYPES = [
  userSignedIn,
  userSignInFailed,
  userSignedOut,
  userSignOutFailed,
  userRegistered,
  userRegistrationFailed,
] as const;
