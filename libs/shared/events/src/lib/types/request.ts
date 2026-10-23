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

export const REQUEST_EVENT_TYPES = [requestCsrfRejected] as const;
