import { z } from 'zod';

import { defineEventType } from '../definition';
import { FIRST_RELEASE } from './fields';

/**
 * The Shared Signals Framework transmitter (issue #410). A stream is the
 * subject, as its `stream_id`; the receiver that asked is the actor and the
 * envelope's `client`.
 */

/** The longest verification `state` QAuth takes, in characters. */
export const SSF_VERIFICATION_STATE_MAX = 256;

export const ssfStreamVerificationRequested = defineEventType({
  name: 'ssf.stream.verification_requested',
  version: 1,
  rc: 0,
  description:
    'A receiver asked for a verification event on one of its Shared Signals Framework streams (SSF 1.0 §8.1.4). QAuth sends the verification Security Event Token to that stream only.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'ssf_stream',
  data: z.strictObject({
    state: z
      .string()
      .min(1)
      .max(SSF_VERIFICATION_STATE_MAX)
      .optional()
      .describe(
        'The opaque value the receiver sent, returned to it in the verification event. Absent when it sent none.'
      ),
  }),
});

export const SSF_EVENT_TYPES = [ssfStreamVerificationRequested] as const;
