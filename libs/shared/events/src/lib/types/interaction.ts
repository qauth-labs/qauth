import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import { FIRST_RELEASE, recordId, stepName } from './fields';

/**
 * The browser ceremonies of the Interaction API (ADR-019 Decision 6, #592):
 * one interaction is one ceremony, from the request that starts it to its end.
 * The client the ceremony is for is in the envelope's `client`; the user, once
 * the ceremony knows who it is, is the subject.
 *
 * None of these carries the interaction id or the flow cookie: both are
 * secrets that let a browser read or answer the ceremony. The events name the
 * interaction by a random reference of its own, which links the events of one
 * interaction and opens nothing.
 */

const interactionRef = () =>
  recordId(
    'The interaction: a random reference the server gave it, which links the events of one interaction. Never the interaction id the browser holds.'
  );

/** Why an interaction began. */
export const INTERACTION_PURPOSES = ['authorization'] as const;

/** What one processed answer led to. */
export const INTERACTION_ANSWER_OUTCOMES = ['next_step', 'authenticated', 'finished'] as const;

/** Why an interaction ended without being finished. */
export const INTERACTION_CANCEL_REASONS = ['user', 'user_switch'] as const;

export const interactionCreated = defineEventType({
  name: 'interaction.created',
  version: 1,
  rc: 0,
  description:
    'A browser ceremony began: the server created an interaction and bound it to the browser that started it with a flow cookie.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    interaction: interactionRef(),
    purpose: extensibleEnum(INTERACTION_PURPOSES).describe(
      '`authorization`: an authorization request at the authorization endpoint. The set may grow in a minor release.'
    ),
    step: stepName('The first step the ceremony asks for.'),
    replaces: recordId(
      'For an interaction that a user switch started: the interaction it replaces, which ended with it. Nothing proved in that one carries over.'
    ).optional(),
  }),
});

export const interactionAnswered = defineEventType({
  name: 'interaction.answered',
  version: 1,
  rc: 0,
  description:
    'The engine processed an answer to the current step of an interaction. Of two answers to one step, only the one processed is recorded.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    interaction: interactionRef(),
    step: stepName('The step the answer was for.'),
    outcome: extensibleEnum(INTERACTION_ANSWER_OUTCOMES).describe(
      '`next_step`: another step comes next, or the same one again after a refused answer. `authenticated`: the answer proved who the user is; the browser session and the flow cookie were replaced. `finished`: the interaction ended, and the request it was for is completed. The set may grow in a minor release.'
    ),
  }),
});

export const interactionCancelled = defineEventType({
  name: 'interaction.cancelled',
  version: 1,
  rc: 0,
  description:
    'An interaction ended before it finished, at the request of the browser that started it.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    interaction: interactionRef(),
    step: stepName('The step the interaction was at.'),
    reason: extensibleEnum(INTERACTION_CANCEL_REASONS).describe(
      '`user`: the person cancelled. `user_switch`: the person chose another account, and a new interaction for the same request replaced this one. The set may grow in a minor release.'
    ),
    sessionEnded: z
      .boolean()
      .describe(
        'For a user switch after the person signed in during this interaction: `true`. The browser session that sign-in started was ended, so no later sign-in or client on the browser continues it. Absent when the interaction held no browser session.'
      )
      .optional(),
  }),
});

export const interactionExpired = defineEventType({
  name: 'interaction.expired',
  version: 1,
  rc: 0,
  description:
    'An interaction expired before it finished or was cancelled: it reached its absolute expiry, or its first step went unanswered for too long. It can no longer be read or answered.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    interaction: interactionRef(),
    step: stepName(
      'The step the interaction was at, when the server still had its record. Absent otherwise.'
    ).optional(),
  }),
});

export const INTERACTION_EVENT_TYPES = [
  interactionCreated,
  interactionAnswered,
  interactionCancelled,
  interactionExpired,
] as const;
