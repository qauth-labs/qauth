import { z } from 'zod';

import { defineEventType } from '../definition';
import { count, FIRST_RELEASE, reason, verifierProfile } from './fields';

/**
 * Wallet federation (ADR-009), behind `WALLET_FEDERATION_ENABLED`. A wallet
 * sign-in is a `user.signed_in` with method `wallet`; these are the steps
 * around it.
 */

export const walletLinked = defineEventType({
  name: 'wallet.linked',
  version: 1,
  description: 'A signed-in user linked a wallet credential to their account.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    credentialId: z
      .string()
      .min(1)
      .max(255)
      .describe('The id of the account credential the wallet was linked as.'),
    subjectSource: z
      .string()
      .min(1)
      .max(64)
      .describe('How the subject was resolved from the presentation (ADR-009).'),
    rebound: z
      .boolean()
      .describe('Whether the link replaced an earlier binding of the same credential.'),
    verifierProfile: verifierProfile(),
  }),
});

export const walletLinkFailed = defineEventType({
  name: 'wallet.link_failed',
  version: 1,
  description: 'A wallet could not be linked, for example because it is linked to another account.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    reason: reason(),
    verifierProfile: verifierProfile().optional(),
  }),
});

export const walletPresentationReceived = defineEventType({
  name: 'wallet.presentation_received',
  version: 1,
  description:
    'The OpenID4VP response endpoint accepted a wallet presentation. This is not a sign-in: the flow that asked for it decides.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  data: z.strictObject({
    verifierProfile: verifierProfile(),
    presentationCount: count('How many presentations the response held.'),
  }),
});

export const WALLET_EVENT_TYPES = [
  walletLinked,
  walletLinkFailed,
  walletPresentationReceived,
] as const;
