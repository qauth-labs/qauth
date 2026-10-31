import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('bruteForce');

/**
 * Failed sign-in throttling (`bruteForce`, #514; read from the realm row by
 * #528).
 *
 * Each loosening is "loosening the brute-force policy" (ADR-019 Decision 7,
 * `credential-path`): switching it off, allowing more attempts, counting them
 * over a shorter window or locking out for less time. The floors these
 * values may not go below arrive with the human-accounts work, as new fields
 * in version 1.
 */
export const BRUTE_FORCE_POLICY_GROUP = {
  enabled: policyField(z.boolean(), {
    seedEnv: 'FAILED_LOGIN_TRACKING_ENABLED',
    default: true,
    direction: 'true-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'Whether repeated failed sign-ins for one identifier lock it out for a while; when off, failures are only logged.',
      link,
    },
  }),
  maxAttempts: policyField(z.number().int().min(1), {
    seedEnv: 'FAILED_LOGIN_MAX_ATTEMPTS',
    default: 5,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'How many failed sign-ins within the window lock an identifier out.',
      link,
    },
  }),
  windowSeconds: policyField(z.number().int().min(1), {
    seedEnv: 'FAILED_LOGIN_WINDOW',
    default: 900,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'The window, in seconds, over which failed sign-ins are counted.',
      link,
    },
  }),
  lockoutSeconds: policyField(z.number().int().min(1), {
    seedEnv: 'FAILED_LOGIN_LOCKOUT_DURATION',
    default: 900,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long, in seconds, a locked-out identifier is refused before any password check.',
      link,
    },
  }),
} as const;
