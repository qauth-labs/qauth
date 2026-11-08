import {
  MAX_FAILED_LOGIN_LOCKOUT_SECONDS,
  MAX_FAILED_LOGIN_WINDOW_SECONDS,
} from '@qauth-labs/server-config';
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
 *
 * The window and the lockout are at most a day (schema version 1-rc.1,
 * #517): anyone who knows an identifier can start its lockout, so a longer
 * one would let them keep the account out for as long as it lasts. A realm
 * that stored a longer one under 1-rc.0 reads it as a day (`upgrades.ts`).
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
  windowSeconds: policyField(z.number().int().min(1).max(MAX_FAILED_LOGIN_WINDOW_SECONDS), {
    seedEnv: 'FAILED_LOGIN_WINDOW',
    default: 900,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'The window, in seconds, over which failed sign-ins are counted, at most 86400 (a day).',
      link,
    },
  }),
  lockoutSeconds: policyField(z.number().int().min(1).max(MAX_FAILED_LOGIN_LOCKOUT_SECONDS), {
    seedEnv: 'FAILED_LOGIN_LOCKOUT_DURATION',
    default: 900,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long, in seconds, a locked-out identifier is refused before any password check, at most 86400 (a day).',
      link,
    },
  }),
} as const;
