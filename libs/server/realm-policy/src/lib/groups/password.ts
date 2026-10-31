import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

/**
 * The password policy (`password`, #514; read from the realm row by #528).
 *
 * Lowering the minimum strength is "loosening the password policy" (ADR-019
 * Decision 7, `credential-path`). The NIST password rules arrive with the
 * human-accounts work, as new fields in version 1.
 */
export const PASSWORD_POLICY_GROUP = {
  minScore: policyField(z.number().int().min(0).max(4), {
    seedEnv: 'PASSWORD_MIN_SCORE',
    default: 2,
    direction: 'higher-is-stricter',
    securityWhen: 'loosening',
    effects: ['credential-path'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'The lowest zxcvbn strength score, from 0 to 4, a new password may have.',
      link: groupDocsLink('password'),
    },
  }),
} as const;
