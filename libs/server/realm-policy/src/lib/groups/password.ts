import {
  DEFAULT_PASSWORD_MIN_LENGTH,
  PASSWORD_MIN_LENGTH_CEILING,
  PASSWORD_MIN_LENGTH_FLOOR,
} from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

/**
 * The password policy (`password`, #514; read from the realm row by #528).
 *
 * Lowering the minimum length or the minimum strength is "loosening the
 * password policy" (ADR-019 Decision 7, `credential-path`). The minimum length
 * (#634, ADR-017 Decision 8) is the first of the NIST SP 800-63B-4 password
 * rules, added to version 1 with a default as a new field: a realm stored
 * without it gets the seed at the next boot.
 */
export const PASSWORD_POLICY_GROUP = {
  minLength: policyField(
    z.number().int().min(PASSWORD_MIN_LENGTH_FLOOR).max(PASSWORD_MIN_LENGTH_CEILING),
    {
      seedEnv: 'PASSWORD_MIN_LENGTH',
      default: DEFAULT_PASSWORD_MIN_LENGTH,
      direction: 'higher-is-stricter',
      securityWhen: 'loosening',
      effects: ['credential-path'],
      secret: false,
      environmentBound: false,
      doc: {
        summary:
          'The fewest characters (Unicode code points, after NFC normalisation) a new password may have, from 8 to 64; below 15 is a recorded deviation from NIST SP 800-63B-4 while a password can be the only factor.',
        link: groupDocsLink('password'),
      },
    }
  ),
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
