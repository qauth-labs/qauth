import { z } from 'zod';

import { ordered, policyField } from '../field';

/**
 * The environment posture (`posture`, #514): the realm's ADR-008 ceiling,
 * today the `realms.max_environment_laxity` column.
 *
 * Tightening is free; loosening is a security operation (ADR-019 Decision 10,
 * `posture-loosening`). The value describes the environment the realm runs
 * in, so a sandbox promotion leaves it out unless it is selected (ADR-019
 * Decision 11).
 */
export const POSTURE_POLICY_GROUP = {
  maxEnvironmentLaxity: policyField(z.enum(['development', 'staging', 'production']), {
    seedEnv: null,
    default: 'production',
    direction: ordered(['development', 'staging', 'production']),
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: true,
    doc: {
      summary:
        'The laxest environment profile a client of the realm may get; a client set to a laxer one gets this one.',
      link: 'https://docs.qauth.dev/operate/environment-authorization/',
    },
  }),
} as const;
