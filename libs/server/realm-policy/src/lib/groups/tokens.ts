import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('tokens');

/** A lifetime in whole seconds, as the environment keys take it. */
const lifetime = () => z.number().int().positive();

/**
 * Token lifetimes (`tokens`, #514; read from the realm row by #527).
 *
 * Shorter is stricter. Lengthening a lifetime is a security operation with
 * the effect `posture-loosening`, as the admin operation registry rules for
 * `realms.policies.update` (#508, `admin-operations-reserved.ts`, and the
 * effect's description in `SECURITY_EFFECTS`); shortening one is a write.
 */
export const TOKENS_POLICY_GROUP = {
  accessTokenLifespanSeconds: policyField(lifetime(), {
    seedEnv: 'ACCESS_TOKEN_LIFESPAN',
    default: 900,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'How long an access token for a staging or production client is valid, in seconds.',
      link,
    },
  }),
  developmentAccessTokenLifespanSeconds: policyField(lifetime(), {
    seedEnv: 'DEV_ACCESS_TOKEN_LIFESPAN',
    default: 28800,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long an access token for a development client is valid, in seconds; no staging or production client receives it.',
      link,
    },
  }),
  refreshTokenLifespanSeconds: policyField(lifetime(), {
    seedEnv: 'REFRESH_TOKEN_LIFESPAN',
    default: 604800,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'How long a refresh token is valid, in seconds.',
      link,
    },
  }),
  adminAccessTokenLifespanSeconds: policyField(lifetime().max(900), {
    seedEnv: null,
    default: 600,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long an access token for the admin API is valid, in seconds, at most 900 (ADR-019 Decision 7: admin tokens are short-lived).',
      link,
    },
  }),
} as const;
