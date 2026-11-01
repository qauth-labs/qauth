import {
  MAX_ACCESS_TOKEN_LIFESPAN_SECONDS,
  MAX_REFRESH_TOKEN_LIFESPAN_SECONDS,
} from '@qauth-labs/server-config';
import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('tokens');

/**
 * A lifetime in whole seconds, as the environment keys take it, at most
 * `max`. The bounds are the environment keys' (`@qauth-labs/server-config`):
 * a day for an access token, which must stay verifiable for its whole life
 * while a retired signing key is kept 14 days, and 90 days for a refresh
 * token. A stored value above its bound is refused like any value the schema
 * refuses: the realm's requests fail rather than issue such a token.
 */
const lifetime = (max: number) => z.number().int().positive().max(max);

/**
 * Token lifetimes (`tokens`, #514; read from the realm row by #527).
 *
 * Shorter is stricter. Lengthening a lifetime is a security operation with
 * the effect `posture-loosening`, as the admin operation registry rules for
 * `realms.policies.update` (#508, `admin-operations-reserved.ts`, and the
 * effect's description in `SECURITY_EFFECTS`); shortening one is a write.
 */
export const TOKENS_POLICY_GROUP = {
  accessTokenLifespanSeconds: policyField(lifetime(MAX_ACCESS_TOKEN_LIFESPAN_SECONDS), {
    seedEnv: 'ACCESS_TOKEN_LIFESPAN',
    default: 900,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long an access token for a staging or production client is valid, in seconds, at most 86400 (a day).',
      link,
    },
  }),
  developmentAccessTokenLifespanSeconds: policyField(lifetime(MAX_ACCESS_TOKEN_LIFESPAN_SECONDS), {
    seedEnv: 'DEV_ACCESS_TOKEN_LIFESPAN',
    default: 28800,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long an access token for a development client is valid, in seconds, at most 86400 (a day); no staging or production client receives it.',
      link,
    },
  }),
  refreshTokenLifespanSeconds: policyField(lifetime(MAX_REFRESH_TOKEN_LIFESPAN_SECONDS), {
    seedEnv: 'REFRESH_TOKEN_LIFESPAN',
    default: 604800,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary: 'How long a refresh token is valid, in seconds, at most 7776000 (90 days).',
      link,
    },
  }),
  adminAccessTokenLifespanSeconds: policyField(lifetime(900), {
    seedEnv: null,
    default: 600,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: false,
    doc: {
      summary:
        'How long an access token for the admin API is valid, in seconds, at most 900, so a token whose audience is the admin API never lives longer, whatever the other lifetimes say (ADR-019 Decision 7: admin tokens are short-lived).',
      link,
    },
  }),
} as const;
