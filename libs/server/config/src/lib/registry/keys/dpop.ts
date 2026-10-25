import { defineKeys } from '../types';

/**
 * DPoP (RFC 9449; ADR-014 §3, ADR-017 Decision 14, issues #479 and #480): the
 * keys of `dpopEnvSchema`.
 *
 * `advanced`: the first-party endpoint (ADR-017 phase F3) and the Authority
 * Tree (ADR-014 phase P1) will read the same switch, and what it turns on
 * there may still change in a minor release.
 */
export const DPOP_KEYS = defineKeys([
  {
    name: 'DPOP_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'tokens',
    default: 'false',
    since: '0.2.0',
    docs: 'Turn DPoP-bound tokens on (RFC 9449): the token endpoint binds tokens to the key of a DPoP proof, and refuses a client marked `dpop_bound_access_tokens` that sends none.',
  },
]);
