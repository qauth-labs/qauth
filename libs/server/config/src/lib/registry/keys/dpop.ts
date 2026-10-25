import { defineKeys } from '../types';

/**
 * DPoP (RFC 9449; ADR-014 §3, ADR-017 Decision 14, issue #479): the keys of
 * `dpopEnvSchema`.
 *
 * `advanced` while the switch is refused: no endpoint binds tokens to a DPoP
 * key yet, and the name may still change before one does.
 */
export const DPOP_KEYS = defineKeys([
  {
    name: 'DPOP_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'tokens',
    default: 'false',
    since: '0.2.0',
    docs: 'Turn DPoP-bound tokens on (RFC 9449); refused at boot until the token endpoint binds tokens to a DPoP key (ADR-017 phase F3).',
  },
]);
