import { defineKeys } from '../types';

/**
 * The Shared Signals Framework transmitter (ADR-018 §3, ADR-019 Decision 8,
 * issue #410): the keys of `ssfEnvSchema`.
 *
 * `advanced`: the transmitter is experimental, and its surface, the mapping
 * of QAuth's security events to SSF events (#540) included, may still change
 * in a minor release.
 */
export const SSF_KEYS = defineKeys([
  {
    name: 'SSF_TRANSMITTER_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'events',
    default: 'false',
    since: '0.2.0',
    docs: 'Turn the Shared Signals Framework transmitter on (`/.well-known/ssf-configuration`, stream management under `/ssf/`, push delivery of Security Event Tokens) for each realm whose `ssf_transmitter_enabled` is also on.',
  },
]);
