import { defineKeys } from '../types';

/**
 * Egress (ADR-019 Decision 8, issue #481): the keys of `egressEnvSchema`.
 *
 * `advanced`: the allowlist's file format may still change in a minor
 * release while the callers of X (upstream providers, back-channel logout,
 * webhooks) move onto the egress client.
 */
export const EGRESS_KEYS = defineKeys([
  {
    name: 'EGRESS_ALLOWLIST_PATH',
    tier: 'advanced',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: 'A JSON file of hosts and address ranges, each for the realms it lists, that outbound calls to destinations the operator or a realm admin set may reach although they are not public; read once at boot, and never applied to a destination that a client, an end user or a fetched document supplies.',
  },
]);
