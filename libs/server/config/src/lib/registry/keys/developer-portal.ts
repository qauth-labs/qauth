import { defineKeys } from '../types';

/**
 * The keys the developer portal reads from `process.env`
 * (`apps/developer-portal/src`). The portal is a separate process, so these
 * are set on its container, not the auth server's.
 *
 * Advanced for now: ADR-020 moves the portal's sign-in to `/oauth/authorize`,
 * which changes its session configuration.
 */
export const DEVELOPER_PORTAL_KEYS = defineKeys([
  {
    name: 'AUTH_SERVER_URL',
    tier: 'advanced',
    role: 'deployment',
    owner: 'developer-portal',
    default: { required: true },
    since: '0.1.0',
    docs: "The base URL the developer portal's server uses to reach the auth server.",
  },
  {
    name: 'PORTAL_SESSION_SECRET',
    tier: 'advanced',
    role: 'deployment',
    owner: 'key-custody',
    default: { required: true },
    since: '0.1.0',
    secret: true,
    docs: "The random secret that signs the developer portal's session cookie; use at least 32 characters.",
  },
  {
    name: 'PORTAL_SESSION_TTL',
    tier: 'advanced',
    role: 'deployment',
    owner: 'developer-portal',
    default: '900',
    since: '0.1.0',
    docs: 'The developer portal session lifetime, in seconds.',
  },
  {
    name: 'PORTAL_TRUST_PROXY',
    tier: 'advanced',
    role: 'deployment',
    owner: 'developer-portal',
    default: null,
    since: '0.1.0',
    docs: 'The proxies in front of the developer portal, as comma-separated IP addresses, whose forwarded client address, protocol and host it believes.',
  },
]);
