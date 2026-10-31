import { defineKeys } from '../types';

/**
 * The admin API's internal listener (ADR-019 Decisions 7 and 8, issue #511):
 * the keys of `adminApiEnvSchema`. Deployment wiring, like `HOST` and `PORT`.
 */
export const ADMIN_API_KEYS = defineKeys([
  {
    name: 'ADMIN_API_ENABLED',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: 'false',
    since: '0.2.0',
    docs: 'Run the admin API on its own internal listener, on a process whose `SERVICE_ROLES` holds `admin`, off by default until the first admin operations (#517) and DPoP-bound admin tokens (#520) ship; `false` serves no admin API on this process, and the public listener never serves it.',
  },
  {
    name: 'ADMIN_API_HOST',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: '127.0.0.1',
    since: '0.2.0',
    docs: "The address the admin API's listener binds to, loopback by default, and loopback only in production until admin tokens are DPoP-bound (#520); the listener grants nothing for a caller's network position, so every call but the one for its OpenAPI document needs an admin token.",
  },
  {
    name: 'ADMIN_API_PORT',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: '3002',
    since: '0.2.0',
    docs: "The TCP port the admin API's listener binds to; it must differ from `PORT`.",
  },
]);
