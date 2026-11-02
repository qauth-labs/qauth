import { defineKeys } from '../types';

/**
 * The admin API's internal listener (ADR-019 Decisions 7 and 8, issues #511
 * and #520): the keys of `adminApiEnvSchema`. Deployment wiring, like `HOST`
 * and `PORT`.
 */
export const ADMIN_API_KEYS = defineKeys([
  {
    name: 'ADMIN_API_BASE_URL',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: null,
    since: '0.2.0',
    docs: "The URL clients call the admin API's listener at, such as `https://admin.auth.example.com`, with a path when a proxy serves the listener under one and strips it; every admin call carries a DPoP proof whose `htu` must be this URL followed by the request's path, never a URL taken from the request, and a process that runs the listener refuses to start without it; in production it must be `https` (terminate TLS in front of the listener), unless both it and `ADMIN_API_HOST` name loopback.",
  },
  {
    name: 'ADMIN_API_ENABLED',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: 'false',
    since: '0.2.0',
    docs: 'Run the admin API on its own internal listener, on a process whose `SERVICE_ROLES` holds `admin`, off by default until the first admin operations (#517) ship; it needs `DPOP_ENABLED` and `ADMIN_API_BASE_URL`, since every admin call carries a DPoP-bound admin token; `false` serves no admin API on this process, and the public listener never serves it.',
  },
  {
    name: 'ADMIN_API_HOST',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: '127.0.0.1',
    since: '0.2.0',
    docs: "The address the admin API's listener binds to, loopback by default; the listener grants nothing for a caller's network position, so every call but the one for its OpenAPI document needs a DPoP-bound admin token and a proof made with its key.",
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
