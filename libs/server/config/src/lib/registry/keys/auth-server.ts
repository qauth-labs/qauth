import { defineKeys } from '../types';

/**
 * The keys the auth server's own env schema adds to the ones it composes from
 * this library (`apps/auth-server/src/config/env-schema.ts`).
 */
export const AUTH_SERVER_KEYS = defineKeys([
  {
    name: 'CORS_ORIGIN',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: {
      computed: 'none in `production`, so cross-origin requests are refused; `*` otherwise',
    },
    since: '0.1.0',
    docs: "The origins, comma-separated, allowed to call the server cross-origin, such as a browser-based client's origin for its calls to the token endpoint; the authorization endpoint and the other sign-in and consent pages answer no CORS, whatever it holds.",
  },
  {
    name: 'ENABLE_SWAGGER',
    tier: 'stable',
    role: 'deployment',
    owner: 'server',
    default: { computed: '`true`, or `false` when `NODE_ENV=production`' },
    since: '0.1.0',
    docs: 'Serve the Swagger UI at `/docs`.',
  },
]);
