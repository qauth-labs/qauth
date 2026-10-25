/**
 * `@qauth-labs/resource-guard/fastify` — the Fastify 5 adapter.
 *
 * {@link resourceGuardPlugin} (also the default export) serves RFC 9728
 * metadata and decorates the instance with `resourceGuard`, `requireBearer`
 * and `requireScopes`. It needs `fastify` (an optional peer dependency of the
 * package); the root entry `@qauth-labs/resource-guard` does not.
 */
export {
  default,
  resourceGuardPlugin,
  type ResourceGuardPluginOptions,
  sendBearerChallenge,
} from './lib/fastify-plugin.js';
