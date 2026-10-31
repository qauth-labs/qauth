export * from './lib/fastify-plugin-cache';
export type * from './types';
/**
 * Read a key and delete it in one Redis `GETDEL` (`@qauth-labs/infra-cache`),
 * for a caller that keys single-use state under `fastify.redis` itself, such as
 * the auth server's interaction store. Re-exported so an app reaches it
 * without depending on the infra library.
 */
export { takeValue } from '@qauth-labs/infra-cache';
