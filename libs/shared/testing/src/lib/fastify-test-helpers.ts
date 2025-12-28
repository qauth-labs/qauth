import type { FastifyInstance, FastifyPluginAsync } from 'fastify';
import Fastify from 'fastify';

/**
 * Build a Fastify app instance for testing
 * @param appPlugin The app plugin function to register
 * @param options Optional Fastify options
 * @returns Fastify instance ready for testing
 */
export async function buildTestApp(
  appPlugin: FastifyPluginAsync,
  options?: { logger?: boolean }
): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: options?.logger ?? false,
  });

  await fastify.register(appPlugin);

  return fastify;
}

/**
 * Close a Fastify app instance
 * @param app Fastify instance to close
 */
export async function closeTestApp(app: FastifyInstance): Promise<void> {
  await app.close();
}
