import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { FastifyInstance } from 'fastify';
import * as path from 'path';

import { env } from '../config/env';
import errorHandler from './plugins/error-handler';
import { rateLimitPlugin } from './plugins/rate-limit';

export async function app(fastify: FastifyInstance, opts: object) {
  await fastify.register(databasePlugin);

  await fastify.register(cachePlugin);

  await fastify.register(rateLimitPlugin);

  await fastify.register(cors, {
    origin: env.CORS_ORIGIN || '*',
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'plugins'),
    options: { ...opts },
    ignorePattern: /error-handler\.ts$/,
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
  });

  // Register error handler last to catch all unhandled errors
  await fastify.register(errorHandler);
}
