import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { FastifyInstance } from 'fastify';
import * as path from 'path';

import { env } from '../config/env';

export async function app(fastify: FastifyInstance, opts: object) {
  await fastify.register(databasePlugin);

  await fastify.register(cachePlugin);

  await fastify.register(cors, {
    origin: env.CORS_ORIGIN || '*',
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'plugins'),
    options: { ...opts },
  });

  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
  });
}
