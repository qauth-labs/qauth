import AutoLoad from '@fastify/autoload';
import cors from '@fastify/cors';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { FastifyInstance } from 'fastify';
import * as path from 'path';

import { env } from '../config/env';

/* eslint-disable-next-line */
export interface AppOptions {}

export async function app(fastify: FastifyInstance, opts: AppOptions) {
  // Register infrastructure plugins first
  await fastify.register(databasePlugin);
  await fastify.register(cachePlugin);

  // Register CORS
  await fastify.register(cors, {
    origin: env.CORS_ORIGIN || '*',
  });

  // Do not touch the following lines

  // This loads all plugins defined in plugins
  // those should be support plugins that are reused
  // through your application
  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'plugins'),
    options: { ...opts },
  });

  // This loads all plugins defined in routes
  // define your routes in one of these
  fastify.register(AutoLoad, {
    dir: path.join(__dirname, 'routes'),
    options: { ...opts },
  });
}
