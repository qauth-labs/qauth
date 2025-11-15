import fastifyEnv from '@fastify/env';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

/**
 * Environment variables schema and validation
 */
const schema = {
  type: 'object',
  required: ['NODE_ENV'],
  properties: {
    // Server configuration
    NODE_ENV: {
      type: 'string',
      default: 'development',
    },
    HOST: {
      type: 'string',
      default: 'localhost',
    },
    PORT: {
      type: 'number',
      default: 3000,
    },
    // Database configuration
    DATABASE_URL: {
      type: 'string',
      default: 'postgresql://qauth:qauth@localhost:5432/qauth',
    },
    // Redis configuration
    REDIS_URL: {
      type: 'string',
      default: 'redis://localhost:6379',
    },
    // CORS configuration
    CORS_ORIGIN: {
      type: 'string',
      default: '*',
    },
  },
};

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      NODE_ENV: string;
      HOST: string;
      PORT: number;
      DATABASE_URL: string;
      REDIS_URL: string;
      CORS_ORIGIN: string;
    };
  }
}

/**
 * Environment plugin for type-safe environment variable access
 *
 * @see https://github.com/fastify/fastify-env
 */
export default fp(async function (fastify: FastifyInstance) {
  fastify.register(fastifyEnv, {
    schema,
    dotenv: true,
    data: process.env,
  });
});
