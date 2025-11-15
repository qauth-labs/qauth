import cors from '@fastify/cors';
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

/**
 * CORS plugin for handling cross-origin requests
 *
 * @see https://github.com/fastify/fastify-cors
 */
export default fp(async function (fastify: FastifyInstance) {
  fastify.register(cors, {
    // Allow requests from any origin in development
    // In production, this should be configured via environment variables
    origin: process.env.CORS_ORIGIN || true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });
});
