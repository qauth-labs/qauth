// Main Fastify application setup
// Registers plugins, routes, and error handling for QAuth OAuth 2.1/OIDC server

import { initializeDatabase } from '@qauth/db';
import { initializeRedis } from '@qauth/redis';
import { FastifyInstance } from 'fastify';

import { getCorsConfig, getDatabaseConfig, getEnv, getRedisConfig } from '../config/env';

/**
 * Build and configure the Fastify application
 * Registers all plugins, routes, and middleware in the correct order
 */
export async function app(fastify: FastifyInstance) {
  const env = getEnv();

  // =============================================================================
  // Core Plugins Registration
  // =============================================================================

  // 1. Environment configuration (already loaded)
  fastify.log.info(
    {
      nodeEnv: env.NODE_ENV,
      port: env.PORT,
      logLevel: env.LOG_LEVEL,
    },
    'Environment loaded'
  );

  // 2. CORS plugin
  await fastify.register(import('@fastify/cors'), getCorsConfig());

  // 3. Security headers
  await fastify.register(import('@fastify/helmet'), {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'https:'],
      },
    },
    hsts: env.NODE_ENV === 'production',
  });

  // 4. Database plugin
  await fastify.register(databasePlugin);

  // 5. Redis plugin
  await fastify.register(redisPlugin);

  // 6. Routes
  await fastify.register(import('./routes/health'), { prefix: '/health' });
  await fastify.register(import('./routes/root'), { prefix: '/' });

  // 7. Error handler (must be registered last)
  fastify.setErrorHandler(errorHandler);

  // 8. Graceful shutdown
  setupGracefulShutdown(fastify);
}

// =============================================================================
// Database Plugin
// =============================================================================

async function databasePlugin(fastify: FastifyInstance) {
  const config = getDatabaseConfig();

  // Initialize database connection
  const db = initializeDatabase(config);

  // Test database connection
  const isConnected = await db.ping();
  if (!isConnected) {
    throw new Error('Failed to connect to database');
  }

  fastify.log.info('Database connected successfully');

  // Decorate Fastify instance with database
  fastify.decorate('db', db);
}

// =============================================================================
// Redis Plugin
// =============================================================================

async function redisPlugin(fastify: FastifyInstance) {
  const config = getRedisConfig();

  // Initialize Redis connection
  const redis = initializeRedis(config);

  // Test Redis connection
  const isConnected = await redis.ping();
  if (!isConnected) {
    throw new Error('Failed to connect to Redis');
  }

  fastify.log.info('Redis connected successfully');

  // Decorate Fastify instance with Redis
  fastify.decorate('redis', redis);
}

// =============================================================================
// Error Handler
// =============================================================================

async function errorHandler(error: Error, request: any, reply: any) {
  const env = getEnv();

  // Log error with context
  request.log.error(
    {
      error: {
        message: error.message,
        stack: env.NODE_ENV === 'development' ? error.stack : undefined,
      },
      request: {
        method: request.method,
        url: request.url,
        userAgent: request.headers['user-agent'],
      },
    },
    'Request error'
  );

  // Determine status code
  let statusCode = 500;
  let errorCode = 'INTERNAL_SERVER_ERROR';
  let message = 'Internal server error';

  if (error.message.includes('validation')) {
    statusCode = 400;
    errorCode = 'VALIDATION_ERROR';
    message = 'Invalid request data';
  } else if (error.message.includes('not found')) {
    statusCode = 404;
    errorCode = 'NOT_FOUND';
    message = 'Resource not found';
  } else if (error.message.includes('unauthorized')) {
    statusCode = 401;
    errorCode = 'UNAUTHORIZED';
    message = 'Authentication required';
  } else if (error.message.includes('forbidden')) {
    statusCode = 403;
    errorCode = 'FORBIDDEN';
    message = 'Access denied';
  }

  // Return structured error response (RFC 7807 format)
  reply.status(statusCode).send({
    error: {
      code: errorCode,
      message,
      statusCode,
      timestamp: new Date().toISOString(),
      path: request.url,
      ...(env.NODE_ENV === 'development' && { details: error.message }),
    },
  });
}

// =============================================================================
// Graceful Shutdown
// =============================================================================

function setupGracefulShutdown(fastify: FastifyInstance) {
  const signals = ['SIGINT', 'SIGTERM'];

  signals.forEach((signal) => {
    process.on(signal, async () => {
      fastify.log.info(`Received ${signal}, starting graceful shutdown...`);

      try {
        // Stop accepting new requests
        await fastify.close();

        // Close database connections
        if (fastify.db) {
          await fastify.db.close();
        }

        // Close Redis connections
        if (fastify.redis) {
          await fastify.redis.disconnect();
        }

        fastify.log.info('Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        fastify.log.error({ error }, 'Error during graceful shutdown');
        process.exit(1);
      }
    });
  });
}

// =============================================================================
// Type Augmentation
// =============================================================================

declare module 'fastify' {
  interface FastifyInstance {
    db: ReturnType<typeof initializeDatabase>;
    redis: ReturnType<typeof initializeRedis>;
  }
}
