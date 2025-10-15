// Main entry point for QAuth OAuth 2.1/OIDC server
// Handles server startup, graceful shutdown, and error handling

import Fastify from 'fastify';
import pino from 'pino';

import { app } from './app/app';
import { getEnv } from './config/env';

/**
 * Create and configure the Fastify server instance
 */
async function createServer() {
  const env = getEnv();

  // Configure logger based on environment
  const logger = pino({
    level: env.LOG_LEVEL,
    transport:
      env.NODE_ENV === 'development'
        ? {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'HH:MM:ss Z',
              ignore: 'pid,hostname',
            },
          }
        : undefined,
    redact: {
      paths: [
        'password',
        'passwordHash',
        'clientSecret',
        'clientSecretHash',
        'authorization',
        'cookie',
        'token',
        'code',
        'codeVerifier',
        'codeChallenge',
      ],
      censor: '[REDACTED]',
    },
  });

  // Create Fastify instance
  const fastify = Fastify({
    logger,
    trustProxy: env.NODE_ENV === 'production',
    requestIdHeader: 'x-request-id',
    genReqId: () => {
      // Generate request ID for tracing
      return Math.random().toString(36).substring(2) + Date.now().toString(36);
    },
  });

  // Register the main application
  await fastify.register(app, {});

  return fastify;
}

/**
 * Start the server
 */
async function start() {
  try {
    const env = getEnv();

    console.log('🚀 Starting QAuth OAuth 2.1/OIDC Server...');
    console.log(`📋 Environment: ${env.NODE_ENV}`);
    console.log(`🔌 Port: ${env.PORT}`);
    console.log(`📊 Log Level: ${env.LOG_LEVEL}`);

    // Create server
    const server = await createServer();

    // Start listening
    await server.listen({
      port: env.PORT,
      host: env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1',
    });

    console.log(`✅ Server started successfully!`);
    console.log(`🌐 Server running at http://localhost:${env.PORT}`);
    console.log(`❤️  Health check: http://localhost:${env.PORT}/health`);
    console.log(`📖 API docs: http://localhost:${env.PORT}/docs`);

    // Log server information
    server.log.info(
      {
        port: env.PORT,
        host: env.NODE_ENV === 'production' ? '0.0.0.0' : '127.0.0.1',
        nodeEnv: env.NODE_ENV,
      },
      'Server started'
    );
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  process.exit(1);
});

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
start();
