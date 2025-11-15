import { config } from 'dotenv';
import Fastify from 'fastify';

import { app } from './app/app';

// Load environment variables
config();

const host = process.env['HOST'] ?? 'localhost';
const port = process.env['PORT'] ? Number(process.env['PORT']) : 3000;
const isDevelopment = process.env['NODE_ENV'] !== 'production';

// Instantiate Fastify with logger config
const server = Fastify({
  logger: {
    level: isDevelopment ? 'info' : 'warn',
    transport: isDevelopment
      ? {
          target: 'pino-pretty',
          options: {
            translateTime: 'HH:MM:ss Z',
            ignore: 'pid,hostname',
          },
        }
      : undefined,
  },
  disableRequestLogging: !isDevelopment,
  requestIdLogLabel: 'reqId',
  requestIdHeader: 'x-request-id',
});

// Register your application as a normal plugin
server.register(app);

// Graceful shutdown handler
const gracefulShutdown = async (signal: string) => {
  server.log.info(`Received ${signal}, starting graceful shutdown...`);

  try {
    await server.close();
    server.log.info('Server closed successfully');
    process.exit(0);
  } catch (err) {
    server.log.error('Error during shutdown:', err);
    process.exit(1);
  }
};

// Register shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors
process.on('uncaughtException', (err) => {
  server.log.error('Uncaught exception:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  server.log.error('Unhandled rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

// Start listening
const start = async () => {
  try {
    await server.listen({ port, host });
    server.log.info(`🚀 QAuth Auth Server ready at http://${host}:${port}`);
    server.log.info(`📚 API docs: http://${host}:${port}/`);
    server.log.info(`🏥 Health check: http://${host}:${port}/health`);
  } catch (err) {
    server.log.error('Error starting server:', err);
    process.exit(1);
  }
};

start();
