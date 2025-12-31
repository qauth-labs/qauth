import { NotFoundError, UniqueConstraintError, WeakPasswordError } from '@qauth/shared-errors';
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

interface ErrorResponse {
  error: string;
  code?: string;
  statusCode: number;
  feedback?: string[];
  constraint?: string;
  retryAfter?: number;
}

/**
 * Global error handler plugin
 * Handles all unhandled errors and converts them to appropriate HTTP responses
 */
export default fp(async function (fastify: FastifyInstance) {
  fastify.setErrorHandler(
    (error: FastifyError | Error, request: FastifyRequest, reply: FastifyReply) => {
      // Log the error
      fastify.log.error(
        {
          err: error,
          url: request.url,
          method: request.method,
        },
        'Error occurred'
      );

      // Handle custom error types
      if (error instanceof WeakPasswordError) {
        const response: ErrorResponse = {
          error: error.message,
          code: error.code,
          statusCode: error.statusCode,
          feedback: error.feedback,
        };
        return reply.code(error.statusCode).send(response);
      }

      if (error instanceof UniqueConstraintError) {
        const response: ErrorResponse = {
          error: error.message,
          code: error.code,
          statusCode: error.statusCode,
          constraint: error.constraint,
        };
        return reply.code(error.statusCode).send(response);
      }

      if (error instanceof NotFoundError) {
        const response: ErrorResponse = {
          error: error.message,
          statusCode: error.statusCode,
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle Fastify validation errors
      if ('validation' in error && error.validation) {
        return reply.code(400).send({
          error: 'Validation error',
          code: 'VALIDATION_ERROR',
          statusCode: 400,
          details: error.validation,
        });
      }

      // Handle Fastify HTTP errors (from @fastify/sensible)
      if ('statusCode' in error && typeof error.statusCode === 'number') {
        const statusCode = error.statusCode;
        const response: ErrorResponse = {
          error: error.message || 'An error occurred',
          statusCode,
        };
        return reply.code(statusCode).send(response);
      }

      // Handle unknown errors
      const isDevelopment = process.env.NODE_ENV !== 'production';
      const response: ErrorResponse = {
        error: isDevelopment ? error.message : 'Internal server error',
        statusCode: 500,
      };

      // Include error details in development
      if (isDevelopment && error.stack) {
        return reply.code(500).send({
          ...response,
          stack: error.stack,
        });
      }

      return reply.code(500).send(response);
    }
  );
});
