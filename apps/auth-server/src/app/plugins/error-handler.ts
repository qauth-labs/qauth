import {
  BadRequestError,
  EmailAlreadyVerifiedError,
  EmailNotVerifiedError,
  InvalidClientError,
  InvalidCredentialsError,
  InvalidGrantError,
  InvalidScopeError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TokenAlreadyUsedError,
  TokenExpiredError,
  TooManyRequestsError,
  UnauthorizedClientError,
  UniqueConstraintError,
  WeakPasswordError,
} from '@qauth-labs/shared-errors';
import type { FastifyError, FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

interface ErrorResponse {
  error: string;
  error_description?: string;
  code?: string;
  statusCode: number;
  feedback?: string[];
  constraint?: string;
  retryAfter?: number;
}

/** Simple errors that only need message and statusCode */
const SimpleErrorClasses = [
  BadRequestError,
  EmailAlreadyVerifiedError,
  EmailNotVerifiedError,
  InvalidCredentialsError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  NotFoundError,
  TokenAlreadyUsedError,
  TokenExpiredError,
  TooManyRequestsError,
  UnauthorizedClientError,
] as const;

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

      // OAuth errors that carry an optional `error_description` (RFC 6749 §5.2)
      if (error instanceof InvalidScopeError || error instanceof InvalidGrantError) {
        const response: ErrorResponse = {
          error: error.message,
          statusCode: error.statusCode,
          code: error.code,
          ...(error.errorDescription ? { error_description: error.errorDescription } : {}),
        };
        return reply.code(error.statusCode).send(response);
      }

      // RFC 6749 §5.2: if the client attempted Basic auth, the 401 response
      // MUST include a `WWW-Authenticate` header matching the scheme used.
      if (error instanceof InvalidClientError) {
        if (/^basic\s/i.test(request.headers.authorization ?? '')) {
          reply.header('WWW-Authenticate', 'Basic realm="OAuth"');
        }
        const response: ErrorResponse = {
          error: error.message,
          statusCode: error.statusCode,
          code: error.code,
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle simple error types (message + statusCode + optional code)
      for (const ErrorClass of SimpleErrorClasses) {
        if (error instanceof ErrorClass) {
          const response: ErrorResponse = {
            error: error.message,
            statusCode: error.statusCode,
            ...('code' in error && error.code ? { code: error.code } : {}),
          };
          return reply.code(error.statusCode).send(response);
        }
      }

      // Handle WeakPasswordError (includes feedback)
      if (error instanceof WeakPasswordError) {
        const response: ErrorResponse = {
          error: error.message,
          code: error.code,
          statusCode: error.statusCode,
          feedback: error.feedback,
        };
        return reply.code(error.statusCode).send(response);
      }

      // Handle UniqueConstraintError (includes constraint)
      if (error instanceof UniqueConstraintError) {
        const response: ErrorResponse = {
          error: error.message,
          code: error.code,
          statusCode: error.statusCode,
          constraint: error.constraint,
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

      // Handle HTTP errors with statusCode property
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
