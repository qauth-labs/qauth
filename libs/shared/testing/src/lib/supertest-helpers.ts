import type { FastifyInstance } from 'fastify';
import request from 'supertest';

/**
 * Create a Supertest request instance from a Fastify app
 * @param app Fastify instance
 * @returns Supertest request instance
 */
export function createTestRequest(app: FastifyInstance): ReturnType<typeof request> {
  return request(app.server);
}

/**
 * Common response assertions for API tests
 */
export const responseAssertions = {
  /**
   * Assert successful response (2xx)
   */
  success: (res: request.Response) => {
    if (res.status < 200 || res.status >= 300) {
      throw new Error(`Expected success status, got ${res.status}: ${JSON.stringify(res.body)}`);
    }
  },

  /**
   * Assert error response (4xx or 5xx)
   */
  error: (res: request.Response) => {
    if (res.status < 400) {
      throw new Error(`Expected error status, got ${res.status}: ${JSON.stringify(res.body)}`);
    }
  },
};
