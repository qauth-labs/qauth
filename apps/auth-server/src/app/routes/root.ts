import type { FastifyInstance } from 'fastify';

export default async function (fastify: FastifyInstance) {
  fastify.get(
    '/',
    {
      schema: {
        description:
          'Root API endpoint. Returns a simple greeting to verify the auth server is running.',
        tags: ['System'],
      },
    },
    async function () {
      return { message: 'Hello API' };
    }
  );
}
