import { db } from '@qauth/db';
import { Redis } from 'ioredis';

declare module 'fastify' {
  interface FastifyInstance {
    db: typeof db;
    redis: Redis;
  }
}
