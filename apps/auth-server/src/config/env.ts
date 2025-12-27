import * as dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  DATABASE_URL: z.url(),
  REDIS_URL: z.url().optional(),
  REDIS_HOST: z.string().optional(),
  REDIS_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  CORS_ORIGIN: z.string().optional(),
  // Rate Limiting
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
  RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(3600),
  REGISTRATION_RATE_LIMIT: z.coerce.number().int().min(1).default(3),
  REGISTRATION_RATE_WINDOW: z.coerce.number().int().min(1).default(3600),
  // Authentication
  DEFAULT_REALM_NAME: z.string().min(1).default('master'),
  // Password
  PASSWORD_MIN_SCORE: z.coerce.number().int().min(0).max(4).default(2),
  PASSWORD_MEMORY_COST: z.coerce.number().int().min(1).default(65536),
  PASSWORD_TIME_COST: z.coerce.number().int().min(1).default(3),
  PASSWORD_PARALLELISM: z.coerce.number().int().min(1).default(4),
});

export const env = envSchema.parse(process.env);
