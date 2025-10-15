// Type-safe environment configuration using Zod
// Validates all environment variables at startup with clear error messages

import { DEFAULT_LOG_LEVEL, DEFAULT_PORT } from '@qauth/constants';
import { z } from 'zod';

// =============================================================================
// Environment Schema Definition
// =============================================================================

/**
 * Zod schema for environment validation
 * Defines all required and optional environment variables with validation rules
 */
const envSchema = z.object({
  // Server Configuration
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(DEFAULT_PORT),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'])
    .default(DEFAULT_LOG_LEVEL),

  // Database Configuration
  DATABASE_URL: z.string().url('DATABASE_URL must be a valid PostgreSQL connection string'),

  // Redis Configuration
  REDIS_URL: z.string().url('REDIS_URL must be a valid Redis connection string').optional(),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.coerce.number().int().min(1).max(65535).default(6379),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_DB: z.coerce.number().int().min(0).default(0),

  // JWT Configuration (for Phase 1)
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters long'),

  // CORS Configuration
  CORS_ORIGIN: z.string().optional(),
  CORS_CREDENTIALS: z.coerce.boolean().default(true),

  // Security Configuration
  RATE_LIMIT_ENABLED: z.coerce.boolean().default(true),
  SESSION_SECURE: z.coerce.boolean().default(false),

  // Monitoring Configuration
  HEALTH_CHECK_ENABLED: z.coerce.boolean().default(true),
  METRICS_ENABLED: z.coerce.boolean().default(false),
});

// =============================================================================
// Environment Types
// =============================================================================

/**
 * Inferred TypeScript type from Zod schema
 */
export type Environment = z.infer<typeof envSchema>;

// =============================================================================
// Environment Validation and Parsing
// =============================================================================

/**
 * Parse and validate environment variables
 * Throws detailed error if validation fails
 */
export function parseEnvironment(): Environment {
  try {
    const result = envSchema.parse(process.env);

    // Additional validation logic
    validateEnvironment(result);

    return result;
  } catch (error) {
    if (error instanceof z.ZodError) {
      // Format Zod validation errors for better readability
      const errorMessages = error.issues.map((err: z.ZodIssue) => {
        const path = err.path.join('.');
        return `  ${path}: ${err.message}`;
      });

      console.error('❌ Environment validation failed:');
      console.error(errorMessages.join('\n'));
      console.error('\n💡 Please check your environment variables and try again.');
      console.error('📖 See .env.example for required variables.');

      process.exit(1);
    }

    throw error;
  }
}

/**
 * Additional environment validation logic
 */
function validateEnvironment(env: Environment): void {
  // Validate JWT secret strength in production
  if (env.NODE_ENV === 'production' && env.JWT_SECRET.length < 64) {
    console.warn('⚠️  Warning: JWT_SECRET should be at least 64 characters in production');
  }

  // Validate CORS configuration
  if (env.NODE_ENV === 'production' && env.CORS_ORIGIN === '*') {
    throw new Error('CORS_ORIGIN cannot be "*" in production. Specify allowed origins.');
  }

  // Validate session security in production
  if (env.NODE_ENV === 'production' && !env.SESSION_SECURE) {
    console.warn('⚠️  Warning: SESSION_SECURE should be true in production for HTTPS');
  }
}

// =============================================================================
// Environment Utilities
// =============================================================================

/**
 * Get environment with type safety
 */
export function getEnv(): Environment {
  if (!globalThis.__env) {
    globalThis.__env = parseEnvironment();
  }
  return globalThis.__env;
}

/**
 * Check if running in development mode
 */
export function isDevelopment(): boolean {
  return getEnv().NODE_ENV === 'development';
}

/**
 * Check if running in production mode
 */
export function isProduction(): boolean {
  return getEnv().NODE_ENV === 'production';
}

/**
 * Check if running in test mode
 */
export function isTest(): boolean {
  return getEnv().NODE_ENV === 'test';
}

/**
 * Get Redis connection options
 */
export function getRedisConfig(): {
  url?: string;
  host: string;
  port: number;
  password?: string;
  db: number;
} {
  const env = getEnv();

  return {
    url: env.REDIS_URL,
    host: env.REDIS_HOST,
    port: env.REDIS_PORT,
    password: env.REDIS_PASSWORD,
    db: env.REDIS_DB,
  };
}

/**
 * Get database configuration
 */
export function getDatabaseConfig(): {
  connectionString: string;
  pool?: {
    min?: number;
    max?: number;
    idleTimeoutMillis?: number;
    connectionTimeoutMillis?: number;
  };
} {
  const env = getEnv();

  return {
    connectionString: env.DATABASE_URL,
    pool: {
      min: 2,
      max: isProduction() ? 10 : 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000,
    },
  };
}

/**
 * Get CORS configuration
 */
export function getCorsConfig(): {
  origin: string | boolean | string[];
  credentials: boolean;
} {
  const env = getEnv();

  let origin: string | boolean | string[];

  if (env.CORS_ORIGIN) {
    if (env.CORS_ORIGIN.includes(',')) {
      // Multiple origins
      origin = env.CORS_ORIGIN.split(',').map((o) => o.trim());
    } else {
      // Single origin
      origin = env.CORS_ORIGIN;
    }
  } else {
    // Default based on environment
    origin = isDevelopment() ? true : false;
  }

  return {
    origin,
    credentials: env.CORS_CREDENTIALS,
  };
}

// =============================================================================
// Global Environment Declaration
// =============================================================================

declare global {
  var __env: Environment | undefined;
}
