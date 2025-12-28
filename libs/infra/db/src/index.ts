// Database factory and utilities
export { createDatabase, DEFAULT_POOL_CONFIG } from './lib/db';

// Export database types (abstracted from implementation)
export type {
  DatabaseConfig,
  DatabaseInstance,
  DatabasePool,
  DatabasePoolConfig,
  DbClient,
} from './lib/db';

// Schema exports
export * as schema from './lib/schema';

// Re-export commonly used Drizzle types for convenience
export type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

// Repository exports
export * from './lib/repositories';
