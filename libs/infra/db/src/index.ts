// Database connection and utilities
export { closeDatabase, db, pool, testConnection } from './lib/db';

// Export database types (abstracted from implementation)
export type { DatabasePool, DbClient } from './lib/db';

// Schema exports
export * as schema from './lib/schema';

// Re-export commonly used Drizzle types for convenience
export type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

// Repository exports
export * from './lib/repositories';
