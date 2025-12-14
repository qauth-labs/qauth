// Database connection and utilities
export { closeDatabase, db, pool, testConnection } from './lib/db';

// Export generic database pool type (abstracted from implementation)
export type { DatabasePool } from './lib/db';

// Schema exports (empty for now, will be populated in P1)
// Note: Schema module is intentionally empty in P0

// Re-export commonly used Drizzle types for convenience
export type { InferInsertModel, InferSelectModel } from 'drizzle-orm';
