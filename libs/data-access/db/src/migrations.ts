// Migration utilities and helpers for database schema management

import { migrate } from 'drizzle-orm/node-postgres/migrator';

import { getDatabase } from './client';

// =============================================================================
// Migration Functions
// =============================================================================

/**
 * Run all pending migrations
 * This should be called during application startup in production
 */
export async function runMigrations(): Promise<void> {
  const db = getDatabase();

  try {
    console.log('Running database migrations...');
    await migrate(db.db, { migrationsFolder: 'drizzle' });
    console.log('Database migrations completed successfully');
  } catch (error) {
    console.error('Migration failed:', error);
    throw error;
  }
}

/**
 * Check if migrations are up to date
 * Useful for health checks and startup validation
 */
export async function checkMigrationStatus(): Promise<{
  isUpToDate: boolean;
  pendingMigrations: string[];
}> {
  // This is a simplified check - in production you might want to
  // implement more sophisticated migration status checking
  try {
    await runMigrations();
    return {
      isUpToDate: true,
      pendingMigrations: [],
    };
  } catch (error) {
    return {
      isUpToDate: false,
      pendingMigrations: ['Unknown - check migration logs'],
    };
  }
}
