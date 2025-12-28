import { startTestDatabase, stopTestDatabase } from '@qauth/testing';
import { execSync } from 'child_process';
import { resolve } from 'path';

/**
 * Global setup for database tests
 * Starts test container and runs migrations
 */
export async function setup() {
  const { connectionString } = await startTestDatabase();

  // Run migrations using drizzle-kit push
  const dbDir = resolve(__dirname, '.');
  try {
    const result = execSync('npx drizzle-kit push', {
      cwd: dbDir,
      env: { ...process.env, DATABASE_URL: connectionString },
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf-8',
      timeout: 30000,
      shell: '/bin/sh',
    });
    if (result && result.trim()) {
      console.log('Migration output:', result.substring(0, 500));
    }
  } catch (error: unknown) {
    const err = error as { stdout?: string; stderr?: string; message?: string };
    const errorMessage = err.stdout || err.stderr || err.message || 'Unknown error';
    if (!errorMessage.includes('No schema changes') && !errorMessage.includes('already exists')) {
      console.error('Migration failed:', errorMessage.substring(0, 500));
      throw new Error(`Migration failed: ${errorMessage.substring(0, 200)}`);
    }
  }
}

/**
 * Global teardown for database tests
 */
export async function teardown() {
  await stopTestDatabase();
}
