import * as dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

// Load environment variables
dotenv.config();

// Database connection configuration
const connectionString = process.env['DATABASE_URL'];

if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is required');
}

// Create PostgreSQL connection pool
const pool = new Pool({
  connectionString,
  max: parseInt(process.env['DB_POOL_MAX'] || '20'),
  min: parseInt(process.env['DB_POOL_MIN'] || '2'),
  idleTimeoutMillis: parseInt(process.env['DB_POOL_IDLE_TIMEOUT'] || '10000'),
  connectionTimeoutMillis: parseInt(process.env['DB_POOL_CONNECTION_TIMEOUT'] || '2000'),
});

// Create Drizzle database instance
export const db = drizzle(pool);

// Export pool for direct access if needed
export { pool };

// Graceful shutdown function
export const closeDatabase = async (): Promise<void> => {
  await pool.end();
};

// Test database connection
export const testConnection = async (): Promise<boolean> => {
  try {
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    return true;
  } catch (error) {
    console.error('Database connection test failed:', error);
    return false;
  }
};
