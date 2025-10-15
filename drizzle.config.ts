// Drizzle Kit configuration for database migrations and introspection

import { config } from 'dotenv';
import type { Config } from 'drizzle-kit';

// Load environment variables
config();

export default {
  schema: './libs/data-access/db/src/schema.ts',
  out: './drizzle',
  driver: 'pg',
  dbCredentials: {
    connectionString:
      process.env.DATABASE_URL || 'postgresql://qauth:qauth@localhost:5432/qauth_dev',
  },
  verbose: true,
  strict: true,
} satisfies Config;
