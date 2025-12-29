import * as dotenv from 'dotenv';
import type { Config } from 'drizzle-kit';

if (process.env.NODE_ENV !== 'test') {
  dotenv.config({ path: '../../../.env' }); // Load .env from project root
}

export default {
  schema: './src/lib/schema/index.ts', // Fixed schema path
  out: './drizzle', // Standard migrations output location
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL || '',
  },
} satisfies Config;
