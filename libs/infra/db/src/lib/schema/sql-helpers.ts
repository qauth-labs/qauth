import { sql } from 'drizzle-orm';
import { customType } from 'drizzle-orm/pg-core';

export const EPOCH_MS_NOW = sql`(EXTRACT(EPOCH FROM NOW())::bigint * 1000)`;

export const JSONB_EMPTY_ARRAY = sql`'[]'::jsonb`;

export const JSONB_EMPTY_OBJECT = sql`'{}'::jsonb`;

/**
 * Postgres `bytea`, read and written as a Node `Buffer` (node-postgres hands
 * `bytea` back as a `Buffer` and binds a `Buffer` parameter as `bytea`).
 * drizzle-orm has no built-in `bytea` column.
 */
export const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
});
