import { sql } from 'drizzle-orm';

export const EPOCH_MS_NOW = sql`(EXTRACT(EPOCH FROM NOW())::bigint * 1000)`;

export const JSONB_EMPTY_ARRAY = sql`'[]'::jsonb`;
