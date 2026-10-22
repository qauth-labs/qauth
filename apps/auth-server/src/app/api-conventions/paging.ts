import { z } from 'zod';

/**
 * Cursor paging for every list operation of the admin, account and developer
 * APIs (#506). A list takes `limit` and `cursor` and answers
 * `{ items, nextCursor }`; `nextCursor` is `null` on the last page. There is no
 * offset and no page number: a cursor stays correct while rows are added
 * between two calls, an offset does not.
 */

/** Items per page when the caller sends no `limit`. */
export const PAGE_LIMIT_DEFAULT = 50;

/** The largest `limit` a list accepts; a larger one is refused, not clamped. */
export const PAGE_LIMIT_MAX = 200;

/**
 * Longest `cursor` a list accepts. A cursor is opaque to the caller, so this
 * bounds what the server decodes, not what a client may build.
 */
export const PAGE_CURSOR_MAX_LENGTH = 512;

/**
 * The query parameters of a list operation. Extend it with the list's own
 * filters (`pageQuerySchema.extend({ ... })`) so `limit` and `cursor` stay the
 * same everywhere.
 *
 * `limit` arrives as a query string. Only a digit string is converted, as in
 * `maxAgeParamSchema` (`schemas/oauth.ts`), and not with `z.coerce.number()`,
 * whose `Number()` accepts `''`, `'0x10'` and `'1e2'`. A value above
 * {@link PAGE_LIMIT_MAX} fails validation (400 `validation_error`, pointer
 * `/limit`) rather than being clamped, so a client never mistakes a short page
 * for the end of the list. The default is a `.prefault()`, which Zod keeps in
 * the published JSON Schema of a preprocessed value (see `boundedArray` in
 * `schemas/common.ts`).
 */
export const pageQuerySchema = z.object({
  limit: z
    .preprocess(
      (value) => (typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value),
      z.number().int().min(1).max(PAGE_LIMIT_MAX)
    )
    .prefault(PAGE_LIMIT_DEFAULT),
  cursor: z.string().min(1).max(PAGE_CURSOR_MAX_LENGTH).optional(),
});

export type PageQuery = z.infer<typeof pageQuerySchema>;

/** The response of a list operation: one page of `item`, and the cursor of the next page. */
export function pageSchema<Item extends z.ZodType>(item: Item) {
  return z.object({
    items: z.array(item),
    nextCursor: z.string().nullable(),
  });
}

export interface Page<Item> {
  items: Item[];
  nextCursor: string | null;
}
