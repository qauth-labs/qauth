import { z } from 'zod';

import { InvalidCursorError } from '../helpers/api-request-errors';
import type { Page } from './paging';

/**
 * The cursor of a list of the account and developer APIs (#506, #524).
 *
 * Each list reads its rows by keyset: newest first, by a time and then the row
 * id, so rows added between two calls never shift a page. The cursor holds the
 * time and id of the last row of a page, and the name of the list that issued
 * it, as base64url JSON. It is opaque to the caller: the API conventions page
 * promises nothing about its form. It is not signed, because it grants
 * nothing: every list filters on its owner first, so a cursor the caller built
 * only picks where in the caller's own list the page starts.
 *
 * A cursor that does not parse, or that another list issued, is refused with
 * 400 `invalid_cursor` ({@link InvalidCursorError}).
 */

/** Where a page ends: the time (epoch milliseconds) and id of its last row. */
export interface PagePosition {
  readonly at: number;
  readonly id: string;
}

const cursorSchema = z.strictObject({
  /** The list that issued the cursor. */
  l: z.string(),
  /** The time of the last row, epoch milliseconds. */
  t: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  /** The id of the last row. */
  i: z.uuid(),
});

/** The cursor of the page after the row at `position`, for the list `list`. */
export function encodeCursor(list: string, position: PagePosition): string {
  return Buffer.from(JSON.stringify({ l: list, t: position.at, i: position.id }), 'utf8').toString(
    'base64url'
  );
}

/**
 * The position a cursor of the list `list` names.
 *
 * @throws {InvalidCursorError} when it does not parse, or another list issued it
 */
export function decodeCursor(list: string, cursor: string): PagePosition {
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw new InvalidCursorError();
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw new InvalidCursorError();
  }
  const result = cursorSchema.safeParse(parsed);
  if (!result.success || result.data.l !== list) throw new InvalidCursorError();
  return { at: result.data.t, id: result.data.i };
}

/**
 * Read one page: ask `read` for one row more than `limit`, so whether a next
 * page exists is known without a count, and give back the page, each row
 * projected by `item`, with the cursor of the next page or `null`.
 *
 * @param list - the name the cursors of this list carry, such as
 *   `developer.clients` or `developer.clients.<id>.apiKeys`
 * @param position - the time and id of a row, as the list orders it
 */
export async function readPage<Row, Item>(
  options: {
    readonly list: string;
    readonly limit: number;
    readonly cursor: string | undefined;
    readonly position: (row: Row) => PagePosition;
    readonly item: (row: Row) => Item | Promise<Item>;
  },
  read: (page: { limit: number; after?: PagePosition }) => Promise<Row[]>
): Promise<Page<Item>> {
  const after =
    options.cursor === undefined ? undefined : decodeCursor(options.list, options.cursor);
  const rows = await read({
    limit: options.limit + 1,
    ...(after === undefined ? {} : { after }),
  });
  const pageRows = rows.slice(0, options.limit);
  const last = pageRows.at(-1);
  const items: Item[] = [];
  for (const row of pageRows) items.push(await options.item(row));
  return {
    items,
    nextCursor:
      rows.length > options.limit && last !== undefined
        ? encodeCursor(options.list, options.position(last))
        : null,
  };
}
