import { describe, expect, it, vi } from 'vitest';

import { InvalidCursorError } from '../helpers/api-request-errors';
import { decodeCursor, encodeCursor, readPage } from './cursor';

const ID_A = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0001';
const ID_B = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0002';
const ID_C = '0190f5a8-7c3e-7d10-8a4b-3c2d1e0f0003';

describe('list cursors (#524)', () => {
  it('names the position it was issued for, and only for its own list', () => {
    const cursor = encodeCursor('developer.clients', { at: 1_700_000_000_123, id: ID_A });

    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeCursor('developer.clients', cursor)).toEqual({ at: 1_700_000_000_123, id: ID_A });
    expect(() => decodeCursor('developer.consents', cursor)).toThrow(InvalidCursorError);
  });

  it.each([
    ['not base64url', 'a+b/c='],
    ['not JSON', Buffer.from('{nope', 'utf8').toString('base64url')],
    ['a JSON array', Buffer.from('[1]', 'utf8').toString('base64url')],
    [
      'an id that is not a UUID',
      Buffer.from(JSON.stringify({ l: 'x', t: 1, i: 'abc' })).toString('base64url'),
    ],
    [
      'a negative time',
      Buffer.from(JSON.stringify({ l: 'x', t: -1, i: ID_A })).toString('base64url'),
    ],
    [
      'an unknown member',
      Buffer.from(JSON.stringify({ l: 'x', t: 1, i: ID_A, o: 5 })).toString('base64url'),
    ],
  ])('refuses a cursor that is %s with invalid_cursor', (_label, cursor) => {
    expect(() => decodeCursor('x', cursor)).toThrow(InvalidCursorError);
  });

  describe('readPage', () => {
    const rows = [
      { at: 30, id: ID_C },
      { at: 20, id: ID_B },
      { at: 20, id: ID_A },
    ];

    it('asks for one row more than the limit, and gives a cursor only when there is one', async () => {
      const read = vi.fn(async (page: { limit: number }) => rows.slice(0, page.limit));
      const first = await readPage(
        {
          list: 'l',
          limit: 2,
          cursor: undefined,
          position: (row) => row,
          item: (row) => row.id,
        },
        read
      );

      expect(read).toHaveBeenCalledWith({ limit: 3 });
      expect(first.items).toEqual([ID_C, ID_B]);
      expect(first.nextCursor).not.toBeNull();
      expect(decodeCursor('l', first.nextCursor as string)).toEqual({ at: 20, id: ID_B });

      read.mockImplementation(async () => rows.slice(2));
      const second = await readPage(
        {
          list: 'l',
          limit: 2,
          cursor: first.nextCursor as string,
          position: (row) => row,
          item: (row) => row.id,
        },
        read
      );
      expect(read).toHaveBeenLastCalledWith({ limit: 3, after: { at: 20, id: ID_B } });
      expect(second).toEqual({ items: [ID_A], nextCursor: null });
    });

    it('refuses another list’s cursor before reading', async () => {
      const read = vi.fn(async () => rows);
      await expect(
        readPage(
          {
            list: 'mine',
            limit: 2,
            cursor: encodeCursor('theirs', { at: 1, id: ID_A }),
            position: (row) => row,
            item: (row) => row,
          },
          read
        )
      ).rejects.toThrow(InvalidCursorError);
      expect(read).not.toHaveBeenCalled();
    });
  });
});
