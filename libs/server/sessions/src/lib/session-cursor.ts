import { z } from 'zod';

import type { SessionListOwner, SessionListPosition } from './ports';

/**
 * The cursor of a session list (#550): an opaque string to the caller, which
 * names the list it belongs to and the last row a page showed.
 *
 * It names its list (the realm, and the user or the client), so a cursor of
 * another list is refused rather than read as a position in this one: the
 * paging rule of the admin, account and developer APIs (`invalid_cursor`). It
 * holds nothing the caller of that list does not already know.
 */

/** Longest cursor read: the APIs' `PAGE_CURSOR_MAX_LENGTH`. */
export const SESSION_CURSOR_MAX_LENGTH = 512;

/** The layout version of a cursor. A change of layout raises it. */
const CURSOR_VERSION = 1;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const cursorSchema = z.strictObject({
  v: z.literal(CURSOR_VERSION),
  /** `u`: a user's sessions; `c`: a client's. */
  k: z.enum(['u', 'c']),
  r: z.string().regex(UUID),
  o: z.string().regex(UUID),
  c: z.number().int().nonnegative(),
  i: z.string().regex(UUID),
});

/** A cursor that does not parse, or belongs to another list. */
export class InvalidSessionCursorError extends Error {
  constructor() {
    super('The cursor does not parse, or it belongs to another list');
    this.name = 'InvalidSessionCursorError';
  }
}

/** The list a cursor belongs to. */
export interface SessionList {
  realmId: string;
  owner: SessionListOwner;
}

function identityOf(list: SessionList): { k: 'u' | 'c'; r: string; o: string } {
  return 'userId' in list.owner
    ? { k: 'u', r: list.realmId, o: list.owner.userId }
    : { k: 'c', r: list.realmId, o: list.owner.oauthClientId };
}

/** The cursor of the page after `position`, in `list`. */
export function encodeSessionCursor(list: SessionList, position: SessionListPosition): string {
  const value = {
    v: CURSOR_VERSION,
    ...identityOf(list),
    c: position.createdAt,
    i: position.sid,
  };
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/**
 * The position a cursor names in `list`.
 *
 * @throws InvalidSessionCursorError when it does not parse or names another list
 */
export function decodeSessionCursor(list: SessionList, cursor: string): SessionListPosition {
  if (cursor.length === 0 || cursor.length > SESSION_CURSOR_MAX_LENGTH) {
    throw new InvalidSessionCursorError();
  }
  if (!/^[A-Za-z0-9_-]+$/.test(cursor)) throw new InvalidSessionCursorError();
  // Node decodes base64url leniently (a stray trailing character is
  // dropped), so only the one encoding this module writes is accepted.
  const bytes = Buffer.from(cursor, 'base64url');
  if (bytes.toString('base64url') !== cursor) throw new InvalidSessionCursorError();
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new InvalidSessionCursorError();
  }
  const result = cursorSchema.safeParse(parsed);
  if (!result.success) throw new InvalidSessionCursorError();
  const expected = identityOf(list);
  const { k, r, o, c, i } = result.data;
  if (k !== expected.k || r !== expected.r || o !== expected.o) {
    throw new InvalidSessionCursorError();
  }
  return { createdAt: c, sid: i };
}
