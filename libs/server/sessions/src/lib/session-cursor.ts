import { z } from 'zod';

import type { SessionListOwner, SessionListPosition, SessionUsePosition } from './ports';

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
  /**
   * `u`: a user's sessions; `c`: a client's; `l`: a user's live sessions,
   * most recently used first, whose `c` is a `lastSeenAt` (#1110).
   */
  k: z.enum(['u', 'c', 'l']),
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

/** The live-session list of a user (#1110): a list of its own, with cursors of its own. */
export interface LiveSessionList {
  realmId: string;
  userId: string;
}

type CursorIdentity = { k: 'u' | 'c' | 'l'; r: string; o: string };

function identityOf(list: SessionList): CursorIdentity {
  return 'userId' in list.owner
    ? { k: 'u', r: list.realmId, o: list.owner.userId }
    : { k: 'c', r: list.realmId, o: list.owner.oauthClientId };
}

function encode(identity: CursorIdentity, at: number, sid: string): string {
  const value = { v: CURSOR_VERSION, ...identity, c: at, i: sid };
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/** The cursor of the page after `position`, in `list`. */
export function encodeSessionCursor(list: SessionList, position: SessionListPosition): string {
  return encode(identityOf(list), position.createdAt, position.sid);
}

/**
 * The position a cursor names in `list`.
 *
 * @throws InvalidSessionCursorError when it does not parse or names another list
 */
export function decodeSessionCursor(list: SessionList, cursor: string): SessionListPosition {
  const { at, sid } = decode(identityOf(list), cursor);
  return { createdAt: at, sid };
}

/** The cursor of the page after `position`, in a user's live-session list. */
export function encodeLiveSessionCursor(
  list: LiveSessionList,
  position: SessionUsePosition
): string {
  return encode({ k: 'l', r: list.realmId, o: list.userId }, position.lastSeenAt, position.sid);
}

/**
 * The position a cursor names in a user's live-session list. A cursor of the
 * user's full list, or of any other, is refused.
 *
 * @throws InvalidSessionCursorError when it does not parse or names another list
 */
export function decodeLiveSessionCursor(list: LiveSessionList, cursor: string): SessionUsePosition {
  const { at, sid } = decode({ k: 'l', r: list.realmId, o: list.userId }, cursor);
  return { lastSeenAt: at, sid };
}

function decode(expected: CursorIdentity, cursor: string): { at: number; sid: string } {
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
  const { k, r, o, c, i } = result.data;
  if (k !== expected.k || r !== expected.r || o !== expected.o) {
    throw new InvalidSessionCursorError();
  }
  return { at: c, sid: i };
}
