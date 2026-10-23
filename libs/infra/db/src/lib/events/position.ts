/**
 * A place in a realm's event stream (ADR-019 Decision 8, issue #457).
 *
 * Events are read in `(xid, seq)` order: the writing transaction's id, then
 * the row's insertion number. A position is the `(xid, seq)` of the last event
 * a reader has, and reading on returns the events after it. The cursor API
 * (#539) hands it to its callers as the cursor, and the delivery role (#460)
 * keeps it as its own place.
 *
 * It is opaque: callers store and pass it back, and never build or read one.
 * It names its realm, so a position taken from one realm is refused when
 * another realm is read. It carries no secret: it only selects a place in a
 * stream its holder may already read.
 */

declare const EVENT_POSITION: unique symbol;

/** An encoded position. Only {@link encodeEventPosition} and the readers make one. */
export type EventPosition = string & { readonly [EVENT_POSITION]: true };

/** What a position holds. */
export interface EventPositionParts {
  /** The realm whose stream the position is in, lower case. */
  readonly realmId: string;
  /** The writing transaction of the last event read, or a horizon (see `readAfter`). */
  readonly xid: bigint;
  /** The `seq` of the last event read; 0 before the first event of `xid`. */
  readonly seq: bigint;
}

/** A position that does not parse, or that belongs to another realm. */
export class EventPositionError extends Error {
  override readonly name = 'EventPositionError';
}

/** The layout of the encoded text. A later layout gets a new prefix. */
const LAYOUT = 'p1';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DECODED_PATTERN = new RegExp(
  `^${LAYOUT}:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(0|[1-9][0-9]{0,19}):(0|[1-9][0-9]{0,18})$`
);
/** An `xid8` is an unsigned 64-bit integer; `seq` a positive `bigint`. */
const XID_MAX = 2n ** 64n - 1n;
const SEQ_MAX = 2n ** 63n - 1n;
/** Longer than any position this layout encodes; anything longer is refused unread. */
const ENCODED_MAX_LENGTH = 128;

function checkParts(parts: EventPositionParts): void {
  if (!UUID_PATTERN.test(parts.realmId)) {
    throw new EventPositionError('event position: the realm id is not a lower-case UUID');
  }
  if (parts.xid < 0n || parts.xid > XID_MAX || parts.seq < 0n || parts.seq > SEQ_MAX) {
    throw new EventPositionError('event position: xid or seq is out of range');
  }
}

/**
 * Encode a position.
 *
 * @throws {EventPositionError} on a realm id that is not a lower-case UUID, or
 *   an `xid` or `seq` out of range
 */
export function encodeEventPosition(parts: EventPositionParts): EventPosition {
  checkParts(parts);
  const text = `${LAYOUT}:${parts.realmId}:${parts.xid}:${parts.seq}`;
  return Buffer.from(text, 'utf8').toString('base64url') as EventPosition;
}

/**
 * Decode a position. Only the exact text {@link encodeEventPosition} writes is
 * accepted, so one position has one spelling.
 *
 * @throws {EventPositionError} on anything else
 */
export function decodeEventPosition(position: string): EventPositionParts {
  if (
    typeof position !== 'string' ||
    position.length === 0 ||
    position.length > ENCODED_MAX_LENGTH ||
    !/^[A-Za-z0-9_-]+$/.test(position)
  ) {
    throw new EventPositionError('event position: not a position');
  }
  const match = DECODED_PATTERN.exec(Buffer.from(position, 'base64url').toString('utf8'));
  if (!match) throw new EventPositionError('event position: not a position');
  const parts = { realmId: match[1], xid: BigInt(match[2]), seq: BigInt(match[3]) };
  checkParts(parts);
  if (encodeEventPosition(parts) !== position) {
    throw new EventPositionError('event position: not a position');
  }
  return parts;
}

/**
 * The position before the first event of a realm: reading on from it returns
 * the realm's oldest retained event first.
 *
 * @throws {EventPositionError} on a realm id that is not a lower-case UUID
 */
export function eventStreamStart(realmId: string): EventPosition {
  return encodeEventPosition({ realmId, xid: 0n, seq: 0n });
}

/** Order two positions of one realm: negative when `a` comes first. */
export function compareEventPositions(a: EventPositionParts, b: EventPositionParts): number {
  if (a.realmId !== b.realmId) {
    throw new EventPositionError('event position: positions of two realms have no order');
  }
  if (a.xid !== b.xid) return a.xid < b.xid ? -1 : 1;
  if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1;
  return 0;
}
