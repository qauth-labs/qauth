import { randomBytes } from 'node:crypto';

const TIMESTAMP_LIMIT = 2 ** 48;

/**
 * A UUIDv7 (RFC 9562 §5.7): 48 bits of Unix time in milliseconds, then 74
 * random bits around the version and the variant. An event's id is made in the
 * application, not by Postgres, because the event is validated, id included,
 * before it is written, and because a writer granted only `INSERT` cannot read
 * a generated value back.
 *
 * Ids made in the same millisecond are not ordered among themselves; nothing
 * orders events by id.
 *
 * @param now - the time to embed, epoch milliseconds
 * @throws {RangeError} when `now` is not an integer in the 48-bit range
 */
export function uuidv7(now: number = Date.now()): string {
  if (!Number.isSafeInteger(now) || now < 0 || now >= TIMESTAMP_LIMIT) {
    throw new RangeError('uuidv7: the time must be epoch milliseconds within 48 bits');
  }
  const bytes = randomBytes(16);
  bytes.writeUIntBE(now, 0, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
