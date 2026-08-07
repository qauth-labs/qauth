import { inflateSync } from 'node:zlib';

import {
  MAX_DECOMPRESSED_STATUS_LIST_BYTES,
  MAX_ENCODED_STATUS_LIST_BYTES,
  STATUS_LIST_BIT_WIDTHS,
  type StatusListBitWidth,
} from './status-list-spec';

/**
 * Decoding the compressed status bit-array (draft-14 §4, issue #297).
 *
 * ## The format, exactly
 *
 * `status_list.lst` is a base64url string (no padding) whose bytes are a ZLIB
 * [RFC 1950] container around a DEFLATE [RFC 1951] stream. Inflated, it is a
 * byte array holding `8 / bits` entries per byte, packed from the LEAST
 * significant bit upward. Entry `idx` therefore lives in byte
 * `floor(idx / (8 / bits))`, at shift `(idx % (8 / bits)) * bits`.
 *
 * Getting the packing direction wrong is the failure mode this module is
 * written to make impossible to get away with: a most-significant-first
 * implementation reads a *different* entry rather than an invalid one, so it
 * returns VALID for a revoked credential with no error anywhere. The tests pin
 * the direction against vectors built from the specification's own worked
 * example.
 *
 * ## Decompression is bounded twice, and the bound is enforced BY zlib
 *
 * `maxOutputLength` makes `inflateSync` abort mid-stream once the limit is
 * passed. That is the difference between a defence and a post-mortem: checking
 * `output.length` after the fact means the allocation an attacker was aiming
 * for already succeeded. The encoded input is bounded too
 * ({@link MAX_ENCODED_STATUS_LIST_BYTES}), because a ~1000:1 DEFLATE ratio
 * means an unbounded input can keep the inflate busy even when its output is
 * capped.
 */

/**
 * The outcome of a bit lookup.
 *
 * A discriminated union rather than `number | undefined`: "the list said 0" and
 * "we could not read the list" are the two answers that must never be confused,
 * and `0` is falsy, which is exactly how they get confused.
 */
export type StatusListLookup =
  | { readonly outcome: 'found'; readonly status: number }
  /** `idx` is past the end of the decoded list — draft-14 §10.3 says reject. */
  | { readonly outcome: 'out-of-range' }
  /** `bits`/`lst` malformed, base64url invalid, or decompression refused. */
  | { readonly outcome: 'unreadable' };

/** Whether `value` is a `bits` width draft-14 §4.1 permits. */
export function isStatusListBitWidth(value: unknown): value is StatusListBitWidth {
  return typeof value === 'number' && (STATUS_LIST_BIT_WIDTHS as readonly number[]).includes(value);
}

/**
 * Strictly decode an unpadded base64url string.
 *
 * `Buffer.from(s, 'base64url')` is LENIENT — it skips characters outside the
 * alphabet instead of failing, so `"AA!!AA"` decodes happily. That turns a
 * corrupt or hostile `lst` into a *different, shorter* bit array rather than an
 * error, and a shorter array silently answers `out-of-range` (or, worse, reads
 * the wrong byte). The alphabet is therefore checked before decoding.
 *
 * @returns the decoded bytes, or `undefined` when the input is not clean
 * unpadded base64url or exceeds {@link MAX_ENCODED_STATUS_LIST_BYTES}.
 */
function decodeBase64Url(value: string): Buffer | undefined {
  if (value.length === 0 || value.length > MAX_ENCODED_STATUS_LIST_BYTES) return undefined;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return undefined;
  // A base64 quantum of length 1 encodes no whole byte and is never emitted by
  // a correct encoder; the lenient decoder would silently drop it.
  if (value.length % 4 === 1) return undefined;
  return Buffer.from(value, 'base64url');
}

/**
 * Inflate a compressed status list under a hard output bound.
 *
 * @returns the decompressed bytes, or `undefined` when the stream is not valid
 * ZLIB/DEFLATE or would exceed {@link MAX_DECOMPRESSED_STATUS_LIST_BYTES}.
 */
function inflateBounded(compressed: Buffer): Buffer | undefined {
  try {
    return inflateSync(compressed, { maxOutputLength: MAX_DECOMPRESSED_STATUS_LIST_BYTES });
  } catch {
    // Both "not a zlib stream" and "output bound exceeded" land here, and both
    // mean the same thing to the caller: this list cannot be read. Telling
    // them apart would be a size oracle over an attacker-supplied document.
    return undefined;
  }
}

/**
 * Read the status entry at `idx` from an encoded status list.
 *
 * Pure and synchronous — no I/O, no caching, no policy. It is given exactly
 * what `status_list` carried plus the index to look at, which is what makes the
 * bit arithmetic testable against specification vectors in isolation.
 *
 * @param lst - the `status_list.lst` member: base64url of a ZLIB stream.
 * @param bits - the `status_list.bits` member; must be 1, 2, 4 or 8.
 * @param idx - the referencing credential's `status_list.idx`.
 * @returns a {@link StatusListLookup}; never throws.
 */
export function readStatusListEntry(lst: unknown, bits: unknown, idx: number): StatusListLookup {
  if (typeof lst !== 'string') return { outcome: 'unreadable' };
  if (!isStatusListBitWidth(bits)) return { outcome: 'unreadable' };
  if (!Number.isSafeInteger(idx) || idx < 0) return { outcome: 'unreadable' };

  const compressed = decodeBase64Url(lst);
  if (compressed === undefined) return { outcome: 'unreadable' };

  const decoded = inflateBounded(compressed);
  if (decoded === undefined) return { outcome: 'unreadable' };

  const entriesPerByte = 8 / bits;
  const byteIndex = Math.floor(idx / entriesPerByte);
  if (byteIndex >= decoded.length) return { outcome: 'out-of-range' };

  // Non-null asserted only after the bound check above; `decoded` is a Buffer,
  // so an in-range index always yields a number.
  const byte = decoded[byteIndex] as number;
  const shift = (idx % entriesPerByte) * bits;
  const mask = (1 << bits) - 1;

  return { outcome: 'found', status: (byte >> shift) & mask };
}
