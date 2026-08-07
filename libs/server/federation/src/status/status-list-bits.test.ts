import { deflateSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { isStatusListBitWidth, readStatusListEntry } from './status-list-bits';
import { MAX_DECOMPRESSED_STATUS_LIST_BYTES } from './status-list-spec';
import { encodeStatusList } from './test/status-list-fixtures';

describe('readStatusListEntry (#297, draft-14 §4)', () => {
  describe('specification vectors', () => {
    it('reads the draft-14 §4.1 one-bit example', () => {
      // The specification's worked example: the sixteen statuses below pack
      // into the two bytes 0xB9 0xA3, least-significant bit first. The BYTES
      // are hard-coded rather than produced by the fixture encoder, which is
      // what pins the packing DIRECTION — a most-significant-first reader
      // returns a valid but WRONG entry, with no error anywhere.
      const expected = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
      const lst = deflateSync(Buffer.from([0xb9, 0xa3])).toString('base64url');

      expected.forEach((value, index) => {
        expect(readStatusListEntry(lst, 1, index)).toEqual({ outcome: 'found', status: value });
      });
    });

    it('reads a two-bit vector packed least-significant-entry-first', () => {
      // [1,2,0,3] → 1 | 2<<2 | 0<<4 | 3<<6 = 0xC9
      // [0,1,0,1] → 0 | 1<<2 | 0<<4 | 1<<6 = 0x44
      // [1,2,3,0] → 1 | 2<<2 | 3<<4 | 0<<6 = 0x39
      const expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 0];
      const lst = deflateSync(Buffer.from([0xc9, 0x44, 0x39])).toString('base64url');

      expected.forEach((value, index) => {
        expect(readStatusListEntry(lst, 2, index)).toEqual({ outcome: 'found', status: value });
      });
    });
  });

  describe.each([1, 2, 4, 8] as const)('at %i bit(s) per entry', (bits) => {
    const maxValue = (1 << bits) - 1;
    const entries = Array.from({ length: 40 }, (_, index) => index % (maxValue + 1));
    const lst = encodeStatusList(entries, bits);

    it('round-trips every entry', () => {
      entries.forEach((value, index) => {
        expect(readStatusListEntry(lst, bits, index)).toEqual({ outcome: 'found', status: value });
      });
    });

    it('reports an index past the end as out of range', () => {
      expect(readStatusListEntry(lst, bits, 10_000)).toEqual({ outcome: 'out-of-range' });
    });
  });

  it('reports out-of-range rather than reading a neighbouring byte', () => {
    // Exactly one byte of one-bit entries: index 7 is the last valid one.
    const lst = encodeStatusList([0, 0, 0, 0, 0, 0, 0, 1], 1);
    expect(readStatusListEntry(lst, 1, 7)).toEqual({ outcome: 'found', status: 1 });
    expect(readStatusListEntry(lst, 1, 8)).toEqual({ outcome: 'out-of-range' });
  });

  it.each([
    ['a non-string lst', 42, 1, 0],
    ['a bit width of 3', encodeStatusList([0], 1), 3, 0],
    ['a bit width of 16', encodeStatusList([0], 1), 16, 0],
    ['a string bit width', encodeStatusList([0], 1), '1', 0],
    ['a negative index', encodeStatusList([0], 1), 1, -1],
    ['a fractional index', encodeStatusList([0], 1), 1, 1.5],
  ])('reports %s as unreadable', (_label, lst, bits, idx) => {
    expect(readStatusListEntry(lst, bits, idx as number)).toEqual({ outcome: 'unreadable' });
  });

  describe('strict base64url decoding', () => {
    it('refuses characters outside the base64url alphabet', () => {
      // `Buffer.from(_, 'base64url')` would silently SKIP these, producing a
      // shorter list that answers out-of-range (or the wrong byte) instead of
      // reporting corruption.
      const valid = encodeStatusList([1, 0, 0, 0, 0, 0, 0, 0], 1);
      expect(readStatusListEntry(`${valid}!!`, 1, 0)).toEqual({ outcome: 'unreadable' });
      expect(readStatusListEntry(valid.replace(/.$/, '='), 1, 0)).toEqual({
        outcome: 'unreadable',
      });
      expect(readStatusListEntry(`${valid.slice(0, 4)}+/`, 1, 0)).toEqual({
        outcome: 'unreadable',
      });
    });

    it('refuses an empty lst', () => {
      expect(readStatusListEntry('', 1, 0)).toEqual({ outcome: 'unreadable' });
    });

    it('refuses a base64 quantum that encodes no whole byte', () => {
      expect(readStatusListEntry('A', 1, 0)).toEqual({ outcome: 'unreadable' });
    });
  });

  describe('decompression bounds', () => {
    it('refuses a payload that is not a zlib stream', () => {
      expect(readStatusListEntry(Buffer.from([1, 2, 3]).toString('base64url'), 1, 0)).toEqual({
        outcome: 'unreadable',
      });
    });

    it('refuses a decompression bomb instead of allocating it', () => {
      // ~64 MiB of zeroes compresses to a few tens of KiB — comfortably past
      // the 16 MiB output bound, and cheap enough for an attacker to mint per
      // credential. The bound is enforced BY zlib, so this test would time out
      // or OOM rather than fail if the guard were applied after the inflate.
      const bomb = deflateSync(Buffer.alloc(MAX_DECOMPRESSED_STATUS_LIST_BYTES * 4));
      expect(bomb.length).toBeLessThan(1024 * 1024);
      expect(readStatusListEntry(bomb.toString('base64url'), 1, 0)).toEqual({
        outcome: 'unreadable',
      });
    });

    it('accepts a large but in-bounds list', () => {
      const large = deflateSync(Buffer.alloc(1024 * 1024, 0x00)).toString('base64url');
      expect(readStatusListEntry(large, 1, 8_000_000)).toEqual({ outcome: 'found', status: 0 });
    });
  });
});

describe('isStatusListBitWidth (#297)', () => {
  it.each([1, 2, 4, 8])('accepts %i', (bits) => {
    expect(isStatusListBitWidth(bits)).toBe(true);
  });

  it.each([0, 3, 5, 7, 16, -1, 1.0000001, '1', null, undefined])('rejects %s', (bits) => {
    expect(isStatusListBitWidth(bits)).toBe(false);
  });
});
