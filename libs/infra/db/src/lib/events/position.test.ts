import { describe, expect, it } from 'vitest';

import {
  compareEventPositions,
  decodeEventPosition,
  encodeEventPosition,
  EventPositionError,
  eventStreamStart,
} from './position';

const REALM_A = '0192f1c4-1111-7000-8000-000000000001';
const REALM_B = '0192f1c4-2222-7000-8000-000000000002';

const encodeText = (text: string) => Buffer.from(text, 'utf8').toString('base64url');

describe('event positions (#457)', () => {
  it('round-trips the realm, xid and seq, up to their largest values', () => {
    for (const parts of [
      { realmId: REALM_A, xid: 0n, seq: 0n },
      { realmId: REALM_A, xid: 758n, seq: 12n },
      { realmId: REALM_B, xid: 2n ** 64n - 1n, seq: 2n ** 63n - 1n },
    ]) {
      expect(decodeEventPosition(encodeEventPosition(parts))).toEqual(parts);
    }
  });

  it('is URL-safe text that does not show its parts as decimals', () => {
    const position = encodeEventPosition({ realmId: REALM_A, xid: 758n, seq: 12n });
    expect(position).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(position).not.toContain('758');
  });

  it('starts a stream before its first event', () => {
    expect(decodeEventPosition(eventStreamStart(REALM_A))).toEqual({
      realmId: REALM_A,
      xid: 0n,
      seq: 0n,
    });
  });

  it.each([
    ['empty', ''],
    ['not base64url', 'p1:abc+/='],
    ['too long', 'A'.repeat(129)],
    ['another layout', encodeText(`p2:${REALM_A}:1:1`)],
    ['an upper-case realm', encodeText(`p1:${REALM_A.toUpperCase()}:1:1`)],
    ['no realm', encodeText('p1::1:1')],
    ['a leading zero', encodeText(`p1:${REALM_A}:01:1`)],
    ['a negative seq', encodeText(`p1:${REALM_A}:1:-1`)],
    ['an xid above 64 bits', encodeText(`p1:${REALM_A}:18446744073709551616:1`)],
    ['a seq above 63 bits', encodeText(`p1:${REALM_A}:1:9223372036854775808`)],
    ['a trailing member', encodeText(`p1:${REALM_A}:1:1:1`)],
  ])('refuses %s', (_label, position) => {
    expect(() => decodeEventPosition(position)).toThrow(EventPositionError);
  });

  it('refuses a second spelling of a valid position', () => {
    const position = encodeEventPosition({ realmId: REALM_A, xid: 758n, seq: 12n });
    const bytes = Buffer.from(position, 'base64url');
    // The last character carries unused low bits; a decoder ignores them, so
    // other last characters spell the same bytes.
    const siblings = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_']
      .map((last) => position.slice(0, -1) + last)
      .filter((spelling) => spelling !== position)
      .filter((spelling) => Buffer.from(spelling, 'base64url').equals(bytes));
    expect(siblings.length).toBeGreaterThan(0);
    for (const spelling of [...siblings, `${position}=`]) {
      expect(() => decodeEventPosition(spelling)).toThrow(EventPositionError);
    }
  });

  it('refuses to encode parts that cannot be a position', () => {
    expect(() => encodeEventPosition({ realmId: 'master', xid: 1n, seq: 1n })).toThrow(
      EventPositionError
    );
    expect(() => encodeEventPosition({ realmId: REALM_A, xid: -1n, seq: 1n })).toThrow(
      EventPositionError
    );
  });

  it('orders positions of one realm by xid, then seq, and refuses two realms', () => {
    const at = (xid: bigint, seq: bigint) => ({ realmId: REALM_A, xid, seq });
    expect(compareEventPositions(at(1n, 9n), at(2n, 1n))).toBeLessThan(0);
    expect(compareEventPositions(at(2n, 2n), at(2n, 1n))).toBeGreaterThan(0);
    expect(compareEventPositions(at(2n, 2n), at(2n, 2n))).toBe(0);
    expect(() => compareEventPositions(at(1n, 1n), { ...at(1n, 1n), realmId: REALM_B })).toThrow(
      EventPositionError
    );
  });
});
