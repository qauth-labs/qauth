import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { uuidv7 } from './uuidv7';

describe('uuidv7 (#457)', () => {
  it('makes an RFC 9562 version 7 UUID with the variant bits set', () => {
    const id = uuidv7();
    expect(z.uuidv7().safeParse(id).success).toBe(true);
    expect(id[14]).toBe('7');
    expect(['8', '9', 'a', 'b']).toContain(id[19]);
  });

  it('carries the given time in its first 48 bits', () => {
    const now = Date.UTC(2026, 9, 23, 12, 0, 0, 123);
    const id = uuidv7(now);
    expect(parseInt(id.replaceAll('-', '').slice(0, 12), 16)).toBe(now);
  });

  it('draws fresh random bits each time', () => {
    const now = Date.now();
    expect(new Set(Array.from({ length: 100 }, () => uuidv7(now))).size).toBe(100);
  });

  it('refuses a time outside 48 bits', () => {
    expect(() => uuidv7(-1)).toThrow(RangeError);
    expect(() => uuidv7(2 ** 48)).toThrow(RangeError);
    expect(() => uuidv7(1.5)).toThrow(RangeError);
  });
});
