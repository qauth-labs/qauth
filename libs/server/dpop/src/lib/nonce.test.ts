import { describe, expect, it } from 'vitest';

import { createHmacDpopNonceSource, MIN_NONCE_SECRET_BYTES } from './nonce';

/** Server-provided nonces (RFC 9449 §8, §9), stateless over an HMAC. */

const SECRET = Buffer.alloc(32, 1);
const START = Date.UTC(2026, 9, 25, 12, 0, 0);

function source(clock: { now: number }, secret: Uint8Array = SECRET, rotateSeconds?: number) {
  return createHmacDpopNonceSource({ secret, rotateSeconds, now: () => clock.now });
}

describe('createHmacDpopNonceSource', () => {
  it('hands out the same nonce for a whole period, on every node with the secret', () => {
    const clock = { now: START };
    const nonce = source(clock).current();

    clock.now = START + 59_000;
    expect(source(clock).current()).toBe(nonce);
  });

  it('writes the nonce in NQCHAR characters only (RFC 9449 §8.1)', () => {
    expect(source({ now: START }).current()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('accepts a nonce during its own period and the next, and refuses it after', () => {
    const clock = { now: START };
    const nonces = source(clock);
    const nonce = nonces.current();

    clock.now = START + 60_000;
    expect(nonces.current()).not.toBe(nonce);
    expect(nonces.accepts(nonce)).toBe(true);

    clock.now = START + 120_000;
    expect(nonces.accepts(nonce)).toBe(false);
  });

  it("refuses another secret's nonce, and values it never handed out", () => {
    const clock = { now: START };
    const other = source(clock, Buffer.alloc(32, 2)).current();
    const nonces = source(clock);

    expect(nonces.accepts(other)).toBe(false);
    expect(nonces.accepts('')).toBe(false);
    expect(nonces.accepts('eyJ7S_zG.eyJH0-Z.HX4w-7v')).toBe(false);
    expect(nonces.accepts(`${nonces.current()}x`)).toBe(false);
  });

  it('rotates at the period the server sets', () => {
    const clock = { now: START };
    const nonces = source(clock, SECRET, 300);
    const nonce = nonces.current();

    clock.now = START + 299_000;
    expect(nonces.current()).toBe(nonce);
  });

  it(`refuses a secret under ${MIN_NONCE_SECRET_BYTES} bytes and a period that is not positive`, () => {
    expect(() => source({ now: START }, Buffer.alloc(MIN_NONCE_SECRET_BYTES - 1))).toThrow(
      TypeError
    );
    expect(() => source({ now: START }, SECRET, 0)).toThrow(TypeError);
    expect(() => source({ now: START }, SECRET, 1.5)).toThrow(TypeError);
  });
});
