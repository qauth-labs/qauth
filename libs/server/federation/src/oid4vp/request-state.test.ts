import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  DEFAULT_OID4VP_REQUEST_TTL_MS,
  generateOid4vpRequestSecrets,
  hashOid4vpState,
  MAX_OID4VP_REQUEST_TTL_MS,
  OID4VP_SECRET_BYTES,
  OID4VP_STATE_HASH_LENGTH,
  resolveOid4vpExpiry,
} from './request-state';

describe('generateOid4vpRequestSecrets', () => {
  it('mints 256 bits of entropy per value, base64url encoded', () => {
    const { state, nonce } = generateOid4vpRequestSecrets();

    expect(OID4VP_SECRET_BYTES).toBe(32);
    expect(Buffer.from(state, 'base64url')).toHaveLength(OID4VP_SECRET_BYTES);
    expect(Buffer.from(nonce, 'base64url')).toHaveLength(OID4VP_SECRET_BYTES);
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('never reuses a state or a nonce, and never equates the two', () => {
    const seen = new Set<string>();

    for (let i = 0; i < 200; i += 1) {
      const { state, nonce } = generateOid4vpRequestSecrets();
      expect(state).not.toBe(nonce);
      seen.add(state);
      seen.add(nonce);
    }

    expect(seen.size).toBe(400);
  });

  it('returns a stateHash that matches the standalone hash function', () => {
    const { state, stateHash } = generateOid4vpRequestSecrets();

    expect(stateHash).toBe(hashOid4vpState(state));
    expect(stateHash).toHaveLength(OID4VP_STATE_HASH_LENGTH);
  });
});

describe('hashOid4vpState', () => {
  it('is SHA-256 hex — the digest the store is keyed by', () => {
    expect(hashOid4vpState('abc')).toBe(createHash('sha256').update('abc', 'utf8').digest('hex'));
    expect(hashOid4vpState('abc')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic, so mint and redeem agree', () => {
    expect(hashOid4vpState('same')).toBe(hashOid4vpState('same'));
    expect(hashOid4vpState('same')).not.toBe(hashOid4vpState('same '));
  });
});

describe('resolveOid4vpExpiry', () => {
  it('defaults to the five-minute TTL', () => {
    expect(resolveOid4vpExpiry(undefined, 1_000)).toBe(1_000 + DEFAULT_OID4VP_REQUEST_TTL_MS);
  });

  it('honours an explicit TTL within the ceiling', () => {
    expect(resolveOid4vpExpiry(60_000, 1_000)).toBe(61_000);
    expect(resolveOid4vpExpiry(MAX_OID4VP_REQUEST_TTL_MS, 0)).toBe(MAX_OID4VP_REQUEST_TTL_MS);
  });

  it('refuses a TTL above the ceiling rather than clamping silently', () => {
    expect(() => resolveOid4vpExpiry(MAX_OID4VP_REQUEST_TTL_MS + 1)).toThrow(/ceiling/);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'refuses the nonsensical TTL %s',
    (ttl) => {
      expect(() => resolveOid4vpExpiry(ttl)).toThrow(/positive whole number/);
    }
  );
});
