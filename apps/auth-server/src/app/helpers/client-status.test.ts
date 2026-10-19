import { describe, expect, it } from 'vitest';

import { isClientUsable } from './client-status';

describe('isClientUsable (ANT-2026-DR5XI3LV)', () => {
  it('is true only for an enabled client no operator suspended', () => {
    expect(isClientUsable({ enabled: true, suspended: false })).toBe(true);
  });

  it('refuses a client its owner disabled', () => {
    expect(isClientUsable({ enabled: false, suspended: false })).toBe(false);
  });

  it('refuses a suspended client even when its owner re-enabled it', () => {
    expect(isClientUsable({ enabled: true, suspended: true })).toBe(false);
    expect(isClientUsable({ enabled: false, suspended: true })).toBe(false);
  });

  it('requires `enabled` to be strictly true', () => {
    expect(isClientUsable({ enabled: 'true' as unknown as boolean, suspended: false })).toBe(false);
  });
});
