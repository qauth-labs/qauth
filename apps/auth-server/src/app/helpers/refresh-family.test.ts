import { describe, expect, it } from 'vitest';

import { refreshFamilyEnd, refreshFamilyEnded, refreshTokenExpiresAt } from './refresh-family';

const MINUTE = 60_000;
const START = 1_792_918_800_000;
const ONE_HOUR = 3600;
const ONE_WEEK = 604_800;

describe('refreshFamilyEnd (#552)', () => {
  it('ends the family sso_max_lifespan after its start', () => {
    expect(refreshFamilyEnd(START, ONE_HOUR)).toBe(START + 60 * MINUTE);
  });

  it('has no end when the realm sets no sso_max_lifespan', () => {
    expect(refreshFamilyEnd(START, null)).toBeNull();
  });

  it('ends the family at its start for a limit of zero', () => {
    expect(refreshFamilyEnd(START, 0)).toBe(START);
  });
});

describe('refreshTokenExpiresAt (#552)', () => {
  it('gives the refresh lifespan from now while the family ends later', () => {
    const now = START + 5 * MINUTE;
    expect(refreshTokenExpiresAt(now, ONE_HOUR, START + 7 * 24 * 60 * MINUTE)).toBe(
      now + 60 * MINUTE
    );
  });

  it('never runs past the end of the family', () => {
    const now = START + 59 * MINUTE;
    expect(refreshTokenExpiresAt(now, ONE_WEEK, refreshFamilyEnd(START, ONE_HOUR))).toBe(
      START + 60 * MINUTE
    );
  });

  it('slides as before when the family has no end', () => {
    const now = START + 59 * MINUTE;
    expect(refreshTokenExpiresAt(now, ONE_WEEK, null)).toBe(now + ONE_WEEK * 1000);
  });
});

describe('refreshFamilyEnded (#552)', () => {
  const end = refreshFamilyEnd(START, ONE_HOUR);

  it('is live before its end', () => {
    expect(refreshFamilyEnded(end, START + 59 * MINUTE)).toBe(false);
    expect(refreshFamilyEnded(end, START + 60 * MINUTE - 1)).toBe(false);
  });

  it('has ended from its end on', () => {
    expect(refreshFamilyEnded(end, START + 60 * MINUTE)).toBe(true);
    expect(refreshFamilyEnded(end, START + 61 * MINUTE)).toBe(true);
  });

  it('never ends without a limit', () => {
    expect(refreshFamilyEnded(null, START + 10 * 365 * 24 * 60 * MINUTE)).toBe(false);
  });
});
