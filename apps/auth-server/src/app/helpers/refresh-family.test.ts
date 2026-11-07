import { describe, expect, it } from 'vitest';

import {
  isBrowserBasedClient,
  refreshFamilyEnd,
  refreshFamilyEnded,
  refreshTokenExpiresAt,
  rotatedRefreshTokenExpiresAt,
} from './refresh-family';

const MINUTE = 60_000;
const START = 1_792_918_800_000;
const ONE_HOUR = 3600;
const ONE_WEEK = 604_800;

describe('refreshFamilyEnd (#552)', () => {
  it('ends the family sso_max_lifespan after its start when no session started it', () => {
    expect(refreshFamilyEnd(START, ONE_HOUR, null)).toBe(START + 60 * MINUTE);
  });

  it('has no end when the realm sets no sso_max_lifespan, whatever the session', () => {
    expect(refreshFamilyEnd(START, null, null)).toBeNull();
    expect(refreshFamilyEnd(START, null, START + MINUTE)).toBeNull();
  });

  it('ends with the browser session that started it when that comes first', () => {
    // A silent re-authorization one minute before the session's end.
    expect(refreshFamilyEnd(START, ONE_HOUR, START + MINUTE)).toBe(START + MINUTE);
  });

  it('keeps its start plus the limit when the session ends later', () => {
    expect(refreshFamilyEnd(START, ONE_HOUR, START + 90 * MINUTE)).toBe(START + 60 * MINUTE);
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
    expect(refreshTokenExpiresAt(now, ONE_WEEK, refreshFamilyEnd(START, ONE_HOUR, null))).toBe(
      START + 60 * MINUTE
    );
  });

  it('slides as before when the family has no end', () => {
    const now = START + 59 * MINUTE;
    expect(refreshTokenExpiresAt(now, ONE_WEEK, null)).toBe(now + ONE_WEEK * 1000);
  });
});

describe('isBrowserBasedClient (RFC 10017, #928)', () => {
  const web = 'https://app.example.com/callback';
  const loopback = 'http://127.0.0.1/callback';
  const privateUse = 'com.example.app:/callback';

  it('is a public client with a web redirect URI', () => {
    expect(isBrowserBasedClient({ tokenEndpointAuthMethod: 'none', redirectUris: [web] })).toBe(
      true
    );
  });

  it('is a public client with a web redirect URI beside native ones', () => {
    expect(
      isBrowserBasedClient({
        tokenEndpointAuthMethod: 'none',
        redirectUris: [loopback, privateUse, web],
      })
    ).toBe(true);
  });

  it('is a public client with no redirect URI at all', () => {
    expect(isBrowserBasedClient({ tokenEndpointAuthMethod: 'none', redirectUris: [] })).toBe(true);
    expect(isBrowserBasedClient({ tokenEndpointAuthMethod: 'none' })).toBe(true);
  });

  it('is not a public client whose every redirect URI is a native app’s', () => {
    for (const redirectUris of [[loopback], [privateUse], [loopback, privateUse]]) {
      expect(isBrowserBasedClient({ tokenEndpointAuthMethod: 'none', redirectUris })).toBe(false);
    }
  });

  it('is never a confidential client, nor one whose auth method is absent', () => {
    for (const tokenEndpointAuthMethod of [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
      undefined,
    ]) {
      expect(isBrowserBasedClient({ tokenEndpointAuthMethod, redirectUris: [web] })).toBe(false);
    }
  });
});

describe('rotatedRefreshTokenExpiresAt (#928)', () => {
  const firstExpiry = START + ONE_WEEK * 1000;

  it('holds a browser-based client’s token at the expiry of the one it replaces', () => {
    const now = START + 3 * 24 * 60 * MINUTE;
    expect(rotatedRefreshTokenExpiresAt(now, ONE_WEEK, null, firstExpiry, true)).toBe(firstExpiry);
  });

  it('slides for every other client, as refreshTokenExpiresAt does', () => {
    const now = START + 3 * 24 * 60 * MINUTE;
    expect(rotatedRefreshTokenExpiresAt(now, ONE_WEEK, null, firstExpiry, false)).toBe(
      now + ONE_WEEK * 1000
    );
  });

  it('is not lengthened by a realm that raised its refresh lifetime since', () => {
    const now = START + MINUTE;
    expect(rotatedRefreshTokenExpiresAt(now, 4 * ONE_WEEK, null, firstExpiry, true)).toBe(
      firstExpiry
    );
  });

  it('is shortened by a realm that lowered its refresh lifetime or ends the family sooner', () => {
    const now = START + MINUTE;
    expect(rotatedRefreshTokenExpiresAt(now, ONE_HOUR, null, firstExpiry, true)).toBe(
      now + 60 * MINUTE
    );
    const familyEnd = refreshFamilyEnd(START, ONE_HOUR, null);
    expect(rotatedRefreshTokenExpiresAt(now, ONE_WEEK, familyEnd, firstExpiry, true)).toBe(
      START + 60 * MINUTE
    );
  });
});

describe('refreshFamilyEnded (#552)', () => {
  const end = refreshFamilyEnd(START, ONE_HOUR, null);

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
