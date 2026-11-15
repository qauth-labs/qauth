import { describe, expect, it } from 'vitest';

import type { ProtectedResourceSettings } from '../lib/repositories/protected-resources.repository';
import { resourceChanges, settingsOf } from './protected-resource-seed';

/**
 * What a `resources` entry of the seed manifest writes and reports (#1087).
 * What it writes against real Postgres is held by
 * `protected-resource-seed.integration.test.ts`.
 */
describe('settingsOf', () => {
  it('writes any_client as an open resource with no list, and a list as it is', () => {
    const scopes = [{ scope: 'files:read', text: { en: 'Read your files' } }];
    expect(settingsOf({ resource: 'https://r.example', scopes, clients: 'any_client' })).toEqual({
      scopes: [{ scope: 'files:read', text: { en: 'Read your files' }, sensitive: false }],
      anyClient: true,
      clientIds: [],
    });
    expect(settingsOf({ resource: 'https://r.example', scopes, clients: ['app'] })).toMatchObject({
      anyClient: false,
      clientIds: ['app'],
    });
  });
});

describe('resourceChanges', () => {
  const before: ProtectedResourceSettings = {
    scopes: [
      { scope: 'files:read', text: { en: 'Read', tr: 'Oku' }, sensitive: false },
      { scope: 'files:write', text: { en: 'Write' }, sensitive: true },
    ],
    anyClient: false,
    clientIds: ['b', 'a'],
  };

  it('names nothing when the entry holds what is stored, whatever the order of its texts', () => {
    const same: ProtectedResourceSettings = {
      ...before,
      scopes: [
        { scope: 'files:read', text: { tr: 'Oku', en: 'Read' }, sensitive: false },
        before.scopes[1],
      ],
      clientIds: ['a', 'b'],
    };
    expect(resourceChanges(before, same)).toEqual([]);
  });

  it('names every scope added, changed or removed, and a widening of who may ask', () => {
    const after: ProtectedResourceSettings = {
      scopes: [
        { scope: 'files:read', text: { en: 'Read your files' }, sensitive: false },
        { scope: 'files:share', text: { en: 'Share' }, sensitive: false },
      ],
      anyClient: true,
      clientIds: [],
    };
    expect(resourceChanges(before, after)).toEqual([
      'scope changed: files:read',
      'scope added: files:share',
      'scope removed: files:write',
      'open to: a, b -> any client',
    ]);
  });

  it('names every scope and who may ask for a new registration', () => {
    expect(resourceChanges(undefined, before)).toEqual([
      'scope added: files:read',
      'scope added: files:write',
      'open to: a, b',
    ]);
  });
});
