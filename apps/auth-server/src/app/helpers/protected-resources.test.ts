import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import { CONSENT_TEXT_PATTERN } from '@qauth-labs/shared-validation';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { DYNAMIC_CLIENT_BADGE_DAYS: 30 } }));

import { filterRequestedScopes } from './consent';
import {
  grantRequestedScopes,
  isScopeGrantable,
  type RegisteredResource,
  registeredResourcesOf,
  resourceScopeDisplay,
  scopeCeilingAt,
  uiLocalesOf,
  withoutUngrantedResourceScopes,
} from './protected-resources';

/**
 * The scope rule of a registered protected resource (#1087): a scope it
 * defines is granted only for that resource, to a client it is open to,
 * whatever the client's own list holds, and dropped otherwise.
 */

const FILES = 'https://files.example/mcp';
const MAIL = 'https://mail.example/mcp';

const files: RegisteredResource = {
  resource: FILES,
  scopes: [
    {
      scope: 'files:read',
      text: { en: 'Read your files', tr: 'Dosyalarınızı okusun', pt: 'Ler os seus arquivos' },
      sensitive: false,
    },
    { scope: 'files:write', text: { en: 'Change your files' }, sensitive: true },
  ],
  anyClient: true,
  clientIds: [],
};

const mail: RegisteredResource = {
  resource: MAIL,
  scopes: [{ scope: 'mail:send', text: { en: 'Send mail as you' }, sensitive: true }],
  anyClient: false,
  clientIds: ['mail-app'],
};

const registered = [files, mail];

/** A CIMD client: no scope list of its own. */
const cimd = { clientId: 'https://agent.example/client.json', scopes: [] as string[] };

describe('grantRequestedScopes', () => {
  it('grants a registered scope to a client with no scope list, for the resource that defines it', () => {
    expect(grantRequestedScopes('files:read files:write', cimd, [FILES], registered)).toEqual([
      'files:read',
      'files:write',
    ]);
  });

  it('drops it without its resource, or with another', () => {
    expect(grantRequestedScopes('files:read', cimd, [], registered)).toEqual([]);
    expect(grantRequestedScopes('files:read', cimd, [MAIL], registered)).toEqual([]);
    expect(
      grantRequestedScopes('files:read', cimd, ['https://other.example/'], registered)
    ).toEqual([]);
  });

  it('drops it without its resource even when the client lists it itself', () => {
    const listing = { clientId: 'app', scopes: ['files:read', 'openid'] };
    expect(grantRequestedScopes('openid files:read', listing, [], registered)).toEqual(['openid']);
    expect(grantRequestedScopes('openid files:read', listing, [FILES], registered)).toEqual([
      'openid',
      'files:read',
    ]);
  });

  it('grants nothing of a resource to a client outside its list', () => {
    expect(grantRequestedScopes('mail:send', cimd, [MAIL], registered)).toEqual([]);
    const listed = { clientId: 'mail-app', scopes: [] };
    expect(grantRequestedScopes('mail:send', listed, [MAIL], registered)).toEqual(['mail:send']);
    // Its own list does not let an unlisted client in.
    const unlisted = { clientId: 'other', scopes: ['mail:send'] };
    expect(grantRequestedScopes('mail:send', unlisted, [MAIL], registered)).toEqual([]);
  });

  it('keeps the client list as the ceiling of every other scope', () => {
    expect(grantRequestedScopes('openid profile files:read', cimd, [FILES], registered)).toEqual([
      'files:read',
    ]);
    const app = { clientId: 'app', scopes: ['openid', 'notes:read'] };
    expect(grantRequestedScopes('openid notes:read', app, [FILES], registered)).toEqual([
      'openid',
      'notes:read',
    ]);
  });

  it('grants a scope for several resources only when each of them grants it', () => {
    // Each resource defines a scope the other does not: neither reaches a
    // token whose `aud` names the other one too.
    const listed = { clientId: 'mail-app', scopes: [] };
    expect(grantRequestedScopes('files:read mail:send', listed, [FILES, MAIL], registered)).toEqual(
      []
    );
    // Two resources that both define it and are both open to the client.
    const MIRROR = 'https://mirror.example/mcp';
    const mirror: RegisteredResource = { ...files, resource: MIRROR };
    expect(grantRequestedScopes('files:read', cimd, [FILES, MIRROR], [files, mirror])).toEqual([
      'files:read',
    ]);
    expect(scopeCeilingAt(cimd, [FILES, MIRROR], [files, mirror])).toContain('files:read');
    // A resource of the same scope name closed to the client, or one the realm
    // does not know, lets nothing through.
    const closedMirror: RegisteredResource = {
      ...mirror,
      anyClient: false,
      clientIds: ['trusted'],
    };
    expect(
      grantRequestedScopes('files:read', cimd, [FILES, MIRROR], [files, closedMirror])
    ).toEqual([]);
    expect(
      grantRequestedScopes('files:read', cimd, [FILES, 'https://unknown.example/'], registered)
    ).toEqual([]);
    expect(withoutUngrantedResourceScopes(['files:read'], cimd, [FILES, MAIL], registered)).toEqual(
      []
    );
    expect(scopeCeilingAt(cimd, [FILES, MAIL], registered)).toEqual([]);
  });

  it('keeps the request order and lists each scope once', () => {
    expect(
      grantRequestedScopes('files:write  files:read files:write', cimd, [FILES], registered)
    ).toEqual(['files:write', 'files:read']);
  });

  it('is the client allowlist alone when the realm registers no resource', () => {
    const app = { clientId: 'app', scopes: ['openid', 'files:read'] };
    for (const raw of ['openid files:read', 'files:read files:write', '', undefined]) {
      expect(grantRequestedScopes(raw, app, [], [])).toEqual(
        filterRequestedScopes(raw, { ...app, isAgent: false } as never)
      );
    }
  });
});

describe('isScopeGrantable', () => {
  it('reads an Object.prototype name as a scope like any other', () => {
    expect(isScopeGrantable('constructor', cimd, [FILES], registered)).toBe(false);
    expect(isScopeGrantable('toString', { clientId: 'a', scopes: [] }, [], registered)).toBe(false);
  });
});

describe('withoutUngrantedResourceScopes (the token endpoint)', () => {
  it('drops the scopes of a resource a narrowed audience leaves out', () => {
    const listed = { clientId: 'mail-app' };
    expect(
      withoutUngrantedResourceScopes(
        ['openid', 'files:read', 'mail:send'],
        listed,
        [MAIL],
        registered
      )
    ).toEqual(['openid', 'mail:send']);
  });

  it('drops the scopes of a resource closed to the client since', () => {
    const closed: RegisteredResource = { ...files, anyClient: false, clientIds: ['someone-else'] };
    expect(withoutUngrantedResourceScopes(['files:read'], cimd, [FILES], [closed])).toEqual([]);
  });

  it('keeps every scope no registered resource defines', () => {
    expect(withoutUngrantedResourceScopes(['openid', 'notes:read'], cimd, [], registered)).toEqual([
      'openid',
      'notes:read',
    ]);
  });
});

describe('scopeCeilingAt (the refresh grant)', () => {
  it('is the client list without registered scopes, with those its resources grant', () => {
    const app = { clientId: 'app', scopes: ['openid', 'files:read', 'mail:send'] };
    expect(new Set(scopeCeilingAt(app, [FILES], registered))).toEqual(
      new Set(['openid', 'files:read', 'files:write'])
    );
    expect(scopeCeilingAt(app, [], registered)).toEqual(['openid']);
  });
});

describe('resourceScopeDisplay (the consent step)', () => {
  it('shows the text in the first locale the resource has, else English', () => {
    expect(resourceScopeDisplay('files:read', cimd, [FILES], registered, ['tr'])).toEqual({
      text: 'Dosyalarınızı okusun',
      sensitive: false,
    });
    expect(resourceScopeDisplay('files:read', cimd, [FILES], registered, ['de', 'pt-BR'])).toEqual({
      text: 'Ler os seus arquivos',
      sensitive: false,
    });
    expect(resourceScopeDisplay('files:read', cimd, [FILES], registered, ['de'])).toEqual({
      text: 'Read your files',
      sensitive: false,
    });
    expect(resourceScopeDisplay('files:write', cimd, [FILES], registered, [])).toEqual({
      text: 'Change your files',
      sensitive: true,
    });
  });

  it('shows nothing for a scope no resource grants this request', () => {
    expect(resourceScopeDisplay('files:read', cimd, [], registered, ['en'])).toBeUndefined();
    expect(resourceScopeDisplay('mail:send', cimd, [MAIL], registered, ['en'])).toBeUndefined();
    expect(resourceScopeDisplay('openid', cimd, [FILES], registered, ['en'])).toBeUndefined();
  });

  it('leaves out a stored text the step could not show', () => {
    const handWritten: RegisteredResource = {
      ...files,
      scopes: [{ scope: 'files:read', text: { en: '<b>Read</b>' }, sensitive: false }],
    };
    expect(resourceScopeDisplay('files:read', cimd, [FILES], [handWritten], [])).toEqual({
      text: undefined,
      sensitive: false,
    });
    const tooLong: RegisteredResource = {
      ...files,
      scopes: [{ scope: 'files:read', text: { en: 'x'.repeat(281) }, sensitive: false }],
    };
    expect(resourceScopeDisplay('files:read', cimd, [FILES], [tooLong], [])?.text).toBeUndefined();
  });
});

describe('uiLocalesOf', () => {
  it('reads the well-formed tags of ui_locales, in order, at most eight', () => {
    expect(uiLocalesOf(undefined)).toEqual([]);
    expect(uiLocalesOf('tr  en-US')).toEqual(['tr', 'en-US']);
    expect(uiLocalesOf('fr-CA <x> en 1x')).toEqual(['fr-CA', 'en']);
    expect(uiLocalesOf('a1 b2 aa ab ac ad ae af ag ah ai')).toEqual([
      'aa',
      'ab',
      'ac',
      'ad',
      'ae',
      'af',
      'ag',
      'ah',
    ]);
  });
});

describe('registeredResourcesOf', () => {
  it("reads the realm's list, in the transaction when given", async () => {
    const listByRealm = vi.fn().mockResolvedValue([files]);
    const fastify = { repositories: { protectedResources: { listByRealm } } } as never;
    expect(await registeredResourcesOf(fastify, 'realm-1')).toEqual([files]);
    const tx = {} as never;
    await registeredResourcesOf(fastify, 'realm-1', tx);
    expect(listByRealm).toHaveBeenLastCalledWith('realm-1', tx);
  });
});

describe('the consent text a resource stores', () => {
  it('is one the consent step shows: the shared rule is the contract pattern', () => {
    expect(CONSENT_TEXT_PATTERN).toBe(DISPLAY_TEXT_PATTERN);
  });
});
