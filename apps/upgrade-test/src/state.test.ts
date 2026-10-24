import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import {
  parseState,
  readState,
  STATE_FORMAT,
  StateFileError,
  type UpgradeState,
  writeState,
} from './state';

const STATE: UpgradeState = {
  format: STATE_FORMAT,
  baseUrl: 'http://localhost:3000',
  populatedAt: 1_792_879_968,
  developer: { userId: 'u-1', email: 'dev@example.com', password: 'p-1' },
  endUser: { userId: 'u-2', email: 'user@example.com', password: 'p-2' },
  appClient: {
    id: 'c-1',
    clientId: 'app',
    clientSecret: 's-1',
    redirectUri: 'http://127.0.0.1:9/cb',
  },
  devClient: { id: 'c-2', clientId: 'tool', clientSecret: 's-2' },
  tokens: {
    accessToken: 'a.b.c',
    accessTokenExpiresAt: 1_792_880_867,
    refreshToken: 'r-1',
    idToken: null,
  },
  consent: { clientId: 'app', scopes: ['openid', 'offline_access'] },
  apiKey: {
    id: 'k-1',
    key: 'qauth_0123456789abcdef_ff',
    prefix: 'qauth_0123456789abcdef',
    last4: '00ff',
  },
};

const dir = mkdtempSync(join(tmpdir(), 'upgrade-state-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('the state file', () => {
  it('round-trips, readable by the owner only', () => {
    const path = join(dir, 'state.json');
    writeState(path, STATE);
    expect(readState(path)).toEqual(STATE);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it('carries a release-candidate format id until 1.0 (ADR-018 §5)', () => {
    expect(STATE_FORMAT).toBe('qauth-upgrade-state/1-rc.0');
  });

  it('refuses another format', () => {
    expect(() => parseState('s.json', { ...STATE, format: 'qauth-upgrade-state/1' })).toThrow(
      /has format "qauth-upgrade-state\/1", expected qauth-upgrade-state\/1-rc\.0/
    );
  });

  it.each([
    ['tokens.refreshToken', { ...STATE, tokens: { ...STATE.tokens, refreshToken: '' } }],
    ['apiKey.key', { ...STATE, apiKey: { ...STATE.apiKey, key: undefined } }],
    ['endUser.password', { ...STATE, endUser: { userId: 'u-2', email: 'user@example.com' } }],
    [
      'tokens.accessTokenExpiresAt',
      { ...STATE, tokens: { ...STATE.tokens, accessTokenExpiresAt: '1' } },
    ],
  ])('names a missing or mistyped %s', (field, document) => {
    expect(() => parseState('s.json', document)).toThrow(StateFileError);
    expect(() => parseState('s.json', document)).toThrow(`has no ${field}`);
  });

  it('refuses consent scopes that are not a list of strings', () => {
    expect(() =>
      parseState('s.json', { ...STATE, consent: { clientId: 'app', scopes: 'openid' } })
    ).toThrow(/consent\.scopes/);
  });

  it('says the populate step may not have run when the file is missing', () => {
    expect(() => readState(join(dir, 'missing.json'))).toThrow(/Did the populate step run\?/);
  });

  it('refuses a file that is not JSON', () => {
    const path = join(dir, 'broken.json');
    writeFileSync(path, '{');
    expect(() => readState(path)).toThrow(/is not valid JSON/);
  });
});
