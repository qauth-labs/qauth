import { describe, expect, it } from 'vitest';

import type { UnshowableRedirectUriScan } from '../types';
import {
  describeUnshowableRedirectUris,
  parseListUnshowableArgs,
  REDIRECT_URI_FIXES,
} from './unshowable-redirect-uris';

/**
 * Arguments and report of the operator's listing command (#914). The database
 * half, `listUnshowableRedirectUris`, is covered against real Postgres in
 * `unshowable-redirect-uris.integration.test.ts`.
 */
describe('parseListUnshowableArgs', () => {
  const argv = (...args: string[]) => ['node', 'list-unshowable-redirect-uris.ts', ...args];

  it('lists every realm by default, or the named one', () => {
    expect(parseListUnshowableArgs(argv())).toEqual({});
    expect(parseListUnshowableArgs(argv('--realm=master'))).toEqual({ realm: 'master' });
  });

  it.each([[['--realm=']], [['--json']], [['master']], [['--realm=master', '--all']]])(
    'refuses %j instead of guessing',
    (args) => {
      expect(parseListUnshowableArgs(argv(...args))).toBeNull();
    }
  );
});

describe('describeUnshowableRedirectUris', () => {
  it('says so when no client holds such a URI', () => {
    expect(describeUnshowableRedirectUris({ clients: [], scanned: 3, complete: true })).toBe(
      'No client holds a redirect URI the consent screen cannot show (3 clients read).'
    );
  });

  it('lists the clients per realm, with why each URI fails and how to replace it', () => {
    const scan: UnshowableRedirectUriScan = {
      clients: [
        {
          id: 'c1',
          realmId: 'r2',
          realmName: 'acme',
          clientId: 'https://agent.example.com/client.json',
          source: 'cimd',
          redirectUris: [{ uri: 'https://my_agent.example.com/cb', reason: 'host' }],
        },
        {
          id: 'c2',
          realmId: 'r1',
          realmName: 'master',
          clientId: 'notes',
          source: 'operator',
          redirectUris: [
            { uri: 'https://[2001:db8::1]/cb', reason: 'ip_literal' },
            { uri: 'not a url', reason: 'unparseable' },
          ],
        },
      ],
      scanned: 40,
      complete: true,
    };

    expect(describeUnshowableRedirectUris(scan).split('\n')).toEqual([
      'Realm "acme" (r2)',
      '  client "https://agent.example.com/client.json" (CIMD)',
      '    "https://my_agent.example.com/cb": its host is not a DNS name of valid labels (an underscore, an empty label, a label over 63 characters or with a hyphen at either end)',
      `    To fix: ${REDIRECT_URI_FIXES.cimd}`,
      '',
      'Realm "master" (r1)',
      '  client "notes" (operator-provisioned)',
      '    "https://[2001:db8::1]/cb": its host is an IPv6 address that is not loopback',
      '    "not a url": not a URL',
      `    To fix: ${REDIRECT_URI_FIXES.operator}`,
      '',
      '2 clients in 2 realms hold a redirect URI the consent screen cannot show (40 clients read). The screen refuses such a URI with invalid_request; replace each one as its client says.',
    ]);
  });

  it('prints a control character a stored value carries escaped, never raw', () => {
    const report = describeUnshowableRedirectUris({
      clients: [
        {
          id: 'c1',
          realmId: 'r1',
          realmName: 'master',
          clientId: 'evil\u001b[2Jclient',
          source: 'other',
          redirectUris: [{ uri: 'https://a_b.example/\u001b]0;x\u0007', reason: 'host' }],
        },
      ],
      scanned: 1,
      complete: true,
    });
    expect(report).not.toContain('\u001b');
    expect(report).not.toContain('\u0007');
    expect(report).toContain('client "evil\\u001b[2Jclient" (unmarked)');
    expect(report).toContain('1 client in 1 realm holds');
  });
});
