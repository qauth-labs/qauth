import { describe, expect, it, vi } from 'vitest';

import {
  type RedirectUriScanRow,
  redirectUriSource,
  scanUnshowableRedirectUris,
  unshowableRedirectUris,
} from './unshowable-redirect-uris';

/**
 * The scan behind the operator's listing command and the boot warning
 * (#914), against a page function instead of Postgres; the query itself is
 * covered by `oauth-clients.repository.test.ts` (its SQL shape) and the
 * scripts' integration suite.
 */

function row(id: string, redirectUris: unknown, extra: Partial<RedirectUriScanRow> = {}) {
  return {
    id,
    realmId: 'r1',
    realmName: 'master',
    clientId: `client-${id}`,
    redirectUris,
    metadata: null,
    provisionedByOperator: false,
    developerId: null,
    ...extra,
  } satisfies RedirectUriScanRow;
}

/** A page function over `rows`, in `id` order, as the repository's query reads them. */
function pages(rows: RedirectUriScanRow[]) {
  const sorted = [...rows].sort((a, b) => (a.id < b.id ? -1 : 1));
  return vi.fn(async (after: string | undefined, limit: number) =>
    sorted.filter((candidate) => after === undefined || candidate.id > after).slice(0, limit)
  );
}

describe('unshowableRedirectUris (#914)', () => {
  it('keeps only the URIs the consent screen cannot show, with why, in stored order', () => {
    expect(
      unshowableRedirectUris([
        'https://app.example.com/cb',
        'https://my_app.example.com/cb',
        'http://127.0.0.1:4000/cb',
        'https://[2001:db8::1]/cb',
        `com.example.${'a'.repeat(53)}:/cb`,
        'not a url',
      ])
    ).toEqual([
      { uri: 'https://my_app.example.com/cb', reason: 'host' },
      { uri: 'https://[2001:db8::1]/cb', reason: 'ip_literal' },
      { uri: `com.example.${'a'.repeat(53)}:/cb`, reason: 'scheme' },
      { uri: 'not a url', reason: 'unparseable' },
    ]);
  });

  it('reads nothing from a stored value that is not a list of strings', () => {
    expect(unshowableRedirectUris({ uri: 'https://my_app.example.com/cb' })).toEqual([]);
    expect(unshowableRedirectUris(null)).toEqual([]);
    expect(unshowableRedirectUris([42, 'https://ok.example.com/cb'])).toEqual([]);
  });
});

describe('redirectUriSource (#914)', () => {
  it('says who can change the redirect URIs, the CIMD mark first', () => {
    const base = { metadata: null, provisionedByOperator: false, developerId: null };
    expect(redirectUriSource({ ...base, metadata: { registrationType: 'cimd' } })).toBe('cimd');
    expect(
      redirectUriSource({
        ...base,
        metadata: { registrationType: 'cimd' },
        provisionedByOperator: true,
      })
    ).toBe('cimd');
    expect(redirectUriSource({ ...base, provisionedByOperator: true })).toBe('operator');
    expect(redirectUriSource({ ...base, developerId: 'u1' })).toBe('developer');
    expect(redirectUriSource({ ...base, metadata: { registrationType: 'dynamic' } })).toBe(
      'dynamic'
    );
    expect(redirectUriSource(base)).toBe('other');
  });
});

describe('scanUnshowableRedirectUris (#914)', () => {
  it('reads every page and keeps the clients with such a URI, by realm and client id', async () => {
    const page = pages([
      row('01', ['https://ok.example.com/cb']),
      row('02', ['https://bad_host.example.com/cb'], {
        realmId: 'r2',
        realmName: 'acme',
        clientId: 'zeta',
        developerId: 'u1',
      }),
      row('03', ['https://ok.example.com/cb', 'https://[2001:db8::2]/cb'], {
        clientId: 'beta',
        metadata: { registrationType: 'dynamic' },
      }),
      row('04', ['https://under_score.example/cb'], {
        realmId: 'r2',
        realmName: 'acme',
        clientId: 'alpha',
        provisionedByOperator: true,
      }),
      row('05', ['https://ok.example.com/cb']),
    ]);

    const scan = await scanUnshowableRedirectUris({ page, pageSize: 2 });

    expect(scan).toEqual({
      clients: [
        {
          id: '04',
          realmId: 'r2',
          realmName: 'acme',
          clientId: 'alpha',
          source: 'operator',
          redirectUris: [{ uri: 'https://under_score.example/cb', reason: 'host' }],
        },
        {
          id: '02',
          realmId: 'r2',
          realmName: 'acme',
          clientId: 'zeta',
          source: 'developer',
          redirectUris: [{ uri: 'https://bad_host.example.com/cb', reason: 'host' }],
        },
        {
          id: '03',
          realmId: 'r1',
          realmName: 'master',
          clientId: 'beta',
          source: 'dynamic',
          redirectUris: [{ uri: 'https://[2001:db8::2]/cb', reason: 'ip_literal' }],
        },
      ],
      scanned: 5,
      complete: true,
    });
    // Keyset pages: each starts after the last id of the one before.
    expect(page.mock.calls).toEqual([
      [undefined, 2],
      ['02', 2],
      ['04', 2],
    ]);
  });

  it('reads one more page after a full last page, and stops at an empty one', async () => {
    const page = pages([row('01', []), row('02', [])]);
    const scan = await scanUnshowableRedirectUris({ page, pageSize: 2 });
    expect(scan).toEqual({ clients: [], scanned: 2, complete: true });
    expect(page).toHaveBeenCalledTimes(2);
  });

  it('stops at the deadline and says the list is incomplete', async () => {
    let clock = 1_000;
    const page = vi.fn(async (after: string | undefined) => {
      clock += 600;
      return after === undefined
        ? [row('01', ['https://bad_host.example/cb']), row('02', [])]
        : [row('03', []), row('04', [])];
    });

    const scan = await scanUnshowableRedirectUris({
      page,
      pageSize: 2,
      deadline: 2_000,
      now: () => clock,
    });

    expect(scan.complete).toBe(false);
    expect(scan.scanned).toBe(4);
    expect(scan.clients.map((client) => client.clientId)).toEqual(['client-01']);
    expect(page).toHaveBeenCalledTimes(2);
  });

  it('reads nothing once the deadline has passed', async () => {
    const page = vi.fn(async () => [row('01', ['https://bad_host.example/cb'])]);
    const scan = await scanUnshowableRedirectUris({ page, deadline: 5, now: () => 5 });
    expect(scan).toEqual({ clients: [], scanned: 0, complete: false });
    expect(page).not.toHaveBeenCalled();
  });
});
