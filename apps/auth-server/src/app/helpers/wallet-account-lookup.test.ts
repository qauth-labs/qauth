import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { createWalletAccountLookup } from './wallet-account-lookup';

/**
 * The account store behind `SubjectAccountLookup` (#238, ADR-009 / #300).
 *
 * The strategies are tested against real credentials in `server-federation`.
 * What is testable — and load-bearing — here is the PROJECTION: which rows a
 * lookup returns, and what `walletBinding` they carry. Two mistakes in this
 * mapping are silent authentication bypasses, and both are pinned below:
 * hiding the password row (which hides ADR-009's second bootstrap case), and
 * reading a binding out of a row that does not carry one.
 */

const BINDING = `wb1:${'a'.repeat(64)}`;

function fastifyWith(rows: {
  byExternalSub?: unknown[];
  byProviderSub?: unknown;
}): FastifyInstance {
  return {
    repositories: {
      userCredentials: {
        findAllByRealmAndExternalSub: vi.fn().mockResolvedValue(rows.byExternalSub ?? []),
        findByRealmProviderSub: vi.fn().mockResolvedValue(rows.byProviderSub),
      },
    },
  } as unknown as FastifyInstance;
}

describe('byAssertedIdentifier — every provider type, not just wallet (#238)', () => {
  it('returns the password row with NO binding, so bootstrap case 2 stays visible', async () => {
    // ADR-009: "An account already exists without a wallet binding (typically a
    // password account on the same email) — the presentation MUST NOT silently
    // create one." The strategy can only refuse that case if it SEES the row.
    const lookup = createWalletAccountLookup(
      fastifyWith({
        byExternalSub: [
          {
            userId: 'user-1',
            providerType: 'password',
            credentialData: { password_hash: 'x', email_verified: true },
          },
        ],
      })
    );

    await expect(lookup.byAssertedIdentifier('realm-1', 'a@example.com')).resolves.toEqual([
      { userId: 'user-1', walletBinding: null },
    ]);
  });

  it('returns both rows of a linked account, so a matching presentation authenticates', async () => {
    const lookup = createWalletAccountLookup(
      fastifyWith({
        byExternalSub: [
          { userId: 'user-1', providerType: 'password', credentialData: {} },
          {
            userId: 'user-1',
            providerType: 'wallet',
            credentialData: { wallet_binding: BINDING, issuer: 'https://i', vct: 'v' },
          },
        ],
      })
    );

    await expect(lookup.byAssertedIdentifier('realm-1', 'a@example.com')).resolves.toEqual([
      { userId: 'user-1', walletBinding: null },
      { userId: 'user-1', walletBinding: BINDING },
    ]);
  });

  it('never reads a binding out of a non-wallet row', async () => {
    // A password row whose `credential_data` happened to carry a `wallet_binding`
    // key — through corruption or a future migration — must not contribute one.
    const lookup = createWalletAccountLookup(
      fastifyWith({
        byExternalSub: [
          {
            userId: 'user-1',
            providerType: 'password',
            credentialData: { wallet_binding: BINDING, issuer: 'https://i', vct: 'v' },
          },
        ],
      })
    );

    await expect(lookup.byAssertedIdentifier('realm-1', 'a@example.com')).resolves.toEqual([
      { userId: 'user-1', walletBinding: null },
    ]);
  });

  it('degrades an unparseable wallet credential_data to null, never to a value', async () => {
    const lookup = createWalletAccountLookup(
      fastifyWith({
        byExternalSub: [{ userId: 'user-1', providerType: 'wallet', credentialData: {} }],
      })
    );

    await expect(lookup.byAssertedIdentifier('realm-1', 'a@example.com')).resolves.toEqual([
      { userId: 'user-1', walletBinding: null },
    ]);
  });

  it('reports "nothing found" as an empty array, never null', async () => {
    // The port's contract: `null` would be a value the strategies do not handle,
    // and `Array.isArray` failing there is treated as a REFUSAL rather than as
    // "no account" — correct, but it would hide the real answer.
    const lookup = createWalletAccountLookup(fastifyWith({}));

    await expect(lookup.byAssertedIdentifier('realm-1', 'a@example.com')).resolves.toEqual([]);
  });

  it('lets a database failure propagate to the strategy’s containment', async () => {
    // Swallowing it here would turn a broken database into "no such account" —
    // a `no-match` a caller is allowed to enrol over.
    const boom = new Error('database is down');
    const fastify = {
      repositories: {
        userCredentials: {
          findAllByRealmAndExternalSub: vi.fn().mockRejectedValue(boom),
          findByRealmProviderSub: vi.fn(),
        },
      },
    } as unknown as FastifyInstance;

    await expect(
      createWalletAccountLookup(fastify).byAssertedIdentifier('realm-1', 'a@example.com')
    ).rejects.toBe(boom);
  });
});

describe('byWalletSubject — wallet rows only (#238)', () => {
  it('resolves a wallet credential to its account and binding', async () => {
    const lookup = createWalletAccountLookup(
      fastifyWith({
        byProviderSub: {
          userId: 'user-2',
          providerType: 'wallet',
          credentialData: { wallet_binding: BINDING, issuer: 'https://i', vct: 'v' },
        },
      })
    );

    await expect(lookup.byWalletSubject('realm-1', 'isc1:abc')).resolves.toEqual([
      { userId: 'user-2', walletBinding: BINDING },
    ]);
  });

  it('asks the repository for the WALLET provider type only', async () => {
    const findByRealmProviderSub = vi.fn().mockResolvedValue(undefined);
    const fastify = {
      repositories: {
        userCredentials: { findAllByRealmAndExternalSub: vi.fn(), findByRealmProviderSub },
      },
    } as unknown as FastifyInstance;

    await createWalletAccountLookup(fastify).byWalletSubject('realm-1', 'isc1:abc');

    expect(findByRealmProviderSub).toHaveBeenCalledWith('realm-1', 'wallet', 'isc1:abc');
  });

  it('returns an empty array when nothing holds that subject', async () => {
    const lookup = createWalletAccountLookup(fastifyWith({ byProviderSub: undefined }));

    await expect(lookup.byWalletSubject('realm-1', 'isc1:abc')).resolves.toEqual([]);
  });
});
