import {
  type DcqlQuery,
  DENY_ALL_TRUST_REGISTRY,
  ISSUER_TRUST_REJECTION_MESSAGE,
  issuerTrustRejection,
  type PresentedCredential,
  type TrustRegistry,
  VERIFIER_PROFILES,
} from '@qauth-labs/server-federation';
import { describe, expect, it, vi } from 'vitest';

import {
  createConfiguredIssuerKeyResolver,
  verifyWalletPresentations,
  type WalletCredentialRefusal,
} from './wallet-credential-verification';

/**
 * The #234 + #236 composition (issue #238).
 *
 * What is worth testing HERE is the composition, not the halves: each half is
 * exhaustively covered in `server-federation` against real signatures. The
 * properties below are the ones that only exist because the two are joined —
 * every refusal renders identically, an empty batch is a refusal rather than a
 * vacuous success, and the server-side reason reaches the operator and only the
 * operator.
 */

/**
 * The refusal class, obtained from the factory rather than imported.
 *
 * `@qauth-labs/shared-errors` is not a dependency of this plugin — it reaches
 * the module under test transitively, through `server-federation` — and adding
 * it just so a test can name a class would make the dependency graph lie about
 * what this package needs.
 */
const REFUSAL_CLASS = issuerTrustRejection().constructor as new () => Error;

const PROFILE = VERIFIER_PROFILES['oid4vp-1.0-base'];

const QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'qauth_wallet_login',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://credentials.example.com/pid'] },
    },
  ],
};

const P256_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

const TRUST_EVERYTHING: TrustRegistry = { isTrusted: () => true };

function malformed(): PresentedCredential[] {
  return [
    { queryId: 'qauth_wallet_login', format: 'dc+sd-jwt', presentation: 'not-a-presentation' },
  ];
}

function optionsOf(overrides: Partial<Parameters<typeof verifyWalletPresentations>[1]> = {}) {
  return {
    profile: PROFILE,
    clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
    nonce: 'n-0S6_WzA2Mj',
    dcqlQuery: QUERY,
    resolveIssuerKey: async () => undefined,
    trustRegistry: TRUST_EVERYTHING,
    // Stated, not omitted (#378) — the seam requires every caller to say
    // whether it wired a checker. These cases exercise the earlier gates, which
    // refuse before a status list is ever consulted.
    credentialStatus: undefined,
    ...overrides,
  };
}

describe('verifyWalletPresentations — one refusal, always (#236)', () => {
  it('refuses an EMPTY batch rather than succeeding vacuously', async () => {
    // The classic way an "all credentials are trusted" loop authenticates
    // nobody's credential: `[].every(...)` is `true`.
    await expect(verifyWalletPresentations([], optionsOf())).rejects.toBeInstanceOf(REFUSAL_CLASS);
  });

  it('refuses a malformed presentation with the SAME error an untrusted issuer gets', async () => {
    const malformedError = await verifyWalletPresentations(malformed(), optionsOf()).catch(
      (error: unknown) => error
    );
    const untrustedError = await verifyWalletPresentations(
      malformed(),
      optionsOf({ trustRegistry: DENY_ALL_TRUST_REGISTRY })
    ).catch((error: unknown) => error);

    expect(malformedError).toBeInstanceOf(REFUSAL_CLASS);
    expect(untrustedError).toBeInstanceOf(REFUSAL_CLASS);
    expect((malformedError as Error).message).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
    expect((untrustedError as Error).message).toBe((untrustedError as Error).message);
    expect((malformedError as Error).message).toBe((untrustedError as Error).message);
  });

  it('carries no reason, no issuer and no realm on the thrown error', async () => {
    // Anything attached here reaches the wire through the global error handler,
    // and a per-case detail is the membership oracle #236 exists to close.
    const error = (await verifyWalletPresentations(malformed(), optionsOf()).catch(
      (caught: unknown) => caught
    )) as Error;

    expect(error.message).toBe(ISSUER_TRUST_REJECTION_MESSAGE);
    expect(JSON.stringify(error)).not.toContain('malformed');
  });

  it('reports the server-side reason to the operator, naming the GATE', async () => {
    const refusals: WalletCredentialRefusal[] = [];
    await verifyWalletPresentations(
      malformed(),
      optionsOf({ onRefusal: (refusal) => refusals.push(refusal) })
    ).catch(() => undefined);

    expect(refusals).toHaveLength(1);
    expect(refusals[0]?.gate).toBe('validation');
    expect(refusals[0]?.detail.length).toBeGreaterThan(0);
  });

  it('does not let a throwing reporter turn a refusal into a fault', async () => {
    const error = await verifyWalletPresentations(
      malformed(),
      optionsOf({
        onRefusal: () => {
          throw new Error('logger exploded');
        },
      })
    ).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(REFUSAL_CLASS);
  });

  it('refuses when no trust registry is available at all', async () => {
    await expect(
      verifyWalletPresentations(
        malformed(),
        optionsOf({ trustRegistry: undefined as unknown as TrustRegistry })
      )
    ).rejects.toBeInstanceOf(REFUSAL_CLASS);
  });

  it('refuses a credential format the profile does not permit', async () => {
    // Profile-driven, not hard-coded: the base profile permits only
    // `dc+sd-jwt`, so an `mso_mdoc` presentation is refused before any adapter
    // is consulted.
    await expect(
      verifyWalletPresentations(
        [{ queryId: 'qauth_wallet_login', format: 'mso_mdoc', presentation: 'x' }],
        optionsOf()
      )
    ).rejects.toBeInstanceOf(REFUSAL_CLASS);
  });

  it('refuses an empty client_id or nonce rather than treating them as "no check"', async () => {
    // A presentation validated against an empty `aud`/`nonce` would not have a
    // weakened binding — it would have none.
    await expect(
      verifyWalletPresentations(malformed(), optionsOf({ clientId: '' }))
    ).rejects.toBeInstanceOf(REFUSAL_CLASS);
    await expect(
      verifyWalletPresentations(malformed(), optionsOf({ nonce: '' }))
    ).rejects.toBeInstanceOf(REFUSAL_CLASS);
  });

  it('propagates a genuine FAULT instead of laundering it into an auth failure', async () => {
    // A broken deployment must not look like a wallet presenting a bad
    // credential — the two need different operator responses.
    const boom = new Error('the process is on fire');
    await expect(
      verifyWalletPresentations(
        malformed(),
        optionsOf({
          dcqlQuery: {
            get credentials(): never {
              throw boom;
            },
          } as unknown as DcqlQuery,
        })
      )
    ).rejects.toBe(boom);
  });
});

describe('createConfiguredIssuerKeyResolver (#234)', () => {
  it('resolves nothing for an issuer that is not configured', async () => {
    const resolve = createConfiguredIssuerKeyResolver({ 'https://a.example': [P256_JWK] });

    await expect(
      resolve({ issuer: 'https://b.example', algorithm: 'ES256' })
    ).resolves.toBeUndefined();
  });

  it('resolves a configured issuer’s single key', async () => {
    const resolve = createConfiguredIssuerKeyResolver({ 'https://a.example': [P256_JWK] });
    const resolved = await resolve({ issuer: 'https://a.example', algorithm: 'ES256' });

    expect(resolved?.identifier).toBe('https://a.example');
    expect(resolved?.keyResolution).toBe('issuer-metadata');
  });

  it('resolves nothing when an issuer has several keys and the credential names none', async () => {
    // Guessing is how a rotated-out key stays live.
    const resolve = createConfiguredIssuerKeyResolver({
      'https://a.example': [
        { ...P256_JWK, kid: 'k1' },
        { ...P256_JWK, kid: 'k2' },
      ],
    });

    await expect(
      resolve({ issuer: 'https://a.example', algorithm: 'ES256' })
    ).resolves.toBeUndefined();
  });

  it('builds an empty resolver from an unconfigured deployment, and it refuses everything', async () => {
    const resolve = createConfiguredIssuerKeyResolver({});

    await expect(
      resolve({ issuer: 'https://a.example', algorithm: 'ES256' })
    ).resolves.toBeUndefined();
  });

  it('throws at construction on a malformed entry — a mis-provisioned deployment', () => {
    expect(() => createConfiguredIssuerKeyResolver({ 'not-a-url': [P256_JWK] })).toThrow();
  });
});

describe('verifyWalletPresentations — the seam authenticates nobody', () => {
  it('never consults the account store, the session, or anything user-shaped', async () => {
    // Structural: the options object carries a profile, two request bindings, a
    // query, a key backend, a trust registry and a revocation checker — and
    // nothing that names a person. A trusted credential is a finding about a
    // document; which USER it belongs to is #300's question.
    //
    // `credentialStatus` (#378) belongs on this list for the same reason
    // `trustRegistry` does: it is DEPLOYMENT configuration, resolved from env
    // before any presentation arrives. It is asserted here rather than excused
    // because this list is the guard that would catch a user-shaped input being
    // added to the seam, and a guard nobody updates deliberately is a guard
    // someone eventually updates carelessly.
    const options = optionsOf();

    expect(Object.keys(options).sort()).toEqual([
      'clientId',
      'credentialStatus',
      'dcqlQuery',
      'nonce',
      'profile',
      'resolveIssuerKey',
      'trustRegistry',
    ]);
  });

  it('does not call the issuer key backend for a batch it refuses structurally', async () => {
    const resolveIssuerKey = vi.fn(async () => undefined);

    await verifyWalletPresentations([], optionsOf({ resolveIssuerKey })).catch(() => undefined);

    expect(resolveIssuerKey).not.toHaveBeenCalled();
  });
});
