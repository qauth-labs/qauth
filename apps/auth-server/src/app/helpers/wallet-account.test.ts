import {
  createSubjectResolutionStrategy,
  type CredentialStatusChecker,
  deriveEnrolmentWalletBinding,
  resolveTrustRegistry,
  type SubjectResolutionConfig,
  type ValidatedCredential,
  ValidatedIssuer,
  walletCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveWalletAccount } from './wallet-account';
import { createWalletAccountLookup } from './wallet-account-lookup';

/**
 * Wallet account resolution (#235, ADR-009).
 *
 * These tests drive the REAL `asserted-lookup` strategy rather than a stubbed
 * one. The strategy decides which account a presentation names, and whether the
 * presentation entitles its holder to it; ADR-009 §1 names that decision as the
 * likeliest thing to get wrong. A stub that never answered `no-match` is how the
 * "unknown and taken identifiers refuse identically" property went untested
 * while the code enrolled on `no-match` (ANT-2026-NCX3VXDP).
 *
 * The credentials are hand-built `ValidatedCredential` values carrying a genuine
 * `ValidatedIssuer`. The cryptography they would have passed is exercised
 * end-to-end in `libs/server/federation` against real signatures; what is under
 * test here is what gets WRITTEN.
 */

const REALM_ID = '11111111-1111-1111-1111-111111111111';
const ISSUER = 'https://issuer.example.com';
const VCT = 'https://credentials.example.com/pid';

const CONFIG: SubjectResolutionConfig = {
  strategy: 'asserted-lookup',
  bindingClaims: ['family_name', 'given_name'],
};

/** What every wallet row a credential from {@link ISSUER} writes records (ANT-2026-ULJIA4P4). */
const PROVENANCE = { issuer: ISSUER, issuer_key_resolution: 'issuer-metadata' };

/** The gates a sign-in re-asks about the rows an earlier presentation left. */
const GATES = {
  trustRegistry: resolveTrustRegistry(
    { name: 'master' },
    { OID4VP_TRUSTED_ISSUERS: { master: [ISSUER] } }
  ),
  credentialStatus: undefined as CredentialStatusChecker | undefined,
};

/** A validated credential, with a genuine branded issuer. */
function credentialFor(claims: Record<string, unknown>, expiresAt?: number): ValidatedCredential {
  return {
    queryId: 'pid',
    format: 'dc+sd-jwt',
    credentialType: VCT,
    issuer: ValidatedIssuer.fromValidatedPresentation({
      identifier: ISSUER,
      keyResolution: 'issuer-metadata',
    }),
    claims,
    validity: expiresAt === undefined ? {} : { expiresAt },
    assurance: {
      credentialType: VCT,
      issuerKeyResolution: 'issuer-metadata',
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: Object.keys(claims).length,
      // #297's evidence, widened off the literal `false` by #378.
      // `'not-required'` is the honest value: nothing here read a status list
      // bit, and account resolution must not read the signal either way.
      statusChecked: 'not-required',
      // #308's evidence. `'none'` is the honest value: nothing here validated a
      // key attestation, and account resolution must not read it either way.
      keyStorageAssurance: { assurance: 'none' },
    },
  };
}

/** One `user_credentials` row, as the repository returns it. */
function credentialRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'cred-1',
    userId: 'user-1',
    realmId: REALM_ID,
    providerType: 'wallet',
    externalSub: 'alice@example.com',
    credentialData: {},
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  };
}

function fakeFastify() {
  const userCredentials = {
    findAllByRealmAndExternalSub: vi.fn().mockResolvedValue([]),
    findByRealmProviderSub: vi.fn().mockResolvedValue(undefined),
    create: vi
      .fn()
      .mockImplementation(async (data: unknown) => ({ id: 'cred-new', ...(data as object) })),
  };
  const userAttributes = {
    upsertMany: vi.fn().mockResolvedValue([]),
    findByUserIdAndSource: vi.fn().mockResolvedValue([]),
    setVerified: vi.fn().mockResolvedValue(undefined),
  };
  const users = { create: vi.fn().mockResolvedValue({ id: 'user-new', realmId: REALM_ID }) };

  const fastify = {
    log: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
    repositories: { userCredentials, userAttributes, users },
    db: {
      transaction: vi.fn().mockImplementation(async (run: (tx: unknown) => unknown) => run('tx')),
    },
  } as unknown as FastifyInstance;

  return { fastify, userCredentials, userAttributes, users };
}

/** Run resolution with the real `asserted-lookup` strategy. */
async function resolve(
  fastify: FastifyInstance,
  credential: ValidatedCredential,
  assertedIdentifier = 'alice@example.com',
  attributeGates = GATES,
  emailVerifyingIssuers: readonly string[] = []
) {
  return resolveWalletAccount(fastify, {
    realmId: REALM_ID,
    credential,
    assertedIdentifier,
    strategy: createSubjectResolutionStrategy(CONFIG),
    config: CONFIG,
    attributeGates,
    emailVerifyingIssuers,
  });
}

/**
 * A returning account whose stored binding `credential` re-derives: the row
 * account linking (#238) writes, or that wallet sign-in wrote while it still
 * enrolled.
 */
function seedReturningAccount(
  harness: ReturnType<typeof fakeFastify>,
  credential: ValidatedCredential,
  userId = 'user-1'
): void {
  harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
    credentialRow({
      userId,
      credentialData: walletCredentialDataSchema.parse({
        credential_format: 'dc+sd-jwt',
        credential_type: VCT,
        issuer: ISSUER,
        wallet_binding: deriveEnrolmentWalletBinding(CONFIG, credential),
        subject_resolution: 'asserted-lookup',
        enrolled_at: 1,
      }),
    }),
  ]);
}

/** Nothing about any account was written: no user, no credential, no attribute. */
function expectNothingWritten(harness: ReturnType<typeof fakeFastify>): void {
  expect(harness.users.create).not.toHaveBeenCalled();
  expect(harness.userCredentials.create).not.toHaveBeenCalled();
  expect(harness.userAttributes.upsertMany).not.toHaveBeenCalled();
  expect(harness.userAttributes.setVerified).not.toHaveBeenCalled();
  expect(harness.fastify.db.transaction).not.toHaveBeenCalled();
}

describe('createWalletAccountLookup (the SubjectAccountLookup port over user_credentials)', () => {
  it('returns every account the asserted identifier resolves to, across provider types', async () => {
    const { fastify, userCredentials } = fakeFastify();
    userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({
        userId: 'user-1',
        providerType: 'password',
        credentialData: { password_hash: 'x' },
      }),
    ]);

    const candidates = await createWalletAccountLookup(fastify).byAssertedIdentifier(
      REALM_ID,
      'alice@example.com'
    );

    // The password row MUST be visible. A lookup scoped to wallet rows would
    // report "no account" for an email that already has one, and "no account"
    // is what a sign-up flow may turn into an account — ADR-009's takeover.
    expect(candidates).toEqual([{ userId: 'user-1', walletBinding: null }]);
    expect(userCredentials.findAllByRealmAndExternalSub).toHaveBeenCalledWith(
      REALM_ID,
      'alice@example.com'
    );
  });

  it('reads the stored binding off a wallet row', async () => {
    const { fastify, userCredentials } = fakeFastify();
    userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({
        credentialData: {
          credential_format: 'dc+sd-jwt',
          credential_type: VCT,
          issuer: ISSUER,
          wallet_binding: 'wb1:deadbeef',
          subject_resolution: 'asserted-lookup',
          enrolled_at: 1,
        },
      }),
    ]);

    expect(
      await createWalletAccountLookup(fastify).byAssertedIdentifier(REALM_ID, 'alice@example.com')
    ).toEqual([{ userId: 'user-1', walletBinding: 'wb1:deadbeef' }]);
  });

  it('treats a corrupt wallet credential_data as UNBOUND, never as matching', async () => {
    const { fastify, userCredentials } = fakeFastify();
    userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ credentialData: { wallet_binding: 42 } }),
    ]);

    expect(
      await createWalletAccountLookup(fastify).byAssertedIdentifier(REALM_ID, 'alice@example.com')
    ).toEqual([{ userId: 'user-1', walletBinding: null }]);
  });

  it('is realm-scoped on the wallet-subject lookup and reports nothing found as []', async () => {
    const { fastify, userCredentials } = fakeFastify();

    expect(await createWalletAccountLookup(fastify).byWalletSubject(REALM_ID, 'isc1:x')).toEqual(
      []
    );
    expect(userCredentials.findByRealmProviderSub).toHaveBeenCalledWith(
      REALM_ID,
      'wallet',
      'isc1:x'
    );
  });
});

describe('resolveWalletAccount — sign-in never creates an account (ADR-009 §1, amended 2026-10-19)', () => {
  let harness: ReturnType<typeof fakeFastify>;

  beforeEach(() => {
    harness = fakeFastify();
  });

  it('refuses a valid, fully disclosed credential on an identifier with no account, writing nothing (ANT-2026-NCX3VXDP)', async () => {
    // Every configured binding claim disclosed, issuer validated and trusted.
    // Before the amendment this enrolled a new account on the identifier the
    // presenter TYPED, bound to their own credential: a free identifier signed
    // in, a taken one was refused, and anyone could claim someone else's.
    const result = await resolve(
      harness.fastify,
      credentialFor(
        { given_name: 'Mallory', family_name: 'Vane', email: 'mallory@example.com' },
        4_102_444_800
      ),
      'nobody@example.com'
    );

    expect(result).toEqual({ status: 'rejected' });
    expectNothingWritten(harness);
    // One lookup, as for a taken identifier, and the reason for the operator.
    expect(harness.userCredentials.findAllByRealmAndExternalSub).toHaveBeenCalledTimes(1);
    expect(harness.fastify.log.info).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_ID }),
      expect.stringContaining('wallet sign-in creates no accounts')
    );
  });

  it('answers an unused identifier exactly as a taken one (no enumeration oracle)', async () => {
    // The scanner's reproducer, at the layer that decides it: the SAME valid
    // credential on Alice's wallet account, on a password-only account, and on
    // an identifier nobody has. Only the account store differs.
    const mallory = credentialFor({ given_name: 'Mallory', family_name: 'Vane' });

    seedReturningAccount(harness, credentialFor({ given_name: 'Alice', family_name: 'Doe' }));
    const walletAccount = await resolve(harness.fastify, mallory, 'alice@example.com');

    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ providerType: 'password', credentialData: { password_hash: 'x' } }),
    ]);
    const passwordAccount = await resolve(harness.fastify, mallory, 'bob@example.com');

    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([]);
    const unused = await resolve(harness.fastify, mallory, 'nobody@example.com');

    expect(unused).toEqual({ status: 'rejected' });
    expect(walletAccount).toEqual(unused);
    expect(passwordAccount).toEqual(unused);
    expect(Object.keys(walletAccount)).toEqual(Object.keys(unused));
    // One lookup each, and nothing else touched the store on any of them.
    expect(harness.userCredentials.findAllByRealmAndExternalSub).toHaveBeenCalledTimes(3);
    expectNothingWritten(harness);
  });

  it('signs in a returning account whose stored binding the credential re-derives, writing no account rows', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    seedReturningAccount(harness, credential);

    expect(await resolve(harness.fastify, credential)).toEqual({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'alice@example.com',
    });
    expect(harness.users.create).not.toHaveBeenCalled();
    expect(harness.userCredentials.create).not.toHaveBeenCalled();
    expect(harness.fastify.db.transaction).not.toHaveBeenCalled();
  });

  it("reports external_sub EXACTLY as #300's strategy resolved it", async () => {
    const strategy = createSubjectResolutionStrategy(CONFIG);
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    seedReturningAccount(harness, credential);
    const context = {
      realmId: REALM_ID,
      assertedIdentifier: '  Alice@Example.COM ',
      lookup: createWalletAccountLookup(harness.fastify),
    };

    const expected = strategy.deriveExternalSub(credential, context);

    const result = await resolveWalletAccount(harness.fastify, {
      realmId: REALM_ID,
      credential,
      assertedIdentifier: '  Alice@Example.COM ',
      strategy,
      config: CONFIG,
      attributeGates: GATES,
      emailVerifyingIssuers: [],
    });

    // The normalized asserted identifier (ADR-009 §1) — never a wallet key, a
    // thumbprint or a DID (ADR-009 Finding 1).
    expect(expected).toBe('alice@example.com');
    expect(result).toEqual({ status: 'authenticated', userId: 'user-1', externalSub: expected });
  });

  it('writes the disclosed claims as verified wallet attributes with the credential’s expiry', async () => {
    const credential = credentialFor(
      { given_name: 'Alice', family_name: 'Doe', birthdate: '1990-01-01' },
      4_102_444_800
    );
    seedReturningAccount(harness, credential);

    await resolve(harness.fastify, credential);

    expect(harness.userAttributes.upsertMany).toHaveBeenCalledWith('user-1', [
      {
        source: 'wallet',
        attrKey: 'given_name',
        attrValue: 'Alice',
        verified: true,
        expiresAt: 4_102_444_800_000,
        provenance: PROVENANCE,
      },
      {
        source: 'wallet',
        attrKey: 'family_name',
        attrValue: 'Doe',
        verified: true,
        expiresAt: 4_102_444_800_000,
        provenance: PROVENANCE,
      },
      {
        source: 'wallet',
        attrKey: 'birthdate',
        attrValue: '1990-01-01',
        verified: true,
        expiresAt: 4_102_444_800_000,
        provenance: PROVENANCE,
      },
    ]);
  });

  it('writes a null expiry when the credential carries no exp', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    seedReturningAccount(harness, credential);

    await resolve(harness.fastify, credential);

    const [, rows] = harness.userAttributes.upsertMany.mock.calls[0] as [
      string,
      { expiresAt: number | null }[],
    ];

    expect(rows.every((row) => row.expiresAt === null)).toBe(true);
  });

  it('refuses a credential that withholds a configured binding claim, before any lookup', async () => {
    // The holder withheld `family_name`, so no binding can be re-derived and
    // the real strategy refuses without touching the account store.
    const result = await resolve(harness.fastify, credentialFor({ given_name: 'Alice' }));

    expect(result).toEqual({ status: 'rejected' });
    expect(harness.userCredentials.findAllByRealmAndExternalSub).not.toHaveBeenCalled();
    expectNothingWritten(harness);
  });
});

describe('resolveWalletAccount — what a wallet attribute rests on (ANT-2026-ULJIA4P4)', () => {
  const STATUS = { status_list: { idx: 7, uri: 'https://status.example.com/lists/1' } };
  const REPLACEMENT_STATUS = { status_list: { idx: 8, uri: 'https://status.example.com/lists/1' } };

  let harness: ReturnType<typeof fakeFastify>;

  /** A returning account whose stored binding the presented credential matches. */
  function returningAccount(credential: ValidatedCredential): void {
    seedReturningAccount(harness, credential);
  }

  /** The email row an EARLIER credential left, which this presentation does not rewrite. */
  function staleEmailRow(provenance: unknown) {
    return {
      id: 'attr-email',
      userId: 'user-1',
      source: 'wallet',
      attrKey: 'email',
      attrValue: 'staff@corp.example',
      verified: true,
      expiresAt: null,
      provenance,
      createdAt: 1,
      updatedAt: 1,
    };
  }

  function checkerRevoking(revoked: unknown): CredentialStatusChecker {
    return {
      resolveCredentialStatus: vi.fn(async (status: unknown) =>
        JSON.stringify(status) === JSON.stringify(revoked)
          ? ({ decision: 'rejected', reason: 'revoked' } as const)
          : ({ decision: 'valid' } as const)
      ),
      assertCredentialNotRevoked: vi.fn(),
    } as unknown as CredentialStatusChecker;
  }

  beforeEach(() => {
    harness = fakeFastify();
  });

  it('records the issuer and the issuer-signed status reference on every row it writes', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe', status: STATUS });
    returningAccount(credential);

    await resolve(harness.fastify, credential);

    const [, rows] = harness.userAttributes.upsertMany.mock.calls[0] as [
      string,
      { provenance: unknown }[],
    ];
    expect(rows.length).toBeGreaterThan(0);
    expect(
      rows.every(
        (row) =>
          JSON.stringify(row.provenance) === JSON.stringify({ ...PROVENANCE, status: STATUS })
      )
    ).toBe(true);
  });

  it('withdraws, at the next wallet sign-in, a row whose credential has since been revoked', async () => {
    // The staff credential that wrote `email` was revoked; its replacement is
    // presented without an `email` Disclosure, so nothing rewrites that row.
    const replacement = credentialFor({
      given_name: 'Alice',
      family_name: 'Doe',
      status: REPLACEMENT_STATUS,
    });
    returningAccount(replacement);
    harness.userAttributes.findByUserIdAndSource.mockResolvedValue([
      staleEmailRow({ ...PROVENANCE, status: STATUS }),
    ]);

    const result = await resolve(harness.fastify, replacement, 'alice@example.com', {
      ...GATES,
      credentialStatus: checkerRevoking(STATUS),
    });

    expect(result).toMatchObject({ status: 'authenticated', userId: 'user-1' });
    expect(harness.userAttributes.findByUserIdAndSource).toHaveBeenCalledWith('user-1', 'wallet');
    expect(harness.userAttributes.setVerified).toHaveBeenCalledWith(
      'user-1',
      'wallet',
      'email',
      false
    );
  });

  it('withdraws a row whose issuer the realm no longer trusts', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    returningAccount(credential);
    harness.userAttributes.findByUserIdAndSource.mockResolvedValue([
      staleEmailRow({ issuer: 'https://former-issuer.example.com', issuer_key_resolution: 'x5c' }),
    ]);

    await resolve(harness.fastify, credential);

    expect(harness.userAttributes.setVerified).toHaveBeenCalledWith(
      'user-1',
      'wallet',
      'email',
      false
    );
  });

  it('keeps a row whose credential is still valid from an issuer still trusted', async () => {
    const credential = credentialFor({
      given_name: 'Alice',
      family_name: 'Doe',
      status: REPLACEMENT_STATUS,
    });
    returningAccount(credential);
    harness.userAttributes.findByUserIdAndSource.mockResolvedValue([
      staleEmailRow({ ...PROVENANCE, status: STATUS }),
    ]);

    await resolve(harness.fastify, credential, 'alice@example.com', {
      ...GATES,
      credentialStatus: checkerRevoking({ status_list: { idx: 99, uri: 'x' } }),
    });

    expect(harness.userAttributes.setVerified).not.toHaveBeenCalled();
  });

  it('does not re-ask about the rows this presentation just wrote', async () => {
    const credential = credentialFor({
      given_name: 'Alice',
      family_name: 'Doe',
      email: 'alice@example.com',
      status: REPLACEMENT_STATUS,
    });
    returningAccount(credential);
    harness.userAttributes.findByUserIdAndSource.mockResolvedValue([
      staleEmailRow({ ...PROVENANCE, status: STATUS }),
    ]);

    await resolve(harness.fastify, credential, 'alice@example.com', {
      ...GATES,
      credentialStatus: checkerRevoking(STATUS),
    });

    expect(harness.userAttributes.setVerified).not.toHaveBeenCalled();
  });
});

describe('resolveWalletAccount — when the wallet email counts as verified (ANT-2026-BGP7XCR2)', () => {
  let harness: ReturnType<typeof fakeFastify>;

  beforeEach(() => {
    harness = fakeFastify();
    // The binding covers `given_name` and `family_name` only, so every
    // credential below signs in to this account whatever email it carries.
    seedReturningAccount(harness, credentialFor({ given_name: 'Alice', family_name: 'Doe' }));
  });

  function emailRow(): { verified: boolean } | undefined {
    const [, rows] = harness.userAttributes.upsertMany.mock.calls[0] as [
      string,
      { attrKey: string; verified: boolean }[],
    ];
    return rows.find((row) => row.attrKey === 'email');
  }

  it('writes the email UNVERIFIED when the presentation discloses no email_verified', async () => {
    // The holder chooses the Disclosures, so absence says nothing about what
    // the issuer signed: it may have been `email_verified: false`, withheld.
    await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice', family_name: 'Doe', email: 'alice@example.com' })
    );

    expect(emailRow()).toMatchObject({ verified: false });
  });

  it('writes it verified when the issuer signed and the holder disclosed email_verified: true', async () => {
    await resolve(
      harness.fastify,
      credentialFor({
        given_name: 'Alice',
        family_name: 'Doe',
        email: 'alice@example.com',
        email_verified: true,
      })
    );

    expect(emailRow()).toMatchObject({ verified: true });
  });

  it('writes it verified for an issuer the operator lists in OID4VP_EMAIL_VERIFYING_ISSUERS', async () => {
    await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice', family_name: 'Doe', email: 'alice@example.com' }),
      'alice@example.com',
      GATES,
      [ISSUER]
    );

    expect(emailRow()).toMatchObject({ verified: true });
  });
});

describe('resolveWalletAccount — the refusals, none of which writes anything', () => {
  let harness: ReturnType<typeof fakeFastify>;

  beforeEach(() => {
    harness = fakeFastify();
  });

  it('does not create a wallet credential for a PRE-EXISTING account with no wallet binding', async () => {
    // ADR-009 §1's second bootstrap case, and issue #235's acceptance criterion:
    // typically a password account on the same email. Enrolling here would let
    // any holder of any trusted credential claim an existing account by
    // asserting its email. That path is linking (#238), under a session.
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ providerType: 'password', credentialData: { password_hash: 'x' } }),
    ]);

    const result = await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice', family_name: 'Doe' })
    );

    expect(result).toEqual({ status: 'rejected' });
    expect(harness.users.create).not.toHaveBeenCalled();
    expect(harness.userCredentials.create).not.toHaveBeenCalled();
    expect(harness.userAttributes.upsertMany).not.toHaveBeenCalled();
    expect(harness.fastify.db.transaction).not.toHaveBeenCalled();
  });

  it('refuses a valid credential presented against SOMEONE ELSE’S account', async () => {
    // The attack ADR-009 §1 says is the likeliest way this gets built wrong: a
    // credential that is valid in every respect, asserting an account it does
    // not entitle its holder to.
    const victimBinding = walletCredentialDataSchema.parse({
      credential_format: 'dc+sd-jwt',
      credential_type: VCT,
      issuer: ISSUER,
      wallet_binding: 'wb1:' + 'a'.repeat(64),
      subject_resolution: 'asserted-lookup',
      enrolled_at: 1,
    });
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ credentialData: victimBinding }),
    ]);

    const result = await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Mallory', family_name: 'Doe' })
    );

    expect(result).toEqual({ status: 'rejected' });
    expect(harness.userAttributes.upsertMany).not.toHaveBeenCalled();
  });

  it('does not let a stranger’s password registration on the identifier lock the wallet owner out (ANT-2026-B5IYOGYF)', async () => {
    // `POST /auth/register` is anonymous and the credential unique index is per
    // provider type, so anyone can add a password row on the identifier a
    // wallet-only account enrolled under. That unbound row must not veto the
    // account that holds the proof.
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    const enrolled = walletCredentialDataSchema.parse({
      credential_format: 'dc+sd-jwt',
      credential_type: VCT,
      issuer: ISSUER,
      wallet_binding: deriveEnrolmentWalletBinding(CONFIG, credential),
      subject_resolution: 'asserted-lookup',
      enrolled_at: 1,
    });
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ userId: 'user-1', credentialData: enrolled }),
      credentialRow({
        id: 'cred-stranger',
        userId: 'user-stranger',
        providerType: 'password',
        credentialData: { password_hash: 'x' },
      }),
    ]);

    const result = await resolve(harness.fastify, credential);

    expect(result).toEqual({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'alice@example.com',
    });
    expect(harness.users.create).not.toHaveBeenCalled();

    // ...and it opens nothing: another holder asserting the same identifier is
    // still refused.
    expect(
      await resolve(harness.fastify, credentialFor({ given_name: 'Mallory', family_name: 'Doe' }))
    ).toEqual({ status: 'rejected' });
  });

  it('refuses an AMBIGUOUS lookup rather than picking an account', async () => {
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ userId: 'user-1', providerType: 'password', credentialData: {} }),
      credentialRow({ id: 'cred-2', userId: 'user-2', providerType: 'wallet', credentialData: {} }),
    ]);

    expect(
      await resolve(harness.fastify, credentialFor({ given_name: 'Alice', family_name: 'Doe' }))
    ).toEqual({ status: 'rejected' });
    expect(harness.users.create).not.toHaveBeenCalled();
  });

  it('refuses when the account store throws, and says so to the operator only', async () => {
    harness.userCredentials.findAllByRealmAndExternalSub.mockRejectedValue(
      new Error('connection reset')
    );

    expect(
      await resolve(harness.fastify, credentialFor({ given_name: 'Alice', family_name: 'Doe' }))
    ).toEqual({ status: 'rejected' });
    expect(harness.fastify.log.error).toHaveBeenCalled();
  });

  it('refuses when no identifier was asserted', async () => {
    expect(
      await resolve(harness.fastify, credentialFor({ given_name: 'Alice', family_name: 'Doe' }), '')
    ).toEqual({ status: 'rejected' });
    expect(harness.users.create).not.toHaveBeenCalled();
  });

  it('tells the operator when an enrolled account stops matching because a binding claim rounded (ANT-2026-FKDN4Q29)', async () => {
    // An account enrolled before numeric binding claims had to be exact. Its
    // binding was derived from a value `JSON.parse` had rounded, so it no
    // longer identifies one person and is refused from now on. The refusal is
    // uniform on the wire; the log is the only place the reason can go.
    const enrolled = walletCredentialDataSchema.parse({
      credential_format: 'dc+sd-jwt',
      credential_type: VCT,
      issuer: ISSUER,
      wallet_binding: 'wb1:' + 'b'.repeat(64),
      subject_resolution: 'asserted-lookup',
      enrolled_at: 1,
    });
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ credentialData: enrolled }),
    ]);

    const result = await resolve(
      harness.fastify,
      credentialFor(JSON.parse('{"given_name":"Alice","family_name":202601150000001234}'))
    );

    expect(result).toEqual({ status: 'rejected' });
    expect(harness.fastify.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_ID, claims: ['family_name'] }),
      expect.stringContaining('cannot represent exactly')
    );
  });

  it('renders every refusal identically (no enumeration oracle)', async () => {
    // The SAME fully disclosed credential for both probes, so the real strategy
    // reaches the account store on both: one finds nothing (`no-match`), the
    // other a password account (`rejected`). A probe that withheld a binding
    // claim would be refused before the lookup and prove nothing about it.
    const probe = credentialFor({ given_name: 'Alice', family_name: 'Doe' });

    const unknownIdentifier = await resolve(harness.fastify, probe, 'nobody@example.com');

    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ providerType: 'password', credentialData: {} }),
    ]);
    const existingAccount = await resolve(harness.fastify, probe);

    expect(unknownIdentifier).toEqual({ status: 'rejected' });
    expect(unknownIdentifier).toEqual(existingAccount);
    expect(harness.userCredentials.findAllByRealmAndExternalSub).toHaveBeenCalledTimes(2);
    expectNothingWritten(harness);
  });
});
