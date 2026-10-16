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
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { resolveWalletAccount } from './wallet-account';
import { createWalletAccountLookup } from './wallet-account-lookup';

/**
 * Wallet account resolution and enrolment (#235, ADR-009).
 *
 * These tests drive the REAL `asserted-lookup` strategy rather than a stubbed
 * one. The strategy is what decides whether a presentation may create an account
 * or must be refused, and ADR-009 §1 names that decision as the likeliest thing
 * to get wrong — so stubbing it would leave the acceptance criterion
 * ("a presentation matching a pre-existing account with no wallet binding does
 * NOT silently create a wallet credential") asserted about a test double.
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
      // bit, and enrolment must not read the signal either way.
      statusChecked: 'not-required',
      // #308's evidence. `'none'` is the honest value: nothing here validated a
      // key attestation, and enrolment must not read it either way.
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
    // report "no account" for an email that already has one, and the caller is
    // allowed to turn "no account" into an enrolment — ADR-009's takeover.
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

describe('resolveWalletAccount — enrolment (ADR-009 §1, first bootstrap case)', () => {
  let harness: ReturnType<typeof fakeFastify>;

  beforeEach(() => {
    harness = fakeFastify();
  });

  it('creates the user, the wallet credential and the attribute rows together', async () => {
    const credential = credentialFor(
      { given_name: 'Alice', family_name: 'Doe', email: 'Alice@Example.COM' },
      4_102_444_800
    );

    const result = await resolve(harness.fastify, credential);

    expect(result).toEqual({
      status: 'authenticated',
      userId: 'user-new',
      externalSub: 'alice@example.com',
      enrolled: true,
    });

    // One transaction: a users row without its credential row would be
    // unloginable AND block re-enrolment.
    expect(harness.fastify.db.transaction).toHaveBeenCalledTimes(1);
    expect(harness.users.create).toHaveBeenCalledWith({ realmId: REALM_ID }, 'tx');
  });

  it("writes external_sub EXACTLY as #300's strategy resolved it", async () => {
    const strategy = createSubjectResolutionStrategy(CONFIG);
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });
    const context = {
      realmId: REALM_ID,
      assertedIdentifier: '  Alice@Example.COM ',
      lookup: createWalletAccountLookup(harness.fastify),
    };

    const expected = strategy.deriveExternalSub(credential, context);

    await resolveWalletAccount(harness.fastify, {
      realmId: REALM_ID,
      credential,
      assertedIdentifier: '  Alice@Example.COM ',
      strategy,
      config: CONFIG,
      attributeGates: GATES,
      emailVerifyingIssuers: [],
    });

    const [written] = harness.userCredentials.create.mock.calls[0] as [Record<string, unknown>];

    expect(written['externalSub']).toBe(expected);
    expect(written['providerType']).toBe('wallet');
    expect(written['realmId']).toBe(REALM_ID);
  });

  it('derives no external_sub from wallet cryptography', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });

    await resolve(harness.fastify, credential);

    const surface = JSON.stringify(harness.userCredentials.create.mock.calls[0]);

    expect(surface).not.toContain('cnf');
    expect(surface).not.toContain('"kty"');
    expect(surface).not.toContain('thumbprint');
    expect(surface).not.toContain('did:');
  });

  it('stores a wallet binding the NEXT presentation can be matched against', async () => {
    const credential = credentialFor({ given_name: 'Alice', family_name: 'Doe' });

    await resolve(harness.fastify, credential);

    const [written] = harness.userCredentials.create.mock.calls[0] as [Record<string, unknown>];
    const stored = walletCredentialDataSchema.parse(written['credentialData']);

    expect(stored.wallet_binding).toMatch(/^wb1:[0-9a-f]{64}$/);
    expect(stored.subject_resolution).toBe('asserted-lookup');
    expect(stored.issuer).toBe(ISSUER);

    // The round trip that matters: replay the same credential against an
    // account carrying the binding that enrolment just wrote.
    const returning = fakeFastify();
    returning.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ credentialData: stored }),
    ]);

    expect(await resolve(returning.fastify, credential)).toEqual({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'alice@example.com',
      enrolled: false,
    });
    expect(returning.users.create).not.toHaveBeenCalled();
    expect(returning.userCredentials.create).not.toHaveBeenCalled();
  });

  it('writes the disclosed claims as verified wallet attributes with the credential’s expiry', async () => {
    const credential = credentialFor(
      { given_name: 'Alice', family_name: 'Doe', birthdate: '1990-01-01' },
      4_102_444_800
    );

    await resolve(harness.fastify, credential);

    expect(harness.userAttributes.upsertMany).toHaveBeenCalledWith(
      'user-new',
      [
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
      ],
      'tx'
    );
  });

  it('writes a null expiry when the credential carries no exp', async () => {
    await resolve(harness.fastify, credentialFor({ given_name: 'Alice', family_name: 'Doe' }));

    const [, rows] = harness.userAttributes.upsertMany.mock.calls[0] as [
      string,
      { expiresAt: number | null }[],
    ];

    expect(rows.every((row) => row.expiresAt === null)).toBe(true);
  });

  it('refuses to enrol an account nothing could later prove entitlement to', async () => {
    // The holder withheld `family_name`, one of the configured binding claims,
    // so no binding can be derived. Enrolling would create an account that
    // `asserted-lookup` can never match — a silent lockout.
    const result = await resolve(harness.fastify, credentialFor({ given_name: 'Alice' }));

    expect(result).toEqual({ status: 'rejected' });
    expect(harness.users.create).not.toHaveBeenCalled();
    expect(harness.userCredentials.create).not.toHaveBeenCalled();
    expect(harness.userAttributes.upsertMany).not.toHaveBeenCalled();
  });

  it('refuses, without a distinguishable outcome, when it loses the unique-index race', async () => {
    harness.userCredentials.create.mockRejectedValue(
      new UniqueConstraintError('idx_user_credentials_realm_provider_sub_unique')
    );

    expect(
      await resolve(harness.fastify, credentialFor({ given_name: 'Alice', family_name: 'Doe' }))
    ).toEqual({ status: 'rejected' });
  });
});

describe('resolveWalletAccount — what a wallet attribute rests on (ANT-2026-ULJIA4P4)', () => {
  const STATUS = { status_list: { idx: 7, uri: 'https://status.example.com/lists/1' } };
  const REPLACEMENT_STATUS = { status_list: { idx: 8, uri: 'https://status.example.com/lists/1' } };

  let harness: ReturnType<typeof fakeFastify>;

  /** A returning account whose stored binding the presented credential matches. */
  function returningAccount(credential: ValidatedCredential): void {
    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({
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
    await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice', family_name: 'Doe', status: STATUS })
    );

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

describe('resolveWalletAccount — the refusals that must NEVER become an enrolment', () => {
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
      enrolled: false,
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
    const unknownIdentifier = await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice' })
    );

    harness.userCredentials.findAllByRealmAndExternalSub.mockResolvedValue([
      credentialRow({ providerType: 'password', credentialData: {} }),
    ]);
    const existingAccount = await resolve(
      harness.fastify,
      credentialFor({ given_name: 'Alice', family_name: 'Doe' })
    );

    expect(unknownIdentifier).toEqual(existingAccount);
  });
});
