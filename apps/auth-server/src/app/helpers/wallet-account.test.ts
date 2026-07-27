import {
  createSubjectResolutionStrategy,
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
      statusChecked: false,
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
  const userAttributes = { upsertMany: vi.fn().mockResolvedValue([]) };
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
  assertedIdentifier = 'alice@example.com'
) {
  return resolveWalletAccount(fastify, {
    realmId: REALM_ID,
    credential,
    assertedIdentifier,
    strategy: createSubjectResolutionStrategy(CONFIG),
    config: CONFIG,
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
        },
        {
          source: 'wallet',
          attrKey: 'family_name',
          attrValue: 'Doe',
          verified: true,
          expiresAt: 4_102_444_800_000,
        },
        {
          source: 'wallet',
          attrKey: 'birthdate',
          attrValue: '1990-01-01',
          verified: true,
          expiresAt: 4_102_444_800_000,
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
