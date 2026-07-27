import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

/**
 * The wallet AUTHENTICATION and LINKING seam (#238), at the app layer.
 *
 * ## What is mocked, and why that is honest
 *
 * The CRYPTOGRAPHY is mocked here and nowhere else: `verifyWalletPresentations`
 * (#234 + #236) and the subject-resolution strategies (#300) are exercised
 * against real signatures, real Disclosures and real branded issuers in
 * `libs/server/federation` — including the attack test where a genuine
 * credential from a trusted issuer asserts someone else's account, and the
 * #238 acceptance test where a linked wallet and the account's password
 * credential resolve to the same `users.id`.
 *
 * `apps/auth-server` is `scope:app` and may not import `scope:server` libraries,
 * so it cannot mint an SD-JWT VC; a fake one would be a fake `ValidatedIssuer`,
 * which is the exact object the nominal type exists to make unconstructible. So
 * this suite tests what only exists HERE: the order of the gates, what is read
 * from where, and what is written to the database.
 */

const { envMock } = vi.hoisted(() => ({
  envMock: {
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_TRUSTED_ISSUERS: {} as Record<string, readonly string[]>,
    OID4VP_ISSUER_JWKS: {} as Record<string, readonly Record<string, unknown>[]>,
  },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

vi.mock('@qauth-labs/fastify-plugin-federation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@qauth-labs/fastify-plugin-federation')>();
  return {
    ...actual,
    verifyWalletPresentations: vi.fn(),
    createSubjectResolutionStrategy: vi.fn(),
    prepareWalletLink: vi.fn(),
  };
});

vi.mock('./wallet-verification', () => ({
  resolveWalletVerificationSetup: vi.fn(),
  resolveRealmTrustRegistry: vi.fn().mockResolvedValue({ isTrusted: () => true }),
}));

import {
  createSubjectResolutionStrategy,
  prepareWalletLink,
  verifyWalletPresentations,
} from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';

import { createWalletAccountLookup } from './wallet-account-lookup';
import { linkWalletPresentation, resolveWalletPresentation } from './wallet-presentation';
import { resolveWalletVerificationSetup } from './wallet-verification';

const CREDENTIAL = {
  queryId: 'qauth_wallet_login',
  format: 'dc+sd-jwt',
  credentialType: 'https://credentials.example.com/pid',
  issuer: { identifier: 'https://issuer.example.com', keyResolution: 'issuer-metadata' },
  claims: { given_name: 'Alice' },
} as never;

const BINDING = `wb1:${'a'.repeat(64)}`;

const DCQL = {
  credentials: [
    {
      id: 'qauth_wallet_login',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://credentials.example.com/pid'] },
    },
  ],
};

const REQUEST = {
  realmId: 'realm-1',
  stateHash: 'a'.repeat(64),
  nonce: 'n-0S6_WzA2Mj',
  clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
  dcqlQuery: DCQL,
};

interface CredentialRow {
  id: string;
  userId: string;
  realmId: string;
  providerType: string;
  externalSub: string;
  credentialData: Record<string, unknown>;
}

/** In-memory `user_credentials`, honouring the shipped unique index. */
function createCredentialStore(seed: CredentialRow[] = []) {
  const rows = [...seed];
  let nextId = seed.length + 1;

  return {
    rows,
    repository: {
      findAllByRealmAndExternalSub: vi.fn(async (realmId: string, externalSub: string) =>
        rows.filter((row) => row.realmId === realmId && row.externalSub === externalSub)
      ),
      findByRealmProviderSub: vi.fn(
        async (realmId: string, providerType: string, externalSub: string) =>
          rows.find(
            (row) =>
              row.realmId === realmId &&
              row.providerType === providerType &&
              row.externalSub === externalSub
          )
      ),
      findByUserIdAndType: vi.fn(async (userId: string, providerType: string) =>
        rows.find((row) => row.userId === userId && row.providerType === providerType)
      ),
      create: vi.fn(async (data: Omit<CredentialRow, 'id'>) => {
        const clash = rows.find(
          (row) =>
            row.realmId === data.realmId &&
            row.providerType === data.providerType &&
            row.externalSub === data.externalSub
        );
        if (clash)
          throw new UniqueConstraintError('idx_user_credentials_realm_provider_sub_unique');
        const created = { id: `cred-${nextId++}`, ...data };
        rows.push(created);
        return created;
      }),
      updateCredentialData: vi.fn(async (id: string, credentialData: Record<string, unknown>) => {
        const row = rows.find((candidate) => candidate.id === id);
        if (!row) throw new Error('not found');
        row.credentialData = credentialData;
        return row;
      }),
    },
  };
}

function makeFastify(store = createCredentialStore()) {
  return {
    store,
    fastify: {
      repositories: { userCredentials: store.repository },
      db: { transaction: vi.fn(async (run: (tx: unknown) => unknown) => run(undefined)) },
      sessionUtils: {
        getSession: vi.fn().mockResolvedValue({
          presentations: [
            { queryId: 'qauth_wallet_login', format: 'dc+sd-jwt', presentation: 'opaque' },
          ],
          at: Date.now(),
        }),
        setSession: vi.fn(),
        deleteSession: vi.fn(),
      },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    } as unknown as FastifyInstance,
  };
}

/** A strategy stub standing in for `asserted-lookup`, using the REAL adapter. */
function assertedLookupStub(binding: string) {
  return {
    id: 'asserted-lookup' as const,
    deriveExternalSub: (_credential: unknown, context: { assertedIdentifier?: string }) =>
      context.assertedIdentifier ?? null,
    resolve: vi.fn(
      async (
        _credential: unknown,
        context: {
          realmId: string;
          assertedIdentifier?: string;
          lookup: ReturnType<typeof createWalletAccountLookup>;
        }
      ) => {
        const candidates = await context.lookup.byAssertedIdentifier(
          context.realmId,
          context.assertedIdentifier ?? ''
        );
        const entitled = candidates.find((candidate) => candidate.walletBinding === binding);
        return entitled === undefined
          ? { kind: 'rejected' as const }
          : { kind: 'matched' as const, userId: entitled.userId };
      }
    ),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  (resolveWalletVerificationSetup as unknown as Mock).mockReturnValue({
    profile: { id: 'oid4vp-1.0-base', credentialFormats: ['dc+sd-jwt'], signingAlgs: ['ES256'] },
    subjectResolution: { strategy: 'asserted-lookup', bindingClaims: ['given_name'] },
    resolveIssuerKey: async () => undefined,
  });
  (verifyWalletPresentations as unknown as Mock).mockResolvedValue([CREDENTIAL]);
  (createSubjectResolutionStrategy as unknown as Mock).mockReturnValue(assertedLookupStub(BINDING));
});

describe('resolveWalletPresentation — the gates run, in order (#234/#236/#300)', () => {
  it('authenticates a presentation whose binding matches the asserted account', async () => {
    const store = createCredentialStore([
      {
        id: 'cred-w',
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'wallet',
        externalSub: 'alice@example.com',
        credentialData: { wallet_binding: BINDING, issuer: 'https://issuer.example.com', vct: 'v' },
      },
    ]);
    const { fastify } = makeFastify(store);

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({
      status: 'authenticated',
      userId: 'user-1',
      externalSub: 'alice@example.com',
    });
  });

  it('refuses when no presentation was parked — the transport signal is not a credential', async () => {
    const { fastify } = makeFastify();
    (fastify.sessionUtils.getSession as unknown as Mock).mockResolvedValue(null);

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
    expect(verifyWalletPresentations).not.toHaveBeenCalled();
  });

  it('refuses when the deployment serves no wallet flows', async () => {
    (resolveWalletVerificationSetup as unknown as Mock).mockReturnValue(undefined);
    const { fastify } = makeFastify();

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
  });

  it('refuses — rather than 500s — when the deployment is HALF-configured', async () => {
    // A distinct status here would be a signal an anonymous caller can drive.
    (resolveWalletVerificationSetup as unknown as Mock).mockImplementation(() => {
      throw new Error('OID4VP_SUBJECT_BINDING_CLAIMS must list at least one credential claim');
    });
    const { fastify } = makeFastify();

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
    expect(fastify.log.error).toHaveBeenCalled();
  });

  it('refuses when validation or issuer trust refuses', async () => {
    (verifyWalletPresentations as unknown as Mock).mockRejectedValue(new Error('refused'));
    const { fastify } = makeFastify();

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
    expect(createSubjectResolutionStrategy).not.toHaveBeenCalled();
  });

  it('checks the presentation against the REQUEST’s nonce and client_id, not the wallet’s', async () => {
    const { fastify } = makeFastify();
    await resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'a@example.com' });

    expect(verifyWalletPresentations).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ nonce: REQUEST.nonce, clientId: REQUEST.clientId })
    );
  });

  it('refuses when the response carries more than one credential', async () => {
    // QAuth requests exactly one Credential Query, so picking one of several
    // would make WHICH credential authenticates depend on wallet-chosen order.
    (verifyWalletPresentations as unknown as Mock).mockResolvedValue([CREDENTIAL, CREDENTIAL]);
    const { fastify } = makeFastify();

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
  });

  it.each([['no-match'], ['ambiguous'], ['rejected']] as const)(
    'renders a %s outcome as the same refusal — no enrolment, no enumeration',
    async (kind) => {
      // `no-match` in particular: the LOGIN path does not enrol. Turning it into
      // an account would make the login screen an enrolment oracle.
      (createSubjectResolutionStrategy as unknown as Mock).mockReturnValue({
        id: 'asserted-lookup',
        deriveExternalSub: () => 'alice@example.com',
        resolve: async () => ({ kind }),
      });
      const { fastify } = makeFastify();

      await expect(
        resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
      ).resolves.toEqual({ status: 'rejected' });
    }
  );

  it('refuses identically for a known and an unknown identifier', async () => {
    const store = createCredentialStore([
      {
        id: 'cred-w',
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'wallet',
        externalSub: 'alice@example.com',
        credentialData: { wallet_binding: 'wb1:other', issuer: 'https://i', vct: 'v' },
      },
    ]);
    const { fastify } = makeFastify(store);

    const known = await resolveWalletPresentation(fastify, {
      ...REQUEST,
      assertedIdentifier: 'alice@example.com',
    });
    const unknown = await resolveWalletPresentation(fastify, {
      ...REQUEST,
      assertedIdentifier: 'nobody@example.com',
    });

    expect(known).toEqual(unknown);
  });

  it('refuses an account that exists with only a password credential (ADR-009 bootstrap 2)', async () => {
    const store = createCredentialStore([
      {
        id: 'cred-p',
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'password',
        externalSub: 'alice@example.com',
        credentialData: { password_hash: 'x', email_verified: true },
      },
    ]);
    const { fastify } = makeFastify(store);

    await expect(
      resolveWalletPresentation(fastify, { ...REQUEST, assertedIdentifier: 'alice@example.com' })
    ).resolves.toEqual({ status: 'rejected' });
  });
});

describe('linkWalletPresentation — bound to the session, never to the presentation (#238)', () => {
  const PASSWORD_ROW: CredentialRow = {
    id: 'cred-p',
    userId: 'user-1',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'alice@example.com',
    credentialData: { password_hash: 'x', email_verified: true },
  };

  beforeEach(() => {
    (prepareWalletLink as unknown as Mock).mockImplementation(
      async (_credential: unknown, _config: unknown, context: { accountIdentifier: string }) => ({
        kind: 'linkable',
        userId: 'user-1',
        externalSub: context.accountIdentifier,
        subjectSource: 'asserted-lookup',
        credentialData: {
          wallet_binding: BINDING,
          issuer: 'https://issuer.example.com',
          vct: 'v',
        },
      })
    );
  });

  it('writes a SECOND user_credentials row under the same users.id', async () => {
    // ADR-004's account-linking model, in one assertion.
    const store = createCredentialStore([PASSWORD_ROW]);
    const { fastify } = makeFastify(store);

    const result = await linkWalletPresentation(fastify, {
      ...REQUEST,
      authenticatedUserId: 'user-1',
    });

    expect(result).toMatchObject({ status: 'linked', rebound: false });
    expect(store.rows).toHaveLength(2);
    expect(store.rows[1]).toMatchObject({
      userId: 'user-1',
      providerType: 'wallet',
      externalSub: 'alice@example.com',
    });
  });

  it('takes external_sub from the ACCOUNT’s existing credential row', async () => {
    // ADR-009 §1: the same column `PasswordProvider` fills. Reading it from the
    // account rather than from user input is what makes a later wallet login
    // resolve back to this account instead of enrolling a duplicate.
    const store = createCredentialStore([PASSWORD_ROW]);
    const { fastify } = makeFastify(store);

    await linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' });

    expect(prepareWalletLink).toHaveBeenCalledWith(
      CREDENTIAL,
      expect.objectContaining({ strategy: 'asserted-lookup' }),
      expect.objectContaining({
        authenticatedUserId: 'user-1',
        accountIdentifier: 'alice@example.com',
      })
    );
  });

  it('refuses when the account carries no identifier-bearing credential', async () => {
    const { fastify } = makeFastify(createCredentialStore());

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toEqual({ status: 'rejected' });
    expect(prepareWalletLink).not.toHaveBeenCalled();
  });

  it('refuses when validation or issuer trust refuses, before touching the account', async () => {
    (verifyWalletPresentations as unknown as Mock).mockRejectedValue(new Error('refused'));
    const store = createCredentialStore([PASSWORD_ROW]);
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toEqual({ status: 'rejected' });
    expect(store.rows).toHaveLength(1);
  });

  it('reports a conflict — and writes nothing — when the plan says so', async () => {
    (prepareWalletLink as unknown as Mock).mockResolvedValue({ kind: 'conflict' });
    const store = createCredentialStore([PASSWORD_ROW]);
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toEqual({ status: 'conflict' });
    expect(store.rows).toHaveLength(1);
  });

  it('never overwrites a wallet row owned by a DIFFERENT account', async () => {
    const store = createCredentialStore([
      PASSWORD_ROW,
      {
        id: 'cred-other',
        userId: 'user-2',
        realmId: 'realm-1',
        providerType: 'wallet',
        externalSub: 'alice@example.com',
        credentialData: { wallet_binding: 'wb1:someone-else', issuer: 'https://i', vct: 'v' },
      },
    ]);
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toEqual({ status: 'conflict' });
    expect(store.rows[1]?.credentialData['wallet_binding']).toBe('wb1:someone-else');
  });

  it('re-binds the caller’s OWN wallet row instead of failing on the unique index', async () => {
    // A re-issued credential must not lock a user out of wallet login. Safe
    // here in a way it never is on the login path: the caller has proven they
    // hold the account with a session (ADR-009 §5).
    const store = createCredentialStore([
      PASSWORD_ROW,
      {
        id: 'cred-w',
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'wallet',
        externalSub: 'alice@example.com',
        credentialData: { wallet_binding: 'wb1:stale', issuer: 'https://i', vct: 'v' },
      },
    ]);
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toMatchObject({ status: 'linked', rebound: true, credentialId: 'cred-w' });
    expect(store.rows).toHaveLength(2);
    expect(store.rows[1]?.credentialData['wallet_binding']).toBe(BINDING);
  });

  it('turns a lost unique-index race into a conflict, not a 500', async () => {
    const store = createCredentialStore([PASSWORD_ROW]);
    store.repository.findByRealmProviderSub.mockResolvedValue(undefined);
    store.repository.create.mockRejectedValue(
      new UniqueConstraintError('idx_user_credentials_realm_provider_sub_unique')
    );
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).resolves.toEqual({ status: 'conflict' });
  });

  it('lets a genuine database fault propagate rather than reporting a conflict', async () => {
    const boom = new Error('connection reset');
    const store = createCredentialStore([PASSWORD_ROW]);
    store.repository.create.mockRejectedValue(boom);
    const { fastify } = makeFastify(store);

    await expect(
      linkWalletPresentation(fastify, { ...REQUEST, authenticatedUserId: 'user-1' })
    ).rejects.toBe(boom);
  });
});

describe('#238 AC3 — after linking, both credentials name the same users.id', () => {
  it('links, then authenticates the SAME account the password credential belongs to', async () => {
    // The password row is what `verifyPasswordCredential` resolves: keyed on
    // (realm, 'password', normalized email) → user-1. Linking writes a wallet
    // row on the SAME identifier, and the wallet login below resolves through
    // the real account-store adapter to the same `users.id` — which is the value
    // that becomes `sub` in every token minted from either session.
    const store = createCredentialStore([
      {
        id: 'cred-p',
        userId: 'user-1',
        realmId: 'realm-1',
        providerType: 'password',
        externalSub: 'alice@example.com',
        credentialData: { password_hash: 'x', email_verified: true },
      },
    ]);
    const { fastify } = makeFastify(store);

    (prepareWalletLink as unknown as Mock).mockImplementation(
      async (_credential: unknown, _config: unknown, context: { accountIdentifier: string }) => ({
        kind: 'linkable',
        userId: 'user-1',
        externalSub: context.accountIdentifier,
        subjectSource: 'asserted-lookup',
        credentialData: {
          wallet_binding: BINDING,
          issuer: 'https://issuer.example.com',
          vct: 'v',
        },
      })
    );

    const linked = await linkWalletPresentation(fastify, {
      ...REQUEST,
      authenticatedUserId: 'user-1',
    });
    expect(linked.status).toBe('linked');

    const passwordRow = await store.repository.findByRealmProviderSub(
      'realm-1',
      'password',
      'alice@example.com'
    );
    const walletRow = await store.repository.findByRealmProviderSub(
      'realm-1',
      'wallet',
      'alice@example.com'
    );

    // One identifier, one account, two credentials.
    expect(walletRow?.externalSub).toBe(passwordRow?.externalSub);
    expect(walletRow?.userId).toBe(passwordRow?.userId);

    const walletLogin = await resolveWalletPresentation(fastify, {
      ...REQUEST,
      assertedIdentifier: 'alice@example.com',
    });

    expect(walletLogin).toEqual({
      status: 'authenticated',
      userId: passwordRow?.userId,
      externalSub: 'alice@example.com',
    });
  });
});
