import { describe, expect, it, vi } from 'vitest';

import {
  type AccountResetPolicy,
  type AccountResetRepositories,
  createRepositoryAccountResets,
  RESET_REFRESH_REVOCATION_REASON,
} from './account-resets';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const OTHER_USER = '0199fa20-5e1a-7000-8000-000000000002';
const ADDRESS = 'alice@example.com';
const AT = 1_800_000_000_000;

const RESET = {
  realmId: REALM,
  clientId: 'notes-web',
  userId: USER,
  identifier: ADDRESS,
  password: 'seven amber kites over the old harbour',
  normalization: 'nfc' as const,
};

interface Options {
  readonly owner?: string;
  readonly credential?: 'none' | 'malformed';
  readonly enabled?: boolean;
  readonly user?: 'none';
  readonly vanished?: boolean;
  readonly failAt?: string;
}

/** Repositories that record every write in one array, as one transaction's would. */
function build(options: Options = {}) {
  const writes: { readonly what: string; readonly data: unknown; readonly tx: unknown }[] = [];
  let committed: typeof writes = [];
  const write = (what: string, data: unknown, tx: unknown) => {
    if (options.failAt === what) throw new Error(`${what} failed`);
    writes.push({ what, data, tx });
  };
  const stores: AccountResetRepositories<string> = {
    userCredentials: {
      findByRealmProviderSub: async (realmId, providerType, externalSub) => {
        if (options.credential === 'none') return undefined;
        expect({ realmId, providerType, externalSub }).toEqual({
          realmId: REALM,
          providerType: 'password',
          externalSub: ADDRESS,
        });
        return {
          id: 'credential-1',
          userId: options.owner ?? USER,
          credentialData:
            options.credential === 'malformed'
              ? { password_hash: 42 }
              : { password_hash: '$argon2id$old', email_verified: false },
        };
      },
      updatePassword: async (realmId, id, passwordData, tx) => {
        write('password', { realmId, id, passwordData }, tx);
        return options.vanished === true ? undefined : { id };
      },
    },
    users: {
      findById: async (_realmId, id) =>
        options.user === 'none' ? undefined : { id, enabled: options.enabled ?? true },
    },
    userAttributes: {
      setVerified: async (userId, source, attrKey, verified, tx) => {
        write('attribute', { userId, source, attrKey, verified }, tx);
        return { userId };
      },
    },
    userRequiredActions: {
      remove: async (realmId, userId, action, tx) => {
        write('required_action', { realmId, userId, action }, tx);
        return true;
      },
    },
    refreshTokens: {
      revokeAllForUser: async (userId, reason, tx) => {
        write('refresh_families', { userId, reason }, tx);
      },
    },
    userSessionEpochs: {
      advance: async (input, tx) => {
        write('epoch', input, tx);
        return { epoch: 3, advancedAt: input.at };
      },
    },
  };
  const policy = {
    allowed: vi.fn(async () => true),
    hash: vi.fn(async (password: string) => `argon2id(${password})`),
    now: () => AT,
    recorded: vi.fn(async (reset, tx) => {
      write('event', reset, tx);
    }),
    committed: vi.fn(async () => undefined),
  } satisfies AccountResetPolicy<string>;
  const transaction = async <T>(work: (tx: string) => Promise<T>): Promise<T> => {
    const before = writes.length;
    try {
      const result = await work('tx-1');
      committed = [...writes];
      return result;
    } catch (error) {
      writes.splice(before);
      throw error;
    }
  };
  const resets = createRepositoryAccountResets(stores, transaction, policy);
  return { resets, policy, writes, committed: () => committed };
}

describe('createRepositoryAccountResets', () => {
  it('replaces the password, verifies the address and ends what the old one opened, in one transaction', async () => {
    const { resets, policy, committed } = build();

    await expect(resets.reset(RESET)).resolves.toEqual({ kind: 'reset' });

    expect(policy.hash).toHaveBeenCalledWith(RESET.password);
    const reset = {
      realmId: REALM,
      clientId: 'notes-web',
      userId: USER,
      identifier: ADDRESS,
      epoch: 3,
      advancedAt: AT,
    };
    expect(committed()).toEqual([
      {
        what: 'password',
        data: {
          realmId: REALM,
          id: 'credential-1',
          passwordData: {
            password_hash: `argon2id(${RESET.password})`,
            email_verified: true,
            password_normalization: 'nfc',
          },
        },
        tx: 'tx-1',
      },
      {
        what: 'attribute',
        data: { userId: USER, source: 'self_reported', attrKey: 'email', verified: true },
        tx: 'tx-1',
      },
      {
        what: 'required_action',
        data: { realmId: REALM, userId: USER, action: 'update_password' },
        tx: 'tx-1',
      },
      {
        what: 'refresh_families',
        data: { userId: USER, reason: RESET_REFRESH_REVOCATION_REASON },
        tx: 'tx-1',
      },
      { what: 'epoch', data: { realmId: REALM, userId: USER, at: AT }, tx: 'tx-1' },
      { what: 'event', data: reset, tx: 'tx-1' },
    ]);
    // After the commit, once.
    expect(policy.committed).toHaveBeenCalledTimes(1);
    expect(policy.committed).toHaveBeenCalledWith(reset);
  });

  it.each([
    ['another user’s credential', { owner: OTHER_USER }, 'subject_mismatch'],
    ['no credential', { credential: 'none' }, 'subject_mismatch'],
    ['no user', { user: 'none' }, 'subject_mismatch'],
    ['a disabled user', { enabled: false }, 'account_disabled'],
  ] as const)('writes nothing for %s', async (_name, options, reason) => {
    const { resets, policy, writes } = build(options);

    await expect(resets.reset(RESET)).resolves.toEqual({ kind: 'refused', reason });

    expect(writes).toEqual([]);
    expect(policy.committed).not.toHaveBeenCalled();
  });

  it('throws, writing nothing, for a credential whose data it cannot read', async () => {
    const { resets, writes, policy } = build({ credential: 'malformed' });

    await expect(resets.reset(RESET)).rejects.toThrow(/malformed credential_data/);
    expect(writes).toEqual([]);
    expect(policy.committed).not.toHaveBeenCalled();
  });

  it('rolls everything back when a write fails, and runs nothing after it', async () => {
    for (const failAt of ['refresh_families', 'epoch', 'event']) {
      const { resets, writes, policy } = build({ failAt });
      await expect(resets.reset(RESET)).rejects.toThrow(`${failAt} failed`);
      expect(writes).toEqual([]);
      expect(policy.committed).not.toHaveBeenCalled();
    }
  });

  it('rolls back when the password row is gone by the time it is written', async () => {
    const { resets, writes } = build({ vanished: true });

    await expect(resets.reset(RESET)).rejects.toThrow(/gone/);
    expect(writes).toEqual([]);
  });

  it('asks the policy whether the client may reset', async () => {
    const { resets, policy } = build();
    policy.allowed.mockResolvedValueOnce(false);

    await expect(resets.allowed({ realmId: REALM, clientId: 'notes-web' })).resolves.toBe(false);
    expect(policy.allowed).toHaveBeenCalledWith({ realmId: REALM, clientId: 'notes-web' });
  });
});
