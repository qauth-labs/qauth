import { describe, expect, it, vi } from 'vitest';

import {
  type AccountRegistrationPolicy,
  type AccountRegistrationRepositories,
  createRepositoryAccountRegistrations,
} from './account-registrations';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const ADDRESS = 'alice@example.com';

class Duplicate extends Error {}

/** Repositories that record every write in one array, as one transaction's would. */
function build(options: { duplicate?: boolean; allowed?: boolean } = {}) {
  const writes: { readonly what: string; readonly data: unknown; readonly tx: unknown }[] = [];
  let committed: typeof writes = [];
  const stores: AccountRegistrationRepositories<string> = {
    users: {
      create: async (data, tx) => {
        writes.push({ what: 'user', data, tx });
        return { id: USER };
      },
    },
    userCredentials: {
      create: async (data, tx) => {
        if (options.duplicate === true) throw new Duplicate();
        writes.push({ what: 'credential', data, tx });
        return { id: 'credential-1' };
      },
    },
    userAttributes: {
      upsertMany: async (userId, attributes, tx) => {
        writes.push({ what: 'attributes', data: { userId, attributes }, tx });
        return [];
      },
    },
  };
  const policy: AccountRegistrationPolicy<string> = {
    allowed: vi.fn(async () => options.allowed ?? true),
    hash: vi.fn(async (password: string) => `argon2id(${password})`),
    isUniqueViolation: (error) => error instanceof Duplicate,
    registered: vi.fn(async (input, tx) => {
      writes.push({ what: 'event', data: input, tx });
    }),
  };
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
  const registrations = createRepositoryAccountRegistrations(stores, transaction, policy);
  return { registrations, policy, writes, committed: () => committed };
}

describe('createRepositoryAccountRegistrations', () => {
  it('creates the user, the verified password credential with its marker, the verified address and the event, in one transaction', async () => {
    const built = build();
    const result = await built.registrations.create({
      realmId: REALM,
      clientId: 'notes-web',
      identifier: ADDRESS,
      password: 'seven amber kites over the old harbour',
      normalization: 'nfc',
    });
    expect(result).toEqual({ kind: 'created', userId: USER });
    expect(built.committed()).toEqual([
      { what: 'user', data: { realmId: REALM }, tx: 'tx-1' },
      {
        what: 'credential',
        data: {
          userId: USER,
          realmId: REALM,
          providerType: 'password',
          externalSub: ADDRESS,
          credentialData: {
            password_hash: 'argon2id(seven amber kites over the old harbour)',
            email_verified: true,
            password_normalization: 'nfc',
          },
        },
        tx: 'tx-1',
      },
      {
        what: 'attributes',
        data: {
          userId: USER,
          attributes: [
            {
              source: 'self_reported',
              attrKey: 'email',
              attrValue: ADDRESS,
              verified: true,
              expiresAt: null,
            },
          ],
        },
        tx: 'tx-1',
      },
      {
        what: 'event',
        data: { realmId: REALM, clientId: 'notes-web', userId: USER },
        tx: 'tx-1',
      },
    ]);
  });

  it('answers a taken address as a conflict, with everything rolled back', async () => {
    const built = build({ duplicate: true });
    const result = await built.registrations.create({
      realmId: REALM,
      clientId: 'notes-web',
      identifier: ADDRESS,
      password: 'seven amber kites over the old harbour',
      normalization: 'nfc',
    });
    expect(result).toEqual({ kind: 'conflict' });
    expect(built.writes).toEqual([]);
    expect(built.policy.registered).not.toHaveBeenCalled();
  });

  it('lets any other failure through, so the round is refused', async () => {
    const built = build();
    const failing = createRepositoryAccountRegistrations(
      {
        users: { create: async () => ({ id: USER }) },
        userCredentials: {
          create: async () => {
            throw new Error('database down');
          },
        },
        userAttributes: { upsertMany: async () => [] },
      },
      async (work) => work('tx'),
      { ...built.policy, hash: async (password) => password }
    );
    await expect(
      failing.create({
        realmId: REALM,
        clientId: 'notes-web',
        identifier: ADDRESS,
        password: 'x',
        normalization: 'nfc',
      })
    ).rejects.toThrow('database down');
  });

  it('asks the policy whether the realm and the client allow registration', async () => {
    const built = build({ allowed: false });
    await expect(
      built.registrations.allowed({ realmId: REALM, clientId: 'notes-web' })
    ).resolves.toBe(false);
    expect(built.policy.allowed).toHaveBeenCalledWith({ realmId: REALM, clientId: 'notes-web' });
  });
});
