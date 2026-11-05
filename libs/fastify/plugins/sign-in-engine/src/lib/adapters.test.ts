import { createHmac, hkdfSync } from 'node:crypto';

import { createSignInEngine, type SignInAuditRecord } from '@qauth-labs/server-sign-in-engine';
import {
  FakeDirectory,
  fakeIdentifierDigest,
  FakePasswords,
  FakePolicy,
  passwordAccount,
} from '@qauth-labs/server-sign-in-engine/src/testing/fakes';
import { STEP_URNS } from '@qauth-labs/server-step-grammar';
import { getEventType } from '@qauth-labs/shared-events';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  type AccountDirectoryRepositories,
  createRepositoryAccountDirectory,
} from './account-directory';
import {
  type AddressVerifierRepositories,
  createRepositoryAddressVerifier,
} from './address-verifier';
import { signInAuditEvent } from './audit-events';
import { type BreachCheckResult, createRealmBreachCheck } from './breached-passwords';
import { signInEnginePlugin } from './fastify-plugin-sign-in-engine';
import {
  createCookieSecretEmailCodeDigest,
  createCookieSecretIdentifierDigest,
  EMAIL_CODE_HMAC_LABEL,
  END_USER_IP_HMAC_LABEL,
  IDENTIFIER_HMAC_LABEL,
} from './identifier-digest';
import {
  createRepositoryPasswordUpdates,
  type PasswordUpdateRepositories,
} from './password-updates';
import { createArgon2PasswordVerifier } from './password-verifier';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const OTHER_REALM = '0199fa20-0000-7000-8000-00000000bbbb';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const IDENTIFIER = 'alice@example.com';

function stubStores(
  overrides: Partial<{
    credential: Record<string, unknown> | undefined;
    user: { id: string; enabled: boolean } | undefined;
    passkeys: { realmId: string; disabledAt?: number | null }[];
    upstreams: Record<string, unknown>[];
    grants: unknown[];
    disabledAt: number | null;
    actions: string[];
  }> = {}
) {
  const state = {
    credential: { password_hash: 'hash', email_verified: true } as
      | Record<string, unknown>
      | undefined,
    user: { id: USER, enabled: true } as { id: string; enabled: boolean } | undefined,
    passkeys: [] as { realmId: string; disabledAt?: number | null }[],
    upstreams: [] as Record<string, unknown>[],
    grants: [] as unknown[],
    disabledAt: null as number | null,
    actions: [] as string[],
    ...overrides,
  };
  const calls: string[] = [];
  const repos: AccountDirectoryRepositories = {
    userCredentials: {
      findByRealmProviderSub: async (realmId, providerType, externalSub) => {
        calls.push(`credential:${realmId}:${providerType}:${externalSub}`);
        return state.credential === undefined
          ? undefined
          : {
              id: 'cred-1',
              userId: USER,
              realmId,
              providerType,
              credentialData: state.credential,
              disabledAt: state.disabledAt,
            };
      },
      findAllByUserId: async (userId) => {
        calls.push(`all:${userId}`);
        return [
          ...(state.credential === undefined
            ? []
            : [
                {
                  id: 'cred-1',
                  userId,
                  realmId: REALM,
                  providerType: 'password',
                  credentialData: state.credential,
                  disabledAt: state.disabledAt,
                },
              ]),
          ...state.passkeys.map((passkey, index) => ({
            id: `passkey-${index}`,
            userId,
            realmId: passkey.realmId,
            providerType: 'webauthn',
            credentialData: {},
            disabledAt: passkey.disabledAt ?? null,
          })),
          ...state.upstreams.map((upstream, index) => ({
            id: `upstream-${index}`,
            userId,
            realmId: REALM,
            providerType: 'oidc_corp',
            credentialData: upstream,
            disabledAt: null,
          })),
        ];
      },
    },
    users: {
      findById: async (realmId, id) => {
        calls.push(`user:${realmId}:${id}`);
        return state.user;
      },
    },
    adminGrants: {
      listLive: async (realmId, userId) => {
        calls.push(`grants:${realmId}:${userId}`);
        return state.grants;
      },
    },
    userRequiredActions: {
      listForUser: async (realmId, userId) => {
        calls.push(`actions:${realmId}:${userId}`);
        return state.actions.map((action) => ({ action }));
      },
    },
  };
  return { repos, calls };
}

const log = () => ({ error: vi.fn<(details: Record<string, unknown>, message: string) => void>() });

describe('the repository account directory', () => {
  it('names no account when the identifier has no password credential in the realm', async () => {
    const { repos, calls } = stubStores({ credential: undefined });
    const directory = createRepositoryAccountDirectory(repos, log());
    expect(await directory.findByIdentifier(REALM, IDENTIFIER)).toBeNull();
    expect(calls).toEqual([`credential:${REALM}:password:${IDENTIFIER}`]);
  });

  it('reads only the credential and the user before the password is checked', async () => {
    const { repos, calls } = stubStores({ passkeys: [{ realmId: REALM }], grants: [{}] });
    const directory = createRepositoryAccountDirectory(repos, log());
    expect(await directory.findByIdentifier(REALM, IDENTIFIER)).toEqual({
      userId: USER,
      enabled: true,
      verified: true,
      password: { disabled: false, hash: 'hash' },
    });
    expect(calls).toEqual([`credential:${REALM}:password:${IDENTIFIER}`, `user:${REALM}:${USER}`]);
  });

  it('reads every factor and the admin grants of the user a factor proved', async () => {
    const { repos } = stubStores({
      passkeys: [{ realmId: REALM }, { realmId: OTHER_REALM }],
      grants: [{ grant: {} }],
    });
    const directory = createRepositoryAccountDirectory(repos, log());
    expect(await directory.findByUserId(REALM, USER)).toEqual({
      userId: USER,
      enabled: true,
      admin: true,
      verified: true,
      // A passkey of another realm's row is not this account's.
      factors: [
        { type: 'password', disabled: false },
        { type: 'passkey', disabled: false },
      ],
      requiredActions: [],
    });
    const { repos: none } = stubStores({ user: undefined });
    expect(
      await createRepositoryAccountDirectory(none, log()).findByUserId(REALM, USER)
    ).toBeNull();
  });

  it('reads the pending required actions of the proved account (#635)', async () => {
    const { repos, calls } = stubStores({
      actions: ['update_password', 'setup_mfa', 'no_such_action', 'update_password'],
    });
    const errors = log();
    const account = await createRepositoryAccountDirectory(repos, errors).findByUserId(REALM, USER);
    expect(account?.requiredActions).toEqual(['update_password', 'setup_mfa']);
    expect(calls).toContain(`actions:${REALM}:${USER}`);
    // An action the engine does not know is reported, never a reason to drop the others.
    expect(errors.error).toHaveBeenCalledWith(
      { userId: USER },
      'unknown required action on a user'
    );
    // None is read before a factor proved the account.
    const before = stubStores({ actions: ['update_password'] });
    await createRepositoryAccountDirectory(before.repos, log()).findByIdentifier(REALM, IDENTIFIER);
    expect(before.calls.some((call) => call.startsWith('actions:'))).toBe(false);
  });

  it('reads the proved account as unverified while its password credential is (#638)', async () => {
    const unverified = stubStores({ credential: { password_hash: 'hash', email_verified: false } });
    expect(
      await createRepositoryAccountDirectory(unverified.repos, log()).findByUserId(REALM, USER)
    ).toMatchObject({ verified: false });
    const unreadable = stubStores({ credential: { password_hash: 42 } });
    expect(
      await createRepositoryAccountDirectory(unreadable.repos, log()).findByUserId(REALM, USER)
    ).toMatchObject({ verified: false });
    // A passkey-only account has no address to prove.
    const passkeyOnly = stubStores({ credential: undefined, passkeys: [{ realmId: REALM }] });
    expect(
      await createRepositoryAccountDirectory(passkeyOnly.repos, log()).findByUserId(REALM, USER)
    ).toMatchObject({ verified: true });
  });

  it("reads an upstream provider's account as its credential's verified says (#639)", async () => {
    const read = async (upstream: Record<string, unknown>) =>
      createRepositoryAccountDirectory(
        stubStores({ credential: undefined, upstreams: [upstream] }).repos,
        log()
      ).findByUserId(REALM, USER);
    expect(
      await read({ kind: 'upstream', iss: 'https://idp.example', verified: true })
    ).toMatchObject({ verified: true, factors: [] });
    expect(await read({ kind: 'upstream', verified: false })).toMatchObject({ verified: false });
    // Malformed: not verified.
    expect(await read({ kind: 'upstream' })).toMatchObject({ verified: false });
  });

  it('reports a disabled, unverified account as such', async () => {
    const { repos } = stubStores({
      credential: { password_hash: 'hash', email_verified: false },
      user: { id: USER, enabled: false },
    });
    expect(
      await createRepositoryAccountDirectory(repos, log()).findByIdentifier(REALM, IDENTIFIER)
    ).toMatchObject({ enabled: false, verified: false });
  });

  it("carries the credential's normalisation marker to the password step (#634)", async () => {
    const { repos } = stubStores({
      credential: { password_hash: 'hash', email_verified: true, password_normalization: 'nfc' },
    });
    expect(
      await createRepositoryAccountDirectory(repos, log()).findByIdentifier(REALM, IDENTIFIER)
    ).toMatchObject({ password: { disabled: false, hash: 'hash', normalization: 'nfc' } });

    // A credential from before the marker has none.
    const { repos: legacy } = stubStores({});
    const account = await createRepositoryAccountDirectory(legacy, log()).findByIdentifier(
      REALM,
      IDENTIFIER
    );
    expect(account?.password).not.toHaveProperty('normalization');
  });

  it('gives an unreadable credential no hash, and logs it without its data', async () => {
    const { repos } = stubStores({ credential: { password_hash: 42 } });
    const logger = log();
    const account = await createRepositoryAccountDirectory(repos, logger).findByIdentifier(
      REALM,
      IDENTIFIER
    );
    expect(account).toMatchObject({ verified: false, password: { disabled: false, hash: null } });
    expect(logger.error).toHaveBeenCalledWith({ credentialId: 'cred-1' }, expect.any(String));
  });

  it('ignores a disabled mark while the hard action is unarmed, and says so', async () => {
    const { repos } = stubStores({ disabledAt: 1_793_491_200_000 });
    const armed = vi.fn(async () => false);
    const directory = createRepositoryAccountDirectory(repos, log(), { hardActionArmed: armed });
    expect(await directory.findByIdentifier(REALM, IDENTIFIER)).toMatchObject({
      password: { disabled: false, hash: 'hash', ignoredMark: true },
    });
    expect(armed).toHaveBeenCalledWith(REALM);
    expect(await directory.findByUserId(REALM, USER)).toMatchObject({
      factors: [{ type: 'password', disabled: false }],
    });
    // With no arming at all, never armed.
    expect(
      await createRepositoryAccountDirectory(repos, log()).findByIdentifier(REALM, IDENTIFIER)
    ).toMatchObject({ password: { disabled: false, ignoredMark: true } });
  });

  it('makes a marked credential unusable while armed, and still bound', async () => {
    const { repos } = stubStores({
      disabledAt: 1_793_491_200_000,
      passkeys: [{ realmId: REALM }, { realmId: REALM, disabledAt: 1 }],
    });
    const directory = createRepositoryAccountDirectory(repos, log(), {
      hardActionArmed: async () => true,
    });
    const candidate = await directory.findByIdentifier(REALM, IDENTIFIER);
    expect(candidate?.password).toEqual({ disabled: true, hash: 'hash' });
    expect(await directory.findByUserId(REALM, USER)).toMatchObject({
      factors: [
        { type: 'password', disabled: true },
        { type: 'passkey', disabled: false },
        { type: 'passkey', disabled: true },
      ],
    });
  });

  it('asks whether the hard action is armed only for a marked credential, and fails closed', async () => {
    const armed = vi.fn(async () => {
      throw new Error('settings unreadable');
    });
    const { repos } = stubStores();
    await createRepositoryAccountDirectory(repos, log(), {
      hardActionArmed: armed,
    }).findByIdentifier(REALM, IDENTIFIER);
    expect(armed).not.toHaveBeenCalled();
    const { repos: marked } = stubStores({ disabledAt: 1 });
    await expect(
      createRepositoryAccountDirectory(marked, log(), { hardActionArmed: armed }).findByIdentifier(
        REALM,
        IDENTIFIER
      )
    ).rejects.toThrow('settings unreadable');
  });

  it('names no account for a credential without a users row', async () => {
    const { repos } = stubStores({ user: undefined });
    const logger = log();
    expect(
      await createRepositoryAccountDirectory(repos, logger).findByIdentifier(REALM, IDENTIFIER)
    ).toBeNull();
    expect(logger.error).toHaveBeenCalledWith({ credentialId: 'cred-1' }, expect.any(String));
  });
});

describe('the Argon2id password verifier', () => {
  function hasher() {
    return {
      hashPassword: vi.fn(async (password: string) => `hash:${password}`),
      verifyPassword: vi.fn(async (hash: string, plain: string) => hash === `hash:${plain}`),
    };
  }

  it('verifies against the stored hash', async () => {
    const argon = hasher();
    const verifier = createArgon2PasswordVerifier(argon, log());
    expect(await verifier.verify('hash:right', 'right')).toBe(true);
    expect(await verifier.verify('hash:right', 'wrong')).toBe(false);
  });

  it('runs one verification against a dummy hash it made once, of a secret nobody holds', async () => {
    const argon = hasher();
    const verifier = createArgon2PasswordVerifier(argon, log());
    await verifier.verifyDecoy('guess-1');
    await verifier.verifyDecoy('guess-2');
    expect(argon.hashPassword).toHaveBeenCalledTimes(1);
    const [secret] = argon.hashPassword.mock.calls[0];
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
    expect(argon.verifyPassword.mock.calls).toEqual([
      [`hash:${secret}`, 'guess-1'],
      [`hash:${secret}`, 'guess-2'],
    ]);
  });

  it('swallows a failure to make the dummy hash, and still spends one Argon2id computation on that miss', async () => {
    const argon = hasher();
    argon.hashPassword.mockRejectedValueOnce(new Error('argon2 failed'));
    const logger = log();
    const verifier = createArgon2PasswordVerifier(argon, logger);
    await expect(verifier.verifyDecoy('guess')).resolves.toBeUndefined();
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(logger.error.mock.calls)).not.toContain('guess');
    // The miss made a new dummy hash in place of the verification it owed.
    expect(argon.hashPassword).toHaveBeenCalledTimes(2);
    expect(argon.verifyPassword).not.toHaveBeenCalled();
    // The next miss verifies against it, making none.
    await verifier.verifyDecoy('guess');
    expect(argon.hashPassword).toHaveBeenCalledTimes(2);
    expect(argon.verifyPassword).toHaveBeenCalledTimes(1);
  });

  it('logs a second failure to make the dummy hash, and tries again on the next miss', async () => {
    const argon = hasher();
    argon.hashPassword.mockRejectedValueOnce(new Error('argon2 failed'));
    argon.hashPassword.mockRejectedValueOnce(new Error('argon2 failed again'));
    const logger = log();
    const verifier = createArgon2PasswordVerifier(argon, logger);
    await expect(verifier.verifyDecoy('guess')).resolves.toBeUndefined();
    expect(logger.error).toHaveBeenCalledTimes(2);
    await verifier.verifyDecoy('guess');
    expect(argon.hashPassword).toHaveBeenCalledTimes(3);
    expect(argon.verifyPassword).toHaveBeenCalledTimes(1);
  });

  it('fails the dummy verification as the real one fails, so an outage tells no account apart', async () => {
    const argon = hasher();
    argon.verifyPassword.mockRejectedValue(new Error('thread pool gone'));
    const verifier = createArgon2PasswordVerifier(argon, log());
    await expect(verifier.verify('hash:x', 'x')).rejects.toThrow('thread pool gone');
    await expect(verifier.verifyDecoy('x')).rejects.toThrow('thread pool gone');
  });
});

describe('the identifier HMAC', () => {
  const secret = Buffer.from('the realm cookie secret, 32 bytes');

  function signer() {
    return {
      getCookieSecrets: vi.fn(async () => ({
        current: { kid: 'cookie-1', secret: Buffer.from(secret) },
        previous: { kid: 'cookie-0', secret: Buffer.from('the retired cookie secret') },
      })),
    };
  }

  it('is HMAC-SHA-256 under a key derived from the realm cookie secret, over realm and identifier', async () => {
    const source = signer();
    const digest = createCookieSecretIdentifierDigest(source);
    const value = await digest({ realmId: REALM, identifier: IDENTIFIER });
    const key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), IDENTIFIER_HMAC_LABEL, 32));
    expect(value).toBe(
      createHmac('sha256', key).update(`${REALM}\u0000${IDENTIFIER}`).digest('base64url')
    );
    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(source.getCookieSecrets).toHaveBeenCalledWith('web', REALM);
    // Both secrets the signer handed over are wiped once used.
    const handed = await source.getCookieSecrets.mock.results[0].value;
    expect(handed.current.secret.every((byte: number) => byte === 0)).toBe(true);
    expect(handed.previous.secret.every((byte: number) => byte === 0)).toBe(true);
  });

  it('is neither a cookie signature under the same secret nor the same in two realms', async () => {
    const digest = createCookieSecretIdentifierDigest(signer());
    const value = await digest({ realmId: REALM, identifier: IDENTIFIER });
    expect(value).not.toBe(createHmac('sha256', secret).update(IDENTIFIER).digest('base64url'));
    // The key is not the cookie signature of the label under the same secret.
    const signedLabel = createHmac('sha256', secret).update(IDENTIFIER_HMAC_LABEL).digest();
    expect(value).not.toBe(
      createHmac('sha256', signedLabel).update(`${REALM}\u0000${IDENTIFIER}`).digest('base64url')
    );
    expect(await digest({ realmId: OTHER_REALM, identifier: IDENTIFIER })).not.toBe(value);
    expect(await digest({ realmId: REALM, identifier: 'bob@example.com' })).not.toBe(value);
  });

  it('derives the end-user IP key under a label of its own, as the signer’s local caller', async () => {
    const source = signer();
    const ipDigest = createCookieSecretIdentifierDigest(source, 'local', END_USER_IP_HMAC_LABEL);
    const value = await ipDigest({ realmId: REALM, identifier: '203.0.113.7' });
    const key = Buffer.from(
      hkdfSync('sha256', secret, Buffer.alloc(0), END_USER_IP_HMAC_LABEL, 32)
    );
    expect(value).toBe(
      createHmac('sha256', key).update(`${REALM}\u0000203.0.113.7`).digest('base64url')
    );
    expect(source.getCookieSecrets).toHaveBeenCalledWith('local', REALM);
    expect(value).not.toBe(
      await createCookieSecretIdentifierDigest(signer())({
        realmId: REALM,
        identifier: '203.0.113.7',
      })
    );
  });
});

describe('the email-code HMAC (#638)', () => {
  const secret = Buffer.from('the realm cookie secret, 32 bytes');
  const signer = () => ({
    getCookieSecrets: vi.fn(async () => ({
      current: { kid: 'cookie-1', secret: Buffer.from(secret) },
      previous: null,
    })),
  });

  it('is HMAC-SHA-256 under a key of its own label, over realm, salt and code', async () => {
    const source = signer();
    const digest = createCookieSecretEmailCodeDigest(source);
    const value = await digest({ realmId: REALM, salt: 's'.repeat(22), code: '012345' });
    const key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), EMAIL_CODE_HMAC_LABEL, 32));
    expect(value).toBe(
      createHmac('sha256', key)
        .update(`${REALM}\u0000${'s'.repeat(22)}\u0000012345`)
        .digest('base64url')
    );
    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(source.getCookieSecrets).toHaveBeenCalledWith('web', REALM);
    const handed = await source.getCookieSecrets.mock.results[0].value;
    expect(handed.current.secret.every((byte: number) => byte === 0)).toBe(true);
    // Another salt, another code or another realm is another digest.
    const again = createCookieSecretEmailCodeDigest(signer());
    expect(await again({ realmId: REALM, salt: 't'.repeat(22), code: '012345' })).not.toBe(value);
    expect(await again({ realmId: REALM, salt: 's'.repeat(22), code: '012346' })).not.toBe(value);
    expect(await again({ realmId: OTHER_REALM, salt: 's'.repeat(22), code: '012345' })).not.toBe(
      value
    );
  });
});

describe('the repository address verifier (#638)', () => {
  function stubWrites(
    overrides: Partial<{
      credential: { id: string; userId: string } | undefined;
      user: { id: string; enabled: boolean } | undefined;
      attribute: unknown;
      upstreams: readonly {
        id: string;
        realmId: string;
        credentialData: Record<string, unknown>;
      }[];
      attributes: readonly { attrKey: string; attrValue: string }[];
    }> = {}
  ) {
    const state = {
      credential: { id: 'cred-1', userId: USER } as { id: string; userId: string } | undefined,
      user: { id: USER, enabled: true } as { id: string; enabled: boolean } | undefined,
      attribute: { verified: true } as unknown,
      upstreams: [
        { id: 'up-1', realmId: REALM, credentialData: { kind: 'upstream', verified: false } },
      ] as readonly { id: string; realmId: string; credentialData: Record<string, unknown> }[],
      attributes: [{ attrKey: 'email', attrValue: 'Alice@Example.com' }] as readonly {
        attrKey: string;
        attrValue: string;
      }[],
      ...overrides,
    };
    const calls: string[] = [];
    const repos: AddressVerifierRepositories<string> = {
      userCredentials: {
        findByRealmProviderSub: async (realmId, providerType, externalSub, tx) => {
          calls.push(`credential:${realmId}:${providerType}:${externalSub}:${tx}`);
          return state.credential;
        },
        setEmailVerified: async (id, tx) => {
          calls.push(`setEmailVerified:${id}:${tx}`);
        },
        findAllByUserIdAndType: async (userId, providerType, tx) => {
          calls.push(`upstreams:${userId}:${providerType}:${tx}`);
          return state.upstreams;
        },
        updateCredentialData: async (id, credentialData, tx) => {
          calls.push(`updateCredentialData:${id}:${JSON.stringify(credentialData)}:${tx}`);
        },
      },
      users: {
        findById: async (realmId, id, tx) => {
          calls.push(`user:${realmId}:${id}:${tx}`);
          return state.user;
        },
      },
      userAttributes: {
        findByUserIdAndSource: async (userId, source, tx) => {
          calls.push(`attributes:${userId}:${source}:${tx}`);
          return state.attributes;
        },
        setVerified: async (userId, source, attrKey, verified, tx) => {
          calls.push(`attribute:${userId}:${source}:${attrKey}:${verified}:${tx}`);
          return state.attribute;
        },
      },
    };
    const transaction = async <T>(work: (tx: string) => Promise<T>) => work('tx-1');
    const warn = vi.fn();
    return {
      verifier: createRepositoryAddressVerifier(repos, transaction, { warn }),
      calls,
      warn,
    };
  }
  const input = { realmId: REALM, userId: USER, identifier: IDENTIFIER };

  it('marks the credential and the email attribute verified, in one transaction', async () => {
    const { verifier, calls, warn } = stubWrites();
    expect(await verifier.markVerified(input)).toEqual({ kind: 'verified' });
    expect(calls).toEqual([
      `credential:${REALM}:password:${IDENTIFIER}:tx-1`,
      `user:${REALM}:${USER}:tx-1`,
      'setEmailVerified:cred-1:tx-1',
      `attribute:${USER}:self_reported:email:true:tx-1`,
    ]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("writes nothing for another user's address, an unknown one, or a disabled user", async () => {
    for (const [overrides, reason] of [
      [{ credential: { id: 'cred-2', userId: 'someone-else' } }, 'subject_mismatch'],
      [{ credential: undefined }, 'subject_mismatch'],
      [{ user: undefined }, 'subject_mismatch'],
      [{ user: { id: USER, enabled: false } }, 'account_disabled'],
    ] as const) {
      const { verifier, calls } = stubWrites(overrides);
      expect(await verifier.markVerified(input)).toEqual({ kind: 'refused', reason });
      expect(calls.filter((call) => !/^(credential|user):/.test(call))).toEqual([]);
    }
  });

  it("marks an upstream provider's credential and its email attribute verified (#639)", async () => {
    const { verifier, calls } = stubWrites();
    expect(await verifier.markVerified({ ...input, upstream: 'oidc_corp' })).toEqual({
      kind: 'verified',
    });
    expect(calls).toEqual([
      `upstreams:${USER}:oidc_corp:tx-1`,
      `user:${REALM}:${USER}:tx-1`,
      `attributes:${USER}:oidc_corp:tx-1`,
      'updateCredentialData:up-1:{"kind":"upstream","verified":true}:tx-1',
      `attribute:${USER}:oidc_corp:email:true:tx-1`,
    ]);
  });

  it("writes nothing for an upstream account whose address is not the provider's, or in another realm (#639)", async () => {
    for (const [overrides, reason] of [
      [
        { attributes: [{ attrKey: 'email', attrValue: 'mallory@example.com' }] },
        'subject_mismatch',
      ],
      [{ attributes: [] }, 'subject_mismatch'],
      [
        {
          upstreams: [
            {
              id: 'up-1',
              realmId: OTHER_REALM,
              credentialData: { kind: 'upstream', verified: false },
            },
          ],
        },
        'subject_mismatch',
      ],
      [{ user: { id: USER, enabled: false } }, 'account_disabled'],
    ] as const) {
      const { verifier, calls } = stubWrites(overrides);
      expect(await verifier.markVerified({ ...input, upstream: 'oidc_corp' })).toEqual({
        kind: 'refused',
        reason,
      });
      expect(calls.filter((call) => /^(updateCredentialData|attribute):/.test(call))).toEqual([]);
    }
  });

  it('reports a missing attribute row and verifies all the same', async () => {
    const { verifier, warn } = stubWrites({ attribute: undefined });
    expect(await verifier.markVerified(input)).toEqual({ kind: 'verified' });
    expect(warn).toHaveBeenCalledWith({ userId: USER }, expect.any(String));
  });
});

describe('the realm breach check (#635)', () => {
  it('asks the checker with the realm setting and maps every result', async () => {
    const calls: unknown[] = [];
    const results: BreachCheckResult[] = [
      { kind: 'off' },
      { kind: 'listed', source: 'local' },
      { kind: 'not_listed', source: 'k_anonymity' },
      { kind: 'failed', source: 'k_anonymity', reason: 'lookup_blocked' },
    ];
    let next = 0;
    const check = createRealmBreachCheck({
      checker: {
        check: async (input) => {
          calls.push(input);
          return results[next++] ?? { kind: 'off' };
        },
      },
      settingOf: async (realmId) => ({ source: 'k_anonymity', name: `name-of-${realmId}` }),
    });
    const verdicts = [];
    for (let index = 0; index < results.length; index += 1) {
      verdicts.push(await check.check({ realmId: REALM, password: 'pw' }));
    }
    expect(verdicts).toEqual([
      { kind: 'off' },
      { kind: 'listed' },
      { kind: 'not_listed' },
      { kind: 'failed', failure: 'lookup_blocked' },
    ]);
    expect(calls[0]).toEqual({ source: 'k_anonymity', password: 'pw', realm: `name-of-${REALM}` });
  });

  it('throws when the realm cannot be read, which the engine counts as a failed check', async () => {
    const check = createRealmBreachCheck({
      checker: { check: async () => ({ kind: 'off' }) },
      settingOf: async () => {
        throw new Error('no such realm');
      },
    });
    await expect(check.check({ realmId: REALM, password: 'pw' })).rejects.toThrow('no such realm');
  });
});

describe('the repository password updates (#635)', () => {
  function stubUpdates(
    overrides: Partial<{
      credential:
        | { id: string; userId: string; credentialData: Record<string, unknown> }
        | undefined;
      user: { id: string; enabled: boolean } | undefined;
    }> = {}
  ) {
    const state = {
      credential: {
        id: 'cred-1',
        userId: USER,
        credentialData: { password_hash: 'old-hash', email_verified: true, extra: 'kept' },
      } as { id: string; userId: string; credentialData: Record<string, unknown> } | undefined,
      user: { id: USER, enabled: true } as { id: string; enabled: boolean } | undefined,
      ...overrides,
    };
    const calls: string[] = [];
    const written: Record<string, unknown>[] = [];
    const repos: PasswordUpdateRepositories<string> = {
      userCredentials: {
        findByRealmProviderSub: async (realmId, providerType, externalSub, tx) => {
          calls.push(`credential:${realmId}:${providerType}:${externalSub}:${tx}`);
          return state.credential;
        },
        updateCredentialData: async (id, data, tx) => {
          calls.push(`update:${id}:${tx}`);
          written.push(data);
        },
        clearDisabledAt: async (realmId, providerType, externalSub, tx) => {
          calls.push(`clear:${realmId}:${providerType}:${externalSub}:${tx}`);
        },
      },
      users: {
        findById: async (realmId, id, tx) => {
          calls.push(`user:${realmId}:${id}:${tx}`);
          return state.user;
        },
      },
      userRequiredActions: {
        remove: async (realmId, userId, action, tx) => {
          calls.push(`remove:${realmId}:${userId}:${action}:${tx}`);
          return true;
        },
      },
    };
    const transaction = async <T>(work: (tx: string) => Promise<T>) => work('tx-1');
    const hash = vi.fn(async (password: string) => `hash(${password})`);
    const updates = createRepositoryPasswordUpdates(repos, transaction, {
      minLength: async () => 15,
      check: async ({ password }) => ({ kind: 'accepted', password, normalization: 'nfc' }),
      hash,
    });
    return { updates, calls, written, hash };
  }
  const input = {
    realmId: REALM,
    userId: USER,
    identifier: IDENTIFIER,
    password: 'a new password of some length',
    normalization: 'nfc' as const,
  };

  it('writes the new hash, clears the mark and the required action, in one transaction', async () => {
    const { updates, calls, written, hash } = stubUpdates();
    expect(await updates.replace(input)).toEqual({ kind: 'replaced' });
    expect(hash).toHaveBeenCalledWith(input.password);
    expect(calls).toEqual([
      `credential:${REALM}:password:${IDENTIFIER}:tx-1`,
      `user:${REALM}:${USER}:tx-1`,
      'update:cred-1:tx-1',
      `clear:${REALM}:password:${IDENTIFIER}:tx-1`,
      `remove:${REALM}:${USER}:update_password:tx-1`,
    ]);
    expect(written).toEqual([
      {
        password_hash: `hash(${input.password})`,
        email_verified: true,
        password_normalization: 'nfc',
        extra: 'kept',
      },
    ]);
  });

  it("writes nothing for another user's credential, none, or a disabled user", async () => {
    for (const [overrides, reason] of [
      [
        { credential: { id: 'cred-2', userId: 'someone-else', credentialData: {} } },
        'subject_mismatch',
      ],
      [{ credential: undefined }, 'subject_mismatch'],
      [{ user: undefined }, 'subject_mismatch'],
      [{ user: { id: USER, enabled: false } }, 'account_disabled'],
    ] as const) {
      const { updates, written, calls } = stubUpdates(overrides);
      expect(await updates.replace(input)).toEqual({ kind: 'refused', reason });
      expect(written).toEqual([]);
      expect(calls.filter((call) => !/^(credential|user):/.test(call))).toEqual([]);
    }
  });

  it('throws, writing nothing, for a credential whose data cannot be read', async () => {
    const { updates, written } = stubUpdates({
      credential: { id: 'cred-1', userId: USER, credentialData: { password_hash: 42 } },
    });
    await expect(updates.replace(input)).rejects.toThrow(/malformed credential_data/);
    expect(written).toEqual([]);
  });

  it('reads the policy through the given reader', async () => {
    const { updates } = stubUpdates();
    expect(await updates.minLength(REALM)).toBe(15);
    expect(await updates.check({ realmId: REALM, identifier: IDENTIFIER, password: 'x' })).toEqual({
      kind: 'accepted',
      password: 'x',
      normalization: 'nfc',
    });
  });
});

describe('audit events', () => {
  const HMAC = 'h'.repeat(43);

  it('maps every record onto a registered event its schema accepts', () => {
    const records: SignInAuditRecord[] = [
      { outcome: 'passed', step: 'identifier', identifierHmac: HMAC },
      { outcome: 'passed', step: 'password', userId: USER },
      { outcome: 'refused', step: 'password', reason: 'invalid_credentials', identifierHmac: HMAC },
      { outcome: 'refused', step: 'password', reason: 'account_disabled', identifierHmac: HMAC },
      { outcome: 'refused', step: 'password', reason: 'email_not_verified', userId: USER },
      { outcome: 'refused', step: 'password', reason: 'locked_out', identifierHmac: HMAC },
      { outcome: 'ended', step: 'identifier', reason: 'subject_mismatch', identifierHmac: HMAC },
      { outcome: 'ended', step: 'password', reason: 'subject_mismatch', userId: USER },
      { outcome: 'passed', step: 'email_code', userId: USER },
      { outcome: 'refused', step: 'email_code', reason: 'invalid_code', userId: USER },
      { outcome: 'refused', step: 'email_code', reason: 'code_expired', userId: USER },
      { outcome: 'refused', step: 'email_code', reason: 'locked_out', userId: USER },
      { outcome: 'refused', step: 'email_code', reason: 'send_capped', userId: USER },
      { outcome: 'ended', step: 'email_code', reason: 'code_burned', userId: USER },
      { outcome: 'passed', step: 'new_password', userId: USER },
      { outcome: 'refused', step: 'new_password', reason: 'password_rejected', userId: USER },
      { outcome: 'refused', step: 'new_password', reason: 'password_breached', userId: USER },
      {
        outcome: 'unchecked',
        step: 'password',
        reason: 'breach_check_failed',
        failure: 'lookup_failed',
        userId: USER,
      },
      {
        outcome: 'unchecked',
        step: 'new_password',
        reason: 'breach_check_failed',
        failure: 'list_not_loaded',
        userId: USER,
      },
    ];
    for (const record of records) {
      const event = signInAuditEvent(record);
      const definition = getEventType(event.type);
      expect(definition, event.type).toBeDefined();
      expect(definition?.data.safeParse(event.data).success, JSON.stringify(record)).toBe(true);
      expect(event.userId).toBe(record.userId ?? null);
    }
    expect(signInAuditEvent(records[0])).toEqual({
      type: 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0',
      data: { step: STEP_URNS.identifier, identifierHmac: HMAC },
      userId: null,
    });
    expect(signInAuditEvent(records[4])).toEqual({
      type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      data: { method: 'password', reason: 'email_not_verified' },
      userId: USER,
    });
    // A breach-list check that could not be made (#635).
    expect(signInAuditEvent(records[17])).toEqual({
      type: 'urn:qauth:event:user.password_breach_check_failed:v1-rc.0',
      data: { step: STEP_URNS.password, reason: 'lookup_failed' },
      userId: USER,
    });
    expect(signInAuditEvent(records[15])).toEqual({
      type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      data: { method: 'password', reason: 'password_rejected' },
      userId: USER,
    });
  });

  it('maps the bot challenge’s records: a pass, and a refusal as captcha_failed (#643)', () => {
    const passed = signInAuditEvent({ outcome: 'passed', step: 'captcha', identifierHmac: HMAC });
    const refused = signInAuditEvent({
      outcome: 'refused',
      step: 'captcha',
      reason: 'captcha_failed',
      identifierHmac: HMAC,
    });
    expect(passed).toEqual({
      type: 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0',
      data: { step: STEP_URNS.captcha, identifierHmac: HMAC },
      userId: null,
    });
    expect(refused).toEqual({
      type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      data: { method: 'password', reason: 'captcha_failed', identifierHmac: HMAC },
      userId: null,
    });
    for (const event of [passed, refused]) {
      expect(getEventType(event.type)?.data.safeParse(event.data).success).toBe(true);
    }
  });

  it('maps the recovery codes’ records as the password sign-in’s (#649)', () => {
    const refused = signInAuditEvent({
      outcome: 'refused',
      step: 'recovery_code',
      reason: 'invalid_credentials',
      userId: USER,
    });
    const passed = signInAuditEvent({ outcome: 'passed', step: 'recovery_codes', userId: USER });
    expect(refused).toEqual({
      type: 'urn:qauth:event:user.sign_in_failed:v1-rc.0',
      data: { method: 'password', reason: 'invalid_credentials' },
      userId: USER,
    });
    expect(passed).toEqual({
      type: 'urn:qauth:event:user.sign_in_step_passed:v1-rc.0',
      data: { step: STEP_URNS.recovery_codes },
      userId: USER,
    });
    for (const event of [passed, refused]) {
      expect(getEventType(event.type)?.data.safeParse(event.data).success).toBe(true);
    }
  });

  it('refuses a step it has no sign-in method for', () => {
    expect(() =>
      signInAuditEvent({
        outcome: 'refused',
        step: 'totp',
        reason: 'invalid_credentials',
        userId: USER,
      })
    ).toThrow(/no sign-in method/);
  });

  it('carries no password or identifier from a run of the engine', async () => {
    const records: SignInAuditRecord[] = [];
    const engine = createSignInEngine({
      accounts: new FakeDirectory(
        new Map([
          [IDENTIFIER, passwordAccount(USER, 'right password')],
          ['carol@example.com', passwordAccount(USER, 'right password', { enabled: false })],
        ])
      ),
      passwords: new FakePasswords(),
      policy: new FakePolicy(),
      identifierDigest: fakeIdentifierDigest,
      requireVerifiedAccount: true,
      clock: { now: () => 0, sleep: async () => undefined },
    });
    const context = (loginHint: string) => ({
      realm: { id: REALM },
      client: { id: 'client' },
      loginHint,
      audit: async (record: SignInAuditRecord) => void records.push(record),
    });
    for (const identifier of [IDENTIFIER, 'carol@example.com', 'nobody@example.com']) {
      for (const password of ['right password', 'wrong password']) {
        await engine.advance(
          null,
          { step: STEP_URNS.password, fields: { password } },
          context(identifier)
        );
      }
    }
    const events = JSON.stringify(records.map(signInAuditEvent));
    for (const secret of [
      'right password',
      'wrong password',
      'alice',
      'carol',
      'nobody',
      '@example',
    ]) {
      expect(events).not.toContain(secret);
    }
  });
});

describe('the plugin', () => {
  it('decorates the server with one engine built from its options', async () => {
    const app = Fastify();
    await app.register(signInEnginePlugin, {
      accounts: new FakeDirectory(new Map([[IDENTIFIER, passwordAccount(USER, 'pw')]])),
      passwords: new FakePasswords(),
      policy: new FakePolicy(),
      identifierDigest: fakeIdentifierDigest,
      requireVerifiedAccount: true,
      clock: { now: () => 0, sleep: async () => undefined },
    });
    await app.ready();
    const result = await app.signInEngine.advance(
      null,
      { step: STEP_URNS.password, fields: { password: 'pw', login_hint: IDENTIFIER } },
      { realm: { id: REALM }, client: { id: 'client' }, audit: async () => undefined }
    );
    expect(result).toMatchObject({ kind: 'complete', signIn: { subject: USER, amr: ['pwd'] } });
    await app.close();
  });

  const dependencies = () => ({
    accounts: new FakeDirectory(new Map([[IDENTIFIER, passwordAccount(USER, 'pw')]])),
    passwords: new FakePasswords(),
    policy: new FakePolicy(),
    identifierDigest: fakeIdentifierDigest,
    requireVerifiedAccount: true,
  });
  const ladder = {
    reserve: async () => ({
      kind: 'reserved' as const,
      settle: async () => ({ ceilingReached: false }),
    }),
  };
  const limits = {
    round: async () => ({ kind: 'continue' as const }),
    reserve: async () => ({ kind: 'reserved' as const, settle: async () => undefined }),
  };
  const passwordHardAction = {
    ceilingReached: async () => undefined,
    clearIgnoredMark: async () => undefined,
  };

  it('refuses to build a production engine without a ladder, so no password is guessed without limit', async () => {
    const app = Fastify();
    await expect(
      (async () => {
        await app.register(signInEnginePlugin, { ...dependencies(), production: true });
        await app.ready();
      })()
    ).rejects.toThrow(/ladder hook/);

    const withLadder = Fastify();
    await withLadder.register(signInEnginePlugin, {
      ...dependencies(),
      hooks: { ladder, limits },
      passwordHardAction,
      production: true,
    });
    await expect(withLadder.ready()).resolves.toBeDefined();
    await withLadder.close();
  });

  it('refuses to build a production engine without the password hard action', async () => {
    const app = Fastify();
    await expect(
      (async () => {
        await app.register(signInEnginePlugin, {
          ...dependencies(),
          hooks: { ladder, limits },
          production: true,
        });
        await app.ready();
      })()
    ).rejects.toThrow(/hard action/);
  });

  it('refuses to build a production engine without the round limits, so no IP tries every account', async () => {
    const app = Fastify();
    await expect(
      (async () => {
        await app.register(signInEnginePlugin, {
          ...dependencies(),
          hooks: { ladder },
          passwordHardAction,
          production: true,
        });
        await app.ready();
      })()
    ).rejects.toThrow(/limits hook/);
  });

  it('reads production from NODE_ENV when the option is absent', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    try {
      const app = Fastify();
      await expect(
        (async () => {
          await app.register(signInEnginePlugin, dependencies());
          await app.ready();
        })()
      ).rejects.toThrow(/ladder hook/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
