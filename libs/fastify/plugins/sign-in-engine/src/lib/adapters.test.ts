import { createHmac } from 'node:crypto';

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
import { signInAuditEvent } from './audit-events';
import { signInEnginePlugin } from './fastify-plugin-sign-in-engine';
import { createCookieSecretIdentifierDigest, IDENTIFIER_HMAC_LABEL } from './identifier-digest';
import { createArgon2PasswordVerifier } from './password-verifier';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';
const OTHER_REALM = '0199fa20-0000-7000-8000-00000000bbbb';
const USER = '0199fa20-5e1a-7000-8000-000000000001';
const IDENTIFIER = 'alice@example.com';

function stubStores(
  overrides: Partial<{
    credential: Record<string, unknown> | undefined;
    user: { id: string; enabled: boolean } | undefined;
    passkeys: { realmId: string }[];
    grants: unknown[];
  }> = {}
) {
  const state = {
    credential: { password_hash: 'hash', email_verified: true } as
      | Record<string, unknown>
      | undefined,
    user: { id: USER, enabled: true } as { id: string; enabled: boolean } | undefined,
    passkeys: [] as { realmId: string }[],
    grants: [] as unknown[],
    ...overrides,
  };
  const calls: string[] = [];
  const repos: AccountDirectoryRepositories = {
    userCredentials: {
      findByRealmProviderSub: async (realmId, providerType, externalSub) => {
        calls.push(`credential:${realmId}:${providerType}:${externalSub}`);
        return state.credential === undefined
          ? undefined
          : { id: 'cred-1', userId: USER, realmId, credentialData: state.credential };
      },
      findAllByUserIdAndType: async (userId, providerType) => {
        calls.push(`all:${userId}:${providerType}`);
        return state.passkeys.map((passkey, index) => ({
          id: `passkey-${index}`,
          userId,
          realmId: passkey.realmId,
          credentialData: {},
        }));
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

  it('reads the user, the password, the passkeys and the admin grants of an account', async () => {
    const { repos } = stubStores({
      passkeys: [{ realmId: REALM }, { realmId: OTHER_REALM }],
      grants: [{ grant: {} }],
    });
    const directory = createRepositoryAccountDirectory(repos, log());
    expect(await directory.findByIdentifier(REALM, IDENTIFIER)).toEqual({
      userId: USER,
      enabled: true,
      verified: true,
      admin: true,
      // A passkey of another realm's row is not this account's.
      factors: [
        { type: 'password', disabled: false, hash: 'hash' },
        { type: 'passkey', disabled: false },
      ],
    });
  });

  it('reports a disabled, unverified account as such', async () => {
    const { repos } = stubStores({
      credential: { password_hash: 'hash', email_verified: false },
      user: { id: USER, enabled: false },
    });
    expect(
      await createRepositoryAccountDirectory(repos, log()).findByIdentifier(REALM, IDENTIFIER)
    ).toMatchObject({ enabled: false, verified: false, admin: false });
  });

  it('gives an unreadable credential no hash, and logs it without its data', async () => {
    const { repos } = stubStores({ credential: { password_hash: 42 } });
    const logger = log();
    const account = await createRepositoryAccountDirectory(repos, logger).findByIdentifier(
      REALM,
      IDENTIFIER
    );
    expect(account).toMatchObject({
      verified: false,
      factors: [{ type: 'password', disabled: false, hash: null }],
    });
    expect(logger.error).toHaveBeenCalledWith({ credentialId: 'cred-1' }, expect.any(String));
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

  it('never throws from the dummy verification, and makes a new dummy hash after a failure', async () => {
    const argon = hasher();
    argon.hashPassword.mockRejectedValueOnce(new Error('argon2 failed'));
    const logger = log();
    const verifier = createArgon2PasswordVerifier(argon, logger);
    await expect(verifier.verifyDecoy('guess')).resolves.toBeUndefined();
    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(logger.error.mock.calls)).not.toContain('guess');
    await verifier.verifyDecoy('guess');
    expect(argon.hashPassword).toHaveBeenCalledTimes(2);
    expect(argon.verifyPassword).toHaveBeenCalledTimes(1);
  });
});

describe('the identifier HMAC', () => {
  const secret = Buffer.from('the realm cookie secret, 32 bytes');

  function signer() {
    return {
      getCookieSecrets: vi.fn(async () => ({
        current: { kid: 'cookie-1', secret: Buffer.from(secret) },
      })),
    };
  }

  it('is HMAC-SHA-256 under a key derived from the realm cookie secret, over realm and identifier', async () => {
    const source = signer();
    const digest = createCookieSecretIdentifierDigest(source);
    const value = await digest({ realmId: REALM, identifier: IDENTIFIER });
    const key = createHmac('sha256', secret).update(IDENTIFIER_HMAC_LABEL).digest();
    expect(value).toBe(
      createHmac('sha256', key).update(`${REALM}\u0000${IDENTIFIER}`).digest('base64url')
    );
    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(source.getCookieSecrets).toHaveBeenCalledWith('web', REALM);
  });

  it('is neither a cookie signature under the same secret nor the same in two realms', async () => {
    const digest = createCookieSecretIdentifierDigest(signer());
    const value = await digest({ realmId: REALM, identifier: IDENTIFIER });
    expect(value).not.toBe(createHmac('sha256', secret).update(IDENTIFIER).digest('base64url'));
    expect(await digest({ realmId: OTHER_REALM, identifier: IDENTIFIER })).not.toBe(value);
    expect(await digest({ realmId: REALM, identifier: 'bob@example.com' })).not.toBe(value);
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
});
