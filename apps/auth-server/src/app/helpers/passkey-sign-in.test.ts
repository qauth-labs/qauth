import {
  type WebAuthnCeremonyState,
  type WebAuthnChallengeStore,
  type WebAuthnProvider,
  WebAuthnRejection,
} from '@qauth-labs/fastify-plugin-federation';
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { DISPLAY_TEXT_PATTERN } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { REDIS_KEYS } from '../constants/redis-keys';
import type { EngineMailer } from './engine-mail';
import {
  accountNameOf,
  createRedisWebAuthnChallenges,
  createServerPasskeyAccounts,
  createServerPasskeys,
  type ServerPasskeyAccountOptions,
} from './passkey-sign-in';

const REALM_ID = 'realm-1';
const USER_ID = 'user-1';
const CLIENT_ID = 'notes-app';
const KEY = 'k'.repeat(43);
const TRANSACTION = `${REALM_ID}:${KEY}`;
const ADDRESS = 'owner@example.test';
const CREDENTIAL_ID = 'Y3JlZGVudGlhbC0x';
const HANDLE = 'dXNlci1oYW5kbGUtMQ';
const REALM = {
  id: REALM_ID,
  name: 'default',
  issuer: 'https://auth.example.test',
  webauthnRpId: null,
};

/** A stored passkey record, as the provider writes it. */
function storedRecord(overrides: Record<string, unknown> = {}) {
  return {
    public_key: 'cHVibGljLWtleQ',
    algorithm: -7,
    sign_count: 4,
    transports: ['internal'],
    backup_eligible: true,
    backed_up: true,
    aaguid: '00000000-0000-0000-0000-000000000000',
    rp_id: 'auth.example.test',
    user_handle: HANDLE,
    nickname: null,
    created_at: 1,
    last_used_at: null,
    sign_counter_regressed_at: null,
    ...overrides,
  };
}

function passkeyRow(overrides: Record<string, unknown> = {}) {
  return {
    id: 'row-1',
    userId: USER_ID,
    realmId: REALM_ID,
    providerType: 'webauthn',
    externalSub: CREDENTIAL_ID,
    credentialData: storedRecord(),
    disabledAt: null,
    ...overrides,
  };
}

function assertionResponse(id = CREDENTIAL_ID): string {
  return JSON.stringify({
    id,
    rawId: id,
    type: 'public-key',
    response: { clientDataJSON: 'Y2Q', authenticatorData: 'YWQ', signature: 'c2ln' },
    clientExtensionResults: {},
  });
}

/** The verified registration a provider returns. */
const ENROLMENT = {
  externalSub: 'bmV3LWNyZWRlbnRpYWw',
  rpId: 'auth.example.test',
  purpose: 'sign-in' as const,
  attestationFormat: 'none',
  credentialData: storedRecord({ sign_count: 0, backed_up: false }),
};

/**
 * The passkey ceremonies of the sign-in engine over the server (#651): the
 * provider's rounds under the realm's RP ID and origins, the realm's
 * `webauthn` credentials, Redis, and the "passkey added" notice.
 */
describe('the server passkey ceremonies (#651)', () => {
  let provider: {
    startAuthentication: ReturnType<typeof vi.fn>;
    verify: ReturnType<typeof vi.fn>;
    startRegistration: ReturnType<typeof vi.fn>;
    finishRegistration: ReturnType<typeof vi.fn>;
  };
  let challenges: { begin: ReturnType<typeof vi.fn>; take: ReturnType<typeof vi.fn> };
  let credentials: {
    findByRealmProviderSub: ReturnType<typeof vi.fn>;
    findAllByUserIdAndType: ReturnType<typeof vi.fn>;
    findByUserIdAndType: ReturnType<typeof vi.fn>;
    updateCredentialData: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
  };
  let users: { findById: ReturnType<typeof vi.fn> };
  let lockRpIdForEnrolment: ReturnType<typeof vi.fn>;
  let client: { webauthnAllowedOrigins: unknown } | undefined;
  let mailer: { sendUncounted: ReturnType<typeof vi.fn> };
  let logInfo: ReturnType<typeof vi.fn>;
  let fromName: string;

  beforeEach(() => {
    provider = {
      startAuthentication: vi.fn(async (input: { rpId: string }) => ({
        challenge: 'c'.repeat(43),
        rpId: input.rpId,
        timeout: 300_000,
        allowCredentials: [],
        userVerification: 'required',
      })),
      verify: vi.fn(async () => ({
        externalSub: CREDENTIAL_ID,
        assuranceLevel: 'low',
        rawClaims: {
          credential_id: CREDENTIAL_ID,
          rp_id: 'auth.example.test',
          origin: 'https://auth.example.test',
          purpose: 'sign-in',
          user_verified: true,
          backup_eligible: true,
          backed_up: true,
          sign_count: 9,
          sign_counter_regressed: false,
        },
      })),
      startRegistration: vi.fn(
        async (input: {
          rp: { id: string; name: string };
          user: { handle: string; name: string; displayName: string };
          excludeCredentials: { id: string; transports?: string[] }[];
        }) => ({
          rp: input.rp,
          user: {
            id: input.user.handle,
            name: input.user.name,
            displayName: input.user.displayName,
          },
          challenge: 'r'.repeat(43),
          pubKeyCredParams: [
            { type: 'public-key', alg: -8 },
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 },
          ],
          timeout: 300_000,
          excludeCredentials: input.excludeCredentials.map((credential) => ({
            type: 'public-key',
            ...credential,
          })),
          authenticatorSelection: {
            residentKey: 'required',
            requireResidentKey: true,
            userVerification: 'required',
          },
          attestation: 'none',
          extensions: { credProps: true },
        })
      ),
      finishRegistration: vi.fn(async () => ENROLMENT),
    };
    challenges = { begin: vi.fn(async () => undefined), take: vi.fn(async () => undefined) };
    credentials = {
      findByRealmProviderSub: vi.fn(async () => passkeyRow()),
      findAllByUserIdAndType: vi.fn(async () => []),
      findByUserIdAndType: vi.fn(async () => ({ realmId: REALM_ID, externalSub: ADDRESS })),
      updateCredentialData: vi.fn(async () => passkeyRow()),
      create: vi.fn(async () => passkeyRow()),
    };
    users = { findById: vi.fn(async () => ({ id: USER_ID, enabled: true })) };
    lockRpIdForEnrolment = vi.fn(async () => ({ rpId: 'auth.example.test' }));
    client = { webauthnAllowedOrigins: ['https://app.example.test'] };
    mailer = { sendUncounted: vi.fn() };
    logInfo = vi.fn();
    fromName = 'Example Notes';
  });

  const build = () =>
    createServerPasskeys(
      {
        repositories: {
          realms: { findById: vi.fn(async () => REALM), lockRpIdForEnrolment },
          oauthClients: { findByClientId: vi.fn(async () => client) },
          userCredentials: credentials,
          users,
        },
        db: { transaction: async (work: (tx: string) => Promise<unknown>) => work('tx') },
        policyStore: {
          ofRealm: () => ({ policies: { mail: { fromName } } }),
        },
        log: { info: logInfo, warn: vi.fn(), error: vi.fn() },
      } as unknown as FastifyInstance,
      {
        mailer: mailer as unknown as EngineMailer,
        provider: provider as unknown as WebAuthnProvider,
        challenges: challenges as unknown as WebAuthnChallengeStore,
        now: () => 1_000,
      }
    );

  describe('an assertion', () => {
    it('starts under the realm’s RP ID and origins, naming no account', async () => {
      const params = await build().startAssertion({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
      });

      expect(provider.startAuthentication).toHaveBeenCalledWith({
        transactionId: TRANSACTION,
        purpose: 'sign-in',
        rpId: 'auth.example.test',
        origins: ['https://auth.example.test', 'https://app.example.test'],
      });
      expect(params).toEqual({
        challenge: 'c'.repeat(43),
        rpId: 'auth.example.test',
        timeout: 300_000,
        userVerification: 'required',
      });
      expect(params).not.toHaveProperty('allowCredentials');
    });

    it('verifies against the passkey the answer names, and records its use', async () => {
      const outcome = await build().verifyAssertion({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        response: assertionResponse(),
      });

      expect(outcome).toEqual({ kind: 'verified', userId: USER_ID, userVerified: true });
      expect(credentials.findByRealmProviderSub).toHaveBeenCalledWith(
        REALM_ID,
        'webauthn',
        CREDENTIAL_ID
      );
      expect(provider.verify).toHaveBeenCalledWith(
        expect.objectContaining({
          transactionId: TRANSACTION,
          credential: { externalSub: CREDENTIAL_ID, credentialData: storedRecord() },
        })
      );
      expect(credentials.updateCredentialData).toHaveBeenCalledWith(
        'row-1',
        expect.objectContaining({ sign_count: 9, last_used_at: 1_000 })
      );
    });

    it('reports the UV flag of the signed authenticator data as it is', async () => {
      const verified = await (
        provider.verify as unknown as () => Promise<{ rawClaims: Record<string, unknown> }>
      )();
      provider.verify.mockResolvedValueOnce({
        ...verified,
        rawClaims: { ...verified.rawClaims, user_verified: false },
      });

      const outcome = await build().verifyAssertion({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        response: assertionResponse(),
      });

      expect(outcome).toEqual({ kind: 'verified', userId: USER_ID, userVerified: false });
    });

    it.each([
      [
        'names no passkey of the realm',
        () => credentials.findByRealmProviderSub.mockResolvedValue(undefined),
        assertionResponse(),
      ],
      [
        'names a disabled passkey',
        () => credentials.findByRealmProviderSub.mockResolvedValue(passkeyRow({ disabledAt: 5 })),
        assertionResponse(),
      ],
      ['is not JSON', () => undefined, 'not json'],
      ['names no credential', () => undefined, JSON.stringify({ type: 'public-key' })],
    ])('refuses an answer that %s, and spends the ceremony', async (_, arrange, response) => {
      arrange();

      const outcome = await build().verifyAssertion({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        response,
      });

      expect(outcome).toEqual({ kind: 'refused' });
      expect(challenges.take).toHaveBeenCalledWith(TRANSACTION);
      expect(provider.verify).not.toHaveBeenCalled();
      expect(credentials.updateCredentialData).not.toHaveBeenCalled();
    });

    it('refuses what the provider refuses, and logs only the reason', async () => {
      provider.verify.mockRejectedValueOnce(new WebAuthnRejection('signature-invalid'));

      const outcome = await build().verifyAssertion({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        response: assertionResponse(),
      });

      expect(outcome).toEqual({ kind: 'refused' });
      expect(logInfo).toHaveBeenCalledWith(
        { realmId: REALM_ID, reason: 'signature-invalid' },
        'a passkey assertion was refused'
      );
      expect(credentials.updateCredentialData).not.toHaveBeenCalled();
    });

    it('lets any other provider error through, as a store fault', async () => {
      provider.verify.mockRejectedValueOnce(new Error('malformed credential_data'));

      await expect(
        build().verifyAssertion({
          realmId: REALM_ID,
          clientId: CLIENT_ID,
          key: KEY,
          response: assertionResponse(),
        })
      ).rejects.toThrow('malformed credential_data');
    });
  });

  describe('a registration', () => {
    it('starts for the account’s user handle, excluding its passkeys, in the grammar’s shape', async () => {
      credentials.findAllByUserIdAndType.mockResolvedValue([
        passkeyRow(),
        passkeyRow({ id: 'row-2', realmId: 'another-realm', externalSub: 'b3RoZXI' }),
      ]);

      const started = await build().startRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        userId: USER_ID,
        identifier: ADDRESS,
      });

      expect(provider.startRegistration).toHaveBeenCalledWith(
        expect.objectContaining({
          transactionId: TRANSACTION,
          purpose: 'sign-in',
          rp: { id: 'auth.example.test', name: 'Example Notes' },
          user: { handle: HANDLE, name: ADDRESS, displayName: ADDRESS },
          excludeCredentials: [{ id: CREDENTIAL_ID, transports: ['internal'] }],
        })
      );
      expect(started.options).toEqual({
        challenge: 'r'.repeat(43),
        rp: { id: 'auth.example.test', name: 'Example Notes' },
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 300_000,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
      });
      expect(started.personal).toEqual({
        user: { id: HANDLE, name: ADDRESS, displayName: ADDRESS },
        excludeCredentials: [{ type: 'public-key', id: CREDENTIAL_ID, transports: ['internal'] }],
      });
    });

    it('names the relying party in display text the grammar takes, however the realm wrote it', async () => {
      const rpNameFor = async (name: string): Promise<string> => {
        fromName = name;
        provider.startRegistration.mockClear();
        const started = await build().startRegistration({
          realmId: REALM_ID,
          clientId: CLIENT_ID,
          key: KEY,
          userId: USER_ID,
          identifier: ADDRESS,
        });
        const rp = (started.options as { rp: { name: string } }).rp;
        expect(new RegExp(DISPLAY_TEXT_PATTERN, 'u').test(rp.name), rp.name).toBe(true);
        expect(rp.name.length).toBeLessThanOrEqual(64);
        return rp.name;
      };

      // 63 letters then an emoji: 65 UTF-16 units, cut before the pair, not inside it.
      expect(await rpNameFor(`${'a'.repeat(63)}🔑 Notes`)).toBe('a'.repeat(63));
      // Hangul fillers render as nothing: a name of them alone falls back.
      expect(await rpNameFor('\u3164\u3164')).not.toContain('\u3164');
      expect(await rpNameFor('Notes\u3164App')).toBe('NotesApp');
    });

    it('makes a new user handle for an account with no passkey', async () => {
      await build().startRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        userId: USER_ID,
        identifier: ADDRESS,
      });

      const [input] = provider.startRegistration.mock.calls[0] as [{ user: { handle: string } }];
      expect(input.user.handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    });

    it('names no account at a registration by passkey: a new handle, nothing excluded (#655)', async () => {
      const started = await build().startRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
      });

      expect(credentials.findAllByUserIdAndType).not.toHaveBeenCalled();
      const [input] = provider.startRegistration.mock.calls[0] as [
        { user: { handle: string; name: string; displayName: string }; excludeCredentials: [] },
      ];
      expect(input.user.handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(input.user.name).toBe(accountNameOf(input.user.handle));
      expect(input.user.displayName).toBe(input.user.name);
      expect(input.excludeCredentials).toEqual([]);
      expect(started.personal).toEqual({
        user: { id: input.user.handle, name: input.user.name, displayName: input.user.name },
        excludeCredentials: [],
      });
    });

    it('names an account by its handle, not "Account", when its address is no display text', async () => {
      await build().startRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        userId: USER_ID,
        identifier: '\u3164',
      });

      const [input] = provider.startRegistration.mock.calls[0] as [
        { user: { handle: string; name: string } },
      ];
      expect(input.user.name).toBe(`account-${input.user.handle.slice(0, 8)}`);
    });

    it('holds a verified registration as JSON, without binding it', async () => {
      const outcome = await build().verifyRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        userId: USER_ID,
        response: JSON.stringify({ id: ENROLMENT.externalSub }),
      });

      expect(outcome).toEqual({ kind: 'verified', registration: JSON.stringify(ENROLMENT) });
      expect(provider.finishRegistration).toHaveBeenCalledWith({
        transactionId: TRANSACTION,
        response: { id: ENROLMENT.externalSub },
      });
      expect(credentials.create).not.toHaveBeenCalled();
    });

    it('refuses what the provider refuses, a registration without UV among them', async () => {
      provider.finishRegistration.mockRejectedValueOnce(new WebAuthnRejection('user-not-verified'));

      const outcome = await build().verifyRegistration({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        key: KEY,
        userId: USER_ID,
        response: JSON.stringify({ id: ENROLMENT.externalSub }),
      });

      expect(outcome).toEqual({ kind: 'refused' });
    });
  });

  describe('a binding', () => {
    const bind = () =>
      build().bind({
        realmId: REALM_ID,
        clientId: CLIENT_ID,
        userId: USER_ID,
        registration: JSON.stringify(ENROLMENT),
      });

    it('writes the passkey under the realm’s RP ID lock, and tells the owner', async () => {
      expect(await bind()).toEqual({ kind: 'bound' });

      expect(lockRpIdForEnrolment).toHaveBeenCalledWith('tx', REALM_ID);
      expect(credentials.create).toHaveBeenCalledWith(
        {
          userId: USER_ID,
          realmId: REALM_ID,
          providerType: 'webauthn',
          externalSub: ENROLMENT.externalSub,
          credentialData: ENROLMENT.credentialData,
        },
        'tx'
      );
      expect(mailer.sendUncounted).toHaveBeenCalledWith(REALM, ADDRESS, {
        template: 'passkey_added',
      });
    });

    it('refuses a disabled account, and writes nothing', async () => {
      users.findById.mockResolvedValue({ id: USER_ID, enabled: false });

      expect(await bind()).toEqual({ kind: 'refused', reason: 'account_disabled' });
      expect(credentials.create).not.toHaveBeenCalled();
      expect(mailer.sendUncounted).not.toHaveBeenCalled();
    });

    it('refuses a credential id the realm already holds', async () => {
      credentials.create.mockRejectedValueOnce(new UniqueConstraintError('UserCredential'));

      expect(await bind()).toEqual({ kind: 'refused', reason: 'credential_exists' });
      expect(mailer.sendUncounted).not.toHaveBeenCalled();
    });

    it('binds all the same when the notice cannot be sent', async () => {
      credentials.findByUserIdAndType.mockRejectedValueOnce(new Error('database down'));

      expect(await bind()).toEqual({ kind: 'bound' });
    });

    it('throws for a held registration that is not one', async () => {
      await expect(
        build().bind({
          realmId: REALM_ID,
          clientId: CLIENT_ID,
          userId: USER_ID,
          registration: JSON.stringify({ externalSub: 'x' }),
        })
      ).rejects.toThrow('not well formed');
    });
  });
});

/**
 * The registration's passkey write (#655): the account, its passkey and its
 * `user.registered` event in one transaction, with no address and no
 * password.
 */
describe('the server passkey accounts (#655)', () => {
  let writes: string[];
  let users: { create: ReturnType<typeof vi.fn> };
  let credentials: { create: ReturnType<typeof vi.fn> };
  let lockRpIdForEnrolment: ReturnType<typeof vi.fn>;
  let registered: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writes = [];
    users = {
      create: vi.fn(async (input: unknown, tx: string) => {
        writes.push(`user ${JSON.stringify(input)} ${tx}`);
        return { id: 'new-user' };
      }),
    };
    credentials = {
      create: vi.fn(async (input: { providerType: string }, tx: string) => {
        writes.push(`credential ${input.providerType} ${tx}`);
        return passkeyRow();
      }),
    };
    lockRpIdForEnrolment = vi.fn(async (tx: string) => {
      writes.push(`lock ${tx}`);
      return { rpId: 'auth.example.test' };
    });
    registered = vi.fn(async (_input: unknown, tx: string) => {
      writes.push(`event ${tx}`);
    });
  });

  const create = (registration: string = JSON.stringify(ENROLMENT)) =>
    createServerPasskeyAccounts(
      {
        repositories: {
          realms: { lockRpIdForEnrolment },
          users,
          userCredentials: credentials,
        },
        db: { transaction: async (work: (tx: string) => Promise<unknown>) => work('tx') },
      } as unknown as FastifyInstance,
      { registered: registered as unknown as ServerPasskeyAccountOptions['registered'] }
    )({ realmId: REALM_ID, clientId: CLIENT_ID, registration });

  it('writes the user, the passkey and the event in one transaction, with no address', async () => {
    expect(await create()).toEqual({ kind: 'created', userId: 'new-user' });

    expect(writes).toEqual([
      `user {"realmId":"${REALM_ID}"} tx`,
      'lock tx',
      'credential webauthn tx',
      'event tx',
    ]);
    expect(credentials.create).toHaveBeenCalledWith(
      {
        userId: 'new-user',
        realmId: REALM_ID,
        providerType: 'webauthn',
        externalSub: ENROLMENT.externalSub,
        credentialData: ENROLMENT.credentialData,
      },
      'tx'
    );
    expect(registered).toHaveBeenCalledWith(
      { realmId: REALM_ID, clientId: CLIENT_ID, userId: 'new-user' },
      'tx'
    );
  });

  it('answers conflict for a credential id the realm holds by then', async () => {
    credentials.create.mockRejectedValueOnce(new UniqueConstraintError('UserCredential'));

    expect(await create()).toEqual({ kind: 'conflict' });
    expect(registered).not.toHaveBeenCalled();
  });

  it('answers conflict for an RP ID that changed under the ceremony, and writes no passkey', async () => {
    lockRpIdForEnrolment.mockResolvedValueOnce({ rpId: 'other.example.test' });

    expect(await create()).toEqual({ kind: 'conflict' });
    expect(credentials.create).not.toHaveBeenCalled();
    expect(registered).not.toHaveBeenCalled();
  });

  it('lets a store fault through', async () => {
    registered.mockRejectedValueOnce(new Error('database down'));

    await expect(create()).rejects.toThrow('database down');
  });

  it('throws for a held registration that is not one', async () => {
    await expect(create(JSON.stringify({ externalSub: 'x' }))).rejects.toThrow('not well formed');
    expect(users.create).not.toHaveBeenCalled();
  });
});

describe('the Redis WebAuthn ceremony store (#651)', () => {
  const STATE: WebAuthnCeremonyState = {
    ceremony: 'authentication',
    purpose: 'sign-in',
    challenge: 'c'.repeat(43),
    rpId: 'auth.example.test',
    origins: ['https://auth.example.test'],
    allowCredentialIds: [],
    expiresAt: 2_000,
  };

  it('writes a ceremony with its timeout and takes it once', async () => {
    const values = new Map<string, string>();
    const redis = {
      set: vi.fn(async (key: string, value: string) => {
        values.set(key, value);
        return 'OK';
      }),
      getdel: vi.fn(async (key: string) => {
        const value = values.get(key) ?? null;
        values.delete(key);
        return value;
      }),
    };
    const store = createRedisWebAuthnChallenges({
      redis,
      log: { error: vi.fn() },
    } as unknown as FastifyInstance);

    await store.begin(TRANSACTION, STATE, 300_000);

    expect(redis.set).toHaveBeenCalledWith(
      REDIS_KEYS.WEBAUTHN_CEREMONY(TRANSACTION),
      JSON.stringify(STATE),
      'PX',
      300_000
    );
    expect(REDIS_KEYS.WEBAUTHN_CEREMONY(TRANSACTION)).not.toContain(KEY);
    expect(await store.take(TRANSACTION)).toEqual(STATE);
    expect(await store.take(TRANSACTION)).toBeUndefined();
  });

  it('reads a state that is not well formed as none', async () => {
    const error = vi.fn();
    const store = createRedisWebAuthnChallenges({
      redis: { getdel: vi.fn(async () => '{"ceremony":"authentication"}') },
      log: { error },
    } as unknown as FastifyInstance);

    expect(await store.take(TRANSACTION)).toBeUndefined();
    expect(error).toHaveBeenCalled();
  });
});
