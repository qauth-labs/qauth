import {
  defaultsFromEnv,
  PolicyValidationError,
  type RealmPolicySnapshot,
  type RealmSecretSeedReport,
  secretSeedKeys,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import {
  mailTransportIncompleteWarning,
  realmMailSource,
  realmSecretCipher,
  type RealmSecretSeedDependencies,
  realmSecretSeedFailedWarning,
  secretSeedKeyIgnoredWarning,
  seedRealmSecrets,
  smtpPasswordForAnotherServerError,
  type SmtpServer,
} from './realm-secrets';

const REALM = testRealm({ id: '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f80' });
const PASSWORD = 'an-smtp-password-the-log-never-sees';

describe('realmSecretCipher (#529)', () => {
  it('encrypts as the signer process and decrypts as the api role, under the context given', async () => {
    const signer = {
      encrypt: vi.fn(async () => 'v1.kid.iv.body'),
      decrypt: vi.fn(async () => Buffer.from(PASSWORD, 'utf8')),
    };
    const cipher = realmSecretCipher({ signer } as unknown as Pick<FastifyInstance, 'signer'>);

    expect(
      await cipher.encrypt({ realmId: REALM.id, plaintext: PASSWORD, context: 'realm_secrets:x' })
    ).toBe('v1.kid.iv.body');
    expect(signer.encrypt).toHaveBeenCalledWith('local', {
      realmId: REALM.id,
      plaintext: Buffer.from(PASSWORD, 'utf8'),
      context: 'realm_secrets:x',
    });
    expect(
      await cipher.decrypt({ realmId: REALM.id, ciphertext: 'v1.kid.iv.body', context: 'c' })
    ).toBe(PASSWORD);
    expect(signer.decrypt).toHaveBeenCalledWith('api', {
      realmId: REALM.id,
      ciphertext: 'v1.kid.iv.body',
      context: 'c',
    });
  });
});

describe('seedRealmSecrets (#529)', () => {
  const seedKeys = secretSeedKeys();
  const SMTP_ENV = {
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM_ADDRESS: 'no-reply@example.com',
    SMTP_HOST: 'smtp.example.com',
    SMTP_PORT: '587',
    SMTP_USER: 'mailer',
  };
  const ENV_SMTP = { host: 'smtp.example.com', port: 587, user: 'mailer' };
  const OTHER = { id: '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f81', name: 'beta' };

  interface RealmSetup {
    readonly id: string;
    readonly name: string;
    /** The environment its policies were filled from. */
    readonly env?: Record<string, string>;
    readonly hasPolicies?: boolean;
    /** `get` throws this, as for a stored document this release refuses. */
    readonly refused?: boolean;
  }

  function deps(
    report: Partial<RealmSecretSeedReport> = {},
    options: { realms?: RealmSetup[]; isSet?: boolean; seedFails?: string } = {}
  ) {
    const realms = options.realms ?? [{ id: REALM.id, name: 'master' }];
    const warn = vi.fn();
    const info = vi.fn();
    const error = vi.fn();
    const seed = vi.fn(async (realmId: string) => {
      if (realmId === options.seedFails) throw new Error('no data-at-rest key');
      return { seeded: [], recordedUnset: [], present: [], leftWithoutRow: [], ...report };
    });
    const isSet = vi.fn(async () => options.isSet ?? false);
    const get = vi.fn(async (realmId: string) => {
      const realm = realms.find((candidate) => candidate.id === realmId);
      if (realm === undefined) return undefined;
      if (realm.refused) {
        throw new PolicyValidationError('The stored realm policies are not valid', [
          { path: 'tokens.accessTokenLifespanSeconds', message: 'is too large' },
        ]);
      }
      return {
        realmId,
        version: realm.hasPolicies === false ? 0 : 1,
        hasPolicies: realm.hasPolicies !== false,
        policies: defaultsFromEnv(realm.env ?? {}),
      } as unknown as RealmPolicySnapshot;
    });
    const value: RealmSecretSeedDependencies = {
      realms: {
        listPolicyRecords: vi.fn(async () =>
          realms.map((realm) => ({ realmId: realm.id, realmName: realm.name }) as never)
        ),
      },
      policies: { get },
      secrets: { seed, isSet },
      log: { warn, info, error },
    };
    return { deps: value, warn, info, error, seed, isSet, get };
  }

  const settings = (seeds: Map<string, string>, environmentSmtp: SmtpServer = ENV_SMTP) => ({
    realmName: 'master',
    seeds,
    seedKeys,
    environmentSmtp,
  });

  it('seeds the default realm from the environment and names what it seeded, never the value', async () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);
    const {
      deps: d,
      info,
      warn,
      seed,
    } = deps(
      { seeded: ['mail.smtp.password'], recordedUnset: ['mail.resend.apiKey'] },
      { realms: [{ id: REALM.id, name: 'master', env: SMTP_ENV }], isSet: true }
    );

    await seedRealmSecrets(d, settings(seeds));

    // smtp needs the password, so it stays without a row were it unset.
    expect(seed).toHaveBeenCalledWith(REALM.id, seeds, {
      leaveWithoutRow: new Set(['mail.smtp.password']),
    });
    expect(info).toHaveBeenCalledWith(
      {
        realm: 'master',
        realmId: REALM.id,
        policy: 'mail.smtp.password',
        variable: 'SMTP_PASSWORD',
      },
      'realm secret seeded from the environment: the realm stores it encrypted from now on'
    );
    expect(warn).not.toHaveBeenCalled();
    expect(JSON.stringify([info.mock.calls, warn.mock.calls])).not.toContain(PASSWORD);
  });

  it('leaves a secret the stored transport needs without a row when the environment lacks it, so a later boot seeds it', async () => {
    const { deps: d, seed } = deps(
      { recordedUnset: ['mail.resend.apiKey'], leftWithoutRow: ['mail.smtp.password'] },
      { realms: [{ id: REALM.id, name: 'master', env: SMTP_ENV }] }
    );

    await seedRealmSecrets(d, settings(new Map()));

    expect(seed).toHaveBeenCalledWith(REALM.id, new Map(), {
      leaveWithoutRow: new Set(['mail.smtp.password']),
    });
  });

  it("does not store SMTP_PASSWORD in a realm whose stored server or user is not the environment's, and says so", async () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);
    const {
      deps: d,
      seed,
      error,
    } = deps(
      { leftWithoutRow: ['mail.smtp.password'] },
      { realms: [{ id: REALM.id, name: 'master', env: SMTP_ENV }] }
    );

    // The environment now names another host than the one the fill stored.
    await seedRealmSecrets(d, settings(seeds, { ...ENV_SMTP, host: 'smtp.new.example' }));

    expect(seed).toHaveBeenCalledWith(REALM.id, new Map(), {
      leaveWithoutRow: new Set(['mail.smtp.password']),
    });
    expect(error.mock.calls).toEqual([
      [
        {
          variable: 'SMTP_PASSWORD',
          realm: 'master',
          realmId: REALM.id,
          policy: 'mail.smtp.password',
        },
        smtpPasswordForAnotherServerError('SMTP_PASSWORD', 'master'),
      ],
    ]);
    expect(JSON.stringify(error.mock.calls)).not.toContain(PASSWORD);
  });

  it("seeds another realm only with a secret its stored transport needs, when its server is the environment's, recording nothing else", async () => {
    const seeds = new Map([
      ['mail.smtp.password', PASSWORD],
      ['mail.resend.apiKey', 're_key'],
    ]);
    const { deps: d, seed } = deps(
      {},
      {
        realms: [
          { id: REALM.id, name: 'master', env: SMTP_ENV },
          { id: OTHER.id, name: 'beta', env: SMTP_ENV },
          { id: 'mock-realm', name: 'gamma' },
          { id: 'elsewhere', name: 'delta', env: { ...SMTP_ENV, SMTP_HOST: 'smtp.b.example' } },
          { id: 'unfilled', name: 'epsilon', env: SMTP_ENV, hasPolicies: false },
        ],
        isSet: true,
      }
    );

    await seedRealmSecrets(d, settings(seeds));

    const everything = new Set(seedKeys.keys());
    expect(seed.mock.calls).toEqual([
      [REALM.id, seeds, { leaveWithoutRow: new Set(['mail.smtp.password']) }],
      [OTHER.id, new Map([['mail.smtp.password', PASSWORD]]), { leaveWithoutRow: everything }],
      // mock needs nothing: nothing is stored, and no row records it unset.
      ['mock-realm', new Map(), { leaveWithoutRow: everything }],
      // Another server: the environment's password is not its.
      ['elsewhere', new Map(), { leaveWithoutRow: everything }],
      // A realm with no policies yet sends with the environment's secrets.
    ]);
  });

  it('goes on past a realm it cannot seed or whose stored policies this release refuses', async () => {
    const {
      deps: d,
      seed,
      warn,
    } = deps(
      {},
      {
        realms: [
          { id: REALM.id, name: 'master', env: SMTP_ENV },
          { id: 'refused', name: 'refused', refused: true },
          { id: OTHER.id, name: 'beta', env: SMTP_ENV },
          { id: 'last', name: 'last', env: SMTP_ENV },
        ],
        isSet: true,
        seedFails: OTHER.id,
      }
    );

    await seedRealmSecrets(d, settings(new Map([['mail.smtp.password', PASSWORD]])));

    expect(seed.mock.calls.map(([realmId]) => realmId)).toEqual([REALM.id, OTHER.id, 'last']);
    expect(warn.mock.calls.map(([fields]) => fields.realm)).toEqual(['refused', 'beta']);
    expect(warn.mock.calls[0]?.[0]).toMatchObject({ paths: ['tokens.accessTokenLifespanSeconds'] });
    expect(warn.mock.calls[1]).toEqual([
      { realm: 'beta', realmId: OTHER.id, error: 'Error' },
      realmSecretSeedFailedWarning('beta'),
    ]);
  });

  it('stops the boot when the default realm cannot be seeded', async () => {
    const { deps: d } = deps(
      {},
      { realms: [{ id: REALM.id, name: 'master', env: SMTP_ENV }], seedFails: REALM.id }
    );
    await expect(
      seedRealmSecrets(d, settings(new Map([['mail.smtp.password', PASSWORD]])))
    ).rejects.toThrow('no data-at-rest key');
  });

  it('warns once for a secret seed key the environment still sets after the first seed', async () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);
    const { deps: d, warn, info } = deps({ present: ['mail.smtp.password', 'mail.resend.apiKey'] });

    await seedRealmSecrets(d, settings(seeds, { host: null, port: null, user: null }));

    // RESEND_API_KEY is not set, so only SMTP_PASSWORD is named.
    expect(warn.mock.calls).toEqual([
      [
        { variable: 'SMTP_PASSWORD', realm: 'master', policy: 'mail.smtp.password' },
        secretSeedKeyIgnoredWarning('SMTP_PASSWORD', 'master', 'mail.smtp.password'),
      ],
    ]);
    expect(info).not.toHaveBeenCalled();
    expect(JSON.stringify(warn.mock.calls)).not.toContain(PASSWORD);
  });

  it('warns for each thing the stored transport lacks, which no longer stops the boot', async () => {
    const run = async (env: Record<string, string>, isSet: boolean) => {
      const d = deps({}, { realms: [{ id: REALM.id, name: 'master', env }], isSet });
      await seedRealmSecrets(d.deps, settings(new Map()));
      return d;
    };
    const whole = {
      EMAIL_FROM_ADDRESS: 'no-reply@example.com',
      SMTP_HOST: 'smtp.example.com',
      SMTP_PORT: '587',
      SMTP_USER: 'mailer',
    };

    // smtp with everything but its password.
    const noPassword = await run({ ...whole, EMAIL_PROVIDER: 'smtp' }, false);
    expect(noPassword.isSet).toHaveBeenCalledWith(REALM.id, 'mail.smtp.password');
    expect(noPassword.warn.mock.calls).toEqual([
      [
        { realm: 'master', realmId: REALM.id, policy: 'mail.smtp.password' },
        mailTransportIncompleteWarning(
          'master',
          'mail.smtp.password',
          'must be set when mail.provider is smtp'
        ),
      ],
    ]);

    // smtp with its password but no host, port or user: the boot used to refuse this.
    const noHost = await run(
      { EMAIL_PROVIDER: 'smtp', EMAIL_FROM_ADDRESS: 'no-reply@example.com' },
      true
    );
    expect(noHost.warn.mock.calls.map(([fields]) => fields.policy)).toEqual([
      'mail.smtp.host',
      'mail.smtp.port',
      'mail.smtp.user',
    ]);

    // A whole transport, and mock, say nothing.
    expect((await run({ ...whole, EMAIL_PROVIDER: 'smtp' }, true)).warn).not.toHaveBeenCalled();
    expect(
      (await run({ EMAIL_PROVIDER: 'resend', EMAIL_FROM_ADDRESS: 'a@example.com' }, true)).warn
    ).not.toHaveBeenCalled();
    expect((await run({}, false)).warn).not.toHaveBeenCalled();
  });

  it('does nothing without a realm', async () => {
    const { deps: d, seed } = deps({}, { realms: [] });
    await seedRealmSecrets(d, settings(new Map()));
    expect(seed).not.toHaveBeenCalled();
  });
});

describe('realmMailSource (#529)', () => {
  const SMTP_POLICIES = defaultsFromEnv({
    EMAIL_PROVIDER: 'smtp',
    EMAIL_FROM_ADDRESS: 'no-reply@example.com',
    EMAIL_FROM_NAME: 'Example',
    SMTP_HOST: 'smtp.example.com',
    SMTP_PORT: '2525',
    SMTP_SECURE: 'false',
    SMTP_USER: 'mailer',
  });

  function source(snapshot: Partial<RealmPolicySnapshot> | undefined) {
    const get = vi.fn(async () =>
      snapshot === undefined
        ? undefined
        : ({ policies: SMTP_POLICIES, ...snapshot } as RealmPolicySnapshot)
    );
    const getForUse = vi.fn(async () => PASSWORD);
    const fastify = {
      policyStore: { get },
      realmSecretStore: { getForUse },
    } as unknown as Pick<FastifyInstance, 'policyStore' | 'realmSecretStore'>;
    return {
      source: realmMailSource(fastify, new Map([['mail.smtp.password', 'from-the-environment']])),
      get,
      getForUse,
    };
  }

  it("reads a realm's transport and sender anew, and its secret from the secret store", async () => {
    const { source: mail, get, getForUse } = source({ version: 7, hasPolicies: true });

    const read = await mail.read(REALM.id);

    expect(get).toHaveBeenCalledWith(REALM.id);
    expect(read?.version).toBe(7);
    expect(read?.mail).toEqual({
      provider: 'smtp',
      fromAddress: 'no-reply@example.com',
      fromName: 'Example',
      smtp: { host: 'smtp.example.com', port: 2525, secure: false, user: 'mailer' },
    });
    expect(await read?.secretOf('mail.smtp.password')).toBe(PASSWORD);
    expect(getForUse).toHaveBeenCalledWith(REALM.id, 'mail.smtp.password');
  });

  it('gives a realm with no policies yet the environment secret, as before', async () => {
    const { source: mail, getForUse } = source({ version: 0, hasPolicies: false });

    const read = await mail.read(REALM.id);

    expect(await read?.secretOf('mail.smtp.password')).toBe('from-the-environment');
    expect(await read?.secretOf('mail.resend.apiKey')).toBeUndefined();
    expect(getForUse).not.toHaveBeenCalled();
  });

  it('reads nothing for an unknown realm', async () => {
    expect(await source(undefined).source.read(REALM.id)).toBeUndefined();
  });
});
