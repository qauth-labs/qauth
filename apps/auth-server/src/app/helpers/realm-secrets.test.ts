import {
  defaultsFromEnv,
  type RealmPolicySnapshot,
  type RealmSecretSeedReport,
  secretSeedKeys,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { testRealm } from '../../testing/request-realm';
import {
  type DefaultRealmSecretSeedDependencies,
  mailSecretMissingWarning,
  realmMailSource,
  realmSecretCipher,
  secretSeedKeyIgnoredWarning,
  seedDefaultRealmSecrets,
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

describe('seedDefaultRealmSecrets (#529)', () => {
  const seedKeys = secretSeedKeys();

  function deps(
    report: RealmSecretSeedReport,
    options: { provider?: 'mock' | 'smtp' | 'resend'; isSet?: boolean; realm?: boolean } = {}
  ) {
    const policies = defaultsFromEnv({ EMAIL_PROVIDER: options.provider ?? 'mock' });
    const warn = vi.fn();
    const info = vi.fn();
    const seed = vi.fn(async () => report);
    const isSet = vi.fn(async () => options.isSet ?? false);
    const value: DefaultRealmSecretSeedDependencies = {
      realms: { findByName: vi.fn(async () => (options.realm === false ? undefined : REALM)) },
      policies: { ofRealm: vi.fn(() => ({ policies }) as unknown as RealmPolicySnapshot) },
      secrets: { seed, isSet },
      log: { warn, info },
    };
    return { deps: value, warn, info, seed, isSet };
  }

  it('seeds the default realm from the environment and names what it seeded, never the value', async () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);
    const {
      deps: d,
      info,
      warn,
      seed,
    } = deps({
      seeded: ['mail.smtp.password'],
      recordedUnset: ['mail.resend.apiKey'],
      present: [],
    });

    await seedDefaultRealmSecrets(d, { realmName: 'master', seeds, seedKeys });

    expect(d.realms.findByName).toHaveBeenCalledWith('master');
    expect(seed).toHaveBeenCalledWith(REALM.id, seeds);
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

  it('warns once for a secret seed key the environment still sets after the first seed', async () => {
    const seeds = new Map([['mail.smtp.password', PASSWORD]]);
    const {
      deps: d,
      warn,
      info,
    } = deps({
      seeded: [],
      recordedUnset: [],
      present: ['mail.smtp.password', 'mail.resend.apiKey'],
    });

    await seedDefaultRealmSecrets(d, { realmName: 'master', seeds, seedKeys });

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

  it('warns when the stored transport lacks its secret, which no longer stops the boot', async () => {
    const report = { seeded: [], recordedUnset: [], present: [] };
    const smtp = deps(report, { provider: 'smtp', isSet: false });
    await seedDefaultRealmSecrets(smtp.deps, { realmName: 'master', seeds: new Map(), seedKeys });
    expect(smtp.isSet).toHaveBeenCalledWith(REALM.id, 'mail.smtp.password');
    expect(smtp.warn).toHaveBeenCalledWith(
      { realm: 'master', realmId: REALM.id, policy: 'mail.smtp.password' },
      mailSecretMissingWarning('master', 'smtp', 'mail.smtp.password')
    );

    const resend = deps(report, { provider: 'resend', isSet: true });
    await seedDefaultRealmSecrets(resend.deps, { realmName: 'master', seeds: new Map(), seedKeys });
    expect(resend.isSet).toHaveBeenCalledWith(REALM.id, 'mail.resend.apiKey');
    expect(resend.warn).not.toHaveBeenCalled();

    const mock = deps(report, { provider: 'mock' });
    await seedDefaultRealmSecrets(mock.deps, { realmName: 'master', seeds: new Map(), seedKeys });
    expect(mock.isSet).not.toHaveBeenCalled();
  });

  it('does nothing without the default realm', async () => {
    const { deps: d, seed } = deps(
      { seeded: [], recordedUnset: [], present: [] },
      { realm: false }
    );
    await seedDefaultRealmSecrets(d, { realmName: 'master', seeds: new Map(), seedKeys });
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
