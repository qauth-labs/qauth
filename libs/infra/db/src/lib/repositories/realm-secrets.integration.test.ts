/**
 * Real-Postgres integration tests for `realm_secrets` (issue #529, migration
 * 0048).
 *
 * The table's promise lives in its DDL: it holds the signer's ciphertext and
 * never a plaintext, and a secret's row stays once written. Only a database
 * can prove the CHECKs, the primary key and the realm's cascade, so this
 * suite writes through the repository and also around it.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmSecretsRepository } from './realm-secrets.repository';
import { createRealmsRepository } from './realms.repository';

/** A value in the signer's `data_at_rest` format, as the secret store writes one. */
const CIPHERTEXT = {
  ciphertext: `v1.kid-1.${'A'.repeat(16)}.${'B'.repeat(40)}`,
  keyId: 'kid-1',
};

describe('realm_secrets integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function database(): IntegrationDb['database'] {
    if (!ctx) throw new Error('no ctx');
    return ctx.database;
  }

  async function newRealm(): Promise<string> {
    const name = `realm-${Math.random().toString(36).slice(2)}`;
    const { realm } = await createRealmsRepository(database().db).createWithPrimaryHost(
      { name, issuer: `https://${name}.example.com` },
      `${name}.example.com`
    );
    return realm.id;
  }

  /** A raw insert, around the repository, so the CHECKs alone decide. */
  async function insertRaw(
    realmId: string,
    name: string,
    ciphertext: string | null,
    keyId: string | null
  ): Promise<void> {
    await database().pool.query(
      'INSERT INTO realm_secrets (realm_id, name, ciphertext, key_id) VALUES ($1, $2, $3, $4)',
      [realmId, name, ciphertext, keyId]
    );
  }

  it('writes, reads and overwrites a ciphertext, and clears it to a row with none', async () => {
    const repository = createRealmSecretsRepository(database().db);
    const realmId = await newRealm();

    expect(await repository.find(realmId, 'mail.smtp.password')).toBeUndefined();
    await repository.write(realmId, 'mail.smtp.password', CIPHERTEXT);
    expect(await repository.find(realmId, 'mail.smtp.password')).toMatchObject(CIPHERTEXT);

    const next = { ciphertext: `v1.kid-2.${'C'.repeat(16)}.${'D'.repeat(40)}`, keyId: 'kid-2' };
    await repository.write(realmId, 'mail.smtp.password', next);
    expect(await repository.find(realmId, 'mail.smtp.password')).toMatchObject(next);

    await repository.write(realmId, 'mail.smtp.password', null);
    expect(await repository.find(realmId, 'mail.smtp.password')).toMatchObject({
      ciphertext: null,
      keyId: null,
    });
  });

  it('inserts a seed only where the realm has no row, whatever the row holds', async () => {
    const repository = createRealmSecretsRepository(database().db);
    const realmId = await newRealm();

    expect(await repository.insertIfAbsent(realmId, 'mail.smtp.password', null)).toBe(true);
    // A cleared secret is a row too: the seed never fills it again.
    expect(await repository.insertIfAbsent(realmId, 'mail.smtp.password', CIPHERTEXT)).toBe(false);
    expect(await repository.find(realmId, 'mail.smtp.password')).toMatchObject({
      ciphertext: null,
    });

    expect(await repository.insertIfAbsent(realmId, 'mail.resend.apiKey', CIPHERTEXT)).toBe(true);
    expect(await repository.insertIfAbsent(realmId, 'mail.resend.apiKey', null)).toBe(false);
    expect(await repository.find(realmId, 'mail.resend.apiKey')).toMatchObject(CIPHERTEXT);
  });

  it('refuses a plaintext and any value outside the signer format', async () => {
    const realmId = await newRealm();
    const refused = [
      // A plaintext password, with or without a key id.
      ['correct horse battery staple', 'kid-1'],
      ['v1.kid-1.not-a-ciphertext', 'kid-1'],
      // The kid of the ciphertext is not the key id.
      [CIPHERTEXT.ciphertext, 'kid-2'],
      // A ciphertext with no key id, and a key id with no ciphertext.
      [CIPHERTEXT.ciphertext, null],
      [null, 'kid-1'],
      // Another format version.
      [`v2.kid-1.${'A'.repeat(16)}.${'B'.repeat(40)}`, 'kid-1'],
    ] as const;
    for (const [ciphertext, keyId] of refused) {
      await expect(insertRaw(realmId, 'mail.smtp.password', ciphertext, keyId)).rejects.toThrow(
        /realm_secrets_(ciphertext_form|value_and_key_together)/
      );
    }
    // Through the repository too.
    await expect(
      createRealmSecretsRepository(database().db).write(realmId, 'mail.smtp.password', {
        ciphertext: 'hunter2',
        keyId: 'hunter2',
      })
    ).rejects.toMatchObject({ cause: { code: '23514' } });
  });

  it('refuses a name that is not a policy field path', async () => {
    const realmId = await newRealm();
    for (const name of [
      'password',
      'mail..password',
      'Mail.smtp.password',
      'mail.smtp.pass word',
    ]) {
      await expect(insertRaw(realmId, name, null, null)).rejects.toThrow(/realm_secrets_name_form/);
    }
  });

  it('keeps one row per realm and name, and drops a realm with its secrets', async () => {
    const realmId = await newRealm();
    const otherRealmId = await newRealm();
    await insertRaw(realmId, 'mail.smtp.password', CIPHERTEXT.ciphertext, CIPHERTEXT.keyId);
    await expect(insertRaw(realmId, 'mail.smtp.password', null, null)).rejects.toThrow(
      /realm_secrets_pk/
    );
    await insertRaw(otherRealmId, 'mail.smtp.password', null, null);

    await database().pool.query('DELETE FROM realms WHERE id = $1', [realmId]);
    const { rows } = await database().pool.query<{ realm_id: string }>(
      'SELECT realm_id FROM realm_secrets'
    );
    expect(rows).toEqual([{ realm_id: otherRealmId }]);
  });
});
