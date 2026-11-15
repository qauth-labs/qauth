/**
 * Real-DB integration tests for the service accounts repository (#522,
 * migration 0078).
 *
 * Exercises what a recording client cannot: the three rows one creation
 * writes in one transaction (a user with no credential, its client, the
 * service account), the refusal of any realm but the operator realm, the
 * unique name and client id, the composite foreign key that holds the
 * account to the row's realm, the name grammar the database checks, the
 * cascades, and the switch.
 *
 * Requires Docker; self-skips without it and fails on CI
 * (`requireDockerOrSkip`).
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { oauthClients, realms, serviceAccounts, userCredentials, users } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import {
  createServiceAccountsRepository,
  type ServiceAccountsRepository,
} from './service-accounts.repository';

const KEYS = {
  keys: [{ kty: 'EC', crv: 'P-256', x: 'x-coordinate', y: 'y-coordinate', kid: 'ci-1' }],
};

describe('service accounts (real Postgres, #522)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repository: ServiceAccountsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repository = createServiceAccountsRepository(ctx.database.db);
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

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  async function realm(name: string, isOperator: boolean): Promise<string> {
    const [row] = await db()
      .insert(realms)
      .values({ name, isOperator })
      .returning({ id: realms.id });
    return row.id;
  }

  it('writes a user with no credential, its private_key_jwt client and the service account', async () => {
    const operator = await realm('operator', true);
    const created = await repository.create({
      realmId: operator,
      name: 'ci-realm-import',
      clientId: 'ci-realm-import',
      jwks: KEYS,
      createdBy: null,
    });

    expect(created.serviceAccount).toMatchObject({
      realmId: operator,
      name: 'ci-realm-import',
      userId: created.userId,
      clientId: created.client.id,
      enabled: true,
      createdBy: null,
    });
    const [user] = await db().select().from(users).where(eq(users.id, created.userId));
    expect(user).toMatchObject({ realmId: operator, enabled: true, isServiceAccount: true });
    expect(
      await db().select().from(userCredentials).where(eq(userCredentials.userId, created.userId))
    ).toEqual([]);

    const [client] = await db()
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.id, created.client.id));
    expect(client).toMatchObject({
      realmId: operator,
      clientId: 'ci-realm-import',
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: KEYS,
      jwksUri: null,
      grantTypes: ['client_credentials'],
      responseTypes: [],
      redirectUris: [],
      audience: ['urn:qauth:aud:admin:v1-rc.0'],
      scopes: ['qauth:admin:read', 'qauth:admin:write', 'qauth:admin:security'],
      dpopBoundAccessTokens: true,
      provisionedByOperator: true,
      developerId: null,
      isAgent: false,
      enabled: true,
    });

    await expect(repository.findByUser(operator, created.userId)).resolves.toEqual(
      created.serviceAccount
    );
    await expect(repository.findByClient(operator, created.client.id)).resolves.toEqual(
      created.serviceAccount
    );
    await expect(repository.findByName(operator, 'ci-realm-import')).resolves.toEqual(
      created.serviceAccount
    );
  });

  it('refuses any realm but the operator realm, and writes nothing', async () => {
    const tenant = await realm('tenant', false);
    await expect(
      repository.create({
        realmId: tenant,
        name: 'ci',
        clientId: 'ci',
        jwksUri: 'https://ci.example.com/jwks.json',
        createdBy: null,
      })
    ).rejects.toThrow(BadRequestError);
    expect(await db().select().from(users)).toEqual([]);
    expect(await db().select().from(oauthClients)).toEqual([]);
  });

  it('refuses a name or client id the realm holds, and rolls the whole creation back', async () => {
    const operator = await realm('operator', true);
    await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    await expect(
      repository.create({
        realmId: operator,
        name: 'ci',
        clientId: 'other-client',
        jwks: KEYS,
        createdBy: null,
      })
    ).rejects.toThrow(UniqueConstraintError);
    // A client id any client of the realm has is refused before anything is
    // written: a service account's client is its own.
    await expect(
      repository.create({
        realmId: operator,
        name: 'other',
        clientId: 'ci',
        jwks: KEYS,
        createdBy: null,
      })
    ).rejects.toThrow(BadRequestError);
    expect(await db().select().from(users)).toHaveLength(1);
    expect(await db().select().from(oauthClients)).toHaveLength(1);
  });

  it("never takes the system client's id, or one the deployment reserves", async () => {
    const operator = await realm('operator', true);
    for (const input of [
      { clientId: 'system' },
      { clientId: 'portal', reservedClientIds: ['portal'] },
    ]) {
      await expect(
        repository.create({ realmId: operator, name: 'ci', jwks: KEYS, createdBy: null, ...input }),
        JSON.stringify(input)
      ).rejects.toThrow(BadRequestError);
    }
    expect(await db().select().from(users)).toEqual([]);
  });

  it('refuses malformed input before anything is read', async () => {
    const operator = await realm('operator', true);
    for (const input of [
      { name: 'CI', clientId: 'ci', jwks: KEYS },
      { name: 'ci', clientId: ' ci', jwks: KEYS },
      { name: 'ci', clientId: 'ci' },
      { name: 'ci', clientId: 'ci', jwks: KEYS, jwksUri: 'https://ci.example.com/jwks.json' },
      { name: 'ci', clientId: 'ci', jwksUri: 'http://ci.example.com/jwks.json' },
      { name: 'ci', clientId: 'ci', jwks: { keys: [{ ...KEYS.keys[0], d: 'private' }] } },
    ]) {
      await expect(
        repository.create({ realmId: operator, createdBy: null, ...input }),
        JSON.stringify(input)
      ).rejects.toThrow(BadRequestError);
    }
    expect(await db().select().from(users)).toEqual([]);
  });

  it('holds the name grammar and the realm of the account in the database too', async () => {
    const operator = await realm('operator', true);
    const tenant = await realm('tenant', false);
    const { client, userId } = await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    const pool = ctx?.database.pool;
    if (!pool) throw new Error('integration db not initialised');
    const [stranger] = await db()
      .insert(users)
      .values({ realmId: tenant })
      .returning({ id: users.id });
    // A client of no service account yet, so the unique client id answers
    // nothing and the foreign key is what refuses the row.
    const [spare] = await db()
      .insert(oauthClients)
      .values({
        realmId: operator,
        clientId: 'spare',
        clientSecretHash: 'unused',
        name: 'Spare',
        redirectUris: [],
      })
      .returning({ id: oauthClients.id });
    // The account of another realm: the composite foreign key refuses it.
    await expect(
      pool.query(
        `INSERT INTO service_accounts (realm_id, name, user_id, client_id) VALUES ($1, 'x', $2, $3)`,
        [operator, stranger.id, spare.id]
      )
    ).rejects.toMatchObject({ constraint: 'service_accounts_user_realm_fk' });
    // One client is one service account's.
    const [local] = await db()
      .insert(users)
      .values({ realmId: operator })
      .returning({ id: users.id });
    await expect(
      pool.query(
        `INSERT INTO service_accounts (realm_id, name, user_id, client_id) VALUES ($1, 'y', $2, $3)`,
        [operator, local.id, client.id]
      )
    ).rejects.toMatchObject({ constraint: 'service_accounts_client_id_unique' });
    await expect(
      pool.query(`UPDATE service_accounts SET name = 'Not A Name' WHERE user_id = $1`, [userId])
    ).rejects.toMatchObject({ constraint: 'service_accounts_name_grammar' });
  });

  it('switches a service account, in its realm only', async () => {
    const operator = await realm('operator', true);
    const other = await realm('other', false);
    const { serviceAccount } = await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    await expect(repository.setEnabled(other, serviceAccount.id, false)).resolves.toBeUndefined();
    await expect(repository.setEnabled(operator, serviceAccount.id, false)).resolves.toMatchObject({
      enabled: false,
    });
    await expect(repository.findById(operator, serviceAccount.id)).resolves.toMatchObject({
      enabled: false,
    });
    await expect(repository.findById(other, serviceAccount.id)).resolves.toBeUndefined();
    await expect(repository.list(operator)).resolves.toHaveLength(1);
    await expect(repository.list(other)).resolves.toEqual([]);
  });

  // #522: disabling a service account disables its account, which ends what
  // it was issued (migration 0044), and enabling it again brings none back.
  it('switches its account with it, and disabling it ends what the account was issued', async () => {
    const operator = await realm('operator', true);
    const { serviceAccount, userId } = await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    const account = async () => (await db().select().from(users).where(eq(users.id, userId)))[0];
    expect(await account()).toMatchObject({ enabled: true, notValidBefore: null });

    const before = Date.now();
    await repository.setEnabled(operator, serviceAccount.id, false);
    const disabled = await account();
    expect(disabled.enabled).toBe(false);
    expect(disabled.notValidBefore).toBeGreaterThanOrEqual(before - 1000);

    await repository.setEnabled(operator, serviceAccount.id, true);
    expect(await account()).toMatchObject({
      enabled: true,
      notValidBefore: disabled.notValidBefore,
    });
  });

  it("ends the tokens of the account a client binds, and of no other account's", async () => {
    const operator = await realm('operator', true);
    const { client, userId } = await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    const [person] = await db()
      .insert(users)
      .values({ realmId: operator })
      .returning({ id: users.id });
    const before = Date.now();
    await expect(repository.endTokensOfClient(operator, client.id)).resolves.toBe(1);
    const [ended] = await db().select().from(users).where(eq(users.id, userId));
    expect(ended.enabled).toBe(true);
    expect(ended.notValidBefore).toBeGreaterThanOrEqual(before - 1000);
    const [untouched] = await db().select().from(users).where(eq(users.id, person.id));
    expect(untouched.notValidBefore).toBeNull();
    // A client no service account binds, or another realm's: nothing moves.
    const [spare] = await db()
      .insert(oauthClients)
      .values({
        realmId: operator,
        clientId: 'spare',
        clientSecretHash: 'unused',
        name: 'Spare',
        redirectUris: [],
      })
      .returning({ id: oauthClients.id });
    await expect(repository.endTokensOfClient(operator, spare.id)).resolves.toBe(0);
    const other = await realm('other', false);
    await expect(repository.endTokensOfClient(other, client.id)).resolves.toBe(0);
  });

  it('keeps the mark of a service account for good', async () => {
    const operator = await realm('operator', true);
    const { userId } = await repository.create({
      realmId: operator,
      name: 'ci',
      clientId: 'ci',
      jwks: KEYS,
      createdBy: null,
    });
    const pool = ctx?.database.pool;
    if (!pool) throw new Error('integration db not initialised');
    await expect(
      pool.query('UPDATE users SET is_service_account = false WHERE id = $1', [userId])
    ).rejects.toMatchObject({ constraint: 'users_service_account_permanent' });
    const [person] = await db()
      .insert(users)
      .values({ realmId: operator })
      .returning({ id: users.id });
    await expect(
      pool.query('UPDATE users SET is_service_account = true WHERE id = $1', [person.id])
    ).rejects.toMatchObject({ constraint: 'users_service_account_permanent' });
  });

  it('goes with its account and its realm, and keeps its client from being deleted', async () => {
    const operator = await realm('operator', true);
    const first = await repository.create({
      realmId: operator,
      name: 'first',
      clientId: 'first',
      jwks: KEYS,
      createdBy: null,
    });
    const second = await repository.create({
      realmId: operator,
      name: 'second',
      clientId: 'second',
      jwks: KEYS,
      createdBy: null,
    });
    const pool = ctx?.database.pool;
    if (!pool) throw new Error('integration db not initialised');
    // The client a service account binds is not deleted, whoever tries.
    await expect(
      pool.query('DELETE FROM oauth_clients WHERE id = $1', [second.client.id])
    ).rejects.toMatchObject({
      code: '23503',
      constraint: 'service_accounts_client_id_oauth_clients_id_fk',
    });
    await db().delete(users).where(eq(users.id, first.userId));
    expect((await db().select().from(serviceAccounts)).map((row) => row.name)).toEqual(['second']);
    // The realm's own cascade removes the row and its client together.
    await db().delete(realms).where(eq(realms.id, operator));
    expect(await db().select().from(serviceAccounts)).toEqual([]);
    expect(await db().select().from(oauthClients)).toEqual([]);
  });
});
