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
    expect(user).toMatchObject({ realmId: operator, enabled: true });
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
    for (const clash of [
      { name: 'ci', clientId: 'other-client' },
      { name: 'other', clientId: 'ci' },
    ]) {
      await expect(
        repository.create({ realmId: operator, ...clash, jwks: KEYS, createdBy: null })
      ).rejects.toThrow(UniqueConstraintError);
    }
    expect(await db().select().from(users)).toHaveLength(1);
    expect(await db().select().from(oauthClients)).toHaveLength(1);
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
    // The account of another realm: the composite foreign key refuses it.
    await expect(
      pool.query(
        `INSERT INTO service_accounts (realm_id, name, user_id, client_id) VALUES ($1, 'x', $2, $3)`,
        [operator, stranger.id, client.id]
      )
    ).rejects.toMatchObject({ constraint: 'service_accounts_user_realm_fk' });
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

  it('goes with its account and with its client', async () => {
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
    await db().delete(users).where(eq(users.id, first.userId));
    await db().delete(oauthClients).where(eq(oauthClients.id, second.client.id));
    expect(await db().select().from(serviceAccounts)).toEqual([]);
  });
});
