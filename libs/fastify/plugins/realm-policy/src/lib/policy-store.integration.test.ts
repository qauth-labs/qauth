/**
 * The policy store over the realms table (#516), against a migrated Postgres:
 *
 * - the four column-backed fields round-trip, and land in their columns;
 * - an update with a stale expected counter fails and changes nothing,
 *   also when the counter moved through a plain realm UPDATE (the trigger);
 * - a new realm gets `defaultsFromEnv`, and a realm with no policies gets its
 *   fill once, keeping the row values the server read before;
 * - two nodes filling a realm at once leave one consistent document, and a
 *   fill never overwrites a plain UPDATE of the row it waited on;
 * - a secret never reaches `realms.policies`;
 * - a document of an earlier schema version is read upgraded, and written
 *   once under the new version by the next release's boot (#908).
 *
 * Requires Docker; self-skips without it.
 */
import {
  createDatabase,
  createRealmsRepository,
  type DatabaseInstance,
  type DbClient,
  type Realm,
} from '@qauth-labs/infra-db';
import {
  BUILT_IN_POLICY_GROUPS,
  createPolicyRegistry,
  createPolicyStore,
  defaultsFromEnv,
  PASSWORD_POLICY_GROUP,
  type PolicySchemaUpgrade,
  PolicyVersionConflictError,
  REALM_POLICY_ENV,
  REALM_POLICY_SCHEMA_VERSION,
  type RealmPolicies,
  type RealmPolicyStore,
  type RealmSecretStore,
} from '@qauth-labs/server-realm-policy';
import {
  applyQauthMigrations,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { createRealmPolicyStorage } from './storage';

const SEEDS = defaultsFromEnv({
  ACCESS_TOKEN_LIFESPAN: '600',
  REFRESH_TOKEN_LIFESPAN: '7200',
  DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid profile',
  PASSWORD_MIN_SCORE: '3',
});
const SECRET = 'an-smtp-password-that-must-stay-out-of-the-row';

describe('policy store over the realms table (integration)', () => {
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let second: DatabaseInstance | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    await applyQauthMigrations(container.connectionString);
    database = createDatabase({ connectionString: container.connectionString });
    // A second pool, as a second node has.
    second = createDatabase({ connectionString: container.connectionString });
  }, 180_000);

  afterAll(async () => {
    await database?.close();
    await second?.close();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !database) {
      testCtx.skip();
      return;
    }
    await database.pool.query('TRUNCATE realms CASCADE');
  });

  function db(): DatabaseInstance {
    if (!database) throw new Error('no database');
    return database;
  }

  function storeOn(
    instance: DatabaseInstance,
    seeds: RealmPolicies = SEEDS,
    secrets?: RealmSecretStore<DbClient>
  ): RealmPolicyStore<Realm, DbClient> {
    const realms = createRealmsRepository(instance.db, {
      seeds: { policies: { document: seeds, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    });
    return createPolicyStore({
      storage: createRealmPolicyStorage(instance.db, realms),
      seeds,
      ...(secrets === undefined ? {} : { secrets }),
    });
  }

  /** A realm as a release before 0046 left it: no policies, the settings an operator made. */
  async function insertPreviousRealm(
    name: string,
    scopes: readonly string[] = ['openid']
  ): Promise<string> {
    const {
      rows: [realm],
    } = await db().pool.query<{ id: string }>(
      `INSERT INTO realms (name, max_environment_laxity, dynamic_registration_allowed_scopes)
       VALUES ($1, 'development', $2::jsonb) RETURNING id`,
      [name, JSON.stringify(scopes)]
    );
    return realm.id;
  }

  async function row(realmId: string): Promise<Record<string, unknown>> {
    const {
      rows: [found],
    } = await db().pool.query(`SELECT * FROM realms WHERE id = $1`, [realmId]);
    return found;
  }

  it('gives a new realm defaultsFromEnv, at counter 1', async () => {
    const realms = createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    });
    const { realm } = await realms.createWithPrimaryHost(
      { name: 'fresh', issuer: 'https://fresh.example.com' },
      'fresh.example.com'
    );

    const snapshot = await storeOn(db()).get(realm.id);

    expect(snapshot).toMatchObject({ version: 1, hasPolicies: true, policies: SEEDS });
    expect(await row(realm.id)).toMatchObject({
      access_token_lifespan: '600',
      refresh_token_lifespan: '7200',
      dynamic_registration_allowed_scopes: ['openid', 'profile'],
      max_environment_laxity: 'production',
      policy_schema_version: REALM_POLICY_SCHEMA_VERSION,
      policies_version: 1,
    });
  });

  it('round-trips the four column-backed fields, which land in their columns only', async () => {
    const store = storeOn(db());
    const realm = await createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    }).create({ name: 'columns' });

    const updated = await store.update(
      realm.id,
      {
        tokens: { accessTokenLifespanSeconds: 120, refreshTokenLifespanSeconds: 3600 },
        registration: { dynamicRegistrationAllowedScopes: ['openid', 'email'] },
        posture: { maxEnvironmentLaxity: 'staging' },
      },
      { expectedVersion: 1 }
    );
    expect(updated.version).toBe(2);

    const stored = await row(realm.id);
    expect(stored).toMatchObject({
      access_token_lifespan: '120',
      refresh_token_lifespan: '3600',
      dynamic_registration_allowed_scopes: ['openid', 'email'],
      max_environment_laxity: 'staging',
      policies_version: 2,
    });
    const members = stored['policies'] as Record<string, Record<string, unknown>>;
    expect(Object.keys(members['tokens'])).not.toContain('accessTokenLifespanSeconds');
    expect(Object.keys(members['tokens'])).not.toContain('refreshTokenLifespanSeconds');
    expect(Object.keys(members['registration'])).not.toContain('dynamicRegistrationAllowedScopes');
    expect(members['posture']).toBeUndefined();

    const read = await store.get(realm.id);
    expect(read?.policies.tokens).toMatchObject({
      accessTokenLifespanSeconds: 120,
      refreshTokenLifespanSeconds: 3600,
    });
    expect(read?.policies.registration.dynamicRegistrationAllowedScopes).toEqual([
      'openid',
      'email',
    ]);
    expect(read?.policies.posture.maxEnvironmentLaxity).toBe('staging');

    // Another field's update leaves them as they are.
    await store.update(realm.id, { password: { minScore: 4 } }, { expectedVersion: 2 });
    expect((await store.get(realm.id))?.policies).toEqual({
      ...read?.policies,
      password: { minScore: 4 },
    });
  });

  it('refuses an update with a stale expected counter and changes nothing', async () => {
    const store = storeOn(db());
    const realm = await createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    }).create({ name: 'stale' });
    await store.update(realm.id, { password: { minScore: 4 } }, { expectedVersion: 1 });
    const before = await row(realm.id);

    await expect(
      store.update(realm.id, { password: { minScore: 0 } }, { expectedVersion: 1 })
    ).rejects.toBeInstanceOf(PolicyVersionConflictError);

    expect(await row(realm.id)).toEqual(before);
  });

  it('refuses a stale counter after a plain realm UPDATE moved it, through the trigger', async () => {
    const store = storeOn(db());
    const realms = createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    });
    const realm = await realms.create({ name: 'trigger' });
    const read = await store.get(realm.id);

    // A writer from before the policies existed, such as /oauth/register's on
    // a node of the previous release during a rolling upgrade. This release's
    // repository writes no policy column (below).
    await db().pool.query(
      `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid"]'::jsonb WHERE id = $1`,
      [realm.id]
    );

    await expect(
      store.update(realm.id, { password: { minScore: 4 } }, { expectedVersion: read?.version ?? 0 })
    ).rejects.toMatchObject({ name: 'PolicyVersionConflictError', currentVersion: 2 });
    expect(
      (await store.get(realm.id))?.policies.registration.dynamicRegistrationAllowedScopes
    ).toEqual(['openid']);
  });

  it("upgrades a document of an earlier schema version once, at the next release's boot (#908)", async () => {
    const realms = createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    });
    const realm = await realms.create({ name: 'earlier' });
    await storeOn(db()).update(realm.id, { password: { minScore: 4 } }, { expectedVersion: 1 });

    // The release that changes the version to 1-rc.1 and renames
    // password.minScore, whose seed it reads as 0: looser than stored.
    const registry = createPolicyRegistry({ version: '1-rc.1', env: REALM_POLICY_ENV });
    for (const [name, shape] of Object.entries(BUILT_IN_POLICY_GROUPS)) {
      registry.registerPolicyGroup(
        name,
        name === 'password' ? { minimumScore: PASSWORD_POLICY_GROUP.minScore } : shape
      );
    }
    const rename: PolicySchemaUpgrade = {
      from: REALM_POLICY_SCHEMA_VERSION,
      to: '1-rc.1',
      upgrade(document) {
        const password = document['password'] as Record<string, unknown>;
        password['minimumScore'] = password['minScore'];
        delete password['minScore'];
        return document;
      },
    };
    const next = createPolicyStore({
      storage: createRealmPolicyStorage(db().db, realms),
      seeds: registry.defaultsFromEnv({ PASSWORD_MIN_SCORE: '0' }),
      registry,
      upgrades: [rename],
    });

    expect(await next.get(realm.id)).toMatchObject({
      version: 2,
      schemaVersion: '1-rc.1',
      policies: { password: { minimumScore: 4 } },
    });
    expect((await row(realm.id)).policy_schema_version).toBe(REALM_POLICY_SCHEMA_VERSION);

    expect((await next.seedRealms()).upgraded).toEqual([
      { realmId: realm.id, realmName: 'earlier', from: REALM_POLICY_SCHEMA_VERSION, paths: [] },
    ]);
    const stored = await row(realm.id);
    expect(stored).toMatchObject({ policy_schema_version: '1-rc.1', policies_version: 3 });
    expect((stored['policies'] as Record<string, unknown>)['password']).toEqual({
      minimumScore: 4,
    });
    expect((await next.seedRealms()).upgraded).toEqual([]);
    // A node of the previous release, during the roll, reads it with its own
    // schema: the renamed field as its seed (3), looser than stored, which is
    // why version.ts has such a change stop the old nodes first. It never
    // writes it.
    const previous = storeOn(db());
    expect(await previous.get(realm.id)).toMatchObject({
      version: 3,
      schemaVersion: '1-rc.1',
      policies: { password: { minScore: 3 } },
    });
    await expect(previous.update(realm.id, {}, { expectedVersion: 3 })).rejects.toMatchObject({
      name: 'PolicySchemaVersionError',
      reason: 'newer',
    });
  });

  it("writes no policy column through the repository's plain update", async () => {
    const realms = createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    });
    const realm = await realms.create({ name: 'plain-update' });
    const before = await row(realm.id);

    // A caller the types do not bind: every policy column is dropped, the
    // rest is written.
    await realms.update(realm.id, {
      enabled: false,
      accessTokenLifespan: 0,
      refreshTokenLifespan: 0,
      dynamicRegistrationAllowedScopes: ['openid', 'openid', 'a scope'],
      maxEnvironmentLaxity: 'development',
      policies: { password: { minScore: 0 } },
      policySchemaVersion: '9',
      policiesVersion: 0,
    } as never);

    const after = await row(realm.id);
    expect(after).toMatchObject({
      enabled: false,
      access_token_lifespan: before.access_token_lifespan,
      refresh_token_lifespan: before.refresh_token_lifespan,
      dynamic_registration_allowed_scopes: before.dynamic_registration_allowed_scopes,
      max_environment_laxity: before.max_environment_laxity,
      policies: before.policies,
      policy_schema_version: before.policy_schema_version,
      policies_version: before.policies_version,
    });
    expect((await storeOn(db()).get(realm.id))?.version).toBe(1);
  });

  it('fills a realm with no policies once, keeping the row values the server read before', async () => {
    const kept = await insertPreviousRealm('master');
    const empty = await insertPreviousRealm('empty-scopes', []);

    const report = await storeOn(db()).seedRealms();

    expect(report.filled.map((realm) => realm.realmName).sort()).toEqual([
      'empty-scopes',
      'master',
    ]);
    // What each row kept over the environment's seeds, which the boot warns about.
    expect(report.filled.find((realm) => realm.realmId === kept)?.keptFromRow).toEqual([
      { path: 'registration.dynamicRegistrationAllowedScopes', differsFromSeed: true },
      { path: 'posture.maxEnvironmentLaxity', differsFromSeed: true },
    ]);
    expect(report.filled.find((realm) => realm.realmId === empty)?.keptFromRow).toEqual([
      { path: 'posture.maxEnvironmentLaxity', differsFromSeed: true },
    ]);
    const master = await storeOn(db()).get(kept);
    expect(master).toMatchObject({ version: 1, hasPolicies: true });
    expect(master?.policies).toEqual({
      ...SEEDS,
      registration: { ...SEEDS.registration, dynamicRegistrationAllowedScopes: ['openid'] },
      posture: { maxEnvironmentLaxity: 'development' },
    });
    // An empty list took the environment's, as /oauth/register used it.
    expect(
      (await storeOn(db()).get(empty))?.policies.registration.dynamicRegistrationAllowedScopes
    ).toEqual(['openid', 'profile']);

    // A later boot with another environment changes no realm.
    const later = defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '30', PASSWORD_MIN_SCORE: '0' });
    const before = await row(kept);
    expect(await storeOn(db(), later).seedRealms()).toEqual({
      filled: [],
      completed: [],
      upgraded: [],
      skipped: [],
    });
    expect(await row(kept)).toEqual(before);
  });

  it('completes a document that lacks a field of this release, once', async () => {
    const id = await insertPreviousRealm('partial');
    await storeOn(db()).seedRealms();
    // As a realm filled by a release without the password group stands.
    await db().pool.query(`UPDATE realms SET policies = policies - 'password' WHERE id = $1`, [id]);
    const { policies_version: version } = await row(id);

    const report = await storeOn(db()).seedRealms();

    expect(report.completed).toEqual([
      { realmId: id, realmName: 'partial', paths: ['password.minScore'] },
    ]);
    expect(await row(id)).toMatchObject({
      policies_version: (version as number) + 1,
      policies: expect.objectContaining({ password: { minScore: 3 } }),
    });
    expect((await storeOn(db()).seedRealms()).completed).toEqual([]);
  });

  describe('two nodes booting at once', () => {
    const seedsA = defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '600', PASSWORD_MIN_SCORE: '1' });
    const seedsB = defaultsFromEnv({ ACCESS_TOKEN_LIFESPAN: '1200', PASSWORD_MIN_SCORE: '4' });

    /** Whether a stored document is wholly one node's fill: no field of the other. */
    function fillOf(policies: RealmPolicies | undefined): 'A' | 'B' | 'mixed' {
      const pair = [policies?.tokens.accessTokenLifespanSeconds, policies?.password.minScore];
      if (pair[0] === 600 && pair[1] === 1) return 'A';
      if (pair[0] === 1200 && pair[1] === 4) return 'B';
      return 'mixed';
    }

    it('lets the first writer win while the other waits on its row, and changes nothing after', async () => {
      if (!second) throw new Error('no second pool');
      const id = await insertPreviousRealm('race');
      const nodeA = storeOn(db(), seedsA);
      const nodeB = storeOn(second, seedsB);

      let release: () => void = () => undefined;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let reportB: Awaited<ReturnType<typeof nodeB.seedRealms>> | undefined;
      const a = db().db.transaction(async (tx) => {
        const report = await nodeA.seedRealms(tx);
        // Node B reads the realm while A's fill is not committed, and its
        // UPDATE waits on A's row lock.
        const b = nodeB.seedRealms().then((result) => {
          reportB = result;
        });
        await waitForLockWait();
        release();
        await held;
        return { report, b };
      });
      const { report: reportA, b } = await a;
      await b;

      expect(reportA.filled).toMatchObject([{ realmId: id, realmName: 'race' }]);
      expect(reportB).toEqual({ filled: [], completed: [], upgraded: [], skipped: [] });
      const stored = await storeOn(db()).get(id);
      expect(stored?.version).toBe(1);
      expect(fillOf(stored?.policies)).toBe('A');
    });

    it('fills a realm as a plain UPDATE that held its row left it, not as the list read it', async () => {
      if (!second) throw new Error('no second pool');
      const id = await insertPreviousRealm('tightened');
      // A previous release's node tightens the ceiling while the fill runs.
      // The trigger keeps the counter at 0, so the counter compare alone would
      // let the fill write the ceiling it read before.
      const client = await db().pool.connect();
      let fill: ReturnType<RealmPolicyStore<Realm, DbClient>['seedRealms']> | undefined;
      try {
        await client.query('BEGIN');
        await client.query(
          `UPDATE realms SET max_environment_laxity = 'production' WHERE id = $1`,
          [id]
        );
        fill = storeOn(second).seedRealms();
        await waitForLockWait();
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      expect((await fill)?.filled).toMatchObject([{ realmId: id, realmName: 'tightened' }]);
      const stored = await storeOn(db()).get(id);
      expect(stored).toMatchObject({ version: 1, hasPolicies: true });
      expect(stored?.policies.posture.maxEnvironmentLaxity).toBe('production');
    });

    it('holds off writes of the row it locks, but not a row that references the realm', async () => {
      if (!second) throw new Error('no second pool');
      const id = await insertPreviousRealm('referenced');
      const realms = createRealmsRepository(db().db);
      const client = await second.pool.connect();
      try {
        await db().db.transaction(async (tx) => {
          expect(await realms.lockPolicyRecord(id, tx)).toMatchObject({ realmId: id });
          // A foreign key check takes FOR KEY SHARE on the realm row, which
          // FOR NO KEY UPDATE does not conflict with: the insert goes through
          // while the fill holds the row. FOR UPDATE would hold it off.
          await client.query(`SET lock_timeout = '2s'`);
          await client.query(
            `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ('referenced.example.com', $1, 'endpoint')`,
            [id]
          );
          // A plain write of the realm row still waits for the lock.
          await expect(
            client.query(`UPDATE realms SET max_environment_laxity = 'production' WHERE id = $1`, [
              id,
            ])
          ).rejects.toThrow(/lock timeout/);
        });
      } finally {
        await client.query(`RESET lock_timeout`).catch(() => undefined);
        client.release();
      }
    });

    it('leaves one consistent document over many concurrent rounds', async () => {
      if (!second) throw new Error('no second pool');
      const nodeA = storeOn(db(), seedsA);
      const nodeB = storeOn(second, seedsB);

      for (let round = 0; round < 25; round++) {
        await db().pool.query('TRUNCATE realms CASCADE');
        const id = await insertPreviousRealm(`round-${round}`);
        const [reportA, reportB] = await Promise.all([nodeA.seedRealms(), nodeB.seedRealms()]);

        expect(reportA.filled.length + reportB.filled.length).toBe(1);
        const stored = await storeOn(db()).get(id);
        expect(stored?.version).toBe(1);
        expect(fillOf(stored?.policies)).toBe(reportA.filled.length === 1 ? 'A' : 'B');
      }
    });

    async function waitForLockWait(): Promise<void> {
      for (let attempt = 0; attempt < 200; attempt++) {
        const {
          rows: [waiting],
        } = await db().pool.query<{ count: string }>(
          `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'`
        );
        if (Number(waiting.count) > 0) return;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      throw new Error('node B never waited on the realm row');
    }
  });

  it('keeps a secret out of realms.policies and hands it to the secret store in the write transaction', async () => {
    const puts: { path: string; value: string | null; inTransaction: boolean }[] = [];
    const secrets: RealmSecretStore<DbClient> = {
      async put(_realmId, path, value, tx) {
        puts.push({ path, value, inTransaction: tx !== undefined });
      },
      isSet: async () => false,
      getForUse: async () => undefined,
    };
    const store = storeOn(db(), SEEDS, secrets);
    const realm = await createRealmsRepository(db().db, {
      seeds: { policies: { document: SEEDS, schemaVersion: REALM_POLICY_SCHEMA_VERSION } },
    }).create({ name: 'secrets' });

    // A complete smtp transport: the mail rule (#529) refuses one without its
    // host, port, user, sender address and password.
    await store.update(
      realm.id,
      {
        mail: {
          provider: 'smtp',
          fromAddress: 'no-reply@example.com',
          smtp: { host: 'smtp.example.com', port: 587, user: 'mailer', password: SECRET },
        },
      },
      { expectedVersion: 1 }
    );

    expect(puts).toEqual([{ path: 'mail.smtp.password', value: SECRET, inTransaction: true }]);
    const {
      rows: [stored],
    } = await db().pool.query<{ text: string }>(
      `SELECT row_to_json(realms)::text AS text FROM realms`
    );
    expect(stored.text).not.toContain(SECRET);
    expect(stored.text).toContain('smtp.example.com');
  });
});
