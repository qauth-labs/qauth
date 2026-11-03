/**
 * Real-Postgres integration tests for the paired sandbox realm (ADR-019
 * Decision 11, issue #554).
 *
 * The rules live in the DDL of migration 0056, so only a database can prove
 * them: the unique index that gives a live realm one sandbox, the CHECKs (not
 * its own sandbox, not the operator realm, never a `development` ceiling), the
 * trigger (no sandbox of a sandbox, none of the operator realm, a pairing that
 * never changes) and the foreign key that keeps a live realm while its sandbox
 * exists. Each is checked through the repository and through plain SQL, which
 * no repository rule stands in front of.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import {
  NotFoundError,
  SandboxPairingError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';

/** A whole policy document, as `defaultsFromEnv` gives one, with a development ceiling. */
const DEVELOPMENT_SEED_DOCUMENT = {
  tokens: {
    accessTokenLifespanSeconds: 900,
    developmentAccessTokenLifespanSeconds: 28800,
    refreshTokenLifespanSeconds: 604800,
    adminAccessTokenLifespanSeconds: 600,
  },
  registration: { dynamicRegistrationAllowedScopes: ['openid'], cimd: { enabled: true } },
  posture: { maxEnvironmentLaxity: 'development' },
  password: { minScore: 2 },
};

describe('paired sandbox realm integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: RealmsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createRealmsRepository(ctx.database.db);
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

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function unique(prefix: string): string {
    return `${prefix}-${Math.random().toString(36).slice(2)}`;
  }

  /** A live realm with an issuer on `host` and that host as its primary host. */
  async function liveRealmOn(host: string): Promise<string> {
    const { realm } = await repo.createWithPrimaryHost(
      { name: unique('live'), issuer: `https://${host}` },
      host
    );
    return realm.id;
  }

  /** The sandbox of `liveRealmId`, on `host`. */
  function sandboxOn(liveRealmId: string, host: string, repository = repo) {
    return repository.createSandboxWithPrimaryHost(
      liveRealmId,
      { name: unique('sandbox'), issuer: `https://${host}` },
      host
    );
  }

  /** The Postgres error behind a rejected promise: `code` and `constraint`. */
  async function pgError(
    promise: Promise<unknown>
  ): Promise<{ code?: string; constraint?: string }> {
    try {
      await promise;
    } catch (error) {
      let current: unknown = error;
      while (current && typeof current === 'object') {
        const candidate = current as { code?: unknown; constraint?: unknown; cause?: unknown };
        if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
          return { code: candidate.code, constraint: candidate.constraint as string | undefined };
        }
        current = candidate.cause;
      }
      throw error;
    }
    throw new Error('expected the statement to fail');
  }

  /** Insert a realm row by hand, past every repository rule. */
  function insertRealm(columns: Record<string, unknown>): Promise<unknown> {
    const names = Object.keys(columns);
    return pool().query(
      `INSERT INTO realms (name, ${names.map((name) => `"${name}"`).join(', ')})
       VALUES ($1, ${names.map((_, i) => `$${i + 2}`).join(', ')})`,
      [unique('by-hand'), ...Object.values(columns)]
    );
  }

  it('creates a sandbox in its own right: own host and issuer, paired, with the staging ceiling', async () => {
    const live = await liveRealmOn('auth.example.com');

    const { realm, host } = await sandboxOn(live, 'sandbox.auth.example.com');

    expect(realm).toMatchObject({
      sandboxOfRealmId: live,
      issuer: 'https://sandbox.auth.example.com',
      maxEnvironmentLaxity: 'staging',
      isOperator: false,
      webauthnRpId: null,
    });
    expect(host).toMatchObject({ host: 'sandbox.auth.example.com', kind: 'primary' });
    expect((await repo.findSandboxOf(live))?.id).toBe(realm.id);
    expect(await repo.findSandboxOf(realm.id)).toBeUndefined();
    expect((await repo.findByHost('sandbox.auth.example.com'))?.realm.id).toBe(realm.id);
  });

  it('gives a sandbox the staging ceiling whatever the policy seed says', async () => {
    if (!ctx) throw new Error('no ctx');
    const seeded = createRealmsRepository(ctx.database.db, {
      seeds: { policies: { document: DEVELOPMENT_SEED_DOCUMENT, schemaVersion: '1-rc.0' } },
    });
    const live = (
      await seeded.createWithPrimaryHost(
        { name: unique('live'), issuer: 'https://auth.example.com' },
        'auth.example.com'
      )
    ).realm;
    expect(live.maxEnvironmentLaxity).toBe('development');

    const { realm } = await sandboxOn(live.id, 'sandbox.example.com', seeded);

    expect(realm).toMatchObject({ maxEnvironmentLaxity: 'staging', policiesVersion: 1 });
  });

  describe('a live realm has one sandbox', () => {
    it('refuses a second sandbox, through the repository and by hand', async () => {
      const live = await liveRealmOn('auth.example.com');
      await sandboxOn(live, 'sandbox-1.example.com');

      const second = sandboxOn(live, 'sandbox-2.example.com');
      await expect(second).rejects.toBeInstanceOf(SandboxPairingError);
      await expect(second).rejects.toMatchObject({ rule: 'one_sandbox' });
      expect(await pgError(insertRealm({ sandbox_of_realm_id: live }))).toEqual({
        code: '23505',
        constraint: 'idx_realms_sandbox_of_realm_id',
      });
      // Rolled back whole: the second sandbox left no host behind.
      expect(await repo.findByHost('sandbox-2.example.com')).toBeUndefined();
    });

    it('refuses a sandbox on a host another realm has, the live realm included', async () => {
      const live = await liveRealmOn('auth.example.com');
      await repo.addEndpointHost(live, 'internal.example.com');

      // A port keeps each issuer apart from the live realm's, so the host is
      // what the database refuses.
      for (const host of [
        'auth.example.com:8443',
        'AUTH.Example.com:8443',
        'auth.example.com.:8443',
        'internal.example.com',
      ]) {
        const taken = sandboxOn(live, host);
        await expect(taken).rejects.toBeInstanceOf(UniqueConstraintError);
        await expect(taken).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
      }
      expect(await repo.findSandboxOf(live)).toBeUndefined();

      // Nor can another realm take the sandbox's host later.
      await sandboxOn(live, 'sandbox.example.com');
      await expect(
        repo.createWithPrimaryHost(
          { name: unique('late'), issuer: 'https://sandbox.example.com:8443' },
          'sandbox.example.com:8443'
        )
      ).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
    });
  });

  describe('what a sandbox can be paired with', () => {
    it('refuses a sandbox of a sandbox', async () => {
      const live = await liveRealmOn('auth.example.com');
      const { realm: sandbox } = await sandboxOn(live, 'sandbox.example.com');

      const nested = sandboxOn(sandbox.id, 'nested.example.com');
      await expect(nested).rejects.toBeInstanceOf(SandboxPairingError);
      await expect(nested).rejects.toMatchObject({ rule: 'sandbox_of_sandbox' });
      expect(await pgError(insertRealm({ sandbox_of_realm_id: sandbox.id }))).toEqual({
        code: '23514',
        constraint: 'realms_sandbox_of_sandbox',
      });
    });

    it('refuses a realm paired with itself', async () => {
      const id = '0190a000-0000-7000-8000-000000000001';
      expect(await pgError(insertRealm({ id, sandbox_of_realm_id: id }))).toEqual({
        code: '23514',
        constraint: 'realms_sandbox_not_self',
      });
    });

    it('refuses a sandbox of the operator realm', async () => {
      const operator = await liveRealmOn('admin.example.com');
      await repo.setOperator(operator, true);

      const paired = sandboxOn(operator, 'sandbox.example.com');
      await expect(paired).rejects.toBeInstanceOf(SandboxPairingError);
      await expect(paired).rejects.toMatchObject({ rule: 'operator' });
      expect(await pgError(insertRealm({ sandbox_of_realm_id: operator }))).toEqual({
        code: '23514',
        constraint: 'realms_sandbox_of_operator',
      });
    });

    it('refuses the operator flag on a sandbox and on a live realm that has one', async () => {
      const live = await liveRealmOn('auth.example.com');
      const { realm: sandbox } = await sandboxOn(live, 'sandbox.example.com');

      await expect(repo.setOperator(sandbox.id, true)).rejects.toMatchObject({
        rule: 'operator',
      });
      await expect(repo.setOperator(live, true)).rejects.toMatchObject({ rule: 'operator' });
      expect(
        await pgError(pool().query('UPDATE realms SET is_operator = true WHERE id = $1', [live]))
      ).toEqual({ code: '23514', constraint: 'realms_sandbox_of_operator' });
      expect(await repo.findOperator()).toBeUndefined();
    });

    it('refuses a live realm that does not exist', async () => {
      const missing = '0190a000-0000-7000-8000-0000000000ff';
      await expect(sandboxOn(missing, 'sandbox.example.com')).rejects.toBeInstanceOf(NotFoundError);
      expect(await pgError(insertRealm({ sandbox_of_realm_id: missing }))).toEqual({
        code: '23503',
        constraint: 'realms_sandbox_of_realm_id_realms_id_fk',
      });
    });

    it('refuses a live realm a later row of the same statement inserts', async () => {
      // The foreign key checks at the end of the statement; the trigger
      // refuses at the row, so no row pairs with a realm it cannot read.
      const live = await liveRealmOn('auth.example.com');
      const first = '0190a000-0000-7000-8000-0000000000a1';
      const second = '0190a000-0000-7000-8000-0000000000a2';
      const twoRows = (rows: readonly (readonly [string, string | null, boolean])[]) =>
        pool().query(
          `INSERT INTO realms (id, name, sandbox_of_realm_id, is_operator)
           VALUES ($1, $2, $3, $4), ($5, $6, $7, $8)`,
          rows.flatMap(([id, sandboxOf, isOperator]) => [
            id,
            unique('by-hand'),
            sandboxOf,
            isOperator,
          ])
        );

      // A sandbox of a sandbox, the inner pairing written second.
      expect(
        await pgError(
          twoRows([
            [second, first, false],
            [first, live, false],
          ])
        )
      ).toEqual({ code: '23503', constraint: 'realms_sandbox_of_realm_id_realms_id_fk' });
      // A sandbox of the operator realm, the operator realm written second.
      expect(
        await pgError(
          twoRows([
            [second, first, false],
            [first, null, true],
          ])
        )
      ).toEqual({ code: '23503', constraint: 'realms_sandbox_of_realm_id_realms_id_fk' });
      // Written first, the operator realm is read, and refused as one.
      expect(
        await pgError(
          twoRows([
            [first, null, true],
            [second, first, false],
          ])
        )
      ).toEqual({ code: '23514', constraint: 'realms_sandbox_of_operator' });
      expect(await repo.findById(first)).toBeUndefined();
      expect(await repo.findById(second)).toBeUndefined();

      // Written first, a realm that is no sandbox is a live realm like any.
      await twoRows([
        [first, null, false],
        [second, first, false],
      ]);
      expect((await repo.findSandboxOf(first))?.id).toBe(second);
    });
  });

  it('keeps the pairing as it was created: never set later, moved or cleared', async () => {
    const live = await liveRealmOn('auth.example.com');
    const other = await liveRealmOn('other.example.com');
    const standalone = await liveRealmOn('standalone.example.com');
    const { realm: sandbox } = await sandboxOn(live, 'sandbox.example.com');

    for (const [id, value] of [
      [standalone, live],
      [sandbox.id, other],
      [sandbox.id, null],
    ] as const) {
      expect(
        await pgError(
          pool().query('UPDATE realms SET sandbox_of_realm_id = $2 WHERE id = $1', [id, value])
        )
      ).toEqual({ code: '23514', constraint: 'realms_sandbox_pairing_permanent' });
    }

    // The repository's update drops the pairing, even from an untyped caller.
    const updated = await repo.update(sandbox.id, {
      name: 'renamed',
      sandboxOfRealmId: other,
    } as never);
    expect(updated).toMatchObject({ name: 'renamed', sandboxOfRealmId: live });
    // Its create does too: a sandbox is made by createSandboxWithPrimaryHost alone.
    const created = await repo.create({ name: unique('plain'), sandboxOfRealmId: live } as never);
    expect(created.sandboxOfRealmId).toBeNull();
  });

  describe("a sandbox's ceiling is never development", () => {
    it('refuses it through writePolicies and by hand', async () => {
      const live = await liveRealmOn('auth.example.com');
      const { realm: sandbox } = await sandboxOn(live, 'sandbox.example.com');
      const document = {
        ...DEVELOPMENT_SEED_DOCUMENT,
        posture: { maxEnvironmentLaxity: 'development' },
      };

      const written = repo.writePolicies(sandbox.id, {
        document,
        schemaVersion: '1-rc.0',
        expectedVersion: sandbox.policiesVersion,
      });
      await expect(written).rejects.toBeInstanceOf(SandboxPairingError);
      await expect(written).rejects.toMatchObject({ rule: 'ceiling' });
      expect(
        await pgError(
          pool().query(`UPDATE realms SET max_environment_laxity = 'development' WHERE id = $1`, [
            sandbox.id,
          ])
        )
      ).toEqual({ code: '23514', constraint: 'realms_sandbox_ceiling' });
      expect(
        await pgError(
          insertRealm({ sandbox_of_realm_id: live, max_environment_laxity: 'development' })
        )
      ).toEqual({ code: '23514', constraint: 'realms_sandbox_ceiling' });

      // Staging and production stay allowed, and a live realm may be development.
      await pool().query(`UPDATE realms SET max_environment_laxity = 'production' WHERE id = $1`, [
        sandbox.id,
      ]);
      const liveWrite = await repo.writePolicies(live, {
        document,
        schemaVersion: '1-rc.0',
        expectedVersion: 0,
      });
      expect(liveWrite?.maxEnvironmentLaxity).toBe('development');
    });
  });

  describe('deleting a paired realm', () => {
    it('refuses deleting a live realm while its sandbox exists, through the repository and by hand', async () => {
      const live = await liveRealmOn('auth.example.com');
      const { realm: sandbox } = await sandboxOn(live, 'sandbox.example.com');

      const deleted = repo.delete(live);
      await expect(deleted).rejects.toBeInstanceOf(SandboxPairingError);
      await expect(deleted).rejects.toMatchObject({ rule: 'live_realm_has_sandbox' });
      expect(await pgError(pool().query('DELETE FROM realms WHERE id = $1', [live]))).toEqual({
        code: '23503',
        constraint: 'realms_sandbox_of_realm_id_realms_id_fk',
      });
      expect(await repo.findById(live)).toBeDefined();

      // The sandbox goes first; then the live realm can.
      expect(await repo.delete(sandbox.id)).toBe(true);
      expect(await repo.delete(live)).toBe(true);
    });
  });
});
