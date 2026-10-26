/**
 * Real-Postgres integration tests for admin roles and grants (issue #510,
 * ADR-019 Decision 7).
 *
 * The realm rule is held twice: by the repository before it writes, and by
 * the trigger `admin_grants_realm_rule` for a row written any other way. Each
 * refusal is checked both ways, the trigger with raw SQL. The other DDL rules
 * (one role per grant, one live grant per account, role and target, the name
 * grammar, the restricting foreign key) and the repository reads are
 * exercised on top.
 *
 * The catalog is a fixture: the auth server's permission catalog lives in the
 * app, which hands its own to the database plugin.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { type AdminGrantsRepository, createAdminGrantsRepository } from './admin-grants.repository';
import {
  type AdminRoleCatalog,
  type AdminRolesRepository,
  createAdminRolesRepository,
} from './admin-roles.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';
import { createUsersRepository, type UsersRepository } from './users.repository';

const CATALOG_ORDER = [
  'realms.read',
  'realms.policies.write',
  'realms.policies.security',
  'approvals.approve',
];
const RETIRED = ['realms.legacy.read'];
const BUILT_IN = ['viewer', 'editor', 'security-admin'];

/** A stand-in for the auth server's catalog: the same shape and outcomes. */
const catalog: AdminRoleCatalog = {
  builtInRoleNames: BUILT_IN,
  isBuiltInRoleName: (name) =>
    BUILT_IN.includes(
      name
        .trim()
        .toLowerCase()
        .replace(/[\s_]+/g, '-')
    ),
  validatePermissionIds(ids) {
    const unknownIds = ids.filter((id) => !CATALOG_ORDER.includes(id) && !RETIRED.includes(id));
    const retiredIds = ids.filter((id) => RETIRED.includes(id));
    if (unknownIds.length > 0 || retiredIds.length > 0) {
      return { valid: false, unknownIds, retiredIds };
    }
    return { valid: true, permissionIds: CATALOG_ORDER.filter((id) => ids.includes(id)) };
  },
};

describe('admin roles and grants (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let roles: AdminRolesRepository;
  let grants: AdminGrantsRepository;
  let realms: RealmsRepository;
  let users: UsersRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    roles = createAdminRolesRepository(ctx.database.db, { catalog });
    grants = createAdminGrantsRepository(ctx.database.db, { catalog });
    realms = createRealmsRepository(ctx.database.db);
    users = createUsersRepository(ctx.database.db);
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

  async function realm(name: string, isOperator = false): Promise<string> {
    const row = await realms.create({ name, isOperator });
    return row.id;
  }

  async function account(realmId: string): Promise<string> {
    const row = await users.create({ realmId });
    return row.id;
  }

  /** The Postgres error behind a rejected promise: `code` and `constraint`. */
  async function pgError(
    promise: Promise<unknown>
  ): Promise<{ code?: string; constraint?: string }> {
    try {
      await promise;
    } catch (error) {
      const { code, constraint } = error as { code?: string; constraint?: string };
      return { code, constraint };
    }
    throw new Error('expected the statement to fail');
  }

  /** Insert a grant by hand, past the repository. */
  function rawGrant(
    userId: string,
    target: string | null,
    role: { builtIn: string } | { roleId: string } = { builtIn: 'viewer' }
  ) {
    return pool().query(
      `INSERT INTO admin_grants (user_id, built_in_role, role_id, target_realm_id)
       VALUES ($1, $2, $3, $4)`,
      [
        userId,
        'builtIn' in role ? role.builtIn : null,
        'roleId' in role ? role.roleId : null,
        target,
      ]
    );
  }

  /** A setup with an operator realm, two tenant realms and an account in each. */
  async function deployment() {
    const operator = await realm('operator', true);
    const a = await realm('tenant-a');
    const b = await realm('tenant-b');
    return {
      operator,
      a,
      b,
      operatorAdmin: await account(operator),
      adminOfA: await account(a),
    };
  }

  describe('the realm rule', () => {
    it('lets an operator-realm account hold a grant on every realm and on any one realm', async () => {
      const d = await deployment();
      const all = await grants.create({
        userId: d.operatorAdmin,
        role: { kind: 'built-in', name: 'viewer' },
        targetRealmId: null,
        createdBy: null,
      });
      expect(all).toMatchObject({ targetRealmId: null, builtInRole: 'viewer', revokedAt: null });
      for (const target of [d.a, d.b, d.operator]) {
        await expect(
          grants.create({
            userId: d.operatorAdmin,
            role: { kind: 'built-in', name: 'editor' },
            targetRealmId: target,
            createdBy: d.operatorAdmin,
          })
        ).resolves.toMatchObject({ targetRealmId: target, createdBy: d.operatorAdmin });
      }
    });

    it('refuses a grant on every realm for a non-operator account, in the repository and in the trigger', async () => {
      const d = await deployment();
      await expect(
        grants.create({
          userId: d.adminOfA,
          role: { kind: 'built-in', name: 'viewer' },
          targetRealmId: null,
          createdBy: null,
        })
      ).rejects.toThrow(BadRequestError);
      await expect(pgError(rawGrant(d.adminOfA, null))).resolves.toEqual({
        code: '23514',
        constraint: 'admin_grants_all_realms_operator_only',
      });
      expect(await grants.listByUser(d.adminOfA)).toEqual([]);
    });

    it("keeps a realm-local account's grants on its own realm, in the repository and in the trigger", async () => {
      const d = await deployment();
      await expect(
        grants.create({
          userId: d.adminOfA,
          role: { kind: 'built-in', name: 'viewer' },
          targetRealmId: d.a,
          createdBy: null,
        })
      ).resolves.toMatchObject({ targetRealmId: d.a });
      for (const target of [d.b, d.operator]) {
        await expect(
          grants.create({
            userId: d.adminOfA,
            role: { kind: 'built-in', name: 'editor' },
            targetRealmId: target,
            createdBy: null,
          })
        ).rejects.toThrow(/own realm only/);
        await expect(pgError(rawGrant(d.adminOfA, target))).resolves.toEqual({
          code: '23514',
          constraint: 'admin_grants_target_own_realm',
        });
      }
      // An UPDATE that moves a grant to another realm meets the trigger too.
      await expect(
        pgError(
          pool().query(`UPDATE admin_grants SET target_realm_id = $1 WHERE user_id = $2`, [
            d.b,
            d.adminOfA,
          ])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_grants_target_own_realm' });
    });

    it('names a custom role only for an account of its realm or a grant on its realm', async () => {
      const d = await deployment();
      const roleOfA = await roles.create({
        realmId: d.a,
        name: 'helpdesk',
        permissionIds: ['realms.read'],
      });
      const roleOfB = await roles.create({
        realmId: d.b,
        name: 'helpdesk',
        permissionIds: ['realms.read'],
      });
      const operatorRole = await roles.create({
        realmId: d.operator,
        name: 'support',
        permissionIds: ['realms.read'],
      });

      // Realm A's account with realm A's role; an operator with realm A's
      // role on realm A, or the operator realm's role on any target.
      const allowed = [
        { userId: d.adminOfA, roleId: roleOfA.id, target: d.a },
        { userId: d.operatorAdmin, roleId: roleOfA.id, target: d.a },
        { userId: d.operatorAdmin, roleId: operatorRole.id, target: d.b },
        { userId: d.operatorAdmin, roleId: operatorRole.id, target: null },
      ];
      for (const { userId, roleId, target } of allowed) {
        await expect(
          grants.create({
            userId,
            role: { kind: 'custom', roleId },
            targetRealmId: target,
            createdBy: null,
          })
        ).resolves.toMatchObject({ roleId, targetRealmId: target });
      }

      const refused = [
        { userId: d.adminOfA, roleId: roleOfB.id, target: d.a },
        { userId: d.operatorAdmin, roleId: roleOfB.id, target: d.a },
        { userId: d.operatorAdmin, roleId: roleOfA.id, target: null },
      ];
      for (const { userId, roleId, target } of refused) {
        await expect(
          grants.create({
            userId,
            role: { kind: 'custom', roleId },
            targetRealmId: target,
            createdBy: null,
          })
        ).rejects.toThrow(/its realm/);
        await expect(pgError(rawGrant(userId, target, { roleId }))).resolves.toEqual({
          code: '23514',
          constraint: 'admin_grants_role_realm',
        });
      }
    });

    it('refuses an account, a target or a role that does not exist, and a malformed id', async () => {
      const d = await deployment();
      const missing = '01900000-0000-7000-8000-000000000000';
      const cases = [
        { userId: missing, targetRealmId: d.a },
        { userId: d.operatorAdmin, targetRealmId: missing },
        { userId: 'not-a-uuid', targetRealmId: d.a },
        { userId: d.operatorAdmin, targetRealmId: 'not-a-uuid' },
      ];
      for (const { userId, targetRealmId } of cases) {
        await expect(
          grants.create({
            userId,
            role: { kind: 'built-in', name: 'viewer' },
            targetRealmId,
            createdBy: null,
          })
        ).rejects.toThrow(BadRequestError);
      }
      await expect(
        grants.create({
          userId: d.operatorAdmin,
          role: { kind: 'custom', roleId: missing },
          targetRealmId: d.a,
          createdBy: null,
        })
      ).rejects.toThrow(/custom role that exists/);
    });
  });

  describe('one operator realm', () => {
    it('refuses a second is_operator realm in the database', async () => {
      await realm('operator', true);
      await expect(
        pgError(pool().query(`INSERT INTO realms (name, is_operator) VALUES ('second', true)`))
      ).resolves.toEqual({ code: '23505', constraint: 'idx_realms_one_operator' });
    });
  });

  describe('the role a grant names', () => {
    it('takes a built-in role only by its exact catalog name', async () => {
      const d = await deployment();
      for (const name of ['Viewer', 'admin', 'security_admin']) {
        await expect(
          grants.create({
            userId: d.operatorAdmin,
            role: { kind: 'built-in', name },
            targetRealmId: d.a,
            createdBy: null,
          })
        ).rejects.toThrow(/not a built-in admin role/);
      }
    });

    it('holds exactly one role, by the CHECK', async () => {
      const d = await deployment();
      const role = await roles.create({ realmId: d.a, name: 'ops', permissionIds: [] });
      await expect(
        pgError(
          pool().query(
            `INSERT INTO admin_grants (user_id, built_in_role, role_id, target_realm_id)
             VALUES ($1, 'viewer', $2, $3)`,
            [d.adminOfA, role.id, d.a]
          )
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_grants_one_role' });
      await expect(
        pgError(
          pool().query(`INSERT INTO admin_grants (user_id, target_realm_id) VALUES ($1, $2)`, [
            d.adminOfA,
            d.a,
          ])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_grants_one_role' });
    });

    it('refuses a disabled custom role, and keeps a granted role from being deleted', async () => {
      const d = await deployment();
      const role = await roles.create({
        realmId: d.a,
        name: 'ops',
        permissionIds: ['realms.read'],
      });
      await grants.create({
        userId: d.adminOfA,
        role: { kind: 'custom', roleId: role.id },
        targetRealmId: d.a,
        createdBy: null,
      });
      await expect(
        pgError(pool().query(`DELETE FROM admin_roles WHERE id = $1`, [role.id]))
      ).resolves.toEqual({ code: '23503', constraint: 'admin_grants_role_id_admin_roles_id_fk' });

      await roles.update(d.a, role.id, { disabled: true });
      await expect(
        grants.create({
          userId: d.operatorAdmin,
          role: { kind: 'custom', roleId: role.id },
          targetRealmId: d.a,
          createdBy: null,
        })
      ).rejects.toThrow(/disabled/);
    });
  });

  describe('deleting', () => {
    it('removes a realm with its roles and every grant that names them or targets it', async () => {
      const d = await deployment();
      const role = await roles.create({
        realmId: d.a,
        name: 'ops',
        permissionIds: ['realms.read'],
      });
      await grants.create({
        userId: d.operatorAdmin,
        role: { kind: 'custom', roleId: role.id },
        targetRealmId: d.a,
        createdBy: null,
      });
      const kept = await grants.create({
        userId: d.operatorAdmin,
        role: { kind: 'built-in', name: 'viewer' },
        targetRealmId: d.b,
        createdBy: d.adminOfA,
      });

      await expect(realms.delete(d.a)).resolves.toBe(true);
      expect(await grants.listByUser(d.operatorAdmin)).toEqual([{ ...kept, createdBy: null }]);
      const { rows } = await pool().query(`SELECT count(*)::int AS n FROM admin_roles`);
      expect(rows).toEqual([{ n: 0 }]);
    });
  });

  describe('live grants', () => {
    it('refuses a second live grant of the same role and target, and allows it again once revoked', async () => {
      const d = await deployment();
      const input = {
        userId: d.operatorAdmin,
        role: { kind: 'built-in', name: 'viewer' } as const,
        targetRealmId: d.a,
        createdBy: null,
      };
      const first = await grants.create(input);
      const again = grants.create(input);
      await expect(again).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(again).rejects.toMatchObject({ constraint: 'idx_admin_grants_live_unique' });
      // The same role on every realm is another grant.
      await grants.create({ ...input, targetRealmId: null });

      const revoked = await grants.revoke(first.id);
      expect(revoked?.revokedAt).toEqual(expect.any(Number));
      expect(revoked?.lastSecurityChangeAt).toBe(revoked?.revokedAt);
      expect(await grants.revoke(first.id)).toBeUndefined();
      await expect(grants.create(input)).resolves.toMatchObject({ revokedAt: null });
      expect(await grants.listByUser(d.operatorAdmin)).toHaveLength(3);
    });

    it('lists only grants that give their role now: not revoked, and the custom role enabled', async () => {
      const d = await deployment();
      const ops = await roles.create({
        realmId: d.a,
        name: 'ops',
        permissionIds: ['realms.policies.write', 'realms.read'],
      });
      const builtIn = await grants.create({
        userId: d.adminOfA,
        role: { kind: 'built-in', name: 'viewer' },
        targetRealmId: d.a,
        createdBy: null,
      });
      const custom = await grants.create({
        userId: d.adminOfA,
        role: { kind: 'custom', roleId: ops.id },
        targetRealmId: d.a,
        createdBy: null,
      });

      const live = await grants.listLive(d.adminOfA);
      expect(live.map(({ grant, role }) => [grant.id, role?.id ?? null])).toEqual([
        [builtIn.id, null],
        [custom.id, ops.id],
      ]);
      expect(live[1].role?.permissionIds).toEqual(['realms.read', 'realms.policies.write']);

      await roles.update(d.a, ops.id, { disabled: true });
      expect((await grants.listLive(d.adminOfA)).map(({ grant }) => grant.id)).toEqual([
        builtIn.id,
      ]);
      await roles.update(d.a, ops.id, { disabled: false });
      await grants.revoke(builtIn.id);
      expect((await grants.listLive(d.adminOfA)).map(({ grant }) => grant.id)).toEqual([custom.id]);
      expect(await grants.listLive('not-a-uuid')).toEqual([]);
    });
  });

  describe('custom roles', () => {
    it('stores the permission ids once each, in catalog order', async () => {
      const realmId = await realm('tenant');
      const role = await roles.create({
        realmId,
        name: 'realm-auditor',
        permissionIds: ['approvals.approve', 'realms.read', 'approvals.approve'],
      });
      expect(role).toMatchObject({
        name: 'realm-auditor',
        permissionIds: ['realms.read', 'approvals.approve'],
        disabledAt: null,
      });
      expect(await roles.findById(realmId, role.id)).toEqual(role);
      expect(await roles.listByRealm(realmId)).toEqual([role]);
    });

    it('refuses unknown and retired permission ids, and writes nothing', async () => {
      const realmId = await realm('tenant');
      for (const permissionIds of [['realms.read', 'nope.read'], RETIRED]) {
        await expect(roles.create({ realmId, name: 'ops', permissionIds })).rejects.toThrow(
          BadRequestError
        );
      }
      expect(await roles.listByRealm(realmId)).toEqual([]);
    });

    it('refuses a name outside the grammar or one that reads as a built-in role', async () => {
      const realmId = await realm('tenant');
      for (const name of [
        'Ops',
        'ops team',
        '-ops',
        'ops--team',
        'ops_team',
        'ops-',
        '1ops',
        'öps',
        'a'.repeat(65),
        '',
      ]) {
        await expect(roles.create({ realmId, name, permissionIds: [] })).rejects.toThrow(
          /lower-case ASCII/
        );
      }
      for (const name of BUILT_IN) {
        await expect(roles.create({ realmId, name, permissionIds: [] })).rejects.toThrow(
          /built-in admin role/
        );
      }
      // The CHECK holds the grammar for a row written by hand.
      await expect(
        pgError(
          pool().query(`INSERT INTO admin_roles (realm_id, name) VALUES ($1, 'Ops')`, [realmId])
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_roles_name_grammar' });
      await expect(
        pgError(
          pool().query(
            `INSERT INTO admin_roles (realm_id, name, permission_ids) VALUES ($1, 'ops', '[1]')`,
            [realmId]
          )
        )
      ).resolves.toEqual({ code: '23514', constraint: 'admin_roles_permission_ids_strings' });
    });

    it('keeps names unique per realm, not across realms', async () => {
      const a = await realm('tenant-a');
      const b = await realm('tenant-b');
      await roles.create({ realmId: a, name: 'ops', permissionIds: [] });
      await expect(
        roles.create({ realmId: b, name: 'ops', permissionIds: [] })
      ).resolves.toBeTruthy();
      await expect(
        roles.create({ realmId: a, name: 'ops', permissionIds: [] })
      ).rejects.toMatchObject({ constraint: 'admin_roles_realm_name_unique' });
    });

    it("finds and changes a role only through its own realm's id", async () => {
      const a = await realm('tenant-a');
      const b = await realm('tenant-b');
      const role = await roles.create({ realmId: a, name: 'ops', permissionIds: [] });
      expect(await roles.findById(b, role.id)).toBeUndefined();
      expect(await roles.update(b, role.id, { disabled: true })).toBeUndefined();
      expect((await roles.findById(a, role.id))?.disabledAt).toBeNull();
    });

    it('moves last_security_change_at of its live grants when what it gives changes', async () => {
      const d = await deployment();
      const role = await roles.create({
        realmId: d.a,
        name: 'ops',
        permissionIds: ['realms.read'],
      });
      const live = await grants.create({
        userId: d.adminOfA,
        role: { kind: 'custom', roleId: role.id },
        targetRealmId: d.a,
        createdBy: null,
      });
      const revoked = await grants.create({
        userId: d.operatorAdmin,
        role: { kind: 'custom', roleId: role.id },
        targetRealmId: d.a,
        createdBy: null,
      });
      await grants.revoke(revoked.id);
      const setOld = () =>
        pool().query(
          `UPDATE admin_grants SET created_at = 1000, last_security_change_at = 1000
           WHERE role_id = $1 AND revoked_at IS NULL`,
          [role.id]
        );
      const changedAt = async (grantId: string) =>
        (await grants.findById(grantId))?.lastSecurityChangeAt;

      // No change: same ids in another order, the state it already has.
      await setOld();
      await roles.update(d.a, role.id, { permissionIds: ['realms.read'], disabled: false });
      expect(await changedAt(live.id)).toBe(1000);

      for (const changes of [
        { permissionIds: ['realms.read', 'approvals.approve'] },
        { disabled: true },
        { disabled: false },
      ]) {
        await setOld();
        const before = Date.now();
        await roles.update(d.a, role.id, changes);
        expect(await changedAt(live.id)).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000);
      }
      // A revoked grant keeps the time of its revocation.
      const revokedRow = await grants.findById(revoked.id);
      expect(revokedRow?.lastSecurityChangeAt).toBe(revokedRow?.revokedAt);
    });

    it('refuses to write without a catalog, and still reads', async () => {
      if (!ctx) throw new Error('no ctx');
      const bare = createAdminRolesRepository(ctx.database.db);
      const bareGrants = createAdminGrantsRepository(ctx.database.db);
      const d = await deployment();
      await expect(bare.create({ realmId: d.a, name: 'ops', permissionIds: [] })).rejects.toThrow(
        /No admin role catalog/
      );
      await expect(
        bareGrants.create({
          userId: d.adminOfA,
          role: { kind: 'built-in', name: 'viewer' },
          targetRealmId: d.a,
          createdBy: null,
        })
      ).rejects.toThrow(/No admin role catalog/);
      const role = await roles.create({ realmId: d.a, name: 'ops', permissionIds: [] });
      expect(await bare.findById(d.a, role.id)).toEqual(role);
      await expect(bare.update(d.a, role.id, { disabled: true })).rejects.toThrow(
        /No admin role catalog/
      );
    });
  });
});
