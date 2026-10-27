import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

// admin-issuance → client-auth → client-resolution → cimd pulls in the env
// module; stub it so the env-schema parse (which needs DB vars) does not run.
vi.mock('../../config/env', () => ({ env: {} }));

import { API_FAMILY_AUDIENCES } from '../api-conventions/families';
import type { LiveAdminGrant } from './admin-authority';
import { adminIssuance } from './admin-issuance';
import { withoutAdminAudience } from './admin-scopes';

const ADMIN = API_FAMILY_AUDIENCES.admin;
const OPERATOR = '01900000-0000-7000-8000-00000000000a';
const REALM_A = '01900000-0000-7000-8000-0000000000a1';
const REALM_B = '01900000-0000-7000-8000-0000000000b1';
const USER = '01900000-0000-7000-8000-000000000001';

const ALL_ADMIN_SCOPES = ['qauth:admin:read', 'qauth:admin:write', 'qauth:admin:security'];

function grant(
  targetRealmId: string | null,
  role: string | { realmId: string; permissionIds: string[] }
): LiveAdminGrant {
  return {
    grant: {
      id: `${targetRealmId}-${JSON.stringify(role)}`,
      userId: USER,
      builtInRole: typeof role === 'string' ? role : null,
      roleId: typeof role === 'string' ? null : 'role-id',
      targetRealmId,
      createdBy: null,
      createdAt: 0,
      revokedAt: null,
      lastSecurityChangeAt: 0,
    },
    role:
      typeof role === 'string'
        ? null
        : {
            id: 'role-id',
            name: 'custom',
            disabledAt: null,
            createdAt: 0,
            updatedAt: 0,
            ...role,
          },
  };
}

function server(
  grants: LiveAdminGrant[],
  user: { realmId: string; enabled: boolean } = { realmId: OPERATOR, enabled: true }
) {
  const fastify = {
    repositories: {
      // Realm-first (#489): the account is found only in its own realm.
      users: {
        findById: vi.fn(async (realmId: string, id: string) =>
          realmId === user.realmId && id === USER ? { id: USER, ...user } : undefined
        ),
      },
      realms: {
        findById: vi.fn(async (id: string) => ({ id, isOperator: id === OPERATOR })),
      },
      adminGrants: { listLive: vi.fn(async () => grants) },
    },
  };
  return fastify as unknown as FastifyInstance & typeof fastify;
}

/** An operator-provisioned client that lists the admin audience. */
const ADMIN_CLIENT = { audience: [ADMIN], metadata: null, dynamicRegisteredAt: null };

describe('adminIssuance', () => {
  it('reads nothing for a token with no qauth: scope and no admin audience', async () => {
    const fastify = server([]);
    await expect(
      adminIssuance(fastify, {
        realmId: OPERATOR,
        client: ADMIN_CLIENT,
        userId: USER,
        scopes: ['openid', 'admin:org'],
        aud: ['https://api.example.com', API_FAMILY_AUDIENCES.account],
      })
    ).resolves.toEqual({ scopes: ['openid', 'admin:org'], withheld: [], audienceRefused: false });
    expect(fastify.repositories.users.findById).not.toHaveBeenCalled();
    expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();
  });

  it('withholds the scopes of the classes the grants do not reach, and keeps the rest in order', async () => {
    const fastify = server([grant(REALM_A, 'viewer')]);
    await expect(
      adminIssuance(fastify, {
        realmId: OPERATOR,
        client: ADMIN_CLIENT,
        userId: USER,
        scopes: ['openid', ...ALL_ADMIN_SCOPES, 'profile'],
        aud: ADMIN,
      })
    ).resolves.toEqual({
      scopes: ['openid', 'qauth:admin:read', 'profile'],
      withheld: ['qauth:admin:write', 'qauth:admin:security'],
      audienceRefused: false,
    });
  });

  it('issues every class a security-admin grant reaches, on any target', async () => {
    const fastify = server([grant(null, 'security-admin')]);
    const decision = await adminIssuance(fastify, {
      realmId: OPERATOR,
      client: ADMIN_CLIENT,
      userId: USER,
      scopes: ALL_ADMIN_SCOPES,
      aud: ADMIN,
    });
    expect(decision).toEqual({ scopes: ALL_ADMIN_SCOPES, withheld: [], audienceRefused: false });
  });

  it("reads a custom role's permissions for its classes", async () => {
    const fastify = server([
      grant(REALM_B, { realmId: OPERATOR, permissionIds: ['approvals.approve'] }),
    ]);
    const decision = await adminIssuance(fastify, {
      realmId: OPERATOR,
      client: ADMIN_CLIENT,
      userId: USER,
      scopes: ALL_ADMIN_SCOPES,
      aud: ADMIN,
    });
    expect(decision.scopes).toEqual(['qauth:admin:security']);
  });

  it('refuses the admin audience and withholds every admin scope for an account with no grant', async () => {
    const fastify = server([]);
    await expect(
      adminIssuance(fastify, {
        realmId: OPERATOR,
        client: ADMIN_CLIENT,
        userId: USER,
        scopes: ['openid', ...ALL_ADMIN_SCOPES],
        aud: [ADMIN],
      })
    ).resolves.toEqual({
      scopes: ['openid'],
      withheld: ALL_ADMIN_SCOPES,
      audienceRefused: true,
    });
  });

  it('refuses the admin audience for grants whose roles give no permission', async () => {
    const fastify = server([
      grant(null, { realmId: OPERATOR, permissionIds: [] }),
      grant(REALM_A, 'retired-built-in'),
    ]);
    await expect(
      adminIssuance(fastify, {
        client: ADMIN_CLIENT,
        realmId: OPERATOR,
        userId: USER,
        scopes: ['openid'],
        aud: ADMIN,
      })
    ).resolves.toMatchObject({ scopes: ['openid'], audienceRefused: true });
  });

  it('gives nothing to a token that names no account', async () => {
    const fastify = server([grant(null, 'security-admin')]);
    await expect(
      adminIssuance(fastify, {
        realmId: OPERATOR,
        client: ADMIN_CLIENT,
        userId: null,
        scopes: ['read:foo', ...ALL_ADMIN_SCOPES],
        aud: ADMIN,
      })
    ).resolves.toEqual({
      scopes: ['read:foo'],
      withheld: ALL_ADMIN_SCOPES,
      audienceRefused: true,
    });
    expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();
  });

  it('gives nothing to a disabled account', async () => {
    const fastify = server([grant(null, 'security-admin')], { realmId: OPERATOR, enabled: false });
    const decision = await adminIssuance(fastify, {
      realmId: OPERATOR,
      client: ADMIN_CLIENT,
      userId: USER,
      scopes: ALL_ADMIN_SCOPES,
      aud: ADMIN,
    });
    expect(decision).toMatchObject({ scopes: [], audienceRefused: true });
  });

  it('withholds admin scopes from a client that does not list the admin audience, or registered itself', async () => {
    const fastify = server([grant(null, 'security-admin')]);
    for (const client of [
      { audience: [API_FAMILY_AUDIENCES.account], metadata: null, dynamicRegisteredAt: null },
      { audience: null, metadata: null, dynamicRegisteredAt: null },
      { audience: [ADMIN], metadata: { registrationType: 'dynamic' }, dynamicRegisteredAt: null },
      { audience: [ADMIN], metadata: null, dynamicRegisteredAt: 1 },
    ]) {
      const decision = await adminIssuance(fastify, {
        realmId: OPERATOR,
        client,
        userId: USER,
        scopes: ALL_ADMIN_SCOPES,
        aud: 'https://api.example.com',
      });
      expect(decision).toEqual({ scopes: [], withheld: ALL_ADMIN_SCOPES, audienceRefused: false });
    }
  });

  it('never issues a qauth: scope that is not an admin scope', async () => {
    const fastify = server([grant(null, 'security-admin')]);
    const odd = ['qauth:other', 'QAuth:admin:read', 'qauth:admin:READ', 'qauth:admin:read '];
    const decision = await adminIssuance(fastify, {
      realmId: OPERATOR,
      client: ADMIN_CLIENT,
      userId: USER,
      scopes: odd,
      aud: ADMIN,
    });
    expect(decision).toEqual({ scopes: [], withheld: odd, audienceRefused: false });
  });

  it("counts only the grants that fit the realm rule for the account's realm", async () => {
    // A realm-local account holding grants the realm rule refuses (the
    // operator flag moved since they were written): nothing counts.
    const fastify = server([grant(null, 'security-admin'), grant(REALM_B, 'editor')], {
      realmId: REALM_A,
      enabled: true,
    });
    await expect(
      adminIssuance(fastify, {
        realmId: REALM_A,
        client: ADMIN_CLIENT,
        userId: USER,
        scopes: ALL_ADMIN_SCOPES,
        aud: ADMIN,
      })
    ).resolves.toMatchObject({ scopes: [], audienceRefused: true });
  });

  it("reads the account and its grants in the request's realm only (#489)", async () => {
    const fastify = server([grant(null, 'security-admin')]);
    await expect(
      adminIssuance(fastify, {
        client: ADMIN_CLIENT,
        realmId: REALM_A,
        userId: USER,
        scopes: ALL_ADMIN_SCOPES,
        aud: ADMIN,
      })
    ).resolves.toMatchObject({ scopes: [], audienceRefused: true });
    expect(fastify.repositories.users.findById).toHaveBeenCalledWith(REALM_A, USER);
    expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();

    await adminIssuance(fastify, {
      client: ADMIN_CLIENT,
      realmId: OPERATOR,
      userId: USER,
      scopes: ALL_ADMIN_SCOPES,
      aud: ADMIN,
    });
    expect(fastify.repositories.adminGrants.listLive).toHaveBeenCalledWith(OPERATOR, USER);
  });
});

describe('withoutAdminAudience', () => {
  it("drops the admin API's audience, and falls back to the client id", () => {
    expect(withoutAdminAudience([ADMIN, 'https://api.example.com'], 'system')).toBe(
      'https://api.example.com'
    );
    expect(withoutAdminAudience(ADMIN, 'system')).toBe('system');
    expect(withoutAdminAudience(['a', 'b'], 'system')).toEqual(['a', 'b']);
  });
});
