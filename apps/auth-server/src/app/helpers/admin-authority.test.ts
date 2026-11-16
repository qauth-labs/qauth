import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  adminAuthorityError,
  type AdminAuthorityRequest,
  adminIssuerResolver,
  deploymentIssuerKeyResolver,
  deploymentRealmIssuerDirectory,
  grantFitsRealmRule,
  type IssuerKeyResolver,
  type IssuerRealm,
  type LiveAdminGrant,
  resolveAdminAuthority,
} from './admin-authority';
import { PERMISSION_REGISTRY } from './admin-permissions';
import { BUILT_IN_ROLES } from './admin-roles';
import { ADMIN_SCOPES } from './admin-scopes';

const ISSUER = 'https://auth.example.com';
const OPERATOR = '01900000-0000-7000-8000-00000000000a';
const REALM_A = '01900000-0000-7000-8000-0000000000a1';
const REALM_B = '01900000-0000-7000-8000-0000000000b1';
const MISSING = '01900000-0000-7000-8000-0000000000ff';
const OPERATOR_ADMIN = '01900000-0000-7000-8000-000000000001';
const ADMIN_OF_A = '01900000-0000-7000-8000-000000000002';
/** A service account's account (#522), in the operator realm. */
const ROBOT = '01900000-0000-7000-8000-000000000003';

function realmRow(id: string, extra: Partial<IssuerRealm> = {}): IssuerRealm {
  return {
    id,
    name: id,
    enabled: true,
    isOperator: false,
    issuer: `https://${id}.example.com`,
    ...extra,
  } as IssuerRealm;
}

const REALMS: Record<string, IssuerRealm> = {
  [OPERATOR]: realmRow(OPERATOR, { isOperator: true, issuer: ISSUER }),
  [REALM_A]: realmRow(REALM_A),
  [REALM_B]: realmRow(REALM_B),
};

const USERS: Record<
  string,
  {
    id: string;
    realmId: string;
    enabled: boolean;
    notValidBefore?: number | null;
    isServiceAccount?: boolean;
  }
> = {
  [OPERATOR_ADMIN]: { id: OPERATOR_ADMIN, realmId: OPERATOR, enabled: true },
  [ADMIN_OF_A]: { id: ADMIN_OF_A, realmId: REALM_A, enabled: true },
  [ROBOT]: { id: ROBOT, realmId: OPERATOR, enabled: true, isServiceAccount: true },
};

let grantSeq = 0;

/** A live grant as the repository lists it. */
function grant(
  userId: string,
  targetRealmId: string | null,
  role: string | { realmId: string; permissionIds: string[]; disabledAt?: number | null }
): LiveAdminGrant {
  grantSeq += 1;
  const id = `01900000-0000-7000-9000-${String(grantSeq).padStart(12, '0')}`;
  const custom =
    typeof role === 'string'
      ? null
      : {
          id: `${id}-role`,
          realmId: role.realmId,
          name: 'custom',
          permissionIds: role.permissionIds,
          disabledAt: role.disabledAt ?? null,
          createdAt: 0,
          updatedAt: 0,
        };
  return {
    grant: {
      id,
      userId,
      builtInRole: typeof role === 'string' ? role : null,
      roleId: custom?.id ?? null,
      targetRealmId,
      createdBy: null,
      createdAt: 0,
      revokedAt: null,
      lastSecurityChangeAt: 0,
    },
    role: custom,
  };
}

/** A service account of the stub (#522) and its client, as the repositories read them. */
interface ServiceAccountFixture {
  readonly id: string;
  readonly realmId: string;
  readonly userId: string;
  readonly name: string;
  readonly enabled: boolean;
  readonly client: {
    readonly id: string;
    readonly clientId: string;
    readonly enabled: boolean;
    readonly suspended: boolean;
    readonly tokenEndpointAuthMethod: string;
    readonly dynamicRegisteredAt?: number | null;
    readonly metadata?: Record<string, unknown> | null;
  };
}

/** A server stub: realms, users, live grants and service accounts as given. */
function server(
  grants: LiveAdminGrant[] = [],
  options: {
    users?: typeof USERS;
    realms?: typeof REALMS;
    serviceAccounts?: readonly ServiceAccountFixture[];
  } = {}
) {
  const realms = options.realms ?? REALMS;
  const users = options.users ?? USERS;
  const serviceAccounts = options.serviceAccounts ?? [];
  const fastify = {
    jwtUtils: {
      // Per realm (#491): a token verifies with the realm's keys, under its issuer.
      verifyAccessToken: vi.fn(async (realm: { id: string; issuer: string }, _token: string) => ({
        iss: realm.issuer,
        sub: OPERATOR_ADMIN,
      })),
      extractCredentialFromHeader: vi.fn((header: string | undefined) =>
        header?.startsWith('Bearer ') ? { scheme: 'Bearer', token: header.slice(7) } : null
      ),
    },
    repositories: {
      realms: {
        findByIssuer: vi.fn(async (value: string) =>
          Object.values(realms).find((realm) => realm.issuer === value)
        ),
        findById: vi.fn(async (id: string) => realms[id]),
      },
      // Realm-first (#489): an account, and its grants, are found only in
      // the account's own realm.
      users: {
        findById: vi.fn(async (realmId: string, id: string) =>
          users[id]?.realmId === realmId ? users[id] : undefined
        ),
      },
      adminGrants: {
        listLive: vi.fn(async (realmId: string, userId: string) =>
          users[userId]?.realmId === realmId
            ? grants.filter((live) => live.grant.userId === userId)
            : []
        ),
      },
      serviceAccounts: {
        findByUser: vi.fn(async (realmId: string, userId: string) => {
          const found = serviceAccounts.find(
            (account) => account.realmId === realmId && account.userId === userId
          );
          return found === undefined ? undefined : { ...found, clientId: found.client.id };
        }),
      },
      oauthClients: {
        findById: vi.fn(
          async (realmId: string, id: string) =>
            serviceAccounts.find(
              (account) => account.realmId === realmId && account.client.id === id
            )?.client
        ),
      },
    },
  };
  return fastify as unknown as FastifyInstance & typeof fastify;
}

function ask(
  fastify: FastifyInstance,
  request: Partial<AdminAuthorityRequest> & { targetRealmId: string }
) {
  return resolveAdminAuthority(fastify, {
    iss: ISSUER,
    sub: OPERATOR_ADMIN,
    scopes: Object.values(ADMIN_SCOPES).join(' '),
    ...request,
  });
}

const ALL_PERMISSIONS = new Set(BUILT_IN_ROLES['security-admin'].permissionIds);

/** A directory that knows every realm of the stub by its stored issuer. */
const EVERY_ISSUER = {
  realmForIssuer: async (issuer: string) =>
    Object.values(REALMS).find((realm) => realm.issuer === issuer),
};

describe('deploymentRealmIssuerDirectory', () => {
  it('names the realm whose stored issuer the iss is, exactly as written (#491)', async () => {
    const fastify = server();
    const directory = deploymentRealmIssuerDirectory(fastify);
    for (const id of [OPERATOR, REALM_A, REALM_B]) {
      const issuer = REALMS[id].issuer as string;
      await expect(directory.realmForIssuer(issuer)).resolves.toBe(REALMS[id]);
      expect(fastify.repositories.realms.findByIssuer).toHaveBeenLastCalledWith(issuer);
    }
    for (const other of [`${ISSUER}/`, 'https://evil.example', '']) {
      await expect(directory.realmForIssuer(other)).resolves.toBeUndefined();
    }
  });
});

describe('deploymentIssuerKeyResolver', () => {
  it('verifies with the keys of the realm the issuer names, its issuer pinned, for every realm (#491)', async () => {
    const fastify = server();
    const keys = deploymentIssuerKeyResolver(fastify);
    for (const id of [OPERATOR, REALM_A]) {
      const realm = REALMS[id];
      await expect(keys.verifyAccessToken(realm, 'token')).resolves.toMatchObject({
        iss: realm.issuer,
      });
      expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenLastCalledWith(
        { id: realm.id, issuer: realm.issuer },
        'token'
      );
    }
  });

  it('passes a refusal of the realm keys on, and verifies nothing for a realm without an issuer', async () => {
    const fastify = server();
    const keys = deploymentIssuerKeyResolver(fastify);
    fastify.jwtUtils.verifyAccessToken.mockRejectedValueOnce(new JWTInvalidError('another key'));
    await expect(keys.verifyAccessToken(REALMS[REALM_A], 'token')).rejects.toThrow(JWTInvalidError);

    const calls = fastify.jwtUtils.verifyAccessToken.mock.calls.length;
    await expect(
      keys.verifyAccessToken(realmRow(MISSING, { issuer: null } as Partial<IssuerRealm>), 'token')
    ).rejects.toThrow(JWTInvalidError);
    expect(fastify.jwtUtils.verifyAccessToken).toHaveBeenCalledTimes(calls);
  });
});

/** Verified claims naming `iss`. */
function claimsOf(iss: string): JWTPayload {
  return { iss, sub: OPERATOR_ADMIN, clientId: 'admin-console' };
}

describe('adminIssuerResolver', () => {
  function request(fastify: FastifyInstance, authorization?: string): FastifyRequest {
    return { server: fastify, headers: { authorization } } as unknown as FastifyRequest;
  }

  it("accepts an issuer that names an enabled realm, when the token verifies with that realm's keys", async () => {
    const fastify = server();
    await expect(adminIssuerResolver()(ISSUER, request(fastify, 'Bearer t'))).resolves.toBe(true);
  });

  it('refuses an unknown issuer, a disabled realm, no credential and a failed verification', async () => {
    const accepts = adminIssuerResolver();
    const fastify = server();
    expect(await accepts('https://evil.example', request(fastify, 'Bearer t'))).toBe(false);
    expect(await accepts(ISSUER, request(fastify))).toBe(false);

    const disabled = server([], {
      realms: { ...REALMS, [OPERATOR]: { ...REALMS[OPERATOR], enabled: false } },
    });
    expect(await accepts(ISSUER, request(disabled, 'Bearer t'))).toBe(false);

    fastify.jwtUtils.verifyAccessToken.mockRejectedValueOnce(new JWTInvalidError('bad'));
    expect(await accepts(ISSUER, request(fastify, 'Bearer t'))).toBe(false);
  });

  it('uses the directory and the key resolver it is given', async () => {
    const fastify = server();
    const realm = REALMS[REALM_A];
    const verifyAccessToken = vi.fn<IssuerKeyResolver['verifyAccessToken']>(async () =>
      claimsOf('https://a.example')
    );
    const accepts = adminIssuerResolver({
      directory: {
        realmForIssuer: async (issuer) => (issuer === 'https://a.example' ? realm : undefined),
      },
      keys: { verifyAccessToken },
    });
    expect(await accepts('https://a.example', request(fastify, 'Bearer t'))).toBe(true);
    expect(verifyAccessToken).toHaveBeenCalledWith(realm, 't');
    // A key that verifies the token under another issuer does not count.
    verifyAccessToken.mockResolvedValueOnce(claimsOf('https://b.example'));
    expect(await accepts('https://a.example', request(fastify, 'Bearer t'))).toBe(false);
  });
});

describe('resolveAdminAuthority', () => {
  describe('rule 1: the issuer names a realm', () => {
    it('refuses an issuer of no realm, or of a disabled realm', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, null, 'viewer')]);
      await expect(
        ask(fastify, { iss: 'https://evil.example', targetRealmId: REALM_A })
      ).resolves.toEqual({ allowed: false, refusal: 'issuer_unknown' });

      const disabled = server([grant(OPERATOR_ADMIN, null, 'viewer')], {
        realms: { ...REALMS, [OPERATOR]: { ...REALMS[OPERATOR], enabled: false } },
      });
      await expect(ask(disabled, { targetRealmId: REALM_A })).resolves.toEqual({
        allowed: false,
        refusal: 'issuer_unknown',
      });
      expect(disabled.repositories.adminGrants.listLive).not.toHaveBeenCalled();
    });

    it('refuses a subject that is not an enabled account of the issuer realm', async () => {
      const fastify = server([grant(ADMIN_OF_A, REALM_A, 'viewer')], {
        users: {
          ...USERS,
          [MISSING]: { id: MISSING, realmId: OPERATOR, enabled: false },
        },
      });
      // Realm A's admin under the operator realm's issuer: another realm's account.
      for (const sub of [
        ADMIN_OF_A,
        MISSING,
        'not-a-uuid',
        '01900000-0000-7000-8000-0000000000ee',
      ]) {
        await expect(ask(fastify, { sub, targetRealmId: REALM_A })).resolves.toEqual({
          allowed: false,
          refusal: 'account_inactive',
        });
      }
      expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();
    });

    /** The stub with the operator admin disabled at `disabledAt` and enabled again since. */
    function reenabledAt(disabledAt: number) {
      return server([grant(OPERATOR_ADMIN, null, 'viewer')], {
        users: {
          ...USERS,
          [OPERATOR_ADMIN]: { ...USERS[OPERATOR_ADMIN], notValidBefore: disabledAt },
        },
      });
    }

    it('refuses a token issued before the account was last disabled, as a disabled account’s (#748)', async () => {
      const disabledAt = Date.now() - 60_000;
      const fastify = reenabledAt(disabledAt);
      const issuedBefore = await ask(fastify, {
        iat: Math.floor((disabledAt - 60_000) / 1000),
        targetRealmId: REALM_A,
      });
      expect(issuedBefore).toEqual({ allowed: false, refusal: 'account_inactive' });
      expect(fastify.repositories.users.findById).toHaveBeenCalledWith(OPERATOR, OPERATOR_ADMIN);
      expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();

      const disabled = server([grant(OPERATOR_ADMIN, null, 'viewer')], {
        users: { ...USERS, [OPERATOR_ADMIN]: { ...USERS[OPERATOR_ADMIN], enabled: false } },
      });
      // One answer: the caller cannot tell the two apart.
      await expect(
        ask(disabled, { iat: Math.floor((disabledAt - 60_000) / 1000), targetRealmId: REALM_A })
      ).resolves.toEqual(issuedBefore);
    });

    it('acts for a token issued after the account was enabled again (#748)', async () => {
      const disabledAt = Date.now() - 600_000;
      const fastify = reenabledAt(disabledAt);
      await expect(
        ask(fastify, { iat: Math.floor((disabledAt + 60_000) / 1000), targetRealmId: REALM_A })
      ).resolves.toMatchObject({
        allowed: true,
        userId: OPERATOR_ADMIN,
        targetRealm: { id: REALM_A },
        permissions: new Set(BUILT_IN_ROLES.viewer.permissionIds),
      });
    });

    it('refuses a token without iat once the account has been disabled, and acts for one of an account never disabled (#748)', async () => {
      const fastify = reenabledAt(Date.now() - 600_000);
      await expect(ask(fastify, { targetRealmId: REALM_A })).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });
      expect(fastify.repositories.adminGrants.listLive).not.toHaveBeenCalled();

      for (const notValidBefore of [undefined, null]) {
        const never = server([grant(OPERATOR_ADMIN, null, 'viewer')], {
          users: { ...USERS, [OPERATOR_ADMIN]: { ...USERS[OPERATOR_ADMIN], notValidBefore } },
        });
        await expect(ask(never, { targetRealmId: REALM_A })).resolves.toMatchObject({
          allowed: true,
          userId: OPERATOR_ADMIN,
          targetRealm: { id: REALM_A },
        });
      }
    });
  });

  describe('rule 2: an operator-realm admin manages a realm by grant', () => {
    it('acts on the realm of its grant and not on another', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, REALM_A, 'security-admin')]);
      const onA = await ask(fastify, { targetRealmId: REALM_A });
      expect(onA).toMatchObject({
        allowed: true,
        operator: true,
        userId: OPERATOR_ADMIN,
        issuerRealm: { id: OPERATOR },
        targetRealm: { id: REALM_A },
        permissions: ALL_PERMISSIONS,
      });
      for (const target of [REALM_B, OPERATOR]) {
        await expect(ask(fastify, { targetRealmId: target })).resolves.toEqual({
          allowed: false,
          refusal: 'realm_not_found',
        });
      }
    });

    it('acts on any realm, the operator realm included, with a grant on every realm', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, null, 'viewer')]);
      for (const target of [REALM_A, REALM_B, OPERATOR]) {
        await expect(ask(fastify, { targetRealmId: target })).resolves.toMatchObject({
          allowed: true,
          targetRealm: { id: target },
          permissions: new Set(BUILT_IN_ROLES.viewer.permissionIds),
        });
      }
    });

    it('answers a realm that does not exist as it answers one outside the grants', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, null, 'viewer')]);
      for (const target of [MISSING, 'not-a-uuid']) {
        await expect(ask(fastify, { targetRealmId: target })).resolves.toEqual({
          allowed: false,
          refusal: 'realm_not_found',
        });
      }
    });

    it('reads a realm id in either case', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, REALM_A, 'viewer')]);
      await expect(ask(fastify, { targetRealmId: REALM_A.toUpperCase() })).resolves.toMatchObject({
        allowed: true,
        targetRealm: { id: REALM_A },
      });
    });

    it('collects the permissions of every matching grant', async () => {
      const fastify = server([
        grant(OPERATOR_ADMIN, null, 'viewer'),
        grant(OPERATOR_ADMIN, REALM_A, {
          realmId: OPERATOR,
          permissionIds: ['realms.policies.write'],
        }),
        grant(OPERATOR_ADMIN, REALM_B, 'security-admin'),
      ]);
      const onA = await ask(fastify, { targetRealmId: REALM_A });
      expect(onA).toMatchObject({
        allowed: true,
        permissions: new Set([...BUILT_IN_ROLES.viewer.permissionIds, 'realms.policies.write']),
      });
      expect(onA.allowed && onA.grantIds).toHaveLength(2);
    });
  });

  describe('rule 3: a realm-local admin manages only its own realm', () => {
    const issA = REALMS[REALM_A].issuer as string;

    it('acts on its own realm with a grant on it', async () => {
      const fastify = server([grant(ADMIN_OF_A, REALM_A, 'editor')]);
      await expect(
        resolveAdminAuthority(
          fastify,
          {
            iss: issA,
            sub: ADMIN_OF_A,
            scopes: Object.values(ADMIN_SCOPES),
            targetRealmId: REALM_A,
          },
          { directory: EVERY_ISSUER }
        )
      ).resolves.toMatchObject({
        allowed: true,
        operator: false,
        targetRealm: { id: REALM_A },
        permissions: new Set(BUILT_IN_ROLES.editor.permissionIds),
      });
    });

    it('never acts on another realm or on the operator realm, whatever its grants say', async () => {
      // Grants that the realm rule refuses when they are written, as if the
      // operator flag had moved since.
      const fastify = server([
        grant(ADMIN_OF_A, REALM_A, 'viewer'),
        grant(ADMIN_OF_A, null, 'security-admin'),
        grant(ADMIN_OF_A, REALM_B, 'security-admin'),
        grant(ADMIN_OF_A, OPERATOR, 'security-admin'),
      ]);
      const directory = EVERY_ISSUER;
      for (const target of [REALM_B, OPERATOR, MISSING]) {
        await expect(
          resolveAdminAuthority(
            fastify,
            { iss: issA, sub: ADMIN_OF_A, scopes: 'qauth:admin:read', targetRealmId: target },
            { directory }
          )
        ).resolves.toEqual({ allowed: false, refusal: 'realm_not_found' });
      }
      // On its own realm, only the grant on it counts.
      await expect(
        resolveAdminAuthority(
          fastify,
          {
            iss: issA,
            sub: ADMIN_OF_A,
            scopes: Object.values(ADMIN_SCOPES).join(' '),
            targetRealmId: REALM_A,
          },
          { directory }
        )
      ).resolves.toMatchObject({
        allowed: true,
        permissions: new Set(BUILT_IN_ROLES.viewer.permissionIds),
      });
    });

    it('answers 404 for its own realm without a grant on it', async () => {
      const fastify = server([]);
      await expect(
        resolveAdminAuthority(
          fastify,
          { iss: issA, sub: ADMIN_OF_A, scopes: 'qauth:admin:read', targetRealmId: REALM_A },
          { directory: EVERY_ISSUER }
        )
      ).resolves.toEqual({ allowed: false, refusal: 'realm_not_found' });
    });
  });

  describe('rule 4: scopes intersect the grants', () => {
    it.each([
      ['qauth:admin:read', ['read']],
      ['qauth:admin:read qauth:admin:security', ['read', 'security']],
      ['qauth:admin:write', ['write']],
      ['openid admin:write qauth:admin:WRITE', []],
      [undefined, []],
    ])(
      'gives a security-admin with scope %j only the classes it names',
      async (scopes, classes) => {
        const fastify = server([grant(OPERATOR_ADMIN, REALM_A, 'security-admin')]);
        const authority = await ask(fastify, { scopes, targetRealmId: REALM_A });
        if (!authority.allowed) throw new Error('refused');
        const expected = PERMISSION_REGISTRY.active
          .filter((permission) => (classes as string[]).includes(permission.class))
          .map((permission) => permission.id);
        expect(authority.permissions).toEqual(new Set(expected));
      }
    );

    it('gives no write permission to a token without qauth:admin:write, whatever the role', async () => {
      const writeIds = PERMISSION_REGISTRY.ofClass('write').map((permission) => permission.id);
      expect(writeIds.length).toBeGreaterThan(0);
      const roles = [
        'editor',
        'security-admin',
        { realmId: OPERATOR, permissionIds: PERMISSION_REGISTRY.active.map((p) => p.id) },
      ] as const;
      for (const role of roles) {
        const fastify = server([grant(OPERATOR_ADMIN, REALM_A, role)]);
        const authority = await ask(fastify, {
          scopes: 'qauth:admin:read qauth:admin:security',
          targetRealmId: REALM_A,
        });
        if (!authority.allowed) throw new Error('refused');
        expect(writeIds.filter((id) => authority.permissions.has(id))).toEqual([]);
      }
    });
  });

  describe('custom roles', () => {
    it('grants a custom role of the account realm or of the target realm, and nothing from a disabled one', async () => {
      const fastify = server([
        grant(OPERATOR_ADMIN, REALM_A, { realmId: REALM_A, permissionIds: ['realms.read'] }),
        grant(OPERATOR_ADMIN, REALM_A, { realmId: REALM_B, permissionIds: ['realms.export'] }),
        grant(OPERATOR_ADMIN, REALM_A, {
          realmId: OPERATOR,
          permissionIds: ['approvals.read'],
          disabledAt: 1,
        }),
      ]);
      await expect(ask(fastify, { targetRealmId: REALM_A })).resolves.toMatchObject({
        allowed: true,
        permissions: new Set(['realms.read']),
      });
    });
  });

  // #522: a service account is an account of the operator realm with no
  // credential; its grants attach to its user row, and it acts only through
  // its own client, which authenticates with private_key_jwt.
  describe('service accounts', () => {
    const ROBOT_CLIENT = 'ci-realm-import';

    function robot(
      changes: Partial<Omit<ServiceAccountFixture, 'client'>> & {
        client?: Partial<ServiceAccountFixture['client']>;
      } = {}
    ): ServiceAccountFixture {
      const { client, ...account } = changes;
      return {
        id: '01900000-0000-7000-a000-000000000001',
        realmId: OPERATOR,
        userId: ROBOT,
        name: 'ci',
        enabled: true,
        ...account,
        client: {
          id: '01900000-0000-7000-a000-0000000000c1',
          clientId: ROBOT_CLIENT,
          enabled: true,
          suspended: false,
          tokenEndpointAuthMethod: 'private_key_jwt',
          ...client,
        },
      };
    }

    function robotServer(account: ServiceAccountFixture = robot(), realms = REALMS) {
      return server([grant(ROBOT, REALM_A, 'security-admin')], {
        serviceAccounts: [account],
        realms,
      });
    }

    /** A request for the robot's account; `null` names no client, as the approval page does. */
    const asRobot = (fastify: FastifyInstance, clientId: string | null = ROBOT_CLIENT) =>
      ask(fastify, {
        sub: ROBOT,
        targetRealmId: REALM_A,
        ...(clientId === null ? {} : { clientId }),
      });

    it('names a person a human caller, with no service account', async () => {
      const fastify = server([grant(OPERATOR_ADMIN, REALM_A, 'viewer')]);
      await expect(
        ask(fastify, { targetRealmId: REALM_A, clientId: 'admin-console' })
      ).resolves.toMatchObject({ allowed: true, kind: 'human', serviceAccount: null });
    });

    it('acts for a service account through its own client, by the grants of its user row', async () => {
      const fastify = robotServer();
      await expect(asRobot(fastify)).resolves.toMatchObject({
        allowed: true,
        kind: 'service_account',
        userId: ROBOT,
        serviceAccount: {
          id: '01900000-0000-7000-a000-000000000001',
          name: 'ci',
          clientId: ROBOT_CLIENT,
        },
        operator: true,
        targetRealm: { id: REALM_A },
        permissions: ALL_PERMISSIONS,
      });
      expect(
        fastify.repositories.serviceAccounts.findByUser.mock.calls.map((call) => call.slice(0, 2))
      ).toEqual([[OPERATOR, ROBOT]]);
    });

    it("refuses its account's token held by another client, or a request that names no client", async () => {
      const fastify = robotServer();
      for (const clientId of ['admin-console', 'CI-REALM-IMPORT', null]) {
        await expect(asRobot(fastify, clientId), String(clientId)).resolves.toEqual({
          allowed: false,
          refusal: 'account_inactive',
        });
      }
    });

    it('refuses a disabled service account from the next request on', async () => {
      await expect(asRobot(robotServer(robot({ enabled: false })))).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });
    });

    it('refuses one whose client is disabled, suspended or no longer private_key_jwt', async () => {
      for (const client of [
        { enabled: false },
        { suspended: true },
        { tokenEndpointAuthMethod: 'client_secret_basic' },
        { tokenEndpointAuthMethod: 'client_secret_post' },
        { tokenEndpointAuthMethod: 'none' },
      ]) {
        await expect(
          asRobot(robotServer(robot({ client }))),
          JSON.stringify(client)
        ).resolves.toEqual({ allowed: false, refusal: 'account_inactive' });
      }
    });

    // Being a service account is a lasting fact of the account: a marked
    // account whose binding is gone is never taken for a person's, and a
    // binding to an account not marked fails closed too.
    it('refuses a marked account whose binding is gone, and a binding to an unmarked account', async () => {
      const unbound = server([grant(ROBOT, REALM_A, 'security-admin')], { serviceAccounts: [] });
      for (const clientId of [ROBOT_CLIENT, 'admin-console', null]) {
        await expect(asRobot(unbound, clientId), String(clientId)).resolves.toEqual({
          allowed: false,
          refusal: 'account_inactive',
        });
      }
      const unmarked = server([grant(ROBOT, REALM_A, 'security-admin')], {
        serviceAccounts: [robot()],
        users: { ...USERS, [ROBOT]: { ...USERS[ROBOT], isServiceAccount: false } },
      });
      await expect(asRobot(unmarked)).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });
    });

    // #1090: account-closer lets a service account delete one realm's
    // accounts with no approval.
    describe('unattended operations', () => {
      function closerServer(grants: LiveAdminGrant[], account: ServiceAccountFixture = robot()) {
        return server(grants, { serviceAccounts: [account] });
      }

      it('names users.delete for a service account that holds account-closer on exactly this realm', async () => {
        const fastify = closerServer([grant(ROBOT, REALM_A, 'account-closer')]);
        await expect(asRobot(fastify)).resolves.toMatchObject({
          allowed: true,
          kind: 'service_account',
          permissions: new Set(['users.delete']),
          unattendedOperations: new Set(['users.delete']),
        });
      });

      it('names none on another realm, nor for an account-closer grant on every realm', async () => {
        const elsewhere = closerServer([
          grant(ROBOT, REALM_B, 'account-closer'),
          grant(ROBOT, REALM_A, 'security-admin'),
        ]);
        await expect(asRobot(elsewhere)).resolves.toMatchObject({
          allowed: true,
          unattendedOperations: new Set(),
        });
        const everywhere = closerServer([grant(ROBOT, null, 'account-closer')]);
        await expect(asRobot(everywhere)).resolves.toMatchObject({
          allowed: true,
          permissions: new Set(['users.delete']),
          unattendedOperations: new Set(),
        });
      });

      it('names none for a service account whose client registered itself', async () => {
        for (const client of [
          { dynamicRegisteredAt: 1_800_000_000_000 },
          { metadata: { registrationType: 'dynamic' } },
          { metadata: { registrationType: 'cimd' } },
        ]) {
          const fastify = closerServer(
            [grant(ROBOT, REALM_A, 'account-closer')],
            robot({ client })
          );
          await expect(asRobot(fastify), JSON.stringify(client)).resolves.toMatchObject({
            allowed: true,
            unattendedOperations: new Set(),
          });
        }
      });

      it('names none for a person who holds account-closer', async () => {
        const fastify = server([grant(OPERATOR_ADMIN, REALM_A, 'account-closer')]);
        await expect(ask(fastify, { targetRealmId: REALM_A })).resolves.toMatchObject({
          allowed: true,
          kind: 'human',
          permissions: new Set(['users.delete']),
          unattendedOperations: new Set(),
        });
      });
    });

    it('refuses one whose realm is no longer the operator realm', async () => {
      const moved = { ...REALMS, [OPERATOR]: { ...REALMS[OPERATOR], isOperator: false } };
      await expect(asRobot(robotServer(robot(), moved))).resolves.toEqual({
        allowed: false,
        refusal: 'account_inactive',
      });
    });
  });
});

describe('grantFitsRealmRule', () => {
  it('admits every target for an operator account, and only its own realm for another', () => {
    const operator = { id: OPERATOR, isOperator: true };
    const local = { id: REALM_A, isOperator: false };
    expect(grantFitsRealmRule(grant(OPERATOR_ADMIN, null, 'viewer'), operator)).toBe(true);
    expect(grantFitsRealmRule(grant(OPERATOR_ADMIN, REALM_B, 'viewer'), operator)).toBe(true);
    expect(grantFitsRealmRule(grant(ADMIN_OF_A, REALM_A, 'viewer'), local)).toBe(true);
    expect(grantFitsRealmRule(grant(ADMIN_OF_A, null, 'viewer'), local)).toBe(false);
    expect(grantFitsRealmRule(grant(ADMIN_OF_A, REALM_B, 'viewer'), local)).toBe(false);
  });
});

describe('adminAuthorityError', () => {
  it('answers 401 for the token and 404 for the realm', () => {
    expect(adminAuthorityError('issuer_unknown', REALM_A)).toBeInstanceOf(JWTInvalidError);
    expect(adminAuthorityError('account_inactive', REALM_A)).toBeInstanceOf(JWTInvalidError);
    const notFound = adminAuthorityError('realm_not_found', REALM_A);
    expect(notFound).toBeInstanceOf(NotFoundError);
    expect(notFound.message).toBe(`Realm with id ${REALM_A} not found`);
  });
});
