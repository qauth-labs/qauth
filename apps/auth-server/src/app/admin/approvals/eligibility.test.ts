import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { eligibleApproverCount, eligibleApprovers } from './eligibility';

/**
 * Who may approve a request on a realm, counted (#589, #521), over fake
 * repositories: the grants on the realm and the operator realm's grants on
 * every realm, read in the handler's transaction, and each candidate's
 * grants for the two-admin rule's 7-day window.
 */

const OPERATOR = '00000000-0000-4000-8000-00000000000a';
const TENANT = '00000000-0000-4000-8000-00000000000b';
const OTHER = '00000000-0000-4000-8000-00000000000c';
const TX = { tx: true };
const NOW = 1_800_000_000_000;
const DAY = 86_400_000;
/** Long before the request: outside the two-admin rule's 7-day window. */
const OLD = NOW - 30 * DAY;

interface RealmFixture {
  id: string;
  isOperator: boolean;
  enabled?: boolean;
  issuer?: string | null;
}

interface GrantFixture {
  userId: string;
  accountRealmId: string;
  target: string | null;
  builtInRole?: string | null;
  role?: { permissionIds: string[] } | null;
  enabled?: boolean;
  notValidBefore?: number | null;
  /** When the account was created; {@link OLD} when absent. */
  accountCreatedAt?: number;
  /** When the grant was made; {@link OLD} when absent. */
  createdAt?: number;
  /** When the account's credentials last changed, as the grant records it. */
  lastSecurityChangeAt?: number;
}

let grantSeq = 0;

function liveGrant(fixture: GrantFixture) {
  grantSeq += 1;
  const roleId = fixture.role
    ? `00000000-0000-4000-8000-0000000001${String(grantSeq).padStart(2, '0')}`
    : null;
  return {
    grant: {
      id: `00000000-0000-4000-8000-0000000000${String(grantSeq).padStart(2, '0')}`,
      userId: fixture.userId,
      builtInRole: fixture.role ? null : (fixture.builtInRole ?? 'security-admin'),
      roleId,
      targetRealmId: fixture.target,
      createdAt: fixture.createdAt ?? OLD,
      createdBy: null,
      revokedAt: null,
      lastSecurityChangeAt: fixture.lastSecurityChangeAt ?? fixture.createdAt ?? OLD,
    },
    role: fixture.role
      ? {
          id: roleId,
          realmId: fixture.accountRealmId,
          permissionIds: fixture.role.permissionIds,
          disabledAt: null,
        }
      : null,
    account: {
      realmId: fixture.accountRealmId,
      enabled: fixture.enabled ?? true,
      notValidBefore: fixture.notValidBefore ?? null,
      createdAt: fixture.accountCreatedAt ?? OLD,
    },
  };
}

/** A server whose grants are `grants`, in realms `realms`; the first operator realm is found. */
function serverWith(realms: RealmFixture[], grants: GrantFixture[]) {
  const rows = realms.map((realm) => ({
    enabled: true,
    issuer: `https://${realm.id}.example`,
    ...realm,
  }));
  const live = grants.map(liveGrant);
  const listLiveOnTarget = vi.fn(async (realmId: string, target: string | null, tx: unknown) => {
    expect(tx).toBe(TX);
    // The rule the repository applies (#489): a grant on the realm from the
    // realm itself, a grant on every realm from its holder's realm.
    return live.filter((entry) =>
      target === null
        ? entry.grant.targetRealmId === null && entry.account.realmId === realmId
        : entry.grant.targetRealmId === target &&
          (realmId === target || entry.account.realmId === realmId)
    );
  });
  const listByUser = vi.fn(async (realmId: string, userId: string, tx: unknown) => {
    expect(tx).toBe(TX);
    return live
      .filter((entry) => entry.account.realmId === realmId && entry.grant.userId === userId)
      .map((entry) => entry.grant);
  });
  const fastify = {
    repositories: {
      adminGrants: { listLiveOnTarget, listByUser },
      realms: {
        findOperator: vi.fn(async (tx: unknown) => {
          expect(tx).toBe(TX);
          return rows.find((realm) => realm.isOperator);
        }),
        findById: vi.fn(async (id: string, tx: unknown) => {
          expect(tx).toBe(TX);
          return rows.find((realm) => realm.id === id);
        }),
      },
    },
  } as unknown as FastifyInstance;
  return { fastify, listLiveOnTarget, listByUser };
}

const REALMS: RealmFixture[] = [
  { id: OPERATOR, isOperator: true },
  { id: TENANT, isOperator: false },
  { id: OTHER, isOperator: false },
];

const requester = { realmId: OPERATOR, accountId: 'requester', kind: 'human' as const };

const count = (
  fastify: FastifyInstance,
  target = TENANT,
  isOperator = false,
  callerRealm = { isOperator: true }
) =>
  eligibleApproverCount(fastify, {
    targetRealm: { id: target, isOperator },
    requester,
    callerRealm,
    tx: TX as never,
    now: NOW,
  });

describe('eligibleApproverCount (#589)', () => {
  it('counts each other account that holds approvals.approve on the realm, once', async () => {
    const { fastify, listLiveOnTarget } = serverWith(REALMS, [
      { userId: 'requester', accountRealmId: OPERATOR, target: TENANT },
      { userId: 'local-admin', accountRealmId: TENANT, target: TENANT },
      // Two grants of one account count once.
      { userId: 'operator-admin', accountRealmId: OPERATOR, target: TENANT },
      { userId: 'operator-admin', accountRealmId: OPERATOR, target: null },
      // A grant on every realm covers the tenant too.
      { userId: 'global-admin', accountRealmId: OPERATOR, target: null },
      {
        userId: 'custom-approver',
        accountRealmId: TENANT,
        target: TENANT,
        role: { permissionIds: ['approvals.approve'] },
      },
    ]);
    expect(await count(fastify)).toBe(4);
    expect(listLiveOnTarget.mock.calls.map(([realmId, target]) => [realmId, target])).toEqual([
      [TENANT, TENANT],
      [OPERATOR, null],
    ]);
  });

  it('never counts the requester, a role without approvals.approve, or a grant on another realm', async () => {
    const { fastify } = serverWith(REALMS, [
      { userId: 'requester', accountRealmId: OPERATOR, target: TENANT },
      { userId: 'requester', accountRealmId: OPERATOR, target: null },
      { userId: 'viewer', accountRealmId: TENANT, target: TENANT, builtInRole: 'viewer' },
      { userId: 'editor', accountRealmId: OPERATOR, target: TENANT, builtInRole: 'editor' },
      { userId: 'unknown-role', accountRealmId: TENANT, target: TENANT, builtInRole: 'owner' },
      {
        userId: 'reader',
        accountRealmId: TENANT,
        target: TENANT,
        role: { permissionIds: ['approvals.read', 'realms.read'] },
      },
      { userId: 'other-admin', accountRealmId: OTHER, target: OTHER },
      { userId: 'operator-on-other', accountRealmId: OPERATOR, target: OTHER },
    ]);
    expect(await count(fastify)).toBe(0);
  });

  it('never counts a disabled account, an account of a disabled realm or one with no issuer', async () => {
    const { fastify } = serverWith(
      [
        { id: OPERATOR, isOperator: true, enabled: false },
        { id: TENANT, isOperator: false, issuer: null },
        { id: OTHER, isOperator: false },
      ],
      [
        { userId: 'of-disabled-realm', accountRealmId: OPERATOR, target: TENANT },
        { userId: 'of-realm-without-issuer', accountRealmId: TENANT, target: TENANT },
      ]
    );
    expect(await count(fastify)).toBe(0);

    const { fastify: disabled } = serverWith(REALMS, [
      { userId: 'disabled', accountRealmId: TENANT, target: TENANT, enabled: false },
      // Disabled once, a day ago, and enabled again since (#748).
      {
        userId: 'enabled-again',
        accountRealmId: TENANT,
        target: TENANT,
        notValidBefore: NOW - 86_400_000,
      },
    ]);
    expect(await count(disabled)).toBe(1);
  });

  it('counts only operator-realm admins on the operator realm', async () => {
    const { fastify } = serverWith(REALMS, [
      { userId: 'operator-admin', accountRealmId: OPERATOR, target: OPERATOR },
      { userId: 'global-admin', accountRealmId: OPERATOR, target: null },
    ]);
    expect(await count(fastify, OPERATOR, true)).toBe(2);
  });

  // A realm-local caller sees no grant on every realm (#489), so the count
  // it is shown leaves them out; the fail-closed check counts them (#521).
  it('counts no grant on every realm for a caller of another realm than the operator realm', async () => {
    const { fastify, listLiveOnTarget } = serverWith(REALMS, [
      { userId: 'local-admin', accountRealmId: TENANT, target: TENANT },
      { userId: 'operator-on-tenant', accountRealmId: OPERATOR, target: TENANT },
      { userId: 'global-admin', accountRealmId: OPERATOR, target: null },
    ]);
    expect(await count(fastify, TENANT, false, { isOperator: false })).toBe(2);
    expect(listLiveOnTarget.mock.calls.map(([realmId, target]) => [realmId, target])).toEqual([
      [TENANT, TENANT],
      [OPERATOR, null],
    ]);
    expect(
      await eligibleApprovers(fastify, {
        targetRealm: { id: TENANT, isOperator: false },
        requester,
        callerRealm: { isOperator: false },
        tx: TX as never,
        now: NOW,
      })
    ).toEqual({ visible: 2, total: 3 });
    expect(await count(fastify)).toBe(3);
  });

  // The two-admin rule (#521): an admin created, granted a role or changed
  // in the 7 days before the request is not one it could come from.
  it('counts no admin created, granted a role or changed in the last 7 days', async () => {
    const { fastify, listByUser } = serverWith(REALMS, [
      { userId: 'eligible', accountRealmId: TENANT, target: TENANT },
      {
        userId: 'created-6-days-ago',
        accountRealmId: TENANT,
        target: TENANT,
        accountCreatedAt: NOW - 6 * DAY,
      },
      {
        userId: 'created-7-days-ago',
        accountRealmId: TENANT,
        target: TENANT,
        accountCreatedAt: NOW - 7 * DAY,
      },
      { userId: 'granted-yesterday', accountRealmId: TENANT, target: TENANT, createdAt: NOW - DAY },
      // An old grant, and a second role granted yesterday.
      { userId: 'regranted', accountRealmId: TENANT, target: TENANT },
      {
        userId: 'regranted',
        accountRealmId: TENANT,
        target: TENANT,
        builtInRole: 'viewer',
        createdAt: NOW - DAY,
      },
      {
        userId: 'changed-2-days-ago',
        accountRealmId: TENANT,
        target: TENANT,
        lastSecurityChangeAt: NOW - 2 * DAY,
      },
    ]);
    expect(await count(fastify)).toBe(2);
    expect(listByUser).toHaveBeenCalledWith(TENANT, 'regranted', TX);
  });

  it('reads the grants on the realm alone where no operator realm exists', async () => {
    const { fastify, listLiveOnTarget } = serverWith(
      [{ id: TENANT, isOperator: false }],
      [{ userId: 'local-admin', accountRealmId: TENANT, target: TENANT }]
    );
    expect(await count(fastify)).toBe(1);
    expect(listLiveOnTarget).toHaveBeenCalledTimes(1);
  });
});
