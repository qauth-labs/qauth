import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { eligibleApproverCount } from './eligibility';

/**
 * Who may approve a request on a realm, counted (#589), over fake
 * repositories: the grants on the realm and the operator realm's grants on
 * every realm, read in the handler's transaction.
 */

const OPERATOR = '00000000-0000-4000-8000-00000000000a';
const TENANT = '00000000-0000-4000-8000-00000000000b';
const OTHER = '00000000-0000-4000-8000-00000000000c';
const TX = { tx: true };
const NOW = 1_800_000_000_000;

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
      revokedAt: null,
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
  const fastify = {
    repositories: {
      adminGrants: { listLiveOnTarget },
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
  return { fastify, listLiveOnTarget };
}

const REALMS: RealmFixture[] = [
  { id: OPERATOR, isOperator: true },
  { id: TENANT, isOperator: false },
  { id: OTHER, isOperator: false },
];

const requester = { realmId: OPERATOR, accountId: 'requester', kind: 'human' as const };

const count = (fastify: FastifyInstance, target = TENANT, isOperator = false) =>
  eligibleApproverCount(fastify, {
    targetRealm: { id: target, isOperator },
    requester,
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

  it('reads the grants on the realm alone where no operator realm exists', async () => {
    const { fastify, listLiveOnTarget } = serverWith(
      [{ id: TENANT, isOperator: false }],
      [{ userId: 'local-admin', accountRealmId: TENANT, target: TENANT }]
    );
    expect(await count(fastify)).toBe(1);
    expect(listLiveOnTarget).toHaveBeenCalledTimes(1);
  });
});
