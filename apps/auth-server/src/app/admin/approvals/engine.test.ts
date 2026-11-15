import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { completeApproval, denyApproval, startApproval } from './engine';
import type { ApprovalFactor } from './factor';

/**
 * A SERVICE ACCOUNT CANNOT APPROVE (#522, ADR-019 Decision 7), at the
 * approval engine, over fake repositories: whatever its grants give, a
 * service account signed in on the approval page (it has no credential to
 * sign in with) is answered as if the approval did not exist, gives no
 * approval and declines none. The factor is never asked for a challenge.
 */

const OPERATOR = '01900000-0000-7000-8000-00000000000a';
const ISSUER = 'https://auth.example.com';
const ROBOT = '01900000-0000-7000-8000-000000000003';
const PERSON = '01900000-0000-7000-8000-000000000001';
const APPROVAL_ID = '01900000-0000-7000-8000-0000000000e1';
const NOW = 1_800_000_000_000;

const operatorRealm = {
  id: OPERATOR,
  name: 'master',
  enabled: true,
  isOperator: true,
  issuer: ISSUER,
};

/** A pending approval of a person's request, which needs a second admin. */
function pendingApproval() {
  return {
    id: APPROVAL_ID,
    realmId: OPERATOR,
    requesterKind: 'human' as const,
    requesterRealmId: OPERATOR,
    requesterId: PERSON,
    operationId: 'keys.rotate',
    method: 'POST',
    params: { realmId: OPERATOR },
    query: {},
    display: { operation: 'keys.rotate', title: 'Rotate the keys', fields: [], reason: null },
    opHash: Buffer.alloc(32, 1),
    nonce: Buffer.alloc(32, 2),
    reason: null,
    classification: { class: 'security', effects: ['key-operation'], permissions: [] },
    approvalsRequired: 2,
    approvals: [
      {
        approverRealmId: OPERATOR,
        approverId: PERSON,
        credentialId: 'passkey-1',
        factor: 'test',
        approvedAt: NOW - 1000,
      },
    ],
    status: 'pending' as const,
    createdAt: NOW - 60_000,
    expiresAt: NOW + 240_000,
    usedAt: null,
  };
}

/** The account's grant: security-admin on every realm, made long before the request. */
const GRANT = {
  id: 'grant-1',
  userId: ROBOT,
  builtInRole: 'security-admin',
  roleId: null,
  targetRealmId: null,
  createdBy: null,
  createdAt: 0,
  revokedAt: null,
  lastSecurityChangeAt: 0,
};

/**
 * A server whose operator realm holds the account {@link ROBOT} with a
 * security-admin grant on every realm: a service account's, or, for the
 * control case, a person's.
 */
function server(options: { serviceAccount: boolean } = { serviceAccount: true }) {
  const addApproval = vi.fn();
  const deny = vi.fn();
  const fastify = {
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    db: { transaction: vi.fn(async (work: (tx: unknown) => unknown) => work({})) },
    repositories: {
      adminApprovals: {
        findById: vi.fn(async (realmId: string, id: string) =>
          realmId === OPERATOR && id === APPROVAL_ID ? pendingApproval() : undefined
        ),
        addApproval,
        deny,
      },
      adminAuditLog: { appendAdminAudit: vi.fn() },
      realms: {
        findById: vi.fn(async (id: string) => (id === OPERATOR ? operatorRealm : undefined)),
        findByIssuer: vi.fn(async (issuer: string) =>
          issuer === ISSUER ? operatorRealm : undefined
        ),
      },
      users: {
        findById: vi.fn(async (realmId: string, id: string) =>
          realmId === OPERATOR && id === ROBOT
            ? { id: ROBOT, realmId: OPERATOR, enabled: true, notValidBefore: null, createdAt: 0 }
            : undefined
        ),
      },
      serviceAccounts: {
        findByUser: vi.fn(async (realmId: string, userId: string) =>
          options.serviceAccount && realmId === OPERATOR && userId === ROBOT
            ? {
                id: 'sa-1',
                realmId: OPERATOR,
                name: 'ci',
                userId: ROBOT,
                clientId: 'client-row-1',
                enabled: true,
              }
            : undefined
        ),
      },
      oauthClients: {
        findById: vi.fn(async () => ({
          id: 'client-row-1',
          clientId: 'ci',
          enabled: true,
          suspended: false,
          tokenEndpointAuthMethod: 'private_key_jwt',
        })),
      },
      adminGrants: {
        listLive: vi.fn(async () => [{ grant: GRANT, role: null }]),
        listByUser: vi.fn(async () => [GRANT]),
      },
    },
  };
  return { fastify: fastify as unknown as FastifyInstance, addApproval, deny };
}

function factor(): ApprovalFactor & { createChallenge: ReturnType<typeof vi.fn> } {
  return {
    name: 'test',
    createChallenge: vi.fn(async () => ({ challenge: 'challenge' })),
    verify: vi.fn(async () => 'passkey-robot'),
    isRegisteredTo: vi.fn(async () => false),
  };
}

const decision = {
  realmId: OPERATOR,
  approvalId: APPROVAL_ID,
  approver: { realmId: OPERATOR, accountId: ROBOT },
  sessionIssuedAtMs: NOW,
};

describe('a service account at the approval engine (#522)', () => {
  // The control: the same account and grant, were they a person's, would be
  // asked for the factor's challenge, so the refusals below are the service
  // account's alone.
  it("asks a person's account with the same grant for a challenge", async () => {
    const { fastify } = server({ serviceAccount: false });
    const test = factor();
    await expect(startApproval(fastify, test, decision, { now: () => NOW })).resolves.toMatchObject(
      { challenge: { challenge: 'challenge' } }
    );
    expect(test.createChallenge).toHaveBeenCalledOnce();
  });

  it('cannot begin an approval: the factor is never asked for a challenge', async () => {
    const { fastify } = server();
    const test = factor();
    await expect(startApproval(fastify, test, decision, { now: () => NOW })).rejects.toThrow(
      NotFoundError
    );
    expect(test.createChallenge).not.toHaveBeenCalled();
  });

  it('cannot give an approval, nor decline one', async () => {
    const { fastify, addApproval, deny } = server();
    const test = factor();
    await expect(
      completeApproval(fastify, test, { ...decision, response: {} }, { now: () => NOW })
    ).rejects.toThrow(NotFoundError);
    await expect(denyApproval(fastify, decision, { now: () => NOW })).rejects.toThrow(
      NotFoundError
    );
    expect(test.verify).not.toHaveBeenCalled();
    expect(addApproval).not.toHaveBeenCalled();
    expect(deny).not.toHaveBeenCalled();
  });
});
