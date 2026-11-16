import { PreconditionFailedError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AccountDeletionConflictError } from '../../helpers/account-deletion-errors';

/**
 * The steps of an admin's deletion of an account (#681), against fakes of the
 * repositories, in the order `./deletion.ts` takes them: the lock, the account
 * under it, the session ending that queues the back-channel logout notices,
 * the deletion, and the admin events last. Every call passes the handler's
 * transaction. The real rows, the cascade and the notices are exercised in
 * `admin-users-delete.integration.test.ts`.
 */

const steps = vi.hoisted(() => [] as string[]);

vi.mock('../../helpers/user-events', () => ({
  emitUserEvent: vi.fn(
    async (
      _request: unknown,
      type: string,
      data: Record<string, unknown>,
      options: { tx: unknown; userId: string; actor: { type: string; id: string } }
    ) => {
      steps.push(
        `event ${type.replace('urn:qauth:event:', '')} ${JSON.stringify(data)} ${options.userId} ${options.actor.type}:${options.actor.id} ${options.tx === TX ? 'tx' : 'no-tx'}`
      );
      return 'event-id';
    }
  ),
}));

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const USER = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e71';
const ADMIN = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e72';
const SID_A = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e81';
const SID_B = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e82';
const TX = vi.hoisted(() => ({ name: 'handler-tx' }));
const CREATED = Date.UTC(2026, 10, 1);

interface Fakes {
  locked?: boolean;
  user?: { id: string; enabled: boolean; createdAt: number; isServiceAccount?: boolean };
  grants?: { revokedAt: number | null }[];
  deleted?: boolean;
  ended?: string[];
}

/** A request whose repositories log each call, with whether it passed the transaction. */
function requestWith(fakes: Fakes = {}): FastifyRequest {
  const log =
    (name: string, answer: unknown) =>
    async (...args: unknown[]) => {
      steps.push(`${name} ${args.includes(TX) ? 'tx' : 'no-tx'}`);
      return answer;
    };
  const user =
    'user' in fakes
      ? fakes.user
      : { id: USER, enabled: true, createdAt: CREATED, isServiceAccount: false };
  return {
    server: {
      repositories: {
        users: {
          lockForDeletion: log('lock', fakes.locked ?? true),
          findById: log('read account', user),
          deleteAccount: log('delete account', fakes.deleted ?? true),
        },
        serviceAccounts: { findByUser: log('read service account', undefined) },
        adminGrants: { listByUser: log('read admin grants', fakes.grants ?? []) },
        userCredentials: { findProofsByUserId: log('read credentials', []) },
        sessions: {
          revokeForUser: async (
            realmId: string,
            userId: string,
            reason: string,
            filter: unknown,
            tx: unknown
          ) => {
            steps.push(
              `end sessions ${realmId === REALM ? 'realm' : 'other'} ${userId} ${reason} ${JSON.stringify(filter)} ${tx === TX ? 'tx' : 'no-tx'}`
            );
            return (fakes.ended ?? [SID_A, SID_B]).map((id) => ({
              session: { id },
              clients: [],
            }));
          },
        },
      },
    },
  } as unknown as FastifyRequest;
}

async function versionOf(account: { enabled: boolean } | null): Promise<string> {
  const { accountDeletionStateVersion } = await import('./operations');
  return accountDeletionStateVersion({
    userId: USER,
    account:
      account === null ? null : { createdAt: CREATED, enabled: account.enabled, credentials: [] },
  });
}

async function run(request: FastifyRequest, stateVersion: string | null) {
  const { deleteAccountOfRealm } = await import('./deletion');
  return deleteAccountOfRealm(request, {
    realmId: REALM,
    userId: USER,
    stateVersion,
    tx: TX as never,
    actor: { type: 'user', id: ADMIN },
  });
}

describe("an admin's deletion of an account, step by step (#681)", () => {
  beforeEach(() => {
    steps.length = 0;
  });

  it('locks, reads, ends every session, deletes, then records the admin events, all in the transaction', async () => {
    const outcome = await run(requestWith(), await versionOf({ enabled: true }));
    expect(outcome).toEqual({
      kind: 'deleted',
      userId: USER,
      account: { createdAt: CREATED, enabled: true, credentials: [] },
      endedSessions: [SID_A, SID_B],
    });
    expect(steps).toEqual([
      'lock tx',
      'read account tx',
      'read service account tx',
      'read admin grants tx',
      'read credentials tx',
      `end sessions realm ${USER} admin {} tx`,
      'delete account tx',
      `event user.session_revoked:v1-rc.0 {"sid":"${SID_A}","reason":"account_deleted"} ${USER} user:${ADMIN} tx`,
      `event user.session_revoked:v1-rc.0 {"sid":"${SID_B}","reason":"account_deleted"} ${USER} user:${ADMIN} tx`,
      `event user.deleted:v1-rc.0 {} ${USER} user:${ADMIN} tx`,
    ]);
  });

  it('records only user.deleted for an account that held no session', async () => {
    await run(requestWith({ ended: [] }), await versionOf({ enabled: true }));
    expect(steps.filter((step) => step.startsWith('event'))).toEqual([
      `event user.deleted:v1-rc.0 {} ${USER} user:${ADMIN} tx`,
    ]);
  });

  it('changes nothing and records nothing for an id the realm does not hold', async () => {
    // Whatever version the call was classified against: absent at the
    // lock, it may have been deleted by another call meanwhile.
    for (const version of [await versionOf(null), await versionOf({ enabled: true })]) {
      steps.length = 0;
      await expect(run(requestWith({ locked: false }), version)).resolves.toEqual({
        kind: 'absent',
      });
      expect(steps).toEqual(['lock tx']);
    }
  });

  it('answers 412 when the account moved since the call was classified, before anything ends', async () => {
    await expect(run(requestWith(), await versionOf({ enabled: false }))).rejects.toBeInstanceOf(
      PreconditionFailedError
    );
    expect(steps.some((step) => step.startsWith('end sessions'))).toBe(false);
    expect(steps).not.toContain('delete account tx');
  });

  it('refuses again under the lock an account that became an admin, before anything ends', async () => {
    await expect(
      run(requestWith({ grants: [{ revokedAt: null }] }), await versionOf({ enabled: true }))
    ).rejects.toBeInstanceOf(AccountDeletionConflictError);
    expect(steps.some((step) => step.startsWith('end sessions'))).toBe(false);
  });

  it("fails, so nothing commits, when the deletion's own guard refuses", async () => {
    await expect(
      run(requestWith({ deleted: false }), await versionOf({ enabled: true }))
    ).rejects.toBeInstanceOf(PreconditionFailedError);
    expect(steps.some((step) => step.startsWith('event'))).toBe(false);
  });
});
