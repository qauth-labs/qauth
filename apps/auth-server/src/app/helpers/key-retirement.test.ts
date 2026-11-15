import {
  KEY_RETIRE_OPERATION,
  type KeyRetirementRecord,
  type RetireNowInput,
} from '@qauth-labs/fastify-plugin-signer';
import { describe, expect, it, vi } from 'vitest';

import { RESERVED_OPERATIONS } from './admin-operations-reserved';
import {
  emergencyRetiredEvent,
  eventActorOf,
  KEY_EMERGENCY_RETIRED_EVENT,
  KEY_RETIRED_REASON,
  keyRetirementAuditEntry,
  type KeyRetirementDependencies,
  type KeyRetirementRepeat,
  keyRetirementRepeatAuditEntry,
  recordKeyRetirementRepeat,
  retireKeyNow,
  revokeSessionsOfRetiredKey,
} from './key-retirement';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const ACCOUNT = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ecc';
const ACTIVATED = 1_790_000_000_000;
/** Stands for the retirement's transaction. */
const TX = Object.freeze({ transaction: 'retire' });

const RECORD: KeyRetirementRecord = {
  operation: KEY_RETIRE_OPERATION,
  approvalId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6ebb',
  actor: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
  operationDigest: Buffer.alloc(32, 0xab),
  realmId: REALM,
  purpose: 'token_signing',
  kid: 'ed-1',
  retiredAt: 1_800_000_000_000,
  retired: [
    { kid: 'ed-1', algorithm: 'EdDSA', previousStatus: 'active', activateAt: ACTIVATED },
    { kid: 'ml-1', algorithm: 'ML-DSA-65', previousStatus: 'active', activateAt: ACTIVATED },
  ],
  replacements: [
    { kid: 'ed-2', algorithm: 'EdDSA' },
    { kid: 'ml-2', algorithm: 'ML-DSA-65' },
  ],
  signedSince: ACTIVATED,
};

/** A retirement over fakes, whose `retire` runs the hook in `TX` and returns `record`. */
function world(record: KeyRetirementRecord = RECORD) {
  const calls: string[] = [];
  const deps = {
    retire: vi.fn(async (input: RetireNowInput<never>) => {
      calls.push('retire');
      await input.onRetired(record, TX as never);
      calls.push('commit');
      return record;
    }),
    refreshTokens: {
      revokeFamiliesOfRealmActiveSince: vi.fn(async () => {
        calls.push('families');
        return { families: 3, tokens: 7 };
      }),
    },
    events: {
      emit: vi.fn(async () => {
        calls.push('event');
        return 'event-id';
      }),
    },
    adminAuditLog: {
      appendAdminAudit: vi.fn(async () => {
        calls.push('audit');
      }),
    },
    sessions: {
      revokeAllForRealm: vi.fn(async () => {
        calls.push('sessions');
        return { ended: 5, batches: 1 };
      }),
    },
    invalidateDenylist: vi.fn(async () => {
      calls.push('denylist');
    }),
  };
  return { calls, deps: deps as typeof deps & KeyRetirementDependencies };
}

const APPROVAL = {} as RetireNowInput<never>['approval'];

describe('retireKeyNow (#551)', () => {
  it('revokes the families, emits one critical event per retired kid and records the run in the transaction, then denies the kids and ends the sessions', async () => {
    const { calls, deps } = world();

    const outcome = await retireKeyNow(deps, { realmId: REALM, kid: 'ed-1', approval: APPROVAL });

    expect(calls).toEqual([
      'retire',
      'families',
      'event',
      'event',
      'audit',
      'commit',
      'denylist',
      'sessions',
    ]);
    expect(deps.retire.mock.calls[0]?.[0]).toMatchObject({
      realmId: REALM,
      kid: 'ed-1',
      approval: APPROVAL,
    });
    expect(deps.refreshTokens.revokeFamiliesOfRealmActiveSince).toHaveBeenCalledWith(
      REALM,
      ACTIVATED,
      KEY_RETIRED_REASON,
      TX
    );
    expect(deps.events.emit.mock.calls).toEqual([
      [TX, emergencyRetiredEvent(RECORD, 'ed-1')],
      [TX, emergencyRetiredEvent(RECORD, 'ml-1')],
    ]);
    expect(deps.adminAuditLog.appendAdminAudit).toHaveBeenCalledWith(
      TX,
      keyRetirementAuditEntry(RECORD)
    );
    expect(deps.invalidateDenylist).toHaveBeenCalledWith([
      { realmId: REALM, kid: 'ed-1' },
      { realmId: REALM, kid: 'ml-1' },
    ]);
    expect(deps.sessions.revokeAllForRealm).toHaveBeenCalledWith({
      realmId: REALM,
      activeSince: ACTIVATED,
      reason: KEY_RETIRED_REASON,
      actor: { type: 'operator_cli', id: 'qauth-ops' },
    });
    expect(outcome).toEqual({
      record: RECORD,
      families: { families: 3, tokens: 7 },
      sessions: { ended: 5, batches: 1 },
    });
  });

  it('revokes nothing for a key that never signed, and still announces and records it', async () => {
    const next: KeyRetirementRecord = {
      ...RECORD,
      retired: [{ kid: 'ed-1', algorithm: 'EdDSA', previousStatus: 'next', activateAt: null }],
      replacements: [],
      signedSince: null,
    };
    const { calls, deps } = world(next);

    const outcome = await retireKeyNow(deps, { realmId: REALM, kid: 'ed-1', approval: APPROVAL });

    expect(calls).toEqual(['retire', 'event', 'audit', 'commit', 'denylist']);
    expect(outcome.families).toEqual({ families: 0, tokens: 0 });
    expect(outcome.sessions).toEqual({ ended: 0, batches: 0 });
  });

  it('rejects with nothing after the commit when the transaction fails', async () => {
    const { deps } = world();
    deps.events.emit.mockRejectedValueOnce(new Error('event log refused'));

    await expect(
      retireKeyNow(deps, { realmId: REALM, kid: 'ed-1', approval: APPROVAL })
    ).rejects.toThrow('event log refused');
    expect(deps.invalidateDenylist).not.toHaveBeenCalled();
    expect(deps.sessions.revokeAllForRealm).not.toHaveBeenCalled();
  });

  it('rejects when the session sweep fails, once the kids were denied', async () => {
    const { deps } = world();
    deps.sessions.revokeAllForRealm.mockRejectedValueOnce(new Error('sessions down'));

    await expect(
      retireKeyNow(deps, { realmId: REALM, kid: 'ed-1', approval: APPROVAL })
    ).rejects.toThrow('sessions down');
    expect(deps.invalidateDenylist).toHaveBeenCalledTimes(1);
  });
});

describe('the records of a retirement', () => {
  it('names the event actor of either requester', () => {
    expect(eventActorOf({ kind: 'break_glass', operatingSystemUser: 'qauth-ops' })).toEqual({
      type: 'operator_cli',
      id: 'qauth-ops',
    });
    expect(eventActorOf({ kind: 'human', realmId: REALM, accountId: ACCOUNT })).toEqual({
      type: 'user',
      id: ACCOUNT,
    });
  });

  it('announces the kid and its purpose as key.emergency_retired in the realm', () => {
    expect(emergencyRetiredEvent(RECORD, 'ml-1')).toEqual({
      type: KEY_EMERGENCY_RETIRED_EVENT,
      realm: REALM,
      actor: { type: 'operator_cli', id: 'qauth-ops' },
      data: { keyId: 'ml-1', purpose: 'token_signing' },
    });
  });

  it("records the operation's effects, its actor, the keys before and after, and its digest", () => {
    const entry = keyRetirementAuditEntry(RECORD);
    const reserved = RESERVED_OPERATIONS.find((operation) => operation.id === KEY_RETIRE_OPERATION);
    expect(entry).toMatchObject({
      realmId: REALM,
      actorKind: 'break_glass_operator',
      actorId: 'qauth-ops',
      actorRealmId: null,
      operationId: 'keys.retire',
      operationClass: 'security',
      effects: reserved?.effects,
      outcome: 'succeeded',
      approvals: [],
      traceId: RECORD.approvalId,
    });
    expect(entry.requestDigest).toEqual(RECORD.operationDigest);
    expect(entry.diff).toEqual({
      change: {
        before: {
          keys: [
            { kid: 'ed-1', algorithm: 'EdDSA', status: 'active' },
            { kid: 'ml-1', algorithm: 'ML-DSA-65', status: 'active' },
          ],
        },
        after: {
          keys: [
            { kid: 'ed-1', algorithm: 'EdDSA', status: 'compromised' },
            { kid: 'ml-1', algorithm: 'ML-DSA-65', status: 'compromised' },
            { kid: 'ed-2', algorithm: 'EdDSA', status: 'active' },
            { kid: 'ml-2', algorithm: 'ML-DSA-65', status: 'active' },
          ],
        },
      },
      annotations: {},
    });
  });

  it('records only a break-glass run: the admin API records its own', () => {
    expect(() =>
      keyRetirementAuditEntry({
        ...RECORD,
        actor: { kind: 'human', realmId: REALM, accountId: ACCOUNT },
      })
    ).toThrow(TypeError);
  });

  it('ends the sessions again on its own, and nothing for a key that never signed', async () => {
    const sessions = { revokeAllForRealm: vi.fn(async () => ({ ended: 2, batches: 1 })) };
    await expect(revokeSessionsOfRetiredKey(sessions, RECORD)).resolves.toEqual({
      ended: 2,
      batches: 1,
    });
    await expect(
      revokeSessionsOfRetiredKey(sessions, { ...RECORD, signedSince: null })
    ).resolves.toEqual({ ended: 0, batches: 0 });
    expect(sessions.revokeAllForRealm).toHaveBeenCalledTimes(1);
  });

  it('records a run again for a key compromised already, and announces it again, in one transaction', async () => {
    const repeat: KeyRetirementRepeat = {
      realmId: REALM,
      kid: 'ed-1',
      algorithm: 'EdDSA',
      actor: { kind: 'break_glass', operatingSystemUser: 'qauth-ops' },
      approvalId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6edd',
      operationDigest: Buffer.alloc(32, 0xcd),
      signedSince: ACTIVATED,
    };
    const entry = keyRetirementRepeatAuditEntry(repeat);
    expect(entry).toMatchObject({
      realmId: REALM,
      actorKind: 'break_glass_operator',
      actorId: 'qauth-ops',
      operationId: 'keys.retire',
      operationClass: 'security',
      outcome: 'succeeded',
      traceId: repeat.approvalId,
    });
    expect(entry.requestDigest).toEqual(repeat.operationDigest);
    const keys = [{ kid: 'ed-1', algorithm: 'EdDSA', status: 'compromised' }];
    expect(entry.diff).toEqual({ change: { before: { keys }, after: { keys } }, annotations: {} });

    const calls: string[] = [];
    const deps = {
      async transaction<T>(work: (tx: never) => Promise<T>): Promise<T> {
        calls.push('begin');
        const value = await work(TX as never);
        calls.push('commit');
        return value;
      },
      events: {
        emit: vi.fn(async () => {
          calls.push('event');
          return 'event-id';
        }),
      },
      adminAuditLog: {
        // The appended row: what the run does not read.
        appendAdminAudit: vi.fn(async () => {
          calls.push('audit');
          return {} as never;
        }),
      },
    };
    await recordKeyRetirementRepeat(deps, repeat);
    expect(calls).toEqual(['begin', 'event', 'audit', 'commit']);
    expect(deps.events.emit).toHaveBeenCalledWith(TX, {
      type: KEY_EMERGENCY_RETIRED_EVENT,
      realm: REALM,
      actor: { type: 'operator_cli', id: 'qauth-ops' },
      data: { keyId: 'ed-1', purpose: 'token_signing' },
    });
    expect(deps.adminAuditLog.appendAdminAudit).toHaveBeenCalledWith(TX, entry);
  });
});
