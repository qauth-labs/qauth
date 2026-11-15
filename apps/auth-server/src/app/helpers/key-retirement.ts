import {
  type DeniedKid,
  KEY_RETIRE_OPERATION,
  type KeyRetirementRecord,
  type RetireNowInput,
  type SecurityOperationActor,
} from '@qauth-labs/fastify-plugin-signer';
import type { FastifyInstance } from 'fastify';

import { RESERVED_OPERATIONS } from './admin-operations-reserved';

/**
 * EMERGENCY KEY RETIREMENT, as the auth server runs it (ADR-019 Decisions 7
 * and 9, issue #551): the key library's `retireNow`, and what the auth
 * server does around it.
 *
 * In the transaction that marks the key compromised (and consumes the
 * approval):
 *
 * - every refresh family of the realm created or used since the key began to
 *   sign is revoked, Authority Trees included, as a token the key signed may
 *   have reached whoever holds it;
 * - a `key.emergency_retired` event names each retired `kid`: a critical
 *   admin event of the realm's audit chain, and a security event every SSF
 *   receiver of the realm gets, so a verifier outside QAuth drops the key
 *   before its JWKS cache expires;
 * - the admin audit log records the operation, its actor and its approval.
 *
 * After the commit, the node's copy of the `kid` denylist learns the retired
 * keys at once and the shared snapshot is replaced from the database, so
 * every node refuses their tokens within seconds; then every browser session
 * of the realm used since the key may have signed is ended, in batches, each
 * batch writing the back-channel logout notices of the clients it served.
 *
 * The break-glass command (`keys-retire.ts`) runs it today. A signer node
 * holds `fastify.keyRotation.retireNow` too, but no route calls it yet: the
 * admin route that will must run it under a database role that may revoke
 * refresh tokens and write the admin audit log, which the signer's may not.
 */

type Repositories = FastifyInstance['repositories'];
type AdminAuditLog = Repositories['adminAuditLog'];

/** One row of the admin audit log, as the repository takes it. */
type AdminAuditEntry = Parameters<AdminAuditLog['appendAdminAudit']>[1];

/** The transaction the admin audit log writes in. */
type DbTransaction = Parameters<AdminAuditLog['appendAdminAudit']>[0];

/**
 * The database client the key library hands its hook: the retirement's
 * transaction, as the key store runs every one in `db.transaction`.
 */
type DbClient = NonNullable<
  Parameters<Repositories['refreshTokens']['revokeFamiliesOfRealmActiveSince']>[3]
>;

type SessionService = FastifyInstance['sessionService'];

/** What the refresh families' sweep did. */
type FamiliesRevocation = Awaited<
  ReturnType<Repositories['refreshTokens']['revokeFamiliesOfRealmActiveSince']>
>;

/** What the browser sessions' sweep did. */
type SessionsRevocation = Awaited<ReturnType<SessionService['revokeAllForRealm']>>;

/** The effects of `keys.retire`, as the reserved operation ids name them. */
export const KEY_RETIRE_EFFECTS = (() => {
  const reserved = RESERVED_OPERATIONS.find((entry) => entry.id === KEY_RETIRE_OPERATION);
  if (reserved === undefined) throw new Error(`'${KEY_RETIRE_OPERATION}' is not reserved`);
  return reserved.effects;
})();

/** Why a refresh token or a session of the retired key's realm was revoked. */
export const KEY_RETIRED_REASON = 'key_retired';

/** The event type an emergency retirement records, once per retired `kid`. */
export const KEY_EMERGENCY_RETIRED_EVENT = 'urn:qauth:event:key.emergency_retired:v1-rc.0' as const;

/** What a retirement reads and writes. */
export interface KeyRetirementDependencies {
  /**
   * The key library's `retireNow`: `fastify.keyRotation.retireNow` on a
   * signer node, `retireKey` of the signer's wiring for the break-glass
   * command.
   */
  readonly retire: (input: RetireNowInput<DbClient>) => Promise<KeyRetirementRecord>;
  readonly refreshTokens: Pick<Repositories['refreshTokens'], 'revokeFamiliesOfRealmActiveSince'>;
  readonly events: Pick<Repositories['events'], 'emit'>;
  readonly adminAuditLog: Pick<AdminAuditLog, 'appendAdminAudit'>;
  readonly sessions: Pick<SessionService, 'revokeAllForRealm'>;
  /**
   * After the commit: deny the retired `kid`s on this node's copy, and
   * replace the shared snapshot (`invalidateKeyDenylist`). It must not throw.
   */
  readonly invalidateDenylist: (retired: readonly DeniedKid[]) => Promise<void>;
}

/** Which key to retire, and the approval of exactly that. */
export interface RetireKeyNowInput {
  readonly realmId: string;
  readonly kid: string;
  readonly approval: RetireNowInput<DbClient>['approval'];
  /** The clock, in epoch ms. Defaults to `Date.now`. */
  readonly now?: () => number;
}

/** What a retirement did. */
export interface KeyRetirementOutcome {
  readonly record: KeyRetirementRecord;
  /** The refresh families revoked, with their tokens, in the retirement's transaction. */
  readonly families: FamiliesRevocation;
  /** The browser sessions ended after the commit. */
  readonly sessions: SessionsRevocation;
}

/** The event actor of a security operation's requester. */
export function eventActorOf(actor: SecurityOperationActor) {
  return actor.kind === 'break_glass'
    ? { type: 'operator_cli' as const, id: actor.operatingSystemUser }
    : { type: 'user' as const, id: actor.accountId };
}

/** The `key.emergency_retired` event of one retired key. */
export function emergencyRetiredEvent(
  record: Pick<KeyRetirementRecord, 'realmId' | 'actor' | 'purpose'>,
  kid: string
) {
  return {
    type: KEY_EMERGENCY_RETIRED_EVENT,
    realm: record.realmId,
    actor: eventActorOf(record.actor),
    data: { keyId: kid, purpose: record.purpose as 'token_signing' },
  };
}

/**
 * The admin audit row of a retirement: the operation `keys.retire` with its
 * effects, the actor, the keys before and after, the operation digest and
 * the approval id. ADR-019 Decision 7: a break-glass run stands outside the
 * approval rule and is recorded, with the operating-system user.
 *
 * @throws TypeError for a requester that is not the break-glass operator:
 *   the admin API records its own operations
 */
export function keyRetirementAuditEntry(record: KeyRetirementRecord): AdminAuditEntry {
  const { actor } = record;
  if (actor.kind !== 'break_glass') {
    throw new TypeError('Only a break-glass retirement is recorded here');
  }
  return {
    realmId: record.realmId,
    actorKind: 'break_glass_operator',
    actorId: actor.operatingSystemUser,
    actorRealmId: null,
    actChain: null,
    operationId: KEY_RETIRE_OPERATION,
    operationClass: 'security',
    effects: KEY_RETIRE_EFFECTS,
    outcome: 'succeeded',
    diff: {
      change: {
        before: {
          keys: record.retired.map((key) => ({
            kid: key.kid,
            algorithm: key.algorithm,
            status: key.previousStatus,
          })),
        },
        after: {
          keys: [
            ...record.retired.map((key) => ({
              kid: key.kid,
              algorithm: key.algorithm,
              status: 'compromised',
            })),
            ...record.replacements.map((key) => ({
              kid: key.kid,
              algorithm: key.algorithm,
              status: 'active',
            })),
          ],
        },
      },
      annotations: {},
    },
    approvals: [],
    requestDigest: Buffer.from(record.operationDigest),
    traceId: record.approvalId,
  };
}

/**
 * A break-glass run for a key compromised already (ADR-019 Decision 7: each
 * use is recorded and announced): it changes no key, and ends the realm's
 * sessions used since the key may have signed again.
 */
export interface KeyRetirementRepeat {
  readonly realmId: string;
  readonly kid: string;
  readonly algorithm: string;
  readonly actor: Extract<SecurityOperationActor, { kind: 'break_glass' }>;
  /** The host approval the run was made under, and the digest of its operation. */
  readonly approvalId: string;
  readonly operationDigest: Buffer;
  /** Epoch ms, or `null` for a key that never signed: no session is ended. */
  readonly signedSince: number | null;
}

/** The admin audit row of a run again: the operation, its actor, the key compromised before and after. */
export function keyRetirementRepeatAuditEntry(repeat: KeyRetirementRepeat): AdminAuditEntry {
  const keys = [{ kid: repeat.kid, algorithm: repeat.algorithm, status: 'compromised' }];
  return {
    realmId: repeat.realmId,
    actorKind: 'break_glass_operator',
    actorId: repeat.actor.operatingSystemUser,
    actorRealmId: null,
    actChain: null,
    operationId: KEY_RETIRE_OPERATION,
    operationClass: 'security',
    effects: KEY_RETIRE_EFFECTS,
    outcome: 'succeeded',
    diff: { change: { before: { keys }, after: { keys } }, annotations: {} },
    approvals: [],
    requestDigest: Buffer.from(repeat.operationDigest),
    traceId: repeat.approvalId,
  };
}

/**
 * Record a run again in one transaction: its admin audit row and the
 * critical `key.emergency_retired` event of the key, which every event route
 * sends again. `before`, when given, writes first in the same transaction:
 * the break-glass CLI's record of its run (#602).
 */
export async function recordKeyRetirementRepeat(
  deps: {
    readonly transaction: <T>(run: (tx: DbTransaction) => Promise<T>) => Promise<T>;
    readonly events: Pick<Repositories['events'], 'emit'>;
    readonly adminAuditLog: Pick<AdminAuditLog, 'appendAdminAudit'>;
  },
  repeat: KeyRetirementRepeat,
  before?: (tx: DbTransaction) => Promise<void>
): Promise<void> {
  await deps.transaction(async (tx) => {
    await before?.(tx);
    await deps.events.emit(
      tx,
      emergencyRetiredEvent({ ...repeat, purpose: 'token_signing' }, repeat.kid)
    );
    await deps.adminAuditLog.appendAdminAudit(tx, keyRetirementRepeatAuditEntry(repeat));
  });
}

/**
 * Retire `input.kid` of the realm in an emergency, and revoke what its
 * tokens may have reached. See the module comment.
 *
 * The browser sessions are ended after the commit, so a failure there leaves
 * the key retired: the call then rejects with that error, and running the
 * session sweep again ({@link revokeSessionsOfRetiredKey}) finishes it.
 *
 * @throws the refusals of `retireNow` (`OperationApprovalError`,
 *   `KeyChangeRefusedError`) with nothing changed, and its faults
 */
export async function retireKeyNow(
  deps: KeyRetirementDependencies,
  input: RetireKeyNowInput
): Promise<KeyRetirementOutcome> {
  let families: FamiliesRevocation = { families: 0, tokens: 0 };
  const record = await deps.retire({
    realmId: input.realmId,
    kid: input.kid,
    approval: input.approval,
    ...(input.now === undefined ? {} : { now: input.now }),
    onRetired: async (retired, client) => {
      // The key store runs the hook inside its transaction, which the event
      // log and the audit log write in.
      const tx = client as DbTransaction;
      if (retired.signedSince !== null) {
        families = await deps.refreshTokens.revokeFamiliesOfRealmActiveSince(
          retired.realmId,
          retired.signedSince,
          KEY_RETIRED_REASON,
          tx
        );
      }
      for (const key of retired.retired) {
        await deps.events.emit(tx, emergencyRetiredEvent(retired, key.kid));
      }
      await deps.adminAuditLog.appendAdminAudit(tx, keyRetirementAuditEntry(retired));
    },
  });
  await deps.invalidateDenylist(
    record.retired.map((key) => ({ realmId: record.realmId, kid: key.kid }))
  );
  const sessions = await revokeSessionsOfRetiredKey(deps.sessions, record);
  return Object.freeze({ record, families, sessions });
}

/**
 * End every browser session of the realm used since the retired key began to
 * sign, as `retireKeyNow` does after its commit. Safe to repeat.
 */
export async function revokeSessionsOfRetiredKey(
  sessions: Pick<SessionService, 'revokeAllForRealm'>,
  record: Pick<KeyRetirementRecord, 'realmId' | 'signedSince' | 'actor'>
): Promise<SessionsRevocation> {
  if (record.signedSince === null) return { ended: 0, batches: 0 };
  return sessions.revokeAllForRealm({
    realmId: record.realmId,
    activeSince: record.signedSince,
    reason: KEY_RETIRED_REASON,
    actor: eventActorOf(record.actor),
  });
}
