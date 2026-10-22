import { and, asc, desc, eq, gt, sql } from 'drizzle-orm';

import type {
  AdminAuditChainBreakReason,
  AdminAuditChainReport,
  AdminAuditEntry,
  AdminAuditLogOptions,
  AdminAuditLogRepository,
  AdminAuditRecord,
  Database,
  DbClient,
  DbTransaction,
} from '../../types';
import { canonicalizeJson } from '../admin-audit/canonical-json';
import { maskSecrets } from '../admin-audit/mask-secrets';
import {
  ADMIN_AUDIT_GENESIS_HASH,
  type AdminAuditRowContent,
  computeAdminAuditRowHash,
} from '../admin-audit/row-hash';
import type {
  AdminAuditActChain,
  AdminAuditActClaim,
  AdminAuditApproval,
} from '../admin-audit/types';
import { adminAuditLog, adminAuditLogCheckpoints } from '../schema/admin-audit';

/**
 * A UUID in the hyphenated form. Postgres also accepts braces and missing
 * hyphens, but prints only this form, lower case; the hash covers the id as
 * Postgres prints it, so anything else is refused here.
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const DEFAULT_VERIFY_BATCH_SIZE = 500;

/**
 * The `varchar` limits of the text columns. Postgres cuts an over-long value
 * silently when the excess is spaces, which would store something other than
 * what was hashed, so a longer value is refused here instead.
 */
const MAX_LENGTH = { actorId: 255, operationId: 128, traceId: 128 } as const;

function canonicalUuid(value: string, field: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new TypeError(`admin audit log: ${field} is not a UUID`);
  }
  return value.toLowerCase();
}

/**
 * The realm's chain lock, transaction-scoped. `admin_audit_log_prune` takes
 * the same key, from the same expression, so neither interleaves with the
 * other.
 */
async function lockRealmChain(tx: DbTransaction, realmId: string): Promise<void> {
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended('qauth:admin-audit:' || (${realmId})::uuid::text, 0))`
  );
}

/** The `seq` and `row_hash` the next row follows: the newest row, else the newest checkpoint. */
async function readChainHead(
  tx: DbClient,
  realmId: string
): Promise<{ seq: number; rowHash: Buffer }> {
  const [row] = await tx
    .select({ seq: adminAuditLog.seq, rowHash: adminAuditLog.rowHash })
    .from(adminAuditLog)
    .where(eq(adminAuditLog.realmId, realmId))
    .orderBy(desc(adminAuditLog.seq))
    .limit(1);
  if (row) return row;
  const checkpoint = await readNewestCheckpoint(tx, realmId);
  return checkpoint ?? { seq: 0, rowHash: ADMIN_AUDIT_GENESIS_HASH };
}

async function readNewestCheckpoint(
  tx: DbClient,
  realmId: string
): Promise<{ seq: number; rowHash: Buffer } | undefined> {
  const [checkpoint] = await tx
    .select({ seq: adminAuditLogCheckpoints.seq, rowHash: adminAuditLogCheckpoints.rowHash })
    .from(adminAuditLogCheckpoints)
    .where(eq(adminAuditLogCheckpoints.realmId, realmId))
    .orderBy(desc(adminAuditLogCheckpoints.seq))
    .limit(1);
  return checkpoint;
}

function checkLength(field: keyof typeof MAX_LENGTH, value: string | null | undefined): void {
  // A JavaScript length counts UTF-16 units, at least the characters Postgres counts.
  if (value != null && value.length > MAX_LENGTH[field]) {
    throw new TypeError(`appendAdminAudit: ${field} is longer than ${MAX_LENGTH[field]}`);
  }
}

/**
 * The stored form of an act claim: its identity claims and the actor before
 * it, every link of the chain and nothing else. A member the type does not
 * name, which a caller could carry in from a decoded token, is not stored.
 */
function storedActClaim(claim: AdminAuditActClaim): AdminAuditActClaim {
  if (typeof claim.sub !== 'string' || claim.sub === '') {
    throw new TypeError('appendAdminAudit: every actor of the act chain needs a sub');
  }
  return {
    sub: claim.sub,
    ...(claim.iss !== undefined ? { iss: claim.iss } : {}),
    ...(claim.client_id !== undefined ? { client_id: claim.client_id } : {}),
    ...(claim.act !== undefined ? { act: storedActClaim(claim.act) } : {}),
  };
}

function storedActChain(chain: AdminAuditActChain | null | undefined): AdminAuditActChain | null {
  if (!chain) return null;
  if (typeof chain.sub !== 'string' || chain.sub === '' || !chain.act) {
    throw new TypeError('appendAdminAudit: an act chain needs the user acted for and an actor');
  }
  return { sub: chain.sub, act: storedActClaim(chain.act) };
}

/** The stored form of an approval: the four members the type names, nothing else. */
function storedApproval(approval: AdminAuditApproval): AdminAuditApproval {
  return {
    approverId: approval.approverId,
    credentialId: approval.credentialId,
    approverCreatedBy: approval.approverCreatedBy,
    approvedAt: approval.approvedAt,
  };
}

/**
 * The content of the row an entry becomes, without its place in the chain and
 * its time: ids in canonical form, the diff masked, the act chain and the
 * approvals with the members their types name.
 *
 * @throws TypeError on an entry that cannot be stored.
 */
function buildAdminAuditRowContent(
  entry: AdminAuditEntry
): Omit<AdminAuditRowContent, 'seq' | 'createdAt'> {
  const hostSide =
    entry.actorKind === 'break_glass_operator' || entry.actorKind === 'host_operator';
  if (hostSide !== (entry.actorRealmId === null)) {
    throw new TypeError(
      'appendAdminAudit: actorRealmId is required for an account actor and null for a host-side actor'
    );
  }
  if (entry.requestDigest && entry.requestDigest.length !== 32) {
    throw new TypeError('appendAdminAudit: requestDigest is not a SHA-256 digest');
  }
  checkLength('actorId', entry.actorId);
  checkLength('operationId', entry.operationId);
  checkLength('traceId', entry.traceId);
  const content = {
    realmId: canonicalUuid(entry.realmId, 'realmId'),
    actorKind: entry.actorKind,
    actorId: entry.actorId,
    actorRealmId:
      entry.actorRealmId === null ? null : canonicalUuid(entry.actorRealmId, 'actorRealmId'),
    actChain: storedActChain(entry.actChain),
    operationId: entry.operationId,
    operationClass: entry.operationClass,
    effects: [...(entry.effects ?? [])],
    outcome: entry.outcome,
    maskedDiff: entry.diff ? maskSecrets(entry.diff.change, entry.diff.annotations) : null,
    approvals: (entry.approvals ?? []).map(storedApproval),
    requestDigest: entry.requestDigest ?? null,
    traceId: entry.traceId ?? null,
  };
  // Every JSON column must canonicalize, or the row cannot be hashed.
  canonicalizeJson([content.actChain, content.effects, content.maskedDiff, content.approvals]);
  return content;
}

const hex = (hash: Buffer): string => hash.toString('hex');

/** Why a row does not continue the chain at `expectedSeq` after `expectedPrev`, if it does not. */
function checkRow(
  row: AdminAuditRecord,
  expectedSeq: number,
  expectedPrev: Buffer
): AdminAuditChainBreakReason | undefined {
  if (row.seq !== expectedSeq) return 'sequence_mismatch';
  if (!row.prevHash.equals(expectedPrev)) return 'prev_hash_mismatch';
  const { prevHash, rowHash, ...content } = row;
  let computed: Buffer;
  try {
    computed = computeAdminAuditRowHash(prevHash, content);
  } catch {
    return 'unhashable_row';
  }
  return computed.equals(rowHash) ? undefined : 'row_hash_mismatch';
}

/**
 * Factory for the admin audit log repository (ADR-019 Decision 7, ADR-020 §3,
 * issue #448).
 *
 * @param defaultDb - The root database: verification opens its own
 *   REPEATABLE READ transaction on it.
 * @param options - The outbox hook, the clock and the verification batch size.
 * @returns Repository implementing {@link AdminAuditLogRepository}
 */
export function createAdminAuditLogRepository(
  defaultDb: Database,
  options: AdminAuditLogOptions = {}
): AdminAuditLogRepository {
  const now = options.now ?? Date.now;
  const batchSize = options.verifyBatchSize ?? DEFAULT_VERIFY_BATCH_SIZE;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new TypeError(
      'createAdminAuditLogRepository: verifyBatchSize must be a positive integer'
    );
  }

  return {
    async appendAdminAudit(tx: DbTransaction, entry: AdminAuditEntry): Promise<AdminAuditRecord> {
      // Built and checked before the lock is taken, so a bad entry never waits for it.
      const draft = buildAdminAuditRowContent(entry);

      await lockRealmChain(tx, draft.realmId);
      const head = await readChainHead(tx, draft.realmId);
      const content: AdminAuditRowContent = { ...draft, seq: head.seq + 1, createdAt: now() };
      const rowHash = computeAdminAuditRowHash(head.rowHash, content);

      const [record] = await tx
        .insert(adminAuditLog)
        .values({ ...content, prevHash: head.rowHash, rowHash })
        .returning();

      // The row as Postgres stored it must hash to its row_hash, or the chain
      // would break at this row for good. Throwing here rolls it back with
      // the caller's change.
      const { prevHash: storedPrev, rowHash: storedHash, ...stored } = record;
      if (!computeAdminAuditRowHash(storedPrev, stored).equals(storedHash)) {
        throw new Error(
          'appendAdminAudit: the stored row does not hash to its row_hash; nothing was appended'
        );
      }

      await options.afterAppend?.(tx, record);
      return record;
    },

    async verifyAdminAuditChain(realmId: string): Promise<AdminAuditChainReport> {
      const realm = canonicalUuid(realmId, 'realmId');
      return defaultDb.transaction(
        async (tx) => {
          const anchor = await readNewestCheckpoint(tx, realm);
          const checkpoint = anchor ? { seq: anchor.seq, rowHash: hex(anchor.rowHash) } : null;

          let expectedSeq = anchor ? anchor.seq + 1 : 1;
          let expectedPrev = anchor ? anchor.rowHash : ADMIN_AUDIT_GENESIS_HASH;
          let rowsChecked = 0;
          let head: { seq: number; rowHash: string } | null = null;
          // Keyset paging from the oldest retained row, whatever the anchor
          // says, so a row left behind a checkpoint is reported too.
          let after = 0;

          for (;;) {
            const rows = await tx
              .select()
              .from(adminAuditLog)
              .where(and(eq(adminAuditLog.realmId, realm), gt(adminAuditLog.seq, after)))
              .orderBy(asc(adminAuditLog.seq))
              .limit(batchSize);

            for (const row of rows) {
              const reason = checkRow(row, expectedSeq, expectedPrev);
              if (reason) {
                return {
                  ok: false,
                  realmId: realm,
                  rowsChecked,
                  checkpoint,
                  break: {
                    seq: row.seq,
                    reason,
                    ...(reason === 'sequence_mismatch' ? { expectedSeq } : {}),
                  },
                };
              }

              rowsChecked += 1;
              expectedSeq = row.seq + 1;
              expectedPrev = row.rowHash;
              head = { seq: row.seq, rowHash: hex(row.rowHash) };
            }

            if (rows.length < batchSize) break;
            after = rows[rows.length - 1].seq;
          }

          return { ok: true, realmId: realm, rowsChecked, checkpoint, head };
        },
        { isolationLevel: 'repeatable read', accessMode: 'read only' }
      );
    },
  };
}
