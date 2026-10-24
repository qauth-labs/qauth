import { createHash } from 'node:crypto';

import type { AdminAuditRecord } from '../../types';
import { canonicalizeJson } from './canonical-json';

/** A row's content: every column but the two hashes. */
export type AdminAuditRowContent = Omit<AdminAuditRecord, 'prevHash' | 'rowHash'>;

/** `prev_hash` of a realm's first row: 32 zero bytes. */
export const ADMIN_AUDIT_GENESIS_HASH: Buffer = Buffer.alloc(32);

/**
 * The chain format's id, hashed first, so a hash says which format made it.
 * A QAuth-defined version, so a release candidate until QAuth 1.0.0
 * (ADR-018 §5): a change to what the hash covers raises `<M>`, and the
 * release that ships 1.0.0 drops the suffix.
 */
export const ADMIN_AUDIT_CHAIN_FORMAT = 'qauth-admin-audit-chain/1-rc.0';

/**
 * The object a row's hash covers: every column but `prev_hash` and
 * `row_hash`, under its column name, with `null` for an empty column. The
 * column names make the hash checkable from the table alone; `bytea` is
 * lowercase hex and a `uuid` its lowercase text form, as Postgres prints them.
 *
 * Changing this shape changes every hash and raises the release candidate
 * of {@link ADMIN_AUDIT_CHAIN_FORMAT}, so a unit test pins it to the table's
 * columns.
 */
export function adminAuditHashPayload(row: AdminAuditRowContent): Record<string, unknown> {
  return {
    realm_id: row.realmId,
    seq: row.seq,
    actor_kind: row.actorKind,
    actor_id: row.actorId,
    actor_realm_id: row.actorRealmId ?? null,
    act_chain: row.actChain ?? null,
    operation_id: row.operationId,
    operation_class: row.operationClass,
    effects: row.effects,
    outcome: row.outcome,
    masked_diff: row.maskedDiff ?? null,
    approvals: row.approvals,
    request_digest: row.requestDigest ? row.requestDigest.toString('hex') : null,
    trace_id: row.traceId ?? null,
    created_at: row.createdAt,
  };
}

/**
 * A row's `row_hash`: SHA-256 over {@link ADMIN_AUDIT_CHAIN_FORMAT} and a NUL
 * byte, the 32 bytes of `prev_hash`, and the UTF-8 bytes of the RFC 8785
 * canonical JSON of {@link adminAuditHashPayload}. `1-rc.0` is the first
 * format with an id; no deployment held a row chained before it.
 *
 * @throws TypeError when a JSON column holds a value outside the I-JSON model.
 */
export function computeAdminAuditRowHash(prevHash: Buffer, row: AdminAuditRowContent): Buffer {
  return createHash('sha256')
    .update(`${ADMIN_AUDIT_CHAIN_FORMAT}\0`, 'utf8')
    .update(prevHash)
    .update(canonicalizeJson(adminAuditHashPayload(row)), 'utf8')
    .digest();
}
