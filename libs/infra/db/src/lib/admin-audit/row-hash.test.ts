import { createHash } from 'node:crypto';

import { getTableConfig } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';

import { adminAuditLog } from '../schema/admin-audit';
import {
  ADMIN_AUDIT_GENESIS_HASH,
  adminAuditHashPayload,
  type AdminAuditRowContent,
  computeAdminAuditRowHash,
} from './row-hash';

/**
 * The admin audit row hash (issue #448): SHA-256 over the previous hash and
 * the RFC 8785 canonical JSON of the row. These tests pin the chain format, so
 * a change to it shows up here before it breaks every stored chain.
 */
const ROW: AdminAuditRowContent = {
  realmId: '0192f1c4-1111-7000-8000-000000000001',
  seq: 1,
  actorKind: 'human_admin',
  actorId: '0192f1c4-2222-7000-8000-000000000002',
  actorRealmId: '0192f1c4-3333-7000-8000-000000000003',
  actChain: null,
  operationId: 'realms.policies.write',
  operationClass: 'write',
  effects: [],
  outcome: 'succeeded',
  maskedDiff: { before: { name: 'a' }, after: { name: 'b' } },
  approvals: [],
  requestDigest: Buffer.alloc(32, 0xab),
  traceId: 'trace-1',
  createdAt: 1_800_000_000_000,
};

describe('adminAuditHashPayload', () => {
  it('covers every column of admin_audit_log except the two hashes', () => {
    const columns = getTableConfig(adminAuditLog).columns.map((column) => column.name);
    const hashed = Object.keys(adminAuditHashPayload(ROW));

    expect([...hashed, 'prev_hash', 'row_hash'].sort()).toEqual([...columns].sort());
  });
});

describe('computeAdminAuditRowHash', () => {
  it('is SHA-256 over prev_hash and the canonical JSON of the row (format version 1)', () => {
    const canonical =
      '{"act_chain":null,"actor_id":"0192f1c4-2222-7000-8000-000000000002","actor_kind":"human_admin",' +
      '"actor_realm_id":"0192f1c4-3333-7000-8000-000000000003","approvals":[],"created_at":1800000000000,' +
      '"effects":[],"masked_diff":{"after":{"name":"b"},"before":{"name":"a"}},' +
      '"operation_class":"write","operation_id":"realms.policies.write","outcome":"succeeded",' +
      `"realm_id":"0192f1c4-1111-7000-8000-000000000001","request_digest":"${'ab'.repeat(32)}",` +
      '"seq":1,"trace_id":"trace-1"}';
    const expected = createHash('sha256')
      .update(ADMIN_AUDIT_GENESIS_HASH)
      .update(canonical, 'utf8')
      .digest();

    expect(computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, ROW).equals(expected)).toBe(true);
  });

  it('does not depend on the member order of the JSON columns', () => {
    const reordered: AdminAuditRowContent = {
      ...ROW,
      maskedDiff: { after: { name: 'b' }, before: { name: 'a' } },
    };

    expect(
      computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, reordered).equals(
        computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, ROW)
      )
    ).toBe(true);
  });

  it('changes when the previous hash changes', () => {
    expect(
      computeAdminAuditRowHash(Buffer.alloc(32, 1), ROW).equals(
        computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, ROW)
      )
    ).toBe(false);
  });

  it.each<[string, Partial<AdminAuditRowContent>]>([
    ['realmId', { realmId: '0192f1c4-1111-7000-8000-00000000000f' }],
    ['seq', { seq: 2 }],
    ['actorKind', { actorKind: 'service_account' }],
    ['actorId', { actorId: 'someone-else' }],
    ['actorRealmId', { actorRealmId: null }],
    ['actChain', { actChain: { sub: 'u', act: { sub: 'a' } } }],
    ['operationId', { operationId: 'realms.read' }],
    ['operationClass', { operationClass: 'security' }],
    ['effects', { effects: ['credentials'] }],
    ['outcome', { outcome: 'denied' }],
    ['maskedDiff', { maskedDiff: null }],
    [
      'approvals',
      {
        approvals: [{ approverId: 'a', credentialId: 'c', approverCreatedBy: null, approvedAt: 1 }],
      },
    ],
    ['requestDigest', { requestDigest: null }],
    ['traceId', { traceId: null }],
    ['createdAt', { createdAt: 1_800_000_000_001 }],
  ])('changes when %s changes', (_column, change) => {
    expect(
      computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, { ...ROW, ...change }).equals(
        computeAdminAuditRowHash(ADMIN_AUDIT_GENESIS_HASH, ROW)
      )
    ).toBe(false);
  });
});
