import { createHash } from 'node:crypto';

import type { EventEnvelope } from '@qauth-labs/shared-events';
import { afterEach, describe, expect, it, vi } from 'vitest';

const userInfo = vi.hoisted(() => vi.fn());
vi.mock('node:os', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:os')>()),
  userInfo,
}));

import { EVENT_CHAIN_GENESIS_HASH, eventChainHash, operatorCliActor } from './chain';

/**
 * The admin chain's hash (issues #459 and #827): SHA-256 over the previous
 * hash, the row's xid as 8 bytes and the RFC 8785 canonical JSON of the
 * envelope. The container suite proves it over rows Postgres stored.
 */

const XID = 905n;

const ENVELOPE: EventEnvelope = {
  id: '0192f1c4-9999-7000-8000-000000000009',
  type: 'urn:qauth:event:admin.change_applied:v1-rc.0',
  time: '2026-10-24T12:00:00.000Z',
  realm: '0192f1c4-1111-7000-8000-000000000001',
  category: 'admin',
  actor: { type: 'operator_cli', id: 'root' },
  data: {
    operation: 'realms.mail.write',
    target: { type: 'realm', id: '0192f1c4-1111-7000-8000-000000000001' },
    diff: [{ path: '/fromName', before: 'QAuth', after: 'Ops' }],
    approvals: [],
  },
};

describe('eventChainHash', () => {
  it('is SHA-256 over the previous hash, the xid and the canonical JSON of the envelope', () => {
    // Members sorted by name, no whitespace: RFC 8785.
    const canonical =
      '{"actor":{"id":"root","type":"operator_cli"},"category":"admin",' +
      '"data":{"approvals":[],"diff":[{"after":"Ops","before":"QAuth","path":"/fromName"}],' +
      '"operation":"realms.mail.write","target":{"id":"0192f1c4-1111-7000-8000-000000000001","type":"realm"}},' +
      '"id":"0192f1c4-9999-7000-8000-000000000009","realm":"0192f1c4-1111-7000-8000-000000000001",' +
      '"time":"2026-10-24T12:00:00.000Z","type":"urn:qauth:event:admin.change_applied:v1-rc.0"}';
    const expected = createHash('sha256')
      .update(EVENT_CHAIN_GENESIS_HASH)
      // 905 as an unsigned 64-bit big-endian integer.
      .update(Buffer.from('0000000000000389', 'hex'))
      .update(canonical, 'utf8')
      .digest();
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, XID, ENVELOPE)).toEqual(expected);
  });

  it('changes with the previous hash, the xid and any member of the envelope', () => {
    const base = eventChainHash(EVENT_CHAIN_GENESIS_HASH, XID, ENVELOPE);
    expect(eventChainHash(Buffer.alloc(32, 1), XID, ENVELOPE)).not.toEqual(base);
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, XID - 1n, ENVELOPE)).not.toEqual(base);
    expect(
      eventChainHash(EVENT_CHAIN_GENESIS_HASH, XID, {
        ...ENVELOPE,
        time: '2026-10-24T12:00:00.001Z',
      })
    ).not.toEqual(base);
    expect(
      eventChainHash(EVENT_CHAIN_GENESIS_HASH, XID, {
        ...ENVELOPE,
        data: { ...ENVELOPE.data, approvals: [{ approverId: 'a' }] },
      })
    ).not.toEqual(base);
  });

  it('takes every xid8, from 0 to 2^64 - 1, and nothing else', () => {
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, 0n, ENVELOPE)).toHaveLength(32);
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, (1n << 64n) - 1n, ENVELOPE)).toHaveLength(32);
    for (const xid of [-1n, 1n << 64n, 905 as unknown as bigint]) {
      expect(() => eventChainHash(EVENT_CHAIN_GENESIS_HASH, xid, ENVELOPE)).toThrow(/xid8/);
    }
  });

  it('starts every chain at 32 zero bytes', () => {
    expect(EVENT_CHAIN_GENESIS_HASH).toEqual(Buffer.alloc(32));
  });

  it('refuses a previous hash that is not a SHA-256 digest', () => {
    expect(() => eventChainHash(Buffer.alloc(31), XID, ENVELOPE)).toThrow(TypeError);
  });
});

describe('operatorCliActor', () => {
  afterEach(() => userInfo.mockReset());

  // The acceptance of #459's CLI task: a command-line tool records the
  // operating-system user as an operator_cli actor.
  it('names the operating-system user', () => {
    userInfo.mockReturnValue({ username: 'deploy' });
    expect(operatorCliActor()).toEqual({ type: 'operator_cli', id: 'deploy' });
  });

  it('falls back to the uid when the user has no name', () => {
    userInfo.mockImplementation(() => {
      throw new Error('ENOENT: no passwd entry');
    });
    expect(operatorCliActor()).toEqual({
      type: 'operator_cli',
      id: `uid:${process.getuid?.() ?? 'unknown'}`,
    });
  });
});
