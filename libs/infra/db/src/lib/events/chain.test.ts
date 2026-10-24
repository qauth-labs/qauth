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
 * The admin chain's hash (issue #459): SHA-256 over the previous hash and the
 * RFC 8785 canonical JSON of the envelope. The container suite proves it over
 * rows Postgres stored.
 */

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
  it('is SHA-256 over the previous hash and the canonical JSON of the envelope', () => {
    // Members sorted by name, no whitespace: RFC 8785.
    const canonical =
      '{"actor":{"id":"root","type":"operator_cli"},"category":"admin",' +
      '"data":{"approvals":[],"diff":[{"after":"Ops","before":"QAuth","path":"/fromName"}],' +
      '"operation":"realms.mail.write","target":{"id":"0192f1c4-1111-7000-8000-000000000001","type":"realm"}},' +
      '"id":"0192f1c4-9999-7000-8000-000000000009","realm":"0192f1c4-1111-7000-8000-000000000001",' +
      '"time":"2026-10-24T12:00:00.000Z","type":"urn:qauth:event:admin.change_applied:v1-rc.0"}';
    const expected = createHash('sha256')
      .update(EVENT_CHAIN_GENESIS_HASH)
      .update(canonical, 'utf8')
      .digest();
    expect(eventChainHash(EVENT_CHAIN_GENESIS_HASH, ENVELOPE)).toEqual(expected);
  });

  it('changes with the previous hash and with any member of the envelope', () => {
    const base = eventChainHash(EVENT_CHAIN_GENESIS_HASH, ENVELOPE);
    expect(eventChainHash(Buffer.alloc(32, 1), ENVELOPE)).not.toEqual(base);
    expect(
      eventChainHash(EVENT_CHAIN_GENESIS_HASH, { ...ENVELOPE, time: '2026-10-24T12:00:00.001Z' })
    ).not.toEqual(base);
    expect(
      eventChainHash(EVENT_CHAIN_GENESIS_HASH, {
        ...ENVELOPE,
        data: { ...ENVELOPE.data, approvals: [{ approverId: 'a' }] },
      })
    ).not.toEqual(base);
  });

  it('starts every chain at 32 zero bytes', () => {
    expect(EVENT_CHAIN_GENESIS_HASH).toEqual(Buffer.alloc(32));
  });

  it('refuses a previous hash that is not a SHA-256 digest', () => {
    expect(() => eventChainHash(Buffer.alloc(31), ENVELOPE)).toThrow(TypeError);
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
