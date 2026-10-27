import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { type LocalHttpsFixture, startLocalHttpsFixture } from '../testing/loopback-fixture';
import { parseEgressAllowlist } from './allowlist';
import { createEgressClient, createTestEgressClient, type EgressClient } from './egress-client';
import { EgressError } from './errors';

/*
 * The test-only client factory (issue #481). It replaces the removed
 * CIMD_ALLOW_PRIVATE_ADDRESSES and ID_JAG_ALLOW_PRIVATE_ADDRESSES switches: a
 * test reaches a local fixture server through it, and nothing else does. The
 * production client below is the real one, over the real network and fetch
 * processes; nothing is mocked in this file.
 */

let fixture: LocalHttpsFixture;

beforeAll(async () => {
  fixture = await startLocalHttpsFixture();
});

afterAll(async () => {
  await fixture.close();
});

afterEach(() => {
  fixture.connections = 0;
  fixture.requests.length = 0;
});

const get = (egress: EgressClient, url: string) =>
  egress.request({ method: 'GET', url, purpose: 'test', source: 'client' });

/** The EgressError a call rejects with. */
async function refusal(call: Promise<unknown>): Promise<EgressError> {
  const err = await call.then(
    () => undefined,
    (e: unknown) => e
  );
  expect(err).toBeInstanceOf(EgressError);
  return err as EgressError;
}

/** Run `work` with NODE_ENV set to `value`, then put it back. */
async function withNodeEnv<T>(value: string | undefined, work: () => T | Promise<T>): Promise<T> {
  const before = process.env['NODE_ENV'];
  if (value === undefined) delete process.env['NODE_ENV'];
  else process.env['NODE_ENV'] = value;
  try {
    return await work();
  } finally {
    process.env['NODE_ENV'] = before;
  }
}

describe('a localhost fixture', () => {
  it('is reachable through the test client', async () => {
    const res = await get(createTestEgressClient(), `${fixture.origin}/doc.json`);
    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe('local fixture');
    expect(fixture.requests.map(({ url }) => url)).toEqual(['/doc.json']);
  });

  it('is refused by the production client, by address and by name', async () => {
    const egress = createEgressClient();
    const literal = await refusal(get(egress, `https://127.0.0.1:${fixture.port}/doc.json`));
    expect(literal).toMatchObject({ reason: 'address', outcome: 'blocked' });
    // `localhost` either does not resolve in DNS or resolves to loopback;
    // either way the call never reaches the fixture.
    await refusal(get(egress, `${fixture.origin}/doc.json`));
    expect(fixture.connections).toBe(0);
  });

  it('is refused by the production client for every source, whatever the allowlist names', async () => {
    const egress = createEgressClient({
      allowlist: parseEgressAllowlist({ entries: [{ host: 'localhost', realms: ['master'] }] }),
    });
    for (const source of ['client', 'end_user', 'remote_document'] as const) {
      await refusal(
        egress.request({
          method: 'GET',
          url: `https://127.0.0.1:${fixture.port}/`,
          purpose: 'test',
          source,
          realm: 'master',
        })
      );
    }
    expect(fixture.connections).toBe(0);
  });
});

describe('the test client', () => {
  it('keeps every other check: https only, no private or metadata address', async () => {
    const egress = createTestEgressClient();
    await expect(refusal(get(egress, `http://localhost:${fixture.port}/`))).resolves.toMatchObject({
      reason: 'scheme',
    });
    for (const url of [
      'https://10.0.0.7/',
      'https://169.254.169.254/',
      'https://[fd00:ec2::254]/',
    ]) {
      await expect(refusal(get(egress, url))).resolves.toMatchObject({
        reason: 'address',
        outcome: 'blocked',
      });
    }
    await expect(refusal(get(egress, 'https://0.0.0.0/'))).resolves.toMatchObject({
      reason: 'address',
    });
  });

  it.each(['production', 'development', undefined])(
    'cannot be created when NODE_ENV is %s',
    async (nodeEnv) => {
      await withNodeEnv(nodeEnv, () => {
        expect(() => createTestEgressClient()).toThrow(/for tests only/);
      });
    }
  );

  it('refuses every call once NODE_ENV is no longer test', async () => {
    const egress = createTestEgressClient();
    await withNodeEnv('production', async () => {
      await expect(get(egress, `${fixture.origin}/`)).rejects.toThrow(/for tests only/);
      await expect(
        egress.validateDestination(`${fixture.origin}/`, { purpose: 'test', source: 'client' })
      ).rejects.toThrow(/for tests only/);
    });
    expect(fixture.connections).toBe(0);
  });
});
