import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { type TestPolicyOverrides, testPolicyStore } from '../../testing/realm-policies';
import { testRealm } from '../../testing/request-realm';
import { createServerBreachedPasswords } from './breached-passwords';

const REALM = testRealm({ id: 'realm-1', name: 'northwind' });
const LISTED = 'correct horse battery staple';
const UNLISTED = 'a quiet violet tram crosses nine rivers';
/** The SHA-1 digests of the two passwords, written out as test vectors. */
const DIGESTS: Record<string, string> = {
  [LISTED]: 'ABF7AAD6438836DBE526AA231ABDE2D0EEF74D42',
  [UNLISTED]: '06285A265590D5E03A68C9C983E3E829D401C284',
};
const sha1 = (password: string): string => {
  const digest = DIGESTS[password];
  if (digest === undefined) throw new Error('no test vector for this password');
  return digest;
};

let directory: string;
let listPath: string;

beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'qauth-breach-'));
  listPath = join(directory, 'breached.txt');
  await writeFile(listPath, `${sha1(LISTED)}:3\n`);
});

afterAll(async () => {
  await rm(directory, { recursive: true, force: true });
});

function stub(source: 'off' | 'local' | 'k_anonymity', egress = vi.fn()) {
  const hooks: (() => Promise<void>)[] = [];
  const inc = vi.fn();
  const groups: TestPolicyOverrides = { password: { breachListSource: source } };
  const fastify = {
    egress: { request: egress },
    policyStore: testPolicyStore({}, groups),
    repositories: {
      realms: {
        findById: vi.fn(async (id: string) => (id === REALM.id ? REALM : undefined)),
      },
    },
    hasDecorator: (name: string) => name === 'metrics',
    metrics: { breachedPasswordChecks: { inc } },
    addHook: (name: string, hook: () => Promise<void>) => {
      if (name === 'onClose') hooks.push(hook);
    },
    log: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  };
  const close = async () => {
    for (const hook of hooks) await hook();
  };
  return { fastify: fastify as unknown as FastifyInstance, inc, close, log: fastify.log };
}

describe("the server's breach check (#635)", () => {
  it('checks nothing, and counts nothing, in a realm whose source is off', async () => {
    const { fastify, inc, close } = stub('off');
    const breached = await createServerBreachedPasswords(fastify, { listPath });
    expect(await breached.check(REALM, LISTED)).toEqual({ kind: 'off' });
    expect(await breached.engine.check({ realmId: REALM.id, password: LISTED })).toEqual({
      kind: 'off',
    });
    expect(inc).not.toHaveBeenCalled();
    await close();
  });

  it('loads the local list at boot and checks a local-list realm against it', async () => {
    const { fastify, inc, close, log } = stub('local');
    const breached = await createServerBreachedPasswords(fastify, { listPath });
    expect(log.info).toHaveBeenCalledWith(
      { trigger: 'boot', size: 1 },
      'breached-password list loaded'
    );
    expect(await breached.check(REALM, LISTED)).toEqual({ kind: 'listed', source: 'local' });
    expect(await breached.engine.check({ realmId: REALM.id, password: UNLISTED })).toEqual({
      kind: 'not_listed',
    });
    expect(inc.mock.calls).toEqual([
      [{ source: 'local', result: 'listed', reason: '' }],
      [{ source: 'local', result: 'not_listed', reason: '' }],
    ]);
    await close();
  });

  it('loads the list again once its file changes, and stops watching once closed', async () => {
    const { fastify, close, log } = stub('local');
    const breached = await createServerBreachedPasswords(fastify, { listPath, pollIntervalMs: 20 });
    await writeFile(listPath, `${sha1(LISTED)}\n${sha1(UNLISTED)}\n`);
    await vi.waitFor(
      () =>
        expect(log.info).toHaveBeenCalledWith(
          { trigger: 'change', size: 2 },
          'breached-password list loaded'
        ),
      { timeout: 5_000 }
    );
    expect(await breached.check(REALM, UNLISTED)).toEqual({ kind: 'listed', source: 'local' });
    await close();
    // Once closed, a change is no longer read.
    const loads = log.info.mock.calls.length;
    await writeFile(listPath, `${sha1(LISTED)}:3\n`);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(log.info.mock.calls.length).toBe(loads);
  });

  it('fails open, counted and logged, when the list did not load at boot', async () => {
    const { fastify, inc, close, log } = stub('local');
    const breached = await createServerBreachedPasswords(fastify, {
      listPath: join(directory, 'missing.txt'),
    });
    expect(log.error).toHaveBeenCalledWith(
      expect.objectContaining({ trigger: 'boot' }),
      expect.stringContaining('fail open')
    );
    expect(await breached.check(REALM, LISTED)).toEqual({
      kind: 'failed',
      source: 'local',
      reason: 'list_not_loaded',
    });
    expect(inc).toHaveBeenCalledWith({
      source: 'local',
      result: 'failed',
      reason: 'list_not_loaded',
    });
    expect(log.warn).toHaveBeenCalledWith(
      { source: 'local', reason: 'list_not_loaded' },
      expect.any(String)
    );
    await close();
  });

  it('answers not_configured for a source the deployment did not set up', async () => {
    const { fastify, close } = stub('k_anonymity');
    const breached = await createServerBreachedPasswords(fastify, {});
    expect(await breached.check(REALM, LISTED)).toEqual({
      kind: 'failed',
      source: 'k_anonymity',
      reason: 'not_configured',
    });
    await close();
  });

  it('sends the range lookup through the egress client, with the realm name and only the prefix', async () => {
    const egress = vi.fn(async () => ({
      status: 200,
      headers: {},
      body: Buffer.from(`${sha1(LISTED).slice(5)}:12\r\n${'0'.repeat(35)}:0\r\n`),
    }));
    const { fastify, close } = stub('k_anonymity', egress);
    const breached = await createServerBreachedPasswords(fastify, {
      rangeUrl: 'https://api.pwnedpasswords.com/range/',
    });
    expect(await breached.check(REALM, LISTED)).toEqual({ kind: 'listed', source: 'k_anonymity' });
    expect(egress).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        method: 'GET',
        url: `https://api.pwnedpasswords.com/range/${sha1(LISTED).slice(0, 5)}`,
        source: 'operator',
        realm: 'northwind',
      })
    );
    await close();
  });

  it('throws from the engine port for a realm that does not exist, which the engine reads as a failed check', async () => {
    const { fastify, close } = stub('local');
    const breached = await createServerBreachedPasswords(fastify, { listPath });
    await expect(
      breached.engine.check({ realmId: 'no-such-realm', password: LISTED })
    ).rejects.toThrow();
    await close();
  });
});
