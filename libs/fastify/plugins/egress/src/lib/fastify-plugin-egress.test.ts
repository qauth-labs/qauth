import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createTestEgressClient, type EgressClientOptions } from '@qauth-labs/server-egress';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import {
  allowlistFileProblems,
  egressPlugin,
  type EgressPluginOptions,
} from './fastify-plugin-egress';

/*
 * The egress plugin (issue #481): it reads EGRESS_ALLOWLIST_PATH once and
 * decorates `fastify.egress` with a client over that list. An IP literal in
 * the URL is checked without any lookup, so `validateDestination` shows what
 * the list opens without touching the network.
 */

const dir = mkdtempSync(join(tmpdir(), 'egress-plugin-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function allowlistFile(name: string, content: unknown, mode = 0o600): string {
  const path = join(dir, name);
  writeFileSync(path, typeof content === 'string' ? content : JSON.stringify(content));
  chmodSync(path, mode);
  return path;
}

const apps: FastifyInstance[] = [];
afterEach(async () => {
  for (const app of apps.splice(0)) await app.close();
});

async function build(options: EgressPluginOptions = {}, warn = vi.fn()): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  apps.push(app);
  vi.spyOn(app.log, 'warn').mockImplementation(warn);
  await app.register(egressPlugin, options);
  await app.ready();
  return app;
}

const PRIVATE_URL = 'https://10.20.0.7/';

describe('egressPlugin', () => {
  it('applies the file to operator and admin destinations of the realms it names', async () => {
    const path = allowlistFile('ok.json', {
      entries: [{ cidr: '10.20.0.0/16', realms: ['master'] }],
    });
    const app = await build({ allowlistPath: path });

    for (const source of ['operator', 'admin'] as const) {
      await expect(
        app.egress.validateDestination(PRIVATE_URL, { purpose: 'test', source, realm: 'master' })
      ).resolves.toMatchObject({ addresses: ['10.20.0.7'] });
    }
    for (const options of [
      { source: 'operator', realm: 'other' },
      { source: 'client', realm: 'master' },
      { source: 'remote_document', realm: 'master' },
    ] as const) {
      await expect(
        app.egress.validateDestination(PRIVATE_URL, { purpose: 'test', ...options })
      ).rejects.toMatchObject({ reason: 'address', outcome: 'blocked' });
    }
  });

  it('refuses every private address when no file is named', async () => {
    const app = await build();
    await expect(
      app.egress.validateDestination(PRIVATE_URL, {
        purpose: 'test',
        source: 'operator',
        realm: 'master',
      })
    ).rejects.toMatchObject({ reason: 'address' });
  });

  it('logs the blocked call through the server logger', async () => {
    const warn = vi.fn();
    const app = await build({}, warn);
    await app.egress
      .validateDestination(PRIVATE_URL, { purpose: 'cimd', source: 'client' })
      .catch(() => undefined);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ purpose: 'cimd', source: 'client', reason: 'address' }),
      'egress call blocked'
    );
  });

  it.each([
    ['a missing file', () => join(dir, 'missing.json'), 'the file cannot be read'],
    ['a file that is not JSON', () => allowlistFile('broken.json', '{'), 'not valid JSON'],
    [
      'an entry with a wildcard',
      () => allowlistFile('wild.json', { entries: [{ host: '*.corp', realms: ['master'] }] }),
      'wildcard',
    ],
  ])('fails the boot on %s, naming the variable', async (_label, path, message) => {
    const file = path();
    const boot = build({ allowlistPath: file });
    await expect(boot).rejects.toThrow(`EGRESS_ALLOWLIST_PATH (${file})`);
    await expect(build({ allowlistPath: file })).rejects.toThrow(message);
  });

  it('fails the boot on a file others can write, naming the variable', async () => {
    const path = allowlistFile('open.json', { entries: [] }, 0o646);
    const warn = vi.fn();
    const boot = build({ allowlistPath: path }, warn);
    await expect(boot).rejects.toThrow(`EGRESS_ALLOWLIST_PATH (${path}): others can write`);
  });

  it('warns when the group can write the file', async () => {
    const path = allowlistFile('group.json', { entries: [] }, 0o664);
    const warn = vi.fn();
    await build({ allowlistPath: path }, warn);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ variable: 'EGRESS_ALLOWLIST_PATH', mode: '664' }),
      expect.stringContaining('its group can write')
    );
  });

  it('does not warn about a file only its owner can write', async () => {
    const path = allowlistFile('closed.json', { entries: [] }, 0o644);
    const warn = vi.fn();
    await build({ allowlistPath: path }, warn);
    expect(warn).not.toHaveBeenCalled();
  });

  it('hands the client factory the allowlist and the logger under NODE_ENV=test', async () => {
    const path = allowlistFile('factory.json', {
      entries: [{ cidr: '10.20.0.0/16', realms: ['master'] }],
    });
    const createClient = vi.fn((options: EgressClientOptions) => createTestEgressClient(options));
    const app = await build({ allowlistPath: path, createClient });

    expect(createClient).toHaveBeenCalledWith(
      expect.objectContaining({ logger: app.log, allowlist: expect.anything() })
    );
    await expect(
      app.egress.validateDestination(PRIVATE_URL, {
        purpose: 'test',
        source: 'operator',
        realm: 'master',
      })
    ).resolves.toMatchObject({ addresses: ['10.20.0.7'] });
  });

  it.each(['production', 'development'])(
    'refuses a client factory when NODE_ENV is %s',
    async (nodeEnv) => {
      const before = process.env['NODE_ENV'];
      process.env['NODE_ENV'] = nodeEnv;
      try {
        await expect(build({ createClient: vi.fn() })).rejects.toThrow(
          'createClient is a test seam and needs NODE_ENV=test'
        );
      } finally {
        process.env['NODE_ENV'] = before;
      }
    }
  );
});

describe('allowlistFileProblems', () => {
  const ME = 1000;

  it.each([
    ['others can write', { mode: 0o100646, uid: ME }],
    ['everyone can write', { mode: 0o100666, uid: 0 }],
  ])('refuses a file %s', (_label, stats) => {
    expect(allowlistFileProblems(stats, ME).refusal).toContain('others can write the file');
  });

  it.each([
    ['its group can write', { mode: 0o100664, uid: ME }, ['its group can write']],
    ['another user owns', { mode: 0o100644, uid: 4242 }, ["neither root nor the server's user"]],
    [
      'its group can write and another user owns',
      { mode: 0o100660, uid: 4242 },
      ['its group can write', "neither root nor the server's user"],
    ],
  ])('warns about a file %s', (_label, stats, expected) => {
    const { refusal, warnings } = allowlistFileProblems(stats, ME);
    expect(refusal).toBeUndefined();
    expect(warnings).toHaveLength(expected.length);
    expected.forEach((text, i) => expect(warnings[i]).toContain(text));
  });

  it.each([
    ['the server user', { mode: 0o100644, uid: ME }],
    ['root', { mode: 0o100600, uid: 0 }],
  ])('passes a file owned by %s that only its owner can write', (_label, stats) => {
    expect(allowlistFileProblems(stats, ME)).toEqual({ refusal: undefined, warnings: [] });
  });
});
