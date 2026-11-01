import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { readWireConfig, serverPath, WireConfigError } from './config';
import setup from './global-setup';

const PROJECT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A complete environment; each test removes or changes what it is about. */
const COMPLETE = {
  QAUTH_WIRE_ALLOW_WRITES: '1',
  QAUTH_BASE_URL: 'http://localhost:3000',
  QAUTH_WIRE_CLIENT_ID: 'wire-confidential',
  QAUTH_WIRE_CLIENT_SECRET: 'secret',
} as const;

function without(name: keyof typeof COMPLETE): Record<string, string> {
  const env: Record<string, string> = { ...COMPLETE };
  delete env[name];
  return env;
}

describe('wire-suite configuration', () => {
  it('reads the base URL, the seeded client and an admin URL that defaults to the base URL', () => {
    expect(readWireConfig(COMPLETE)).toEqual({
      baseUrl: 'http://localhost:3000',
      adminUrl: 'http://localhost:3000',
      confidentialClient: { id: 'wire-confidential', secret: 'secret' },
      ssfTransmitter: false,
      mailUrl: undefined,
    });
    expect(readWireConfig({ ...COMPLETE, QAUTH_ADMIN_URL: 'http://localhost:3100' }).adminUrl).toBe(
      'http://localhost:3100'
    );
  });

  it('expects the SSF transmitter only when QAUTH_WIRE_SSF_TRANSMITTER=1', () => {
    expect(readWireConfig({ ...COMPLETE, QAUTH_WIRE_SSF_TRANSMITTER: '1' }).ssfTransmitter).toBe(
      true
    );
    expect(readWireConfig({ ...COMPLETE, QAUTH_WIRE_SSF_TRANSMITTER: '0' }).ssfTransmitter).toBe(
      false
    );
    expect(() => readWireConfig({ ...COMPLETE, QAUTH_WIRE_SSF_TRANSMITTER: 'yes' })).toThrow(
      WireConfigError
    );
  });

  it('reads the mail sink URL only when QAUTH_WIRE_MAIL_URL is set, and refuses one that is not a URL', () => {
    expect(
      readWireConfig({ ...COMPLETE, QAUTH_WIRE_MAIL_URL: 'http://localhost:8025' }).mailUrl
    ).toBe('http://localhost:8025');
    expect(readWireConfig({ ...COMPLETE, QAUTH_WIRE_MAIL_URL: '' }).mailUrl).toBeUndefined();
    expect(() => readWireConfig({ ...COMPLETE, QAUTH_WIRE_MAIL_URL: 'localhost:8025' })).toThrow(
      WireConfigError
    );
  });

  it('keeps the base URL exactly as given, because discovery must report it exactly', () => {
    expect(
      readWireConfig({ ...COMPLETE, QAUTH_BASE_URL: 'https://id.example/tenant' }).baseUrl
    ).toBe('https://id.example/tenant');
  });

  describe('refuses to start without QAUTH_WIRE_ALLOW_WRITES=1', () => {
    it.each([
      ['unset', undefined],
      ['empty', ''],
      ['"true"', 'true'],
      ['"yes"', 'yes'],
      ['"0"', '0'],
      ['" 1"', ' 1'],
    ])('when it is %s', (_label, value) => {
      const env: Record<string, string | undefined> = {
        ...COMPLETE,
        QAUTH_WIRE_ALLOW_WRITES: value,
      };
      expect(() => readWireConfig(env)).toThrow(WireConfigError);
      expect(() => readWireConfig(env)).toThrow(/QAUTH_WIRE_ALLOW_WRITES=1/);
    });

    it('before it reads anything else, so a run with nothing configured names the confirmation', () => {
      expect(() => readWireConfig({})).toThrow(/QAUTH_WIRE_ALLOW_WRITES=1/);
    });

    it('in the global setup, which runs before any test file is collected', () => {
      const saved = process.env['QAUTH_WIRE_ALLOW_WRITES'];
      delete process.env['QAUTH_WIRE_ALLOW_WRITES'];
      try {
        expect(() => setup()).toThrow(/refusing to start/);
      } finally {
        if (saved !== undefined) process.env['QAUTH_WIRE_ALLOW_WRITES'] = saved;
      }
    });

    it('as a whole run: the wire config exits non-zero and runs no test', () => {
      // The property the issue asks for, observed the way CI and a developer
      // would meet it. The base URL points at a closed port, so if the guard
      // were gone the suite would still fail, but on connection errors from
      // tests that ran; the assertions below tell the two apart.
      const require = createRequire(import.meta.url);
      const vitest = join(dirname(require.resolve('vitest/package.json')), 'vitest.mjs');
      const env: NodeJS.ProcessEnv = { ...process.env, ...without('QAUTH_WIRE_ALLOW_WRITES') };
      env['QAUTH_BASE_URL'] = 'http://127.0.0.1:9';
      delete env['QAUTH_WIRE_ALLOW_WRITES'];
      delete env['VITEST'];
      delete env['VITEST_POOL_ID'];
      delete env['VITEST_WORKER_ID'];

      const run = spawnSync(
        process.execPath,
        [vitest, 'run', '--config', 'vitest.wire.config.mts'],
        {
          cwd: PROJECT_ROOT,
          env,
          encoding: 'utf8',
          timeout: 60_000,
        }
      );
      const output = `${run.stdout}\n${run.stderr}`;

      expect(run.status, output).not.toBe(0);
      expect(output).toContain('wire-suite: refusing to start');
      expect(output).toContain('QAUTH_WIRE_ALLOW_WRITES=1');
      expect(output).not.toMatch(/Tests\s+\d+\s+(passed|failed)/);
    }, 60_000);
  });

  it.each([
    ['QAUTH_BASE_URL', 'QAUTH_BASE_URL is not set'],
    ['QAUTH_WIRE_CLIENT_ID', 'QAUTH_WIRE_CLIENT_ID is not set'],
    ['QAUTH_WIRE_CLIENT_SECRET', 'QAUTH_WIRE_CLIENT_SECRET is not set'],
  ] as const)('refuses to start without %s', (name, message) => {
    expect(() => readWireConfig(without(name))).toThrow(message);
  });

  it.each([
    ['a relative URL', 'localhost:3000'],
    ['a non-http scheme', 'ftp://localhost:3000'],
    ['a query', 'http://localhost:3000?tenant=a'],
    ['an empty query', 'http://localhost:3000?'],
    ['a fragment', 'http://localhost:3000#top'],
  ])('refuses a base URL with %s', (_label, value) => {
    expect(() => readWireConfig({ ...COMPLETE, QAUTH_BASE_URL: value })).toThrow(WireConfigError);
  });

  it('refuses an invalid QAUTH_ADMIN_URL instead of falling back to the base URL', () => {
    expect(() => readWireConfig({ ...COMPLETE, QAUTH_ADMIN_URL: 'not a url' })).toThrow(
      /QAUTH_ADMIN_URL/
    );
  });
});

describe('serverPath', () => {
  it('appends a path to a base with or without a terminating slash', () => {
    expect(serverPath('http://localhost:3000', '/health')).toBe('http://localhost:3000/health');
    expect(serverPath('https://id.example/tenant/', '/.well-known/openid-configuration')).toBe(
      'https://id.example/tenant/.well-known/openid-configuration'
    );
  });

  it('rejects a relative path', () => {
    expect(() => serverPath('http://localhost:3000', 'health')).toThrow();
  });
});
