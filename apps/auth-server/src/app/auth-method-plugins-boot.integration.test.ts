import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { fixturePluginImporter, fixturePluginMethod } from '../testing/auth-method-plugins';
import {
  baseEnvironment,
  bootAuthServer,
  type BootAuthServerOptions,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE PLUGIN RUNTIME AT BOOT (#600, ADR-019 Decision 12, ADR-018 §4 and §5),
 * against a real Postgres and Redis.
 *
 * The suite boots the real app with fixture plugin packages: the harness
 * hands the loader an importer over fixture modules and, for the first-party
 * case, a first-party list (test support the app refuses outside
 * NODE_ENV=test). What it checks is what a deployment sees at boot: which
 * plugins load, what the server logs, and which boots fail.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

/** pino's numeric level for `warn`. */
const PINO_WARN_LEVEL = 40;

/** One parsed line of the server's own log. */
interface LogLine {
  readonly level: number;
  readonly msg?: string;
  readonly [key: string]: unknown;
}

const THIRD_PARTY = '@example/qauth-plugin-corp-sso';
const FIRST_PARTY = '@qauth-labs/plugin-fixture';
const PLUGIN_DOCS = 'https://docs.qauth.dev/reference/experimental-features/#plugin-api';

const MODULES = {
  [THIRD_PARTY]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
  [FIRST_PARTY]: { authMethod: fixturePluginMethod({ type: 'fixture_sso', id: 'fixture' }) },
};

describe('the AuthMethod plugin runtime at boot (#600, real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  interface Booted {
    readonly log: readonly LogLine[];
    /** The `type` of each AuthMethod the provider registry holds. */
    readonly methods: readonly string[];
    /** The status of a GET to the callback of each type, on the default realm's host. */
    readonly callbackStatus: (type: string) => Promise<number>;
  }

  /** Boot a deployment with `overrides` and the fixture plugins, observe it, and close it. */
  async function boot(
    overrides: Record<string, string>,
    authMethodPlugins: BootAuthServerOptions['authMethodPlugins'] = {
      importPackage: fixturePluginImporter(MODULES),
    }
  ): Promise<Booted> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    const log: LogLine[] = [];
    let booted: BootedAuthServer | undefined;
    try {
      booted = await bootAuthServer(
        { ...baseEnvironment(infra, jwt), ...overrides },
        {
          logStream: { write: (line) => log.push(JSON.parse(line) as LogLine) },
          authMethodPlugins,
        }
      );
      const app = booted.app;
      const methods = app.providerRegistry.authMethods().map((method) => method.type);
      const statuses = new Map<string, number>();
      for (const type of ['corp_sso', 'fixture_sso']) {
        const response = await app.inject({ method: 'GET', url: `/upstream/${type}/callback` });
        statuses.set(type, response.statusCode);
      }
      return { log, methods, callbackStatus: async (type) => statuses.get(type) ?? 0 };
    } finally {
      await booted?.close();
    }
  }

  const pluginLines = (log: readonly LogLine[]) =>
    log.filter((line) => line['authMethodPlugin'] !== undefined);
  const experimentalLines = (log: readonly LogLine[]) =>
    log.filter((line) => line['experimentalFeature'] !== undefined);

  // Acceptance criterion: with the switch off, a third-party plugin does not
  // load and boot logs why.
  it('does not load a third-party plugin with the switch off, and logs why', async () => {
    const booted = await boot({ AUTH_METHOD_PLUGINS: THIRD_PARTY });

    expect(booted.methods).toEqual([]);
    expect(pluginLines(booted.log)).toEqual([
      expect.objectContaining({
        level: PINO_WARN_LEVEL,
        authMethodPlugin: THIRD_PARTY,
        reason: 'plugin-api-off',
        msg: `The AuthMethod plugin ${THIRD_PARTY} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`,
      }),
    ]);
    // Its routes do not exist; nothing names the plugin API either.
    expect(await booted.callbackStatus('corp_sso')).toBe(404);
    expect(experimentalLines(booted.log)).toEqual([]);
  });

  // Acceptance criterion: with the switch on, boot logs a warning and the
  // plugin loads.
  it('loads a third-party plugin with the switch on, and warns that the plugin API is experimental', async () => {
    const booted = await boot({ AUTH_METHOD_PLUGINS: THIRD_PARTY, PLUGIN_API_ENABLED: 'true' });

    expect(booted.methods).toEqual(['corp_sso']);
    expect(experimentalLines(booted.log)).toEqual([
      expect.objectContaining({
        level: PINO_WARN_LEVEL,
        experimentalFeature: 'plugin-api',
        docs: PLUGIN_DOCS,
        msg: `Experimental feature plugin-api is on. It may change in a minor release, without a deprecation window. See ${PLUGIN_DOCS}`,
      }),
    ]);
    // No warn line about the plugin itself: it loaded.
    expect(pluginLines(booted.log)).toEqual([]);
    // Mounted, and off in the realm until an admin enables it: 404.
    expect(await booted.callbackStatus('corp_sso')).toBe(404);
  });

  // Acceptance criterion: first-party plugins load with the switch off.
  it('loads a first-party plugin with the switch off, beside a third-party one it skips', async () => {
    const booted = await boot(
      { AUTH_METHOD_PLUGINS: `${FIRST_PARTY},${THIRD_PARTY}` },
      { importPackage: fixturePluginImporter(MODULES), firstParty: [FIRST_PARTY] }
    );

    expect(booted.methods).toEqual(['fixture_sso']);
    expect(
      pluginLines(booted.log).map((line) => [line['authMethodPlugin'], line['reason']])
    ).toEqual([[THIRD_PARTY, 'plugin-api-off']]);
    expect(experimentalLines(booted.log)).toEqual([]);
  });

  it('boots with no plugin and logs nothing about plugins by default', async () => {
    const booted = await boot({});

    expect(booted.methods).toEqual([]);
    expect(pluginLines(booted.log)).toEqual([]);
    expect(experimentalLines(booted.log)).toEqual([]);
  });

  // Acceptance criterion: a plugin with a wrong contract version fails boot.
  it('fails the boot for a plugin written against another contract version', async () => {
    await expect(
      boot(
        { AUTH_METHOD_PLUGINS: THIRD_PARTY, PLUGIN_API_ENABLED: 'true' },
        {
          importPackage: fixturePluginImporter({
            [THIRD_PARTY]: {
              authMethod: fixturePluginMethod({
                type: 'corp_sso',
                contract: 'qauth-auth-method/0-rc.9',
              }),
            },
          }),
        }
      )
    ).rejects.toThrow(
      `The AuthMethod plugin package ${THIRD_PARTY} cannot be loaded:\n- it is written against the contract qauth-auth-method/0-rc.9, and this server implements qauth-auth-method/1-rc.0`
    );
  });

  it('fails the boot for two plugins with the same id, and for a package that is not installed', async () => {
    await expect(
      boot(
        { AUTH_METHOD_PLUGINS: `${FIRST_PARTY},${THIRD_PARTY}`, PLUGIN_API_ENABLED: 'true' },
        {
          importPackage: fixturePluginImporter({
            [FIRST_PARTY]: { authMethod: fixturePluginMethod({ type: 'fixture_sso', id: 'corp' }) },
            [THIRD_PARTY]: { authMethod: fixturePluginMethod({ type: 'corp_sso', id: 'corp' }) },
          }),
        }
      )
    ).rejects.toThrow(/its id corp is the id of @qauth-labs\/plugin-fixture/);

    await expect(
      boot(
        { AUTH_METHOD_PLUGINS: '@example/not-installed', PLUGIN_API_ENABLED: 'true' },
        { importPackage: fixturePluginImporter({}) }
      )
    ).rejects.toThrow(/@example\/not-installed cannot be loaded:\n- it is not installed/);
  });

  it('fails the boot for a value of AUTH_METHOD_PLUGINS that is not a package name', async () => {
    await expect(boot({ AUTH_METHOD_PLUGINS: './plugins/corp-sso.js' })).rejects.toMatchObject({
      issues: [expect.objectContaining({ path: ['AUTH_METHOD_PLUGINS'] })],
    });
    delete process.env['AUTH_METHOD_PLUGINS'];
  });
});
