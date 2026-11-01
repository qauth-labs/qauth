import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { CONFIG_KEY_REGISTRY } from '@qauth-labs/server-config';
import {
  enabledExperimentalItems,
  EXPERIMENTAL_ITEMS,
  experimentalBootWarning,
  type ExperimentalItem,
  type ExperimentalSwitches,
} from '@qauth-labs/shared-stability';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import type { ExperimentalSwitchConfig } from './experimental-features';

/**
 * The experimental-feature boot warning and `listEnabledExperimental()`
 * (ADR-018 §5, #476), and the agreement between the experimental-feature
 * registry and the configuration key registry.
 *
 * `experimental-features.ts` imports `env.ts`, which parses `process.env`
 * when it loads, so the module is imported after a valid environment is set,
 * with the module registry reset between environments.
 */

const BASE: Record<string, string> = {
  NODE_ENV: 'development',
  DATABASE_URL: 'postgresql://u:p@localhost:5431/qauth',
  EMAIL_FROM_ADDRESS: 'noreply@example.com',
  EMAIL_BASE_URL: 'http://localhost:3000',
  JWT_ISSUER: 'http://localhost:3000',
  JWT_PRIVATE_KEY:
    '-----BEGIN PRIVATE KEY-----\nMEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlBgkqhkiG9w0BBw0BAgMEBQQE\nBicqAwQBZw==\n-----END PRIVATE KEY-----',
};

/** Every key a case below may set, so one case's setting cannot reach the next. */
const SETTINGS = [
  ...new Set(
    EXPERIMENTAL_ITEMS.flatMap((item) => [
      ...(item.switchKey !== null && item.surface === 'server' ? [item.switchKey] : []),
      ...item.requires.map((setting) => setting.split('=')[0]),
    ])
  ),
];

const saved = new Map<string, string | undefined>();
beforeAll(() => {
  for (const key of [...Object.keys(BASE), ...SETTINGS]) saved.set(key, process.env[key]);
});
afterAll(() => {
  for (const [key, value] of saved) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** Load the module under a deployment of BASE plus `settings` (`KEY=value`). */
async function loadWith(settings: readonly string[]) {
  for (const key of SETTINGS) delete process.env[key];
  for (const [key, value] of Object.entries(BASE)) process.env[key] = value;
  for (const setting of settings) {
    const at = setting.indexOf('=');
    process.env[setting.slice(0, at)] = setting.slice(at + 1);
  }
  vi.resetModules();
  return import('./experimental-features');
}

/** A logger that records its `warn` calls. */
function recordingLog() {
  const lines: Array<{ object: object; message: string }> = [];
  return {
    lines,
    warn(object: object, message: string) {
      lines.push({ object, message });
    },
  };
}

const PILOT_ON: ExperimentalSwitchConfig = {
  WALLET_FEDERATION_ENABLED: true,
  OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
  PLUGIN_API_ENABLED: false,
};

const BUILT_SERVER_ITEMS: readonly ExperimentalItem[] = EXPERIMENTAL_ITEMS.filter(
  (item) => item.built && item.surface === 'server'
);

const UNBUILT_SERVER_SWITCHES: readonly ExperimentalItem[] = EXPERIMENTAL_ITEMS.filter(
  (item) => !item.built && item.surface === 'server' && item.switchKey !== null
);

describe('logExperimentalFeatures', () => {
  // The acceptance criterion of #476: enabling an experimental switch logs one
  // warning for that item at boot; a disabled item logs none.
  it('logs one warning for an item that is on, with its id, the terms and its docs link', async () => {
    const { logExperimentalFeatures } = await loadWith([]);
    const log = recordingLog();

    logExperimentalFeatures(log, PILOT_ON);

    expect(log.lines).toEqual([
      {
        object: {
          experimentalFeature: 'oid4vp-1.0-base',
          docs: 'https://docs.qauth.dev/reference/experimental-features/#oid4vp-10-base',
        },
        message:
          'Experimental feature oid4vp-1.0-base is on. It may change in a minor release, ' +
          'without a deprecation window. See ' +
          'https://docs.qauth.dev/reference/experimental-features/#oid4vp-10-base',
      },
    ]);
  });

  it.each<[string, ExperimentalSwitchConfig]>([
    [
      'nothing is on',
      {
        WALLET_FEDERATION_ENABLED: false,
        OID4VP_VERIFIER_PROFILE: undefined,
        PLUGIN_API_ENABLED: false,
      },
    ],
    [
      'the stable profile',
      {
        WALLET_FEDERATION_ENABLED: true,
        OID4VP_VERIFIER_PROFILE: 'haip-1.0',
        PLUGIN_API_ENABLED: false,
      },
    ],
    [
      'the base profile with wallet sign-in off',
      {
        WALLET_FEDERATION_ENABLED: false,
        OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
        PLUGIN_API_ENABLED: false,
      },
    ],
  ])('logs nothing for %s', async (_label, config) => {
    const { logExperimentalFeatures } = await loadWith([]);
    const log = recordingLog();

    logExperimentalFeatures(log, config);

    expect(log.lines).toEqual([]);
  });

  // #600: the plugin API warns at boot while its switch is on.
  it('logs one warning for the plugin API while PLUGIN_API_ENABLED is on', async () => {
    const { logExperimentalFeatures } = await loadWith([]);
    const log = recordingLog();

    logExperimentalFeatures(log, {
      WALLET_FEDERATION_ENABLED: false,
      OID4VP_VERIFIER_PROFILE: undefined,
      PLUGIN_API_ENABLED: true,
    });

    expect(log.lines).toEqual([
      {
        object: {
          experimentalFeature: 'plugin-api',
          docs: 'https://docs.qauth.dev/reference/experimental-features/#plugin-api',
        },
        message:
          'Experimental feature plugin-api is on. It may change in a minor release, ' +
          'without a deprecation window. See ' +
          'https://docs.qauth.dev/reference/experimental-features/#plugin-api',
      },
    ]);
  });

  it('reads the deployment when no configuration is passed', async () => {
    const { logExperimentalFeatures } = await loadWith([
      'WALLET_FEDERATION_ENABLED=true',
      'OID4VP_VERIFIER_PROFILE=oid4vp-1.0-base',
    ]);
    const log = recordingLog();

    logExperimentalFeatures(log);

    expect(log.lines.map((line) => line.object)).toEqual([
      expect.objectContaining({ experimentalFeature: 'oid4vp-1.0-base' }),
    ]);
  });
});

describe('listEnabledExperimental', () => {
  it('lists the registry entry of each item that is on', async () => {
    const { listEnabledExperimental } = await loadWith([]);

    expect(listEnabledExperimental(PILOT_ON)).toEqual([
      EXPERIMENTAL_ITEMS.find((item) => item.id === 'oid4vp-1.0-base'),
    ]);
  });

  it('lists nothing for a default deployment', async () => {
    const { listEnabledExperimental } = await loadWith([]);

    expect(listEnabledExperimental()).toEqual([]);
  });

  // The registry says, as `KEY=value`, what turns each built item on; the
  // reader in experimental-features.ts says it in code. Each case sets the
  // raw environment, so the env schema's own parsing sits between the two.
  describe.each(BUILT_SERVER_ITEMS.map((item) => [item.id, item] as const))('%s', (id, item) => {
    const switchSetting = `${item.switchKey}=${item.switchValue}`;

    it(`is on with ${[switchSetting, ...item.requires].join(' and ')}`, async () => {
      const { listEnabledExperimental } = await loadWith([switchSetting, ...item.requires]);
      expect(listEnabledExperimental().map((enabled) => enabled.id)).toContain(id);
    });

    it('is off without its switch', async () => {
      const { listEnabledExperimental } = await loadWith(item.requires);
      expect(listEnabledExperimental().map((enabled) => enabled.id)).not.toContain(id);
    });

    it.each(item.requires.map((setting) => [setting] as const))(
      'is off without %s',
      async (setting) => {
        const { listEnabledExperimental } = await loadWith([
          switchSetting,
          ...item.requires.filter((other) => other !== setting),
        ]);
        expect(listEnabledExperimental().map((enabled) => enabled.id)).not.toContain(id);
      }
    );
  });
});

/**
 * #477: an item whose switch is on is in discovery, by the members its
 * registry entry lists, and warns at boot (ADR-018 §5). Off, it is neither.
 */
describe('an experimental item whose switch is on', () => {
  const ISSUER = 'https://auth.example.com';

  /** Both discovery documents, as the well-known routes build them for `experimentalItems`. */
  async function discoveryDocuments(experimentalItems: readonly ExperimentalItem[]) {
    const { buildAuthorizationServerMetadata, buildOpenIdConfiguration } =
      await import('../app/helpers/discovery');
    return [
      buildAuthorizationServerMetadata({ issuer: ISSUER, experimentalItems }),
      buildOpenIdConfiguration({ issuer: ISSUER, experimentalItems }),
    ];
  }

  describe.each(BUILT_SERVER_ITEMS.map((item) => [item.id, item] as const))('%s', (id, item) => {
    const switchSetting = `${item.switchKey}=${item.switchValue}`;

    it('adds its discovery members and logs its boot warning', async () => {
      const { listEnabledExperimental, logExperimentalFeatures } = await loadWith([
        switchSetting,
        ...item.requires,
      ]);
      const log = recordingLog();

      for (const document of await discoveryDocuments(listEnabledExperimental())) {
        for (const member of item.discoveryMembers) expect(document).toHaveProperty(member);
      }
      logExperimentalFeatures(log);
      expect(log.lines).toContainEqual({
        object: { experimentalFeature: id, docs: experimentalBootWarning(item).docs },
        message: experimentalBootWarning(item).message,
      });
    });

    it('adds neither without its switch', async () => {
      const { listEnabledExperimental, logExperimentalFeatures } = await loadWith(item.requires);
      const log = recordingLog();

      for (const document of await discoveryDocuments(listEnabledExperimental())) {
        for (const member of item.discoveryMembers) {
          expect(Object.keys(document)).not.toContain(member);
        }
      }
      logExperimentalFeatures(log);
      expect(log.lines.map((line) => line.object)).not.toContainEqual(
        expect.objectContaining({ experimentalFeature: id })
      );
    });
  });

  // The registry's only built item adds no discovery member, so the whole
  // path, from the switch to the members and the warning, is also run for an
  // item made up for the test, through the functions the server uses.
  describe('for an item that adds members', () => {
    const SAMPLE: ExperimentalItem = {
      ...BUILT_SERVER_ITEMS[0],
      id: 'sample-feature',
      switchKey: 'SAMPLE_FEATURE_ENABLED',
      switchValue: 'true',
      requires: [],
      discoveryMembers: ['sample_endpoint'],
      docsPage: '/integrate/sample-feature/',
    };
    const switches = {
      'sample-feature': (config: { SAMPLE_FEATURE_ENABLED: boolean }) =>
        config.SAMPLE_FEATURE_ENABLED,
    } as unknown as ExperimentalSwitches<{ SAMPLE_FEATURE_ENABLED: boolean }>;
    const values = {
      'sample-feature': (issuer: string) => ({ sample_endpoint: `${issuer}/sample` }),
    };

    async function boot(on: boolean) {
      const { buildAuthorizationServerMetadata } = await import('../app/helpers/discovery');
      const enabled = enabledExperimentalItems({ SAMPLE_FEATURE_ENABLED: on }, switches, [SAMPLE]);
      return {
        document: buildAuthorizationServerMetadata({
          issuer: ISSUER,
          experimentalItems: enabled,
          experimentalMemberValues: values,
        }),
        warnings: enabled.map((item) => experimentalBootWarning(item).id),
      };
    }

    it('adds its members and warns once its switch is on', async () => {
      const { document, warnings } = await boot(true);
      expect(document['sample_endpoint']).toBe(`${ISSUER}/sample`);
      expect(warnings).toEqual(['sample-feature']);
    });

    it('adds no member, not even as null or false, and does not warn while it is off', async () => {
      const { document, warnings } = await boot(false);
      expect(Object.keys(document)).not.toContain('sample_endpoint');
      expect(warnings).toEqual([]);
    });
  });
});

/**
 * Config keys of experimental items are marked experimental in the documented
 * key list (#476): the switch of a built server item is an experimental key,
 * or its value one of the key's experimental values, so the configuration page
 * shows it.
 */
describe('the experimental-feature registry and the configuration key registry', () => {
  it.each(BUILT_SERVER_ITEMS.map((item) => [item.id, item] as const))(
    '%s switches on through a key marked experimental',
    (_id, item) => {
      const key = CONFIG_KEY_REGISTRY.find((candidate) => candidate.name === item.switchKey);
      expect(key, `${item.switchKey} is not in the configuration key registry`).toBeDefined();
      expect(
        key?.tier === 'experimental' || key?.experimentalValues.includes(item.switchValue ?? ''),
        `${item.switchKey}=${item.switchValue} is not marked experimental`
      ).toBe(true);
    }
  );

  // An item is added to the registry in the pull request that adds its switch
  // (#476), and that pull request marks it built. Until then the key must not
  // exist: the server would read it, but listEnabledExperimental() and the
  // boot warning skip an item that is not built.
  it.each(UNBUILT_SERVER_SWITCHES.map((item) => [item.id, item.switchKey] as const))(
    '%s is not built, so its switch %s is not a key the server reads yet',
    (_id, switchKey) => {
      expect(CONFIG_KEY_REGISTRY.map((key) => key.name)).not.toContain(switchKey);
    }
  );

  it.each(BUILT_SERVER_ITEMS.flatMap((item) => item.requires.map((setting) => [item.id, setting])))(
    '%s requires %s, a registered key',
    (_id, setting) => {
      const name = setting.split('=')[0];
      expect(CONFIG_KEY_REGISTRY.map((key) => key.name)).toContain(name);
    }
  );
});

/** Find `app/app.ts` from the cwd, as `main.invariants.test.ts` finds `main.ts`. */
function resolveAppPath(): string {
  let dir = process.cwd();
  for (let depth = 0; depth < 8; depth += 1) {
    for (const candidate of [
      join(dir, 'src', 'app', 'app.ts'),
      join(dir, 'apps', 'auth-server', 'src', 'app', 'app.ts'),
    ]) {
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error('Could not locate apps/auth-server/src/app/app.ts from cwd ' + process.cwd());
}

// Behaviour is tested above and, against a booted server, in
// experimental-features-boot.integration.test.ts; this pins that every boot of
// the app logs the warnings, in the unit suite CI's `affected (test)` and
// `coverage` jobs run.
describe('app.ts', () => {
  it('logs the experimental-feature warnings through the app logger', () => {
    const code = readFileSync(resolveAppPath(), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    expect(code).toMatch(/\blogExperimentalFeatures\(\s*fastify\.log\s*\)/);
  });
});
