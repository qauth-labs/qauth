import {
  AUTH_METHOD_CONTRACT,
  defineUpstreamOidcPreset,
  UPSTREAM_OIDC_METHOD_ID,
  UPSTREAM_OIDC_TYPE_PATTERN,
} from '@qauth-labs/plugin-sdk';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';

import { createSampleAuthMethod } from '../../testing/sample-auth-method.fixture';
import {
  AuthMethodPluginError,
  type BuildUpstreamOidcPreset,
  type ImportAuthMethodPlugin,
  loadAuthMethodPlugins,
  skippedAuthMethodPluginMessage,
} from './plugin-loader';

/**
 * The plugin loader (#600): which listed packages are imported, and what
 * fails the boot. Packages are served by a fake importer; the real `import()`
 * is exercised for a package that is not installed.
 */

const FIRST_PARTY = '@qauth-labs/plugin-first';
const THIRD_PARTY = '@example/qauth-plugin-corp-sso';

/** A fake importer over named modules; a name it does not hold is "not installed". */
function importerOf(modules: Record<string, unknown>) {
  return vi.fn<ImportAuthMethodPlugin>(async (name) => {
    if (Object.hasOwn(modules, name)) return modules[name];
    const error = new Error(`Cannot find package '${name}' imported from /app/main.js`);
    (error as NodeJS.ErrnoException).code = 'ERR_MODULE_NOT_FOUND';
    throw error;
  });
}

const sample = (type: string, id = type) => ({ ...createSampleAuthMethod({ type }), id });

async function refusal(promise: Promise<unknown>): Promise<AuthMethodPluginError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  if (!(error instanceof AuthMethodPluginError)) {
    throw new Error(`expected an AuthMethodPluginError, got ${String(error)}`);
  }
  return error;
}

describe('loadAuthMethodPlugins (#600)', () => {
  it('loads nothing when no package is listed', async () => {
    const importPackage = importerOf({});
    expect(
      await loadAuthMethodPlugins({
        packages: [],
        pluginApiEnabled: false,
        firstParty: [FIRST_PARTY],
        importPackage,
      })
    ).toEqual({ installed: [], skipped: [] });
    expect(importPackage).not.toHaveBeenCalled();
  });

  // Acceptance criterion: with the switch off, a third-party plugin does not
  // load, and the boot can say why.
  it('never imports a third-party package while the plugin API is off', async () => {
    const importPackage = importerOf({ [THIRD_PARTY]: { authMethod: sample('corp_sso') } });
    const loaded = await loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: false,
      firstParty: [FIRST_PARTY],
      importPackage,
    });
    expect(loaded).toEqual({
      installed: [],
      skipped: [{ package: THIRD_PARTY, reason: 'plugin-api-off' }],
    });
    expect(importPackage).not.toHaveBeenCalled();
    expect(skippedAuthMethodPluginMessage(loaded.skipped[0])).toBe(
      `The AuthMethod plugin ${THIRD_PARTY} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`
    );
  });

  it('reads the switch as on only when it is exactly true', async () => {
    const importPackage = importerOf({ [THIRD_PARTY]: { authMethod: sample('corp_sso') } });
    const loaded = await loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: 'true' as unknown as boolean,
      firstParty: [],
      importPackage,
    });
    expect(loaded.installed).toEqual([]);
    expect(importPackage).not.toHaveBeenCalled();
  });

  // Acceptance criterion: first-party plugins load with the switch off.
  it('loads a first-party package with the switch off, and a third-party one with it on', async () => {
    const modules = {
      [FIRST_PARTY]: { authMethod: sample('first_sso') },
      [THIRD_PARTY]: { authMethod: sample('corp_sso') },
    };
    const off = await loadAuthMethodPlugins({
      packages: [FIRST_PARTY, THIRD_PARTY],
      pluginApiEnabled: false,
      firstParty: [FIRST_PARTY],
      importPackage: importerOf(modules),
    });
    expect(off.installed.map((plugin) => [plugin.package, plugin.firstParty])).toEqual([
      [FIRST_PARTY, true],
    ]);
    expect(off.skipped.map((skipped) => skipped.package)).toEqual([THIRD_PARTY]);

    const on = await loadAuthMethodPlugins({
      packages: [FIRST_PARTY, THIRD_PARTY],
      pluginApiEnabled: true,
      firstParty: [FIRST_PARTY],
      importPackage: importerOf(modules),
    });
    expect(
      on.installed.map(({ package: name, firstParty, id, type, secretPaths }) => ({
        name,
        firstParty,
        id,
        type,
        secretPaths,
      }))
    ).toEqual([
      {
        name: FIRST_PARTY,
        firstParty: true,
        id: 'first_sso',
        type: 'first_sso',
        secretPaths: ['clientSecret'],
      },
      {
        name: THIRD_PARTY,
        firstParty: false,
        id: 'corp_sso',
        type: 'corp_sso',
        secretPaths: ['clientSecret'],
      },
    ]);
    expect(on.skipped).toEqual([]);
  });

  it('keeps a frozen snapshot of the method, not the object the package exported', async () => {
    const exported = sample('corp_sso');
    const loaded = await loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: true,
      firstParty: [],
      importPackage: importerOf({ [THIRD_PARTY]: { authMethod: exported } }),
    });
    const [plugin] = loaded.installed;
    expect(plugin.method).not.toBe(exported);
    expect(Object.isFrozen(plugin.method)).toBe(true);
    (exported as { type: string }).type = 'wallet';
    expect(plugin.method.type).toBe('corp_sso');
  });

  it('reads the method of a CommonJS package under default', async () => {
    const loaded = await loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: true,
      firstParty: [],
      importPackage: importerOf({ [THIRD_PARTY]: { default: { authMethod: sample('corp_sso') } } }),
    });
    expect(loaded.installed.map((plugin) => plugin.type)).toEqual(['corp_sso']);
  });

  // Acceptance criterion (unit half): a wrong contract version fails the boot.
  it('refuses a plugin written against another contract version, before any other check', async () => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: [THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [],
        importPackage: importerOf({
          // It breaks other rules too: the version is what it is told.
          [THIRD_PARTY]: {
            authMethod: { ...sample('corp_sso'), contract: 'qauth-auth-method/0', routes: [] },
          },
        }),
      })
    );
    expect(error.packageName).toBe(THIRD_PARTY);
    expect(error.problems).toEqual([
      `it is written against the contract qauth-auth-method/0, and this server implements ${AUTH_METHOD_CONTRACT}: install a version of the plugin built for ${AUTH_METHOD_CONTRACT}`,
    ]);
  });

  it.each<[string, unknown, RegExp]>([
    ['exports no authMethod', { createAuthMethod: () => undefined }, /it exports no authMethod/],
    [
      'exports a value that is not an object',
      { authMethod: 'corp_sso' },
      /it exports no authMethod/,
    ],
    [
      'declares no contract',
      { authMethod: { ...sample('corp_sso'), contract: undefined } },
      /names no contract version/,
    ],
    [
      'breaks the contract',
      { authMethod: { ...sample('corp_sso'), type: 'Corp SSO' } },
      /type must match/,
    ],
    [
      'takes a reserved type',
      { authMethod: { ...sample('password'), type: 'password' } },
      /type password is reserved/,
    ],
    [
      'marks a secret it cannot keep write-only',
      {
        authMethod: {
          ...sample('corp_sso'),
          configSchema: z.object({ keys: z.array(z.string().meta({ writeOnly: true })) }),
        },
      },
      /cannot be kept write-only/,
    ],
  ])('refuses a package that %s', async (_case, module, problem) => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: [THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [],
        importPackage: importerOf({ [THIRD_PARTY]: module }),
      })
    );
    expect(error.problems.join('\n')).toMatch(problem);
    expect(error.message).toContain(THIRD_PARTY);
  });

  it('refuses a package that is not installed, naming it', async () => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: [THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [],
        importPackage: importerOf({}),
      })
    );
    expect(error.problems).toEqual([
      'it is not installed: install it with the deployment, or remove it from AUTH_METHOD_PLUGINS',
    ]);
  });

  it('refuses a package that is not installed through the real import()', async () => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: ['@qauth-labs/no-such-plugin-600'],
        pluginApiEnabled: true,
        firstParty: [],
      })
    );
    expect(error.packageName).toBe('@qauth-labs/no-such-plugin-600');
    expect(error.problems[0]).toMatch(/^it is not installed/);
  });

  it('refuses a package whose own code throws as it is imported, with its first line only', async () => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: [THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [],
        importPackage: async () => {
          throw new Error('boom at import\n    at secret stack line');
        },
      })
    );
    expect(error.problems).toEqual(['importing it failed: boom at import']);
  });

  // Fail boot on a duplicate id.
  it('refuses two plugins with the same id, or the same type', async () => {
    const sameId = await refusal(
      loadAuthMethodPlugins({
        packages: [FIRST_PARTY, THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [FIRST_PARTY],
        importPackage: importerOf({
          [FIRST_PARTY]: { authMethod: sample('first_sso', 'corp') },
          [THIRD_PARTY]: { authMethod: sample('corp_sso', 'corp') },
        }),
      })
    );
    expect(sameId.packageName).toBe(THIRD_PARTY);
    expect(sameId.problems).toEqual([
      `its id corp is the id of ${FIRST_PARTY}: two plugins cannot share an id`,
    ]);

    const sameType = await refusal(
      loadAuthMethodPlugins({
        packages: [FIRST_PARTY, THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [FIRST_PARTY],
        importPackage: importerOf({
          [FIRST_PARTY]: { authMethod: sample('corp_sso', 'first') },
          [THIRD_PARTY]: { authMethod: sample('corp_sso', 'second') },
        }),
      })
    );
    expect(sameType.problems).toEqual([
      `its type corp_sso is the type of ${FIRST_PARTY}: two plugins cannot share a type`,
    ]);
  });

  it("refuses a plugin that takes the generic upstream OIDC client's id or a type in its namespace", async () => {
    const load = (authMethod: unknown) =>
      refusal(
        loadAuthMethodPlugins({
          packages: [THIRD_PARTY],
          pluginApiEnabled: true,
          firstParty: [],
          importPackage: importerOf({ [THIRD_PARTY]: { authMethod } }),
        })
      );

    expect((await load(sample('corp_sso', UPSTREAM_OIDC_METHOD_ID))).problems).toEqual([
      "its id oidc is the generic upstream OpenID Connect client's, which no plugin may take",
    ]);
    for (const type of ['oidc_corp', 'oidc_0', `oidc_${'a'.repeat(58)}`]) {
      expect(UPSTREAM_OIDC_TYPE_PATTERN.test(type), type).toBe(true);
      const error = await load(sample(type, 'corp'));
      expect(error.packageName).toBe(THIRD_PARTY);
      expect(error.problems).toEqual([
        `its type ${type} is in the generic upstream OpenID Connect client's namespace (oidc_<alias>), which no plugin may take`,
      ]);
    }
    // A first-party package is held to it too.
    const firstParty = await refusal(
      loadAuthMethodPlugins({
        packages: [FIRST_PARTY],
        pluginApiEnabled: false,
        firstParty: [FIRST_PARTY],
        importPackage: importerOf({ [FIRST_PARTY]: { authMethod: sample('oidc_corp', 'oidc') } }),
      })
    );
    expect(firstParty.problems).toHaveLength(2);

    // A type outside the namespace, such as `oidcx` or `corp_oidc`, loads.
    for (const type of ['oidcx', 'corp_oidc']) {
      const loaded = await loadAuthMethodPlugins({
        packages: [THIRD_PARTY],
        pluginApiEnabled: true,
        firstParty: [],
        importPackage: importerOf({ [THIRD_PARTY]: { authMethod: sample(type, 'corp') } }),
      });
      expect(loaded.installed.map((plugin) => plugin.type)).toEqual([type]);
    }
  });

  it('refuses a package listed twice', async () => {
    const error = await refusal(
      loadAuthMethodPlugins({
        packages: [FIRST_PARTY, FIRST_PARTY],
        pluginApiEnabled: false,
        firstParty: [FIRST_PARTY],
        importPackage: importerOf({ [FIRST_PARTY]: { authMethod: sample('first_sso') } }),
      })
    );
    expect(error.problems).toEqual(['AUTH_METHOD_PLUGINS lists it twice']);
  });
});

describe('loadAuthMethodPlugins: a package that exports an upstream OpenID Connect preset (#671)', () => {
  const configSchema = z.strictObject({
    clientId: z.string().min(1),
    clientSecret: z.string().min(1).meta({ writeOnly: true }),
  });
  const preset = defineUpstreamOidcPreset({
    id: 'corp-idp',
    type: 'corp_idp',
    display: { name: 'Corp IdP' },
    origins: ['https://idp.example.com'],
    configSchema,
    upstreamConfig: (config) => ({
      issuer: 'https://idp.example.com',
      clientId: config.clientId,
      clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
    }),
    responseMembers: { profile: (value) => value },
  });

  /** Stands in for the server's client: a sample method under the preset's id and type. */
  const builder = () => vi.fn<BuildUpstreamOidcPreset>((given) => sample(given.type, given.id));

  const load = (module: unknown, build?: BuildUpstreamOidcPreset) =>
    loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: true,
      firstParty: [],
      importPackage: importerOf({ [THIRD_PARTY]: module }),
      ...(build === undefined ? {} : { buildUpstreamOidcPreset: build }),
    });

  it("builds the method with the server's builder and records how it was built", async () => {
    const build = builder();
    const loaded = await load({ upstreamOidcPreset: preset }, build);
    expect(build).toHaveBeenCalledTimes(1);
    expect(build).toHaveBeenCalledWith(preset);
    const [plugin] = loaded.installed;
    expect(plugin).toMatchObject({
      package: THIRD_PARTY,
      id: 'corp-idp',
      type: 'corp_idp',
      kind: 'upstream-oidc-preset',
      responseMembers: ['profile'],
      secretPaths: ['clientSecret'],
    });
    expect(Object.isFrozen(plugin.method)).toBe(true);

    // A package that builds its own method is the other kind, with no members.
    const plain = await load({ authMethod: sample('corp_sso') }, build);
    expect(plain.installed[0]).toMatchObject({ kind: 'auth-method', responseMembers: [] });
  });

  it('reads a CommonJS preset package under default too', async () => {
    const loaded = await load({ default: { upstreamOidcPreset: preset } }, builder());
    expect(loaded.installed.map((plugin) => plugin.kind)).toEqual(['upstream-oidc-preset']);
  });

  it('keeps a preset package out while the plugin API is off, as any package it does not list first-party', async () => {
    const build = builder();
    const importPackage = importerOf({ [THIRD_PARTY]: { upstreamOidcPreset: preset } });
    const loaded = await loadAuthMethodPlugins({
      packages: [THIRD_PARTY],
      pluginApiEnabled: false,
      firstParty: [],
      importPackage,
      buildUpstreamOidcPreset: build,
    });
    expect(loaded).toEqual({
      installed: [],
      skipped: [{ package: THIRD_PARTY, reason: 'plugin-api-off' }],
    });
    expect(importPackage).not.toHaveBeenCalled();
    expect(build).not.toHaveBeenCalled();
  });

  it('refuses a package that exports both an authMethod and a preset', async () => {
    const error = await refusal(
      load({ authMethod: sample('corp_sso'), upstreamOidcPreset: preset }, builder())
    );
    expect(error.problems).toEqual([
      'it exports both authMethod and upstreamOidcPreset: a plugin package exports one of them',
    ]);
  });

  it('refuses a preset when the server builds none', async () => {
    const error = await refusal(load({ upstreamOidcPreset: preset }));
    expect(error.problems).toEqual([
      'it exports an upstreamOidcPreset, and this server builds no upstream OpenID Connect preset',
    ]);
  });

  it('refuses a preset that fails its checks before it is built, naming each problem', async () => {
    const build = builder();
    const error = await refusal(
      load(
        {
          upstreamOidcPreset: { ...preset, type: 'oidc_corp', origins: ['http://idp.example.com'] },
        },
        build
      )
    );
    expect(error.problems).toEqual([
      "type oidc_corp is in the generic upstream OpenID Connect client's namespace (oidc_<alias>), which no preset may take",
      'origins[0] must be a bare https origin, such as https://idp.example.com',
    ]);
    expect(build).not.toHaveBeenCalled();

    const versioned = await refusal(
      load({ upstreamOidcPreset: { ...preset, contract: 'qauth-auth-method/0' } }, build)
    );
    expect(versioned.problems).toEqual([
      `it is written against the contract qauth-auth-method/0, and this server implements ${AUTH_METHOD_CONTRACT}: install a version of the plugin built for ${AUTH_METHOD_CONTRACT}`,
    ]);
    expect((await refusal(load({ upstreamOidcPreset: 'corp' }, build))).problems).toEqual([
      expect.stringContaining('it exports no authMethod'),
    ]);
  });

  it("refuses a preset the builder cannot build, with each of the builder's reasons", async () => {
    const error = await refusal(
      load({ upstreamOidcPreset: preset }, () => {
        throw new TypeError('The preset cannot be built:\n- one problem\n- another');
      })
    );
    expect(error.problems).toEqual([
      'its upstreamOidcPreset cannot be built: one problem',
      'its upstreamOidcPreset cannot be built: another',
    ]);
  });

  it('holds the built method to the whole contract, as a package-built one', async () => {
    const error = await refusal(
      load({ upstreamOidcPreset: preset }, () => ({ ...sample('corp_idp'), type: 'Corp IdP' }))
    );
    expect(error.problems.join('\n')).toMatch(/type must match/);
    const notAMethod = await refusal(
      load(
        { upstreamOidcPreset: preset },
        () => 'corp' as unknown as ReturnType<BuildUpstreamOidcPreset>
      )
    );
    expect(notAMethod.problems.join('\n')).toMatch(/not an object/);
  });
});
