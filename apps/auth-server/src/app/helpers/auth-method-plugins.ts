import type {
  RealmAuthMethodPlugin,
  RealmAuthMethodPluginBinding,
} from '@qauth-labs/fastify-plugin-db';
import {
  type AuthMethod,
  type AuthMethodContext,
  createAuthMethodContext,
  type ImportAuthMethodPlugin,
  type InstalledAuthMethodPlugin,
  loadAuthMethodPlugins,
  skippedAuthMethodPluginMessage,
  withConfigMembers,
  withoutConfigMembers,
} from '@qauth-labs/fastify-plugin-federation';
import { AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX } from '@qauth-labs/fastify-plugin-signer';
import type { FastifyBaseLogger, FastifyInstance, FastifyRequest } from 'fastify';

import { realmIssuer } from './realm-url';
import { requestRealm } from './request-realm';

/**
 * THE PLUGIN RUNTIME (ADR-019 Decision 12, ADR-018 §4, issue #600).
 *
 * - At boot, `app.ts` loads the packages `AUTH_METHOD_PLUGINS` lists
 *   ({@link loadDeploymentAuthMethodPlugins}): a first-party one always, any
 *   other only while `PLUGIN_API_ENABLED` is on. Each loaded plugin's method
 *   joins the provider registry, and its routes mount under
 *   `/upstream/<type>` (`routes/upstream.ts`).
 * - Per realm, a plugin is off until an admin enables it through the admin
 *   API (`admin/plugins/`): its state and config are a row of
 *   `realm_auth_method_plugins`, its secret members stored encrypted with the
 *   realm's `data_at_rest` key. A disabled plugin's routes answer 404, as a
 *   path no route serves.
 * - A realm's state belongs to the plugin that wrote it, its package and its
 *   type (#949): a state another package, or another type, wrote is off, and
 *   its secrets do not open, until a configure under the installed plugin
 *   writes it again and an enable is approved
 *   ({@link authMethodPluginStateMismatch}). A new version of the same
 *   package, under the same type, keeps the state.
 * - A plugin is handed only its context ({@link authMethodPluginContext}):
 *   its config for the realm, parsed by its schema, the egress client and the
 *   signer bound to the realm and to the plugin, and a logger. No database
 *   handle and no key.
 *
 * The admin console never uploads or edits plugin code: the code is what the
 * operator installed with the deployment.
 */

/**
 * The first-party plugins: the packages that load whatever
 * `PLUGIN_API_ENABLED` says. A fixed list in the server's code, never a
 * setting (#600). Empty.
 *
 * A first-party plugin is one QAuth makes and releases, and it may live in
 * its own repository (ADR-018 §3, amended 2026-11-05). The first such
 * plugin, for example the GitHub one (#672), is not on this list: it loads,
 * as any package the operator installs, only while the plugin API is on.
 * Whether it joins the list before 1.0 is decided when the plugin API leaves
 * the experiment.
 *
 * The generic upstream OIDC client (`@qauth-labs/server-upstream-oidc`,
 * #601) is no plugin: it is a factory that builds one method per provider a
 * realm configures, every one with the id `oidc`, which the loader reserves,
 * where a plugin package exports one `authMethod`. The realm's provider rows
 * run it (#639, #714). A preset plugin built on it
 * (`createUpstreamOidcPresetMethod`, #951) is a plugin like any other, with
 * its own id, type and config, so it can be listed here, as the presets of
 * #671 are meant to be.
 */
export const FIRST_PARTY_AUTH_METHOD_PLUGINS: readonly string[] = Object.freeze([]);

/**
 * The signer caller a plugin's context signs as, and a plugin secret
 * decrypts as: `api`, whose grant holds `signClientAssertion` and the
 * `auth-method-plugin:` contexts among the three kinds of stored secret it
 * may decrypt (`AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX`), as it opens an
 * upstream OpenID Connect client's secret (#601). `web`, which serves a
 * plugin's routes, may neither decrypt nor sign a client assertion, and
 * `local` would open every stored secret. The admin API's configure and
 * enable open a stored or sealed secret as `api` too.
 *
 * In a single deployment every role shares the signer's process. A split
 * signer (#497) takes the role from the caller's certificate and never
 * accepts `local` from a peer, so the admin API, which seals as `local`
 * ({@link AUTH_METHOD_PLUGIN_SEAL_CALLER}) and opens as `api`, still needs a
 * grant of its own there; until then a process without the signer refuses
 * both.
 */
export const AUTH_METHOD_PLUGIN_SIGNER_CALLER = 'api';

/**
 * The signer caller a plugin secret is sealed as: `local`, the caller inside
 * the signer's own process, as the realm secret store (#529) encrypts. The
 * admin API gets a grant of its own when it moves out (#497).
 */
export const AUTH_METHOD_PLUGIN_SEAL_CALLER = 'local';

/**
 * What names a plugin's secrets and its state in a realm: its AuthMethod
 * `id`, the npm package it was loaded from and its `type` (#949).
 */
export type AuthMethodPluginIdentity = Pick<InstalledAuthMethodPlugin, 'id' | 'package' | 'type'>;

/**
 * The `context` a plugin secret is encrypted under, beside its realm:
 * `auth-method-plugin:<plugin id>:<package>:<type>:<path>`, under the prefix
 * the signer's policy lets `api` decrypt. It binds the ciphertext to the
 * plugin, to the package and the type that sealed it (#949), and to the
 * member, so a ciphertext of one plugin's secret, of another package behind
 * the same id, or of another member, never decrypts as this one. No id,
 * package name (`AUTH_METHOD_PLUGINS` takes npm names only) or type holds a
 * `:`, so a context reads one way only.
 */
export function authMethodPluginSecretContext(
  plugin: AuthMethodPluginIdentity,
  path: string
): string {
  return `${AUTH_METHOD_PLUGIN_SECRET_CONTEXT_PREFIX}${plugin.id}:${plugin.package}:${plugin.type}:${path}`;
}

/** Seals and opens a plugin's secret members over the signer (#600). */
export interface AuthMethodPluginSecretCipher {
  /** Encrypt `plaintext` for `path` of the plugin in the realm, as {@link AUTH_METHOD_PLUGIN_SEAL_CALLER}. */
  seal(
    realmId: string,
    plugin: AuthMethodPluginIdentity,
    path: string,
    plaintext: string
  ): Promise<string>;
  /** Decrypt a ciphertext sealed for `path` of the plugin in the realm, as {@link AUTH_METHOD_PLUGIN_SIGNER_CALLER}. */
  open(
    realmId: string,
    plugin: AuthMethodPluginIdentity,
    path: string,
    ciphertext: string
  ): Promise<string>;
}

/**
 * The plugin secrets' cipher over the signer (#600), as `realmSecretCipher`
 * is the realm secrets' (#529): it encrypts as `local` and decrypts as
 * `api`. `fastify.signer` is read on each call.
 */
export function authMethodPluginSecretCipher(
  fastify: Pick<FastifyInstance, 'signer'>
): AuthMethodPluginSecretCipher {
  return Object.freeze({
    seal: (realmId: string, plugin: AuthMethodPluginIdentity, path: string, plaintext: string) =>
      fastify.signer.encrypt(AUTH_METHOD_PLUGIN_SEAL_CALLER, {
        realmId,
        plaintext: Buffer.from(plaintext, 'utf8'),
        context: authMethodPluginSecretContext(plugin, path),
      }),
    async open(
      realmId: string,
      plugin: AuthMethodPluginIdentity,
      path: string,
      ciphertext: string
    ) {
      const plaintext = await fastify.signer.decrypt(AUTH_METHOD_PLUGIN_SIGNER_CALLER, {
        realmId,
        ciphertext,
        context: authMethodPluginSecretContext(plugin, path),
      });
      return plaintext.toString('utf8');
    },
  });
}

/** The plugins this process loaded, by id and by type. */
export interface AuthMethodPluginRuntime {
  /** In the order `AUTH_METHOD_PLUGINS` lists them. */
  readonly installed: readonly InstalledAuthMethodPlugin[];
  /** The plugin whose AuthMethod `id` is `pluginId`, or `undefined`. */
  find(pluginId: string): InstalledAuthMethodPlugin | undefined;
  /** The plugin whose AuthMethod `type` is `type`, or `undefined`. */
  ofType(type: string): InstalledAuthMethodPlugin | undefined;
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The AuthMethod plugins this process loaded (#600). Empty on a process
     * whose roles neither serve the sign-in pages (`web`) nor the admin API
     * (`admin`).
     */
    authMethodPlugins: AuthMethodPluginRuntime;
  }
}

/** A runtime over `installed`. */
export function authMethodPluginRuntime(
  installed: readonly InstalledAuthMethodPlugin[]
): AuthMethodPluginRuntime {
  const byId = new Map(installed.map((plugin) => [plugin.id, plugin]));
  const byType = new Map(installed.map((plugin) => [plugin.type, plugin]));
  return Object.freeze({
    installed: Object.freeze([...installed]),
    find: (pluginId: string) => byId.get(pluginId),
    ofType: (type: string) => byType.get(type),
  });
}

/**
 * TEST SUPPORT — what a test boot may replace in the loader: the `import()`
 * of a package, and the first-party list. Refused unless NODE_ENV is `test`,
 * so a deployment can never widen the list.
 */
export interface AuthMethodPluginTestSupport {
  readonly importPackage?: ImportAuthMethodPlugin;
  readonly firstParty?: readonly string[];
}

/** What {@link loadDeploymentAuthMethodPlugins} reads of the configuration. */
export interface AuthMethodPluginSettings {
  /** `AUTH_METHOD_PLUGINS`. */
  readonly packages: readonly string[];
  /** `PLUGIN_API_ENABLED`. */
  readonly pluginApiEnabled: boolean;
  /** `NODE_ENV`, which the test support needs to be `test`. */
  readonly nodeEnv: string;
}

/**
 * Load this deployment's plugins (#600) and log what happened: one `warn`
 * line per listed package the switch kept out, saying why, and one `info`
 * line per plugin loaded. A package that cannot be loaded throws, and the
 * boot fails.
 *
 * @throws AuthMethodPluginError as `loadAuthMethodPlugins` does
 * @throws Error when test support is passed outside NODE_ENV=test
 */
export async function loadDeploymentAuthMethodPlugins(
  log: Pick<FastifyBaseLogger, 'info' | 'warn'>,
  settings: AuthMethodPluginSettings,
  testSupport?: AuthMethodPluginTestSupport
): Promise<AuthMethodPluginRuntime> {
  if (testSupport !== undefined && settings.nodeEnv !== 'test') {
    throw new Error(
      'The AuthMethod plugin test support (an importer or a first-party list) is refused unless NODE_ENV is test'
    );
  }
  const loaded = await loadAuthMethodPlugins({
    packages: settings.packages,
    pluginApiEnabled: settings.pluginApiEnabled,
    firstParty: testSupport?.firstParty ?? FIRST_PARTY_AUTH_METHOD_PLUGINS,
    ...(testSupport?.importPackage === undefined
      ? {}
      : { importPackage: testSupport.importPackage }),
  });
  for (const skipped of loaded.skipped) {
    log.warn(
      { authMethodPlugin: skipped.package, reason: skipped.reason },
      skippedAuthMethodPluginMessage(skipped)
    );
  }
  for (const plugin of loaded.installed) {
    log.info(
      {
        authMethodPlugin: plugin.package,
        id: plugin.id,
        type: plugin.type,
        firstParty: plugin.firstParty,
        contract: plugin.method.contract,
      },
      `AuthMethod plugin ${plugin.package} loaded: ${plugin.id} (${plugin.type})`
    );
  }
  return authMethodPluginRuntime(loaded.installed);
}

/** What the plugin runtime reads of the server. */
export type AuthMethodPluginServer = Pick<
  FastifyInstance,
  'authMethodPlugins' | 'repositories' | 'signer'
>;

/**
 * Why a realm's stored state of a plugin is not the installed plugin's
 * (#949), as `plugins.get` says it:
 *
 * - `package_unrecorded`: the state names no package; it was written before
 *   QAuth recorded which plugin wrote it (by 0.2, or by a node of it during
 *   a rolling upgrade).
 * - `package_changed`: another package wrote it; the deployment put another
 *   package behind the plugin's id.
 * - `type_changed`: the same package wrote it under another type; a version
 *   of the package that changed its type, and so its routes and the
 *   credentials it writes.
 */
export const AUTH_METHOD_PLUGIN_STATE_MISMATCHES = Object.freeze([
  'package_unrecorded',
  'package_changed',
  'type_changed',
] as const);

/** One of {@link AUTH_METHOD_PLUGIN_STATE_MISMATCHES}. */
export type AuthMethodPluginStateMismatch = (typeof AUTH_METHOD_PLUGIN_STATE_MISMATCHES)[number];

/** The package and type a realm's stored state was written for, or `null` when it names none. */
export function authMethodPluginStateBinding(
  row: Pick<RealmAuthMethodPlugin, 'pluginPackage' | 'pluginType'>
): RealmAuthMethodPluginBinding | null {
  return row.pluginPackage === null || row.pluginType === null
    ? null
    : { package: row.pluginPackage, type: row.pluginType };
}

/**
 * Why the realm's stored state `row` is not the state of the installed
 * `plugin` (#949), or `null` when it is: the package and the type that wrote
 * it are the plugin's own. A version upgrade of the same package, under the
 * same type, matches. A state that does not match is off whatever its
 * `enabled` says, and its secrets do not open: they were sealed under a
 * context that names the package and the type
 * ({@link authMethodPluginSecretContext}).
 */
export function authMethodPluginStateMismatch(
  plugin: Pick<InstalledAuthMethodPlugin, 'package' | 'type'>,
  row: Pick<RealmAuthMethodPlugin, 'pluginPackage' | 'pluginType'>
): AuthMethodPluginStateMismatch | null {
  const binding = authMethodPluginStateBinding(row);
  if (binding === null) return 'package_unrecorded';
  if (binding.package !== plugin.package) return 'package_changed';
  if (binding.type !== plugin.type) return 'type_changed';
  return null;
}

/**
 * Whether the realm has the plugin on: it has a row for it, enabled, and
 * written by this plugin's package under its type (#949).
 */
export async function authMethodPluginEnabledIn(
  fastify: Pick<FastifyInstance, 'repositories'>,
  realmId: string,
  plugin: AuthMethodPluginIdentity
): Promise<boolean> {
  const row = await fastify.repositories.realmAuthMethodPlugins.find(realmId, plugin.id);
  return row?.enabled === true && authMethodPluginStateMismatch(plugin, row) === null;
}

/**
 * The realm's config of the plugin as the plugin's schema takes it: the
 * stored plain members, with each secret member decrypted back into place;
 * and the decrypted secrets by path, which the context keeps out of its log
 * lines and its egress labels. For the plugin's context only; never for a
 * response, an event or a log.
 */
export async function authMethodPluginConfig(
  fastify: Pick<FastifyInstance, 'signer'>,
  plugin: AuthMethodPluginIdentity & Pick<InstalledAuthMethodPlugin, 'secretPaths'>,
  row: Pick<RealmAuthMethodPlugin, 'realmId' | 'config' | 'secrets'>
): Promise<{ config: Record<string, unknown>; secrets: ReadonlyMap<string, string> }> {
  const cipher = authMethodPluginSecretCipher(fastify);
  const secrets = new Map<string, string>();
  for (const path of plugin.secretPaths) {
    if (!Object.hasOwn(row.secrets, path)) continue;
    secrets.set(path, await cipher.open(row.realmId, plugin, path, row.secrets[path]));
  }
  // A member the plugin marks secret comes only from the secret store, never
  // from the plain config an earlier version of the plugin may have kept.
  return {
    config: withConfigMembers(withoutConfigMembers(row.config, plugin.secretPaths), secrets),
    secrets,
  };
}

/** The context of a plugin the request's realm has not enabled: never built. */
export class AuthMethodPluginDisabledError extends Error {
  override readonly name = 'AuthMethodPluginDisabledError';
}

/**
 * The context a plugin's method is handed for the request's realm (ADR-019
 * Decision 12): its config, parsed by its schema; the egress client, which
 * adds the realm; the signer, bound to the realm, to the plugin's type as the
 * provider and to {@link AUTH_METHOD_PLUGIN_SIGNER_CALLER}; and the request's
 * logger with the plugin's id. `createAuthMethodContext` passes on only the
 * members the contract names, so the plugin reaches no database or cache
 * handle, no `decrypt` and no key.
 *
 * @throws AuthMethodPluginDisabledError when the method is no loaded plugin's,
 *   the realm has not enabled it, or its state was written by another
 *   package or under another type (#949)
 * @throws AuthMethodConfigError when the stored config fails the schema
 */
export async function authMethodPluginContext(
  fastify: AuthMethodPluginServer & Pick<FastifyInstance, 'egress'>,
  request: FastifyRequest,
  method: AuthMethod
): Promise<AuthMethodContext> {
  const realm = requestRealm(request);
  const plugin = fastify.authMethodPlugins.ofType(method.type);
  const row =
    plugin === undefined
      ? undefined
      : await fastify.repositories.realmAuthMethodPlugins.find(realm.id, plugin.id);
  if (
    plugin === undefined ||
    row?.enabled !== true ||
    authMethodPluginStateMismatch(plugin, row) !== null
  ) {
    throw new AuthMethodPluginDisabledError(
      `The AuthMethod ${method.type} is not an enabled plugin of the realm`
    );
  }
  const { config, secrets } = await authMethodPluginConfig(fastify, plugin, row);
  return createAuthMethodContext(plugin.method, {
    config,
    secrets,
    // The routes answer on the realm's host, at its root.
    origin: new URL(realmIssuer(realm)).origin,
    realmName: realm.name,
    realmId: realm.id,
    providerId: plugin.type,
    signerCaller: AUTH_METHOD_PLUGIN_SIGNER_CALLER,
    egress: fastify.egress,
    signer: fastify.signer,
    log: request.log.child({ authMethodPlugin: plugin.id }),
  });
}
