import type { RealmAuthMethodPlugin } from '@qauth-labs/fastify-plugin-db';
import {
  type AuthMethod,
  type AuthMethodContext,
  createAuthMethodContext,
  type ImportAuthMethodPlugin,
  type InstalledAuthMethodPlugin,
  loadAuthMethodPlugins,
  skippedAuthMethodPluginMessage,
  withConfigMembers,
} from '@qauth-labs/fastify-plugin-federation';
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
 * setting (#600): the first-party provider plugins of ADR-020 §4 add their
 * packages here as they ship (#671, #672, #673). Empty until then.
 */
export const FIRST_PARTY_AUTH_METHOD_PLUGINS: readonly string[] = Object.freeze([]);

/**
 * The signer caller a plugin's context signs and a plugin secret decrypts as.
 * `local`: in a single deployment every role shares the signer's process
 * (ADR-019 Decision 9), as the realm secret store does (#529). A split
 * deployment gives the web role a grant of its own when the signer service
 * runs apart (#497); until then a process without the signer refuses both.
 */
export const AUTH_METHOD_PLUGIN_SIGNER_CALLER = 'local';

/**
 * The `context` a plugin secret is encrypted under, beside its realm: it
 * binds the ciphertext to the plugin and to the member, so a ciphertext of
 * one plugin's secret, or of another member, never decrypts as this one.
 */
export function authMethodPluginSecretContext(pluginId: string, path: string): string {
  return `auth-method-plugin:${pluginId}:${path}`;
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

/** Whether the realm has the plugin on: it has a row for it, enabled. */
export async function authMethodPluginEnabledIn(
  fastify: Pick<FastifyInstance, 'repositories'>,
  realmId: string,
  plugin: Pick<InstalledAuthMethodPlugin, 'id'>
): Promise<boolean> {
  const row = await fastify.repositories.realmAuthMethodPlugins.find(realmId, plugin.id);
  return row?.enabled === true;
}

/**
 * The realm's config of the plugin as the plugin's schema takes it: the
 * stored plain members, with each secret member decrypted back into place.
 * For the plugin's context only; never for a response, an event or a log.
 */
export async function authMethodPluginConfig(
  fastify: Pick<FastifyInstance, 'signer'>,
  plugin: Pick<InstalledAuthMethodPlugin, 'id' | 'secretPaths'>,
  row: Pick<RealmAuthMethodPlugin, 'realmId' | 'config' | 'secrets'>
): Promise<Record<string, unknown>> {
  const secrets = new Map<string, string>();
  for (const path of plugin.secretPaths) {
    if (!Object.hasOwn(row.secrets, path)) continue;
    const plaintext = await fastify.signer.decrypt(AUTH_METHOD_PLUGIN_SIGNER_CALLER, {
      realmId: row.realmId,
      ciphertext: row.secrets[path],
      context: authMethodPluginSecretContext(plugin.id, path),
    });
    secrets.set(path, plaintext.toString('utf8'));
  }
  return withConfigMembers(row.config, secrets);
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
 *   or the realm has not enabled it
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
  if (plugin === undefined || row?.enabled !== true) {
    throw new AuthMethodPluginDisabledError(
      `The AuthMethod ${method.type} is not an enabled plugin of the realm`
    );
  }
  return createAuthMethodContext(plugin.method, {
    config: await authMethodPluginConfig(fastify, plugin, row),
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
