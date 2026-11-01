import type { AuthMethod } from './auth-method.interface';
import { AUTH_METHOD_CONTRACT, AUTH_METHOD_CONTRACT_NAME } from './contract';
import { AuthMethodContractError } from './errors';
import { authMethodSecretPaths } from './secret-members';
import { assertAuthMethod, authMethodSnapshot } from './validate';

/**
 * THE PLUGIN LOADER (ADR-019 Decision 12, ADR-018 §4, issue #600).
 *
 * A plugin is an npm package the operator installs with the deployment and
 * lists in `AUTH_METHOD_PLUGINS`. At boot the server imports each listed
 * package, checks the contract version its method is written against, holds
 * the method to the whole AuthMethod contract and reads which members of its
 * config are secret. A package that is not installed, exports no method, is
 * written against another contract, breaks the contract, or repeats another
 * plugin's `id` or `type` fails the boot. The admin API can then enable,
 * configure and disable an installed plugin per realm; it never uploads or
 * edits plugin code.
 *
 * The plugin API is experimental. A package outside the server's first-party
 * list loads only while its switch, `PLUGIN_API_ENABLED`, is on; with it off,
 * the package is never imported, and the boot says why. Which packages are
 * first-party is a fixed list in the server's code, never a setting.
 *
 * Plugin code is trusted code that runs in-process: a package's own code
 * runs as it is imported. The loader cannot sandbox it, so the switch and the
 * list decide whose code is imported at all.
 *
 * @experimental
 */

/**
 * The export a plugin package names its method by: `authMethod`, an
 * AuthMethod object. A CommonJS package may put it under `default`.
 *
 * ```ts
 * // index.ts of @example/qauth-plugin-corp-sso
 * export const authMethod: AuthMethod<CorpSsoConfig, CorpSsoTransaction> = { … };
 * ```
 *
 * @experimental
 */
export const AUTH_METHOD_PLUGIN_EXPORT = 'authMethod';

/**
 * Imports a plugin package by name. The production one is `import()`;
 * replaceable for tests.
 *
 * @experimental
 */
export type ImportAuthMethodPlugin = (packageName: string) => Promise<unknown>;

const importPackage: ImportAuthMethodPlugin = (packageName) => import(packageName);

/**
 * Options of {@link loadAuthMethodPlugins}.
 *
 * @experimental
 */
export interface LoadAuthMethodPluginsOptions {
  /** The packages to load, in order: `AUTH_METHOD_PLUGINS`. */
  readonly packages: readonly string[];
  /** `PLUGIN_API_ENABLED`: whether a package outside {@link firstParty} loads. */
  readonly pluginApiEnabled: boolean;
  /** The first-party packages, which load whatever the switch says. */
  readonly firstParty: readonly string[];
  /** Replaces the dynamic `import()`, for tests. */
  readonly importPackage?: ImportAuthMethodPlugin;
}

/**
 * One installed plugin: its package and the method it registers.
 *
 * @experimental
 */
export interface InstalledAuthMethodPlugin {
  /** The npm package it was loaded from. */
  readonly package: string;
  /** It is on the server's first-party list. */
  readonly firstParty: boolean;
  /** The method's `id`: what the admin API names the plugin by. */
  readonly id: string;
  /** The method's `type`: its registry key and the segment of its route prefix. */
  readonly type: string;
  /** The method, as the registry keeps it: a frozen snapshot, checked against the contract. */
  readonly method: AuthMethod;
  /** The paths of its config's secret members, which stay write-only. */
  readonly secretPaths: readonly string[];
}

/**
 * A listed package the loader did not import, and why.
 *
 * - `plugin-api-off`: it is not first-party, and `PLUGIN_API_ENABLED` is off.
 *
 * @experimental
 */
export interface SkippedAuthMethodPlugin {
  readonly package: string;
  readonly reason: 'plugin-api-off';
}

/**
 * What {@link loadAuthMethodPlugins} answers.
 *
 * @experimental
 */
export interface LoadedAuthMethodPlugins {
  /** The plugins loaded, in the order listed. */
  readonly installed: readonly InstalledAuthMethodPlugin[];
  /** The listed packages that were not imported. */
  readonly skipped: readonly SkippedAuthMethodPlugin[];
}

/**
 * A listed plugin package cannot be loaded: the boot fails. The message names
 * the package and every problem; it never holds a config value.
 *
 * @experimental
 */
export class AuthMethodPluginError extends Error {
  /** The package, when the problem is one package's. */
  readonly packageName: string | undefined;
  /** Every problem found, one sentence each. */
  readonly problems: readonly string[];

  constructor(packageName: string | undefined, problems: readonly string[]) {
    const subject =
      packageName === undefined
        ? 'The AuthMethod plugins cannot be loaded'
        : `The AuthMethod plugin package ${packageName} cannot be loaded`;
    super(`${subject}:\n- ${problems.join('\n- ')}`);
    this.name = 'AuthMethodPluginError';
    this.packageName = packageName;
    this.problems = Object.freeze([...problems]);
    Object.setPrototypeOf(this, AuthMethodPluginError.prototype);
  }
}

/**
 * Whether `error` says that `packageName` itself is missing, rather than a
 * package the plugin imports. Node quotes the missing name on the first line
 * of the message (the same rule as the KEK provider loader).
 */
function isMissingPackage(error: unknown, packageName: string): boolean {
  if (!(error instanceof Error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  if (code !== 'ERR_MODULE_NOT_FOUND' && code !== 'MODULE_NOT_FOUND') return false;
  const firstLine = error.message.split('\n', 1)[0];
  return firstLine.includes(`'${packageName}'`) || firstLine.includes(`"${packageName}"`);
}

/** The `authMethod` export of a module, or `undefined`. */
function exportedMethod(module: unknown): unknown {
  if (typeof module !== 'object' || module === null) return undefined;
  const direct = (module as Record<string, unknown>)[AUTH_METHOD_PLUGIN_EXPORT];
  if (direct !== undefined) return direct;
  // A CommonJS package imported from ESM arrives under `default`.
  const fallback = (module as { default?: unknown }).default;
  return typeof fallback === 'object' && fallback !== null
    ? (fallback as Record<string, unknown>)[AUTH_METHOD_PLUGIN_EXPORT]
    : undefined;
}

/**
 * The contract version a candidate declares, checked first and on its own,
 * so a plugin written for another version says so, whatever else it breaks.
 */
function contractVersionProblem(candidate: unknown): string | undefined {
  const contract =
    typeof candidate === 'object' && candidate !== null
      ? (candidate as Record<string, unknown>)['contract']
      : undefined;
  if (contract === AUTH_METHOD_CONTRACT) return undefined;
  if (typeof contract === 'string' && contract.startsWith(`${AUTH_METHOD_CONTRACT_NAME}/`)) {
    return `it is written against the contract ${contract.slice(0, 64)}, and this server implements ${AUTH_METHOD_CONTRACT}: install a version of the plugin built for ${AUTH_METHOD_CONTRACT}`;
  }
  return `its ${AUTH_METHOD_PLUGIN_EXPORT} names no contract version: it must declare contract ${AUTH_METHOD_CONTRACT}`;
}

/** Load one package: import it and check what it exports. */
async function loadPackage(
  packageName: string,
  firstParty: boolean,
  importer: ImportAuthMethodPlugin
): Promise<InstalledAuthMethodPlugin> {
  let module: unknown;
  try {
    module = await importer(packageName);
  } catch (error) {
    if (isMissingPackage(error, packageName)) {
      throw new AuthMethodPluginError(packageName, [
        'it is not installed: install it with the deployment, or remove it from AUTH_METHOD_PLUGINS',
      ]);
    }
    throw new AuthMethodPluginError(packageName, [
      `importing it failed: ${error instanceof Error ? error.message.split('\n', 1)[0] : 'the package threw a value that is not an Error'}`,
    ]);
  }

  const candidate = exportedMethod(module);
  if (typeof candidate !== 'object' || candidate === null) {
    throw new AuthMethodPluginError(packageName, [
      `it exports no ${AUTH_METHOD_PLUGIN_EXPORT}: a plugin package exports its AuthMethod as ${AUTH_METHOD_PLUGIN_EXPORT}`,
    ]);
  }
  const versionProblem = contractVersionProblem(candidate);
  if (versionProblem !== undefined) {
    throw new AuthMethodPluginError(packageName, [versionProblem]);
  }

  // The snapshot the registry keeps, held to the whole contract, and the
  // secret members of its config, read once from that snapshot.
  let method: AuthMethod;
  let secretPaths: string[];
  try {
    const snapshot = authMethodSnapshot(candidate);
    assertAuthMethod(snapshot);
    method = snapshot;
    secretPaths = authMethodSecretPaths(method);
  } catch (error) {
    if (error instanceof AuthMethodContractError) {
      throw new AuthMethodPluginError(packageName, error.problems);
    }
    throw error;
  }
  return Object.freeze({
    package: packageName,
    firstParty,
    id: method.id,
    type: method.type,
    method,
    secretPaths: Object.freeze([...secretPaths]),
  });
}

/**
 * Load the plugins `AUTH_METHOD_PLUGINS` lists (#600), in order.
 *
 * A first-party package always loads. Any other loads only with
 * `pluginApiEnabled`; without it the package is never imported, and it is
 * answered among `skipped`, for the boot to log why.
 *
 * @throws AuthMethodPluginError when a package is listed twice, is not
 *   installed, fails as it is imported, exports no `authMethod`, is written
 *   against another contract version, does not meet the contract, marks a
 *   secret config member the server cannot keep write-only, or repeats the
 *   `id` or the `type` of a plugin loaded before it
 * @experimental
 */
export async function loadAuthMethodPlugins(
  options: LoadAuthMethodPluginsOptions
): Promise<LoadedAuthMethodPlugins> {
  const importer = options.importPackage ?? importPackage;
  const firstParty = new Set(options.firstParty);
  const listed = new Set<string>();
  const installed: InstalledAuthMethodPlugin[] = [];
  const skipped: SkippedAuthMethodPlugin[] = [];

  for (const packageName of options.packages) {
    if (listed.has(packageName)) {
      throw new AuthMethodPluginError(packageName, ['AUTH_METHOD_PLUGINS lists it twice']);
    }
    listed.add(packageName);

    const isFirstParty = firstParty.has(packageName);
    // Strict `=== true`: this decides whose code is imported at all.
    if (!isFirstParty && options.pluginApiEnabled !== true) {
      skipped.push(Object.freeze({ package: packageName, reason: 'plugin-api-off' }));
      continue;
    }

    const plugin = await loadPackage(packageName, isFirstParty, importer);
    const sameId = installed.find((other) => other.id === plugin.id);
    if (sameId !== undefined) {
      throw new AuthMethodPluginError(packageName, [
        `its id ${plugin.id} is the id of ${sameId.package}: two plugins cannot share an id`,
      ]);
    }
    const sameType = installed.find((other) => other.type === plugin.type);
    if (sameType !== undefined) {
      throw new AuthMethodPluginError(packageName, [
        `its type ${plugin.type} is the type of ${sameType.package}: two plugins cannot share a type`,
      ]);
    }
    installed.push(plugin);
  }

  return Object.freeze({
    installed: Object.freeze(installed),
    skipped: Object.freeze(skipped),
  });
}

/**
 * The log line of a skipped package, which the boot writes at `warn`.
 *
 * @experimental
 */
export function skippedAuthMethodPluginMessage(skipped: SkippedAuthMethodPlugin): string {
  return `The AuthMethod plugin ${skipped.package} is not loaded: it is not a first-party plugin, and the experimental plugin API is off. Set PLUGIN_API_ENABLED=true to load it, or remove it from AUTH_METHOD_PLUGINS`;
}
