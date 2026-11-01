import { z } from 'zod';

/**
 * AuthMethod plugins (ADR-019 Decision 12, ADR-018 §4, issue #600).
 *
 * - `AUTH_METHOD_PLUGINS` lists the npm packages the auth server loads at
 *   boot, by package name, comma-separated. The operator installs them with
 *   the deployment: the server never fetches code, and a value that is not a
 *   package name (a path, a URL, a `file:` or `git+` specifier) fails the
 *   boot. Each listed package must export an AuthMethod on the contract this
 *   server implements, or the boot fails too.
 * - `PLUGIN_API_ENABLED` is the switch of the experimental item `plugin-api`.
 *   A listed package that is not one of QAuth's first-party plugins loads
 *   only while it is on; with it off, such a package is skipped and the boot
 *   says why. First-party plugins load either way. Which plugins are
 *   first-party is a fixed list in the server's code, never a setting.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */

/**
 * An npm package name, as npm accepts a new one: lower case, an optional
 * `@scope/`, letters, digits, `-`, `.`, `_` and `~`, not starting with `.` or
 * `_`, at most 214 characters.
 */
export const PLUGIN_PACKAGE_NAME_PATTERN =
  /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

/** The longest package name npm accepts. */
export const MAX_PLUGIN_PACKAGE_NAME_LENGTH = 214;

/** The most packages `AUTH_METHOD_PLUGINS` may list. */
export const MAX_AUTH_METHOD_PLUGINS = 32;

/** Same parsing as `SSF_TRANSMITTER_ENABLED`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/**
 * The package names of `AUTH_METHOD_PLUGINS`, in the order written. Blank is
 * no plugin. Each entry is trimmed; an empty entry, a name npm would not
 * accept and a name listed twice are refused, so a typo fails the boot.
 */
const pluginPackageList = z
  .preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z
      .string()
      .max(MAX_AUTH_METHOD_PLUGINS * (MAX_PLUGIN_PACKAGE_NAME_LENGTH + 1))
      .optional()
  )
  .transform((value) =>
    Object.freeze(value === undefined ? [] : value.split(',').map((entry) => entry.trim()))
  )
  .refine((names) => names.length <= MAX_AUTH_METHOD_PLUGINS, {
    message: `AUTH_METHOD_PLUGINS lists at most ${MAX_AUTH_METHOD_PLUGINS} packages`,
  })
  .refine(
    (names) =>
      names.every(
        (name) =>
          name.length > 0 &&
          name.length <= MAX_PLUGIN_PACKAGE_NAME_LENGTH &&
          PLUGIN_PACKAGE_NAME_PATTERN.test(name)
      ),
    {
      message:
        'AUTH_METHOD_PLUGINS lists npm package names, comma-separated, such as @example/qauth-plugin-corp-sso: no path, URL or empty entry',
    }
  )
  .refine((names) => new Set(names).size === names.length, {
    message: 'AUTH_METHOD_PLUGINS lists a package twice',
  });

/**
 * Plugin environment configuration schema.
 */
export const pluginsEnvSchema = z.object({
  /** The AuthMethod plugin packages to load at boot, comma-separated. Default none. */
  AUTH_METHOD_PLUGINS: pluginPackageList,
  /**
   * The switch of the experimental plugin API (`plugin-api`): a plugin that
   * is not first-party loads only while it is on. Default off.
   */
  PLUGIN_API_ENABLED: strictBoolean(false),
});

export type PluginsEnv = z.infer<typeof pluginsEnvSchema>;
