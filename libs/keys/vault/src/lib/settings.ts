import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import type { KekEnv, KekWarning } from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { readSecretFile } from './secret-file';

/**
 * The settings of the Vault Transit KEK provider (ADR-019 Decision 9, #578),
 * read from the provider context's environment.
 *
 * - `KEK_VAULT_ADDR`, required: the `https://` origin of the Vault server,
 *   such as `https://vault.internal:8200`. Plain `http://` is refused: every
 *   call carries a Vault token and a data key.
 * - `KEK_VAULT_TRANSIT_KEY`, required: the name of the Transit key that is the
 *   KEK.
 * - `KEK_VAULT_TRANSIT_MOUNT`, optional: the path the Transit engine is
 *   mounted at, `transit` by default.
 * - `KEK_VAULT_NAMESPACE`, optional: the Vault namespace that holds the mount
 *   and the auth method, sent as `X-Vault-Namespace`.
 * - `KEK_VAULT_CA_CERT_FILE`, optional: a PEM file of the CA certificates that
 *   sign Vault's TLS certificate. When set, Vault calls trust these instead of
 *   Node's default CA store.
 * - Exactly one way to log in:
 *   - `KEK_VAULT_TOKEN_FILE`: a file holding a Vault token, such as the sink
 *     of a Vault Agent; or
 *   - `KEK_VAULT_ROLE_ID` and `KEK_VAULT_SECRET_ID_FILE`: an AppRole role ID,
 *     and a file holding a secret ID for it, with `KEK_VAULT_APPROLE_MOUNT`
 *     (optional, `approle` by default) naming the AppRole auth mount.
 *
 * A token or a secret ID is never read from a variable: any other `KEK_VAULT_*`
 * variable, such as `KEK_VAULT_TOKEN`, is refused, without its value in the
 * error.
 */

/** The `KEK_PROVIDER` value that selects this provider. */
export const VAULT_KEK_PROVIDER = 'vault';

/** The variables this provider reads. */
export const ADDR_VARIABLE = 'KEK_VAULT_ADDR';
export const TRANSIT_KEY_VARIABLE = 'KEK_VAULT_TRANSIT_KEY';
export const TRANSIT_MOUNT_VARIABLE = 'KEK_VAULT_TRANSIT_MOUNT';
export const NAMESPACE_VARIABLE = 'KEK_VAULT_NAMESPACE';
export const CA_CERT_FILE_VARIABLE = 'KEK_VAULT_CA_CERT_FILE';
export const TOKEN_FILE_VARIABLE = 'KEK_VAULT_TOKEN_FILE';
export const ROLE_ID_VARIABLE = 'KEK_VAULT_ROLE_ID';
export const SECRET_ID_FILE_VARIABLE = 'KEK_VAULT_SECRET_ID_FILE';
export const APPROLE_MOUNT_VARIABLE = 'KEK_VAULT_APPROLE_MOUNT';

const SETTINGS: readonly string[] = [
  ADDR_VARIABLE,
  TRANSIT_KEY_VARIABLE,
  TRANSIT_MOUNT_VARIABLE,
  NAMESPACE_VARIABLE,
  CA_CERT_FILE_VARIABLE,
  TOKEN_FILE_VARIABLE,
  ROLE_ID_VARIABLE,
  SECRET_ID_FILE_VARIABLE,
  APPROLE_MOUNT_VARIABLE,
];
const PREFIX = 'KEK_VAULT_';

/** Variables that would hold a credential itself, with the file variable to use instead. */
const CREDENTIAL_VARIABLES: Readonly<Record<string, string>> = {
  KEK_VAULT_TOKEN: TOKEN_FILE_VARIABLE,
  KEK_VAULT_SECRET_ID: SECRET_ID_FILE_VARIABLE,
};

/** The default Transit mount. */
export const DEFAULT_TRANSIT_MOUNT = 'transit';
/** The default AppRole auth mount. */
export const DEFAULT_APPROLE_MOUNT = 'approle';

/** The variables of the default provider, which this one does not read. */
const LOCAL_KEK_VARIABLES = ['KEK', 'KEK_PATH', 'KEK_PREVIOUS', 'KEK_PREVIOUS_PATH'];

/** How the provider logs in to Vault. */
export type VaultAuthSettings =
  | { readonly method: 'token'; readonly tokenFile: string }
  | {
      readonly method: 'approle';
      readonly roleId: string;
      readonly secretIdFile: string;
      readonly mount: string;
    };

/** What {@link readVaultSettings} returns. */
export interface VaultSettings {
  /** The Vault origin, such as `https://vault.internal:8200`, with no path. */
  readonly address: string;
  /** The Transit mount path, without leading or trailing `/`. */
  readonly transitMount: string;
  /** The Transit key name. */
  readonly keyName: string;
  /** The namespace, without leading or trailing `/`; `undefined` for the root namespace. */
  readonly namespace: string | undefined;
  /** The PEM text of the CA certificates to trust, or `undefined` for Node's defaults. */
  readonly caCertificates: string | undefined;
  readonly auth: VaultAuthSettings;
}

/**
 * A Transit key name as Vault accepts it: word characters, with `-`, `.` and
 * `@` inside. Capped at 128 characters.
 */
const KEY_NAME = /^[A-Za-z0-9_](?:[A-Za-z0-9_.@-]{0,126}[A-Za-z0-9_])?$/;

/** A mount path or namespace: segments of word characters, `-` and `.`, joined by `/`. */
const PATH = /^[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$/;
const MAX_PATH_LENGTH = 256;

/** An AppRole role ID: printable, without spaces. */
const ROLE_ID = /^[\x21-\x7e]{1,256}$/;

const EXAMPLE_ADDR = 'https://vault.internal:8200';

/** A blank value counts as unset, since Docker Compose passes an absent variable as `''`. */
function setting(env: KekEnv, variable: string): string | undefined {
  const value = env[variable]?.trim();
  return value ? value : undefined;
}

/**
 * `value` as an `https://` origin, or an error naming what is wrong with it.
 * The value is never put in the error: a query or a user name could hold a
 * credential.
 */
function vaultOrigin(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new InvalidConfigurationError(
      `${ADDR_VARIABLE} must be the https:// address of the Vault server, for example ${EXAMPLE_ADDR}.`,
      { variable: ADDR_VARIABLE }
    );
  }
  if (url.username !== '' || url.password !== '') {
    throw new InvalidConfigurationError(
      `${ADDR_VARIABLE} must not hold a user name or password. Vault credentials come from ${TOKEN_FILE_VARIABLE} or ${SECRET_ID_FILE_VARIABLE} only.`,
      { variable: ADDR_VARIABLE }
    );
  }
  if (url.protocol !== 'https:') {
    throw new InvalidConfigurationError(
      `${ADDR_VARIABLE} must use https://: every Vault call carries a token and a data key. See this error's "details" for the scheme it has.`,
      { variable: ADDR_VARIABLE, scheme: url.protocol.replace(/:$/, '') }
    );
  }
  if ((url.pathname !== '/' && url.pathname !== '') || url.search !== '' || url.hash !== '') {
    throw new InvalidConfigurationError(
      `${ADDR_VARIABLE} must be the server's origin only, such as ${EXAMPLE_ADDR}, with no path, query or fragment.`,
      { variable: ADDR_VARIABLE }
    );
  }
  return url.origin;
}

/** A mount path or namespace, without leading or trailing `/`. */
function vaultPath(variable: string, value: string, what: string): string {
  const path = value.replace(/^\/+|\/+$/g, '');
  if (path === '' || path.length > MAX_PATH_LENGTH || !PATH.test(path)) {
    throw new InvalidConfigurationError(
      `${variable} must be ${what}: segments of letters, digits, "_", "-" and ".", separated by "/". See this error's "details" for the value.`,
      { variable, value }
    );
  }
  return path;
}

/** Read and check the PEM CA certificates in `path`. */
function readCaCertificates(path: string): string {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new InvalidConfigurationError(
      `The file ${CA_CERT_FILE_VARIABLE} names could not be read. See this error's "details" for the reason.`,
      { variable: CA_CERT_FILE_VARIABLE, path, code: (error as NodeJS.ErrnoException).code }
    );
  }
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) {
    throw new InvalidConfigurationError(
      `The file ${CA_CERT_FILE_VARIABLE} names holds no PEM certificate.`,
      { variable: CA_CERT_FILE_VARIABLE, path }
    );
  }
  for (const block of blocks) {
    try {
      new X509Certificate(block);
    } catch {
      throw new InvalidConfigurationError(
        `The file ${CA_CERT_FILE_VARIABLE} names holds a certificate that does not parse.`,
        { variable: CA_CERT_FILE_VARIABLE, path }
      );
    }
  }
  return blocks.join('\n');
}

/** Read and check how the provider logs in. */
function readAuthSettings(env: KekEnv, warn: (warning: KekWarning) => void): VaultAuthSettings {
  const tokenFile = setting(env, TOKEN_FILE_VARIABLE);
  const roleId = setting(env, ROLE_ID_VARIABLE);
  const secretIdFile = setting(env, SECRET_ID_FILE_VARIABLE);
  const appRoleMount = setting(env, APPROLE_MOUNT_VARIABLE);
  const appRole = roleId !== undefined || secretIdFile !== undefined || appRoleMount !== undefined;

  if (tokenFile !== undefined && appRole) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} logs in one way: set ${TOKEN_FILE_VARIABLE} for a token, or ${ROLE_ID_VARIABLE} and ${SECRET_ID_FILE_VARIABLE} for AppRole, not both.`,
      {
        variables: [
          TOKEN_FILE_VARIABLE,
          ROLE_ID_VARIABLE,
          SECRET_ID_FILE_VARIABLE,
          APPROLE_MOUNT_VARIABLE,
        ].filter((name) => setting(env, name) !== undefined),
      }
    );
  }

  if (tokenFile !== undefined) {
    readSecretFile(tokenFile, TOKEN_FILE_VARIABLE, warn);
    return Object.freeze({ method: 'token', tokenFile });
  }

  if (!appRole) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} needs a way to log in to Vault: ${TOKEN_FILE_VARIABLE}, a file holding a Vault token, or ${ROLE_ID_VARIABLE} and ${SECRET_ID_FILE_VARIABLE} for AppRole.`,
      { variables: [TOKEN_FILE_VARIABLE, ROLE_ID_VARIABLE, SECRET_ID_FILE_VARIABLE] }
    );
  }
  if (roleId === undefined || secretIdFile === undefined) {
    const missing = roleId === undefined ? ROLE_ID_VARIABLE : SECRET_ID_FILE_VARIABLE;
    throw new InvalidConfigurationError(
      `AppRole login needs both ${ROLE_ID_VARIABLE} and ${SECRET_ID_FILE_VARIABLE}; ${missing} is not set.`,
      { variable: missing }
    );
  }
  if (!ROLE_ID.test(roleId)) {
    throw new InvalidConfigurationError(
      `${ROLE_ID_VARIABLE} must be an AppRole role ID: printable characters with no spaces, at most 256.`,
      { variable: ROLE_ID_VARIABLE }
    );
  }
  readSecretFile(secretIdFile, SECRET_ID_FILE_VARIABLE, warn);
  return Object.freeze({
    method: 'approle',
    roleId,
    secretIdFile,
    mount:
      appRoleMount === undefined
        ? DEFAULT_APPROLE_MOUNT
        : vaultPath(
            APPROLE_MOUNT_VARIABLE,
            appRoleMount,
            'the path the AppRole auth method is mounted at'
          ),
  });
}

/**
 * Read and check the provider's settings. Reads the token or secret ID file
 * once to check it, and the CA file; makes no Vault call.
 *
 * @param warn - receives a warning for each variable of the default provider
 *   that is set, since this provider ignores it, and for a token or secret ID
 *   file that group or others can read
 * @throws InvalidConfigurationError naming the variable at fault
 */
export function readVaultSettings(env: KekEnv, warn: (warning: KekWarning) => void): VaultSettings {
  const unknown = Object.keys(env)
    .filter(
      (name) =>
        name.startsWith(PREFIX) && !SETTINGS.includes(name) && setting(env, name) !== undefined
    )
    .sort();
  const credential = unknown.find((name) => name in CREDENTIAL_VARIABLES);
  if (credential !== undefined) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} never reads a Vault credential from a variable, where it would show in the process environment. Write it to a file readable only by the signer and set ${CREDENTIAL_VARIABLES[credential]} instead. Remove the variables this error's "details" names.`,
      { variables: unknown }
    );
  }
  if (unknown.length > 0) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} reads only ${SETTINGS.join(', ')}. Remove the variables this error's "details" names.`,
      { variables: unknown }
    );
  }

  const addr = setting(env, ADDR_VARIABLE);
  if (addr === undefined) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} needs ${ADDR_VARIABLE}: the https:// address of the Vault server, for example ${EXAMPLE_ADDR}.`,
      { variable: ADDR_VARIABLE }
    );
  }
  const address = vaultOrigin(addr);

  const keyName = setting(env, TRANSIT_KEY_VARIABLE);
  if (keyName === undefined) {
    throw new InvalidConfigurationError(
      `KEK_PROVIDER=${VAULT_KEK_PROVIDER} needs ${TRANSIT_KEY_VARIABLE}: the name of the Transit key that wraps every stored key, for example qauth-kek.`,
      { variable: TRANSIT_KEY_VARIABLE }
    );
  }
  if (!KEY_NAME.test(keyName)) {
    throw new InvalidConfigurationError(
      `${TRANSIT_KEY_VARIABLE} must be a Transit key name: letters, digits and "_", with "-", "." or "@" inside, at most 128 characters. See this error's "details" for the value.`,
      { variable: TRANSIT_KEY_VARIABLE, value: keyName }
    );
  }

  const mount = setting(env, TRANSIT_MOUNT_VARIABLE);
  const transitMount =
    mount === undefined
      ? DEFAULT_TRANSIT_MOUNT
      : vaultPath(TRANSIT_MOUNT_VARIABLE, mount, 'the path the Transit engine is mounted at');

  const namespaceValue = setting(env, NAMESPACE_VARIABLE);
  const namespace =
    namespaceValue === undefined
      ? undefined
      : vaultPath(NAMESPACE_VARIABLE, namespaceValue, 'a Vault namespace path');

  const caFile = setting(env, CA_CERT_FILE_VARIABLE);
  const caCertificates = caFile === undefined ? undefined : readCaCertificates(caFile);

  const auth = readAuthSettings(env, warn);

  for (const variable of LOCAL_KEK_VARIABLES) {
    if (setting(env, variable) !== undefined) {
      warn({
        variable,
        message: `${variable} is set, but KEK_PROVIDER=${VAULT_KEK_PROVIDER} does not read it: keys are wrapped and unwrapped by the Transit key in ${TRANSIT_KEY_VARIABLE}. Keys wrapped under the local KEK do not open with this provider. Remove ${variable}.`,
      });
    }
  }

  return Object.freeze({ address, transitMount, keyName, namespace, caCertificates, auth });
}
