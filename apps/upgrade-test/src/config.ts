/**
 * The upgrade test's configuration, read from the environment and nothing else.
 *
 * The test is a client of a RUNNING QAuth: the baseline release while it
 * populates, the new build when it verifies, and either one for the smoke
 * tests (#475, ADR-018 §5). It knows the server by its URL. It also reaches the
 * database directly, for the two things no release offers over HTTP: marking a
 * client `development` (the operator step that static API keys need, see the
 * docs site's `operate/environment-authorization` page) and checking a stored
 * API key against its plaintext.
 */

/** The variable that confirms the target server and database may be written to. */
export const ALLOW_WRITES_VARIABLE = 'QAUTH_UPGRADE_ALLOW_WRITES';

export interface UpgradeConfig {
  /**
   * The server's issuer identifier, e.g. `http://localhost:3000`. Discovery
   * must report exactly this value.
   */
  readonly baseUrl: string;
  /** The server's database. */
  readonly databaseUrl: string;
  /** The state file the populate step writes and the verify step reads. */
  readonly statePath: string;
  /** The HTTP address of the Mailpit instance the server sends its mail to. */
  readonly mailUrl: string;
}

/** A configuration problem. The run does not start when one is raised. */
export class UpgradeConfigError extends Error {
  constructor(message: string) {
    super(`upgrade-test: refusing to start. ${message}`);
    this.name = 'UpgradeConfigError';
  }
}

type Environment = Readonly<Record<string, string | undefined>>;

function required(env: Environment, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new UpgradeConfigError(`${name} is not set.`);
  }
  return value;
}

/**
 * Read and check the configuration.
 *
 * The write confirmation is checked FIRST, before anything else is read, so a
 * run against the wrong server stops before a single request is sent: the test
 * registers users, creates clients and writes to the database.
 *
 * @throws {UpgradeConfigError} when the confirmation is missing or a value is invalid
 */
export function readUpgradeConfig(env: Environment = process.env): UpgradeConfig {
  if (env[ALLOW_WRITES_VARIABLE] !== '1') {
    throw new UpgradeConfigError(
      'The test creates users and clients on the server it targets and writes to its database. ' +
        `Set ${ALLOW_WRITES_VARIABLE}=1 to confirm that this server may be written to.`
    );
  }

  const baseUrl = required(env, 'QAUTH_BASE_URL');
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new UpgradeConfigError(`QAUTH_BASE_URL is not an absolute URL: ${baseUrl}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new UpgradeConfigError(`QAUTH_BASE_URL must use http or https: ${baseUrl}`);
  }
  if (url.search !== '' || url.hash !== '' || baseUrl.includes('?') || baseUrl.includes('#')) {
    throw new UpgradeConfigError(`QAUTH_BASE_URL must have no query and no fragment: ${baseUrl}`);
  }

  const databaseUrl = required(env, 'QAUTH_UPGRADE_DATABASE_URL');
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) {
    throw new UpgradeConfigError('QAUTH_UPGRADE_DATABASE_URL must be a postgresql:// URL.');
  }

  const mailUrl = required(env, 'QAUTH_UPGRADE_MAIL_URL');
  if (!/^https?:\/\//.test(mailUrl)) {
    throw new UpgradeConfigError('QAUTH_UPGRADE_MAIL_URL must be an http(s) URL.');
  }

  return { baseUrl, databaseUrl, statePath: required(env, 'QAUTH_UPGRADE_STATE'), mailUrl };
}

let cached: UpgradeConfig | undefined;

/** The configuration of this run, read once per test worker. */
export function upgradeConfig(): UpgradeConfig {
  cached ??= readUpgradeConfig();
  return cached;
}

/** A URL on the server, from a path that starts with `/`. */
export function serverPath(base: string, path: string): string {
  if (!path.startsWith('/')) {
    throw new Error(`serverPath expects an absolute path, got "${path}"`);
  }
  return `${base.replace(/\/$/, '')}${path}`;
}
