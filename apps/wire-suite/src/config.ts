/**
 * The wire suite's configuration, read from the environment and nothing else.
 *
 * The suite is a client of a running QAuth (ADR-018 §5). It knows the server
 * only by the URLs and credentials below, never by importing its code: a helper
 * shared with the server could carry the same encoding bug on both sides and
 * hide it.
 */

/** The variable that confirms the target server may be written to. */
export const ALLOW_WRITES_VARIABLE = 'QAUTH_WIRE_ALLOW_WRITES';

/** A client the CI job provisions from `seed/clients.json` before the run. */
export interface SeededClient {
  readonly id: string;
  readonly secret: string;
}

export interface WireConfig {
  /**
   * The server's issuer identifier. Discovery must report exactly this value,
   * so it is used as given: no trailing slash is added or removed.
   */
  readonly baseUrl: string;
  /** Where admin operations go. Defaults to {@link baseUrl}. */
  readonly adminUrl: string;
  /** The confidential client from the seed manifest. */
  readonly confidentialClient: SeededClient;
  /**
   * Whether the target's realm runs the Shared Signals Framework transmitter
   * (`QAUTH_WIRE_SSF_TRANSMITTER=1`). Off unless set: a default deployment
   * serves no SSF metadata.
   */
  readonly ssfTransmitter: boolean;
  /**
   * The HTTP API of the mail sink the target delivers to
   * (`QAUTH_WIRE_MAIL_URL`, a Mailpit instance), or undefined. When set, every
   * account the suite signs in is verified first, the way a person verifies
   * it: the token from the mail, then `POST /auth/verify`. Leave it unset only
   * for a target that signs in unverified accounts
   * (`REQUIRE_VERIFIED_ACCOUNT=false`).
   */
  readonly mailUrl: string | undefined;
}

/** A configuration problem. The suite does not start when one is raised. */
export class WireConfigError extends Error {
  constructor(message: string) {
    super(`wire-suite: refusing to start. ${message}`);
    this.name = 'WireConfigError';
  }
}

type Environment = Readonly<Record<string, string | undefined>>;

function required(env: Environment, name: string): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new WireConfigError(`${name} is not set.`);
  }
  return value;
}

/** An absolute http(s) URL with no query and no fragment, returned as given. */
function serverUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new WireConfigError(`${name} is not an absolute URL: ${value}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new WireConfigError(`${name} must use http or https: ${value}`);
  }
  if (url.search !== '' || url.hash !== '' || value.includes('?') || value.includes('#')) {
    throw new WireConfigError(`${name} must have no query and no fragment: ${value}`);
  }
  return value;
}

/**
 * Read and check the configuration.
 *
 * The write confirmation is checked FIRST, before anything else is read, so a
 * run against the wrong server stops before a single request is sent: the
 * suite registers users and uses the seeded clients.
 *
 * @throws {WireConfigError} when the confirmation is missing or a value is invalid
 */
export function readWireConfig(env: Environment = process.env): WireConfig {
  if (env[ALLOW_WRITES_VARIABLE] !== '1') {
    throw new WireConfigError(
      `The suite creates users and uses clients on the server it targets. ` +
        `Set ${ALLOW_WRITES_VARIABLE}=1 to confirm that this server may be written to.`
    );
  }

  const baseUrl = serverUrl('QAUTH_BASE_URL', required(env, 'QAUTH_BASE_URL'));
  const adminValue = env['QAUTH_ADMIN_URL']?.trim();
  const adminUrl = adminValue ? serverUrl('QAUTH_ADMIN_URL', adminValue) : baseUrl;

  const ssf = env['QAUTH_WIRE_SSF_TRANSMITTER'];
  if (ssf !== undefined && ssf !== '' && ssf !== '0' && ssf !== '1') {
    throw new WireConfigError(`QAUTH_WIRE_SSF_TRANSMITTER must be 1, 0 or unset: ${ssf}`);
  }

  const mailValue = env['QAUTH_WIRE_MAIL_URL']?.trim();
  const mailUrl = mailValue ? serverUrl('QAUTH_WIRE_MAIL_URL', mailValue) : undefined;

  return {
    baseUrl,
    adminUrl,
    confidentialClient: {
      id: required(env, 'QAUTH_WIRE_CLIENT_ID'),
      secret: required(env, 'QAUTH_WIRE_CLIENT_SECRET'),
    },
    ssfTransmitter: ssf === '1',
    mailUrl,
  };
}

let cached: WireConfig | undefined;

/** The configuration of this run, read once per test worker. */
export function wireConfig(): WireConfig {
  cached ??= readWireConfig();
  return cached;
}

/**
 * A URL on the server, from a path that starts with `/`.
 *
 * A terminating `/` on the base is dropped first, which is how OIDC Discovery
 * 1.0 §4.1 builds the well-known URL from an issuer that has a path.
 */
export function serverPath(base: string, path: string): string {
  if (!path.startsWith('/')) {
    throw new Error(`serverPath expects an absolute path, got "${path}"`);
  }
  return `${base.replace(/\/$/, '')}${path}`;
}
