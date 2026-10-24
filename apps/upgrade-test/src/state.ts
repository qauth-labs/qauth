import { readFileSync, writeFileSync } from 'node:fs';

/**
 * The state file: what the populate step wrote through the baseline release,
 * kept for the verify step to use against the new build (#475).
 *
 * It holds the test data's secrets (passwords, tokens, a client secret, an API
 * key) in the clear. They exist only on the throwaway database of one run; the
 * file is written with mode 0600 and never uploaded.
 */

/** The format id. QAuth-defined, so a release candidate until 1.0 (ADR-018 §5). */
export const STATE_FORMAT = 'qauth-upgrade-state/1-rc.0';

export interface StateUser {
  readonly userId: string;
  readonly email: string;
  readonly password: string;
}

export interface StateClient {
  readonly id: string;
  readonly clientId: string;
  readonly clientSecret: string;
}

export interface UpgradeState {
  readonly format: typeof STATE_FORMAT;
  /** The issuer the baseline was configured with; the new build must keep it. */
  readonly baseUrl: string;
  /** Epoch seconds of the populate run. */
  readonly populatedAt: number;
  /** Signs in to the developer API and owns both clients. */
  readonly developer: StateUser;
  /** Signs in through the hosted pages, consents and holds the tokens. */
  readonly endUser: StateUser;
  /** A production confidential client: the authorization code flow and the consent. */
  readonly appClient: StateClient & { readonly redirectUri: string };
  /** A client the operator marked `development`, which owns the API key. */
  readonly devClient: StateClient;
  /** The end user's tokens from the code exchange. */
  readonly tokens: {
    readonly accessToken: string;
    /** The access token's `exp`, epoch seconds. */
    readonly accessTokenExpiresAt: number;
    readonly refreshToken: string;
    readonly idToken: string | null;
  };
  /** The consent the end user granted the app client. */
  readonly consent: { readonly clientId: string; readonly scopes: readonly string[] };
  readonly apiKey: {
    readonly id: string;
    readonly key: string;
    readonly prefix: string;
    readonly last4: string;
  };
}

/** The state file is missing, unreadable or of another shape. */
export class StateFileError extends Error {
  constructor(path: string, message: string) {
    super(`upgrade-test: the state file ${path} ${message}`);
    this.name = 'StateFileError';
  }
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** Paths of the string fields every state file must have, as `a.b`. */
const STRING_FIELDS = [
  'baseUrl',
  'developer.userId',
  'developer.email',
  'developer.password',
  'endUser.userId',
  'endUser.email',
  'endUser.password',
  'appClient.id',
  'appClient.clientId',
  'appClient.clientSecret',
  'appClient.redirectUri',
  'devClient.id',
  'devClient.clientId',
  'devClient.clientSecret',
  'tokens.accessToken',
  'tokens.refreshToken',
  'consent.clientId',
  'apiKey.id',
  'apiKey.key',
  'apiKey.prefix',
  'apiKey.last4',
] as const;

function at(document: unknown, path: string): unknown {
  let value: unknown = document;
  for (const key of path.split('.')) {
    value = isObject(value) ? value[key] : undefined;
  }
  return value;
}

/**
 * Check a parsed state file.
 *
 * @throws {StateFileError} naming the first field that is missing or of the wrong type
 */
export function parseState(path: string, document: unknown): UpgradeState {
  if (!isObject(document)) throw new StateFileError(path, 'is not a JSON object.');
  if (document['format'] !== STATE_FORMAT) {
    throw new StateFileError(
      path,
      `has format ${JSON.stringify(document['format'])}, expected ${STATE_FORMAT}.`
    );
  }
  for (const field of STRING_FIELDS) {
    const value = at(document, field);
    if (typeof value !== 'string' || value === '') {
      throw new StateFileError(path, `has no ${field}.`);
    }
  }
  for (const field of ['populatedAt', 'tokens.accessTokenExpiresAt']) {
    if (!Number.isInteger(at(document, field))) {
      throw new StateFileError(path, `has no ${field}.`);
    }
  }
  const idToken = at(document, 'tokens.idToken');
  if (idToken !== null && typeof idToken !== 'string') {
    throw new StateFileError(path, 'has a tokens.idToken that is neither a string nor null.');
  }
  const scopes = at(document, 'consent.scopes');
  if (!Array.isArray(scopes) || !scopes.every((scope) => typeof scope === 'string')) {
    throw new StateFileError(path, 'has no consent.scopes list.');
  }
  return document as unknown as UpgradeState;
}

/** Write the state file, readable by the owner only. */
export function writeState(path: string, state: UpgradeState): void {
  writeFileSync(path, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
}

/** Read and check the state file the populate step wrote. */
export function readState(path: string): UpgradeState {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new StateFileError(
      path,
      `cannot be read (${(error as Error).message}). Did the populate step run?`
    );
  }
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new StateFileError(path, 'is not valid JSON.');
  }
  return parseState(path, document);
}
