import type { RawEnv } from './aliases';

/**
 * A configuration key QAuth no longer reads. Setting one fails the boot with
 * a message that names what replaces it, so a deployment never runs believing
 * a setting it relies on still applies.
 */
export interface RemovedConfigKey {
  /** The variable name. */
  readonly name: string;
  /** The release that removed it. */
  readonly removedIn: string;
  /** What replaces it, in one sentence that names the variable or tool to use. */
  readonly replacement: string;
}

/**
 * Every removed key. A pull request that removes a key from the registry adds
 * it here, unless it is renamed (an alias, `KeyAlias`) instead.
 */
export const REMOVED_CONFIG_KEYS: readonly RemovedConfigKey[] = Object.freeze([
  {
    name: 'CIMD_ALLOW_PRIVATE_ADDRESSES',
    removedIn: '0.2.0',
    replacement:
      'A metadata document or client jwks_uri never reaches a private address now; list an operator-set private destination in the file EGRESS_ALLOWLIST_PATH names, and reach a test server through createTestEgressClient.',
  },
  {
    name: 'ID_JAG_ALLOW_PRIVATE_ADDRESSES',
    removedIn: '0.2.0',
    replacement:
      "A trusted issuer's discovery URL on a private address is listed, for its realms, in the file EGRESS_ALLOWLIST_PATH names; the jwks_uri its discovery document names never reaches a private address. Tests reach a local issuer through createTestEgressClient.",
  },
]);

/**
 * Removed keys that are set. The boot fails, naming every one at once.
 */
export class RemovedConfigKeyError extends Error {
  constructor(
    readonly keys: readonly string[],
    messages: readonly string[]
  ) {
    super(messages.join(' '));
    this.name = 'RemovedConfigKeyError';
  }
}

/**
 * Refuse an environment that sets a removed key. Unset and blank are the same,
 * as for an alias: `docker-compose.yml` forwards a variable in the `${VAR:-}`
 * form. Any other value, `false` included, is refused: the key does nothing
 * any more, and the operator should know which setting replaces it.
 *
 * @throws RemovedConfigKeyError naming each removed key that is set and its replacement
 */
export function refuseRemovedKeys(
  env: RawEnv,
  removed: readonly RemovedConfigKey[] = REMOVED_CONFIG_KEYS
): void {
  const set = removed.filter(({ name }) => {
    const value = env[name];
    return value !== undefined && value.trim() !== '';
  });
  if (set.length === 0) return;
  throw new RemovedConfigKeyError(
    set.map(({ name }) => name),
    set.map(
      ({ name, removedIn, replacement }) =>
        `${name} was removed in ${removedIn} and is set. ${replacement} Unset ${name}.`
    )
  );
}
