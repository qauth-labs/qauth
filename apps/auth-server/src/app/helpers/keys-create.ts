import { parseArgs } from 'node:util';

import type { CreateRealmKeyInput } from '@qauth-labs/fastify-plugin-signer';

/**
 * The arguments of the operator command `auth-server:keys:create` (ADR-019
 * Decision 9, issue #485), which creates one key for a realm, purpose and
 * algorithm on a host that holds the KEK.
 */

export const KEYS_CREATE_USAGE = `Usage: keys:create --purpose <purpose> [--algorithm <algorithm>] [--realm <name>] [--status active|next] [--scope <id>]

Create one key for a realm, sealed under the KEK and stored in the realm's key store.

  --purpose    A key purpose, such as token_signing.
  --algorithm  One of the purpose's algorithms, such as RS256. Default: the purpose's default.
  --realm      The realm's name. Default: DEFAULT_REALM_NAME.
  --status     active (the default) or next. A realm has one active key per purpose and
               algorithm; create a replacement as next.
  --scope      The owner of a scoped key, for a scoped purpose only.

Example, an RS256 signing key for an OpenID Foundation conformance run:

  pnpm nx run auth-server:keys:create --purpose=token_signing --algorithm=RS256`;

/** Thrown for arguments the command does not take; the message ends with the usage. */
export class KeysCreateUsageError extends Error {
  constructor(problem: string) {
    super(`${problem}\n\n${KEYS_CREATE_USAGE}`);
    this.name = 'KeysCreateUsageError';
  }
}

/**
 * Read the command's arguments.
 *
 * @param argv - the arguments after the script name
 * @param defaultRealm - `DEFAULT_REALM_NAME`, used when `--realm` is absent
 * @throws KeysCreateUsageError for an unknown option, a missing `--purpose`
 *   or a `--status` other than `active` or `next`
 */
export function parseKeysCreateArguments(
  argv: readonly string[],
  defaultRealm: string
): CreateRealmKeyInput {
  let values: Record<string, string | undefined>;
  try {
    ({ values } = parseArgs({
      args: [...argv],
      options: {
        purpose: { type: 'string' },
        algorithm: { type: 'string' },
        realm: { type: 'string' },
        status: { type: 'string' },
        scope: { type: 'string' },
      },
      strict: true,
      allowPositionals: false,
    }));
  } catch (error) {
    throw new KeysCreateUsageError(error instanceof Error ? error.message : String(error));
  }

  const { purpose, algorithm, realm, status, scope } = values;
  if (purpose === undefined || purpose.length === 0) {
    throw new KeysCreateUsageError('--purpose is required.');
  }
  if (status !== undefined && status !== 'active' && status !== 'next') {
    throw new KeysCreateUsageError(`--status is active or next, not "${status}".`);
  }
  return {
    realmName: realm ?? defaultRealm,
    purpose,
    ...(algorithm === undefined ? {} : { algorithm }),
    ...(status === undefined ? {} : { status }),
    ...(scope === undefined ? {} : { scopeId: scope }),
  };
}
