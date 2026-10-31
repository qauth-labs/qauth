import { createPublicKey } from 'node:crypto';

import type {
  EnvironmentKeySettings,
  EnvironmentKeySource,
} from '@qauth-labs/fastify-plugin-signer';
import { DEV_SESSION_COOKIE_SECRET_DEFAULT } from '@qauth-labs/server-config';
import { calculateJwkThumbprint, type JWK } from 'jose';

/**
 * The key variables of a deployment from before the key store, handed to the
 * key boot step (ADR-019 Decision 9, issue #485).
 *
 * At its first boot after the upgrade, the default realm imports these keys
 * into its encrypted store; at every boot, each one still set gets a warning
 * that names it. The configuration has already read the `*_PATH` files, so the
 * values come from the parsed configuration, and the variable names from the
 * raw environment: a warning names exactly the variables the operator set.
 */

/** The parsed settings this module reads. */
export interface KeyVariableConfig {
  readonly JWT_PRIVATE_KEY?: string;
  readonly JWT_PUBLIC_KEY?: string;
  readonly JWT_RS256_PRIVATE_KEY?: string;
  readonly JWT_RS256_PUBLIC_KEY?: string;
  readonly JWT_RS256_KID?: string;
  readonly JWT_MLDSA_PRIVATE_KEY?: string;
  readonly JWT_MLDSA_KID?: string;
  readonly HYBRID_SIGNING_ENABLED: boolean;
  readonly SESSION_COOKIE_SECRET?: string;
}

/**
 * The key settings for the boot step: each key whose variable is set.
 *
 * - The ML-DSA-65 seed only with hybrid signing on: the store keeps it only as
 *   the second key of a hybrid pair.
 * - `SESSION_COOKIE_SECRET` only when the operator set it, and never the
 *   published development value `.env.example` ships: a development stack
 *   generates its cookie key instead. A set value the store lacks replaces
 *   the stored cookie key (#493).
 *
 * @param config - the parsed configuration (`env`)
 * @param raw - the environment it was parsed from (`process.env`)
 */
export function keyVariableSettings(
  config: KeyVariableConfig,
  raw: Readonly<Record<string, string | undefined>>
): EnvironmentKeySettings {
  const source = (
    value: string | undefined,
    ...names: string[]
  ): EnvironmentKeySource | undefined => {
    if (value === undefined || value.length === 0) return undefined;
    return { value, variables: names.filter((name) => (raw[name]?.trim() ?? '') !== '') };
  };

  const ed25519 = source(config.JWT_PRIVATE_KEY, 'JWT_PRIVATE_KEY', 'JWT_PRIVATE_KEY_PATH');
  const ed25519Public = source(config.JWT_PUBLIC_KEY, 'JWT_PUBLIC_KEY', 'JWT_PUBLIC_KEY_PATH');
  const rs256 = source(
    config.JWT_RS256_PRIVATE_KEY,
    'JWT_RS256_PRIVATE_KEY',
    'JWT_RS256_PRIVATE_KEY_PATH'
  );
  const rs256Public = source(
    config.JWT_RS256_PUBLIC_KEY,
    'JWT_RS256_PUBLIC_KEY',
    'JWT_RS256_PUBLIC_KEY_PATH'
  );
  const rs256Kid = source(config.JWT_RS256_KID, 'JWT_RS256_KID');
  const mlDsa = config.HYBRID_SIGNING_ENABLED
    ? source(config.JWT_MLDSA_PRIVATE_KEY, 'JWT_MLDSA_PRIVATE_KEY', 'JWT_MLDSA_PRIVATE_KEY_PATH')
    : undefined;
  const mlDsaKid = source(config.JWT_MLDSA_KID, 'JWT_MLDSA_KID');
  const cookieSecret =
    config.SESSION_COOKIE_SECRET === DEV_SESSION_COOKIE_SECRET_DEFAULT
      ? undefined
      : source(config.SESSION_COOKIE_SECRET, 'SESSION_COOKIE_SECRET');

  return {
    ...(ed25519 === undefined
      ? {}
      : {
          ed25519: {
            privateKey: ed25519,
            ...(ed25519Public === undefined ? {} : { publicKey: ed25519Public }),
          },
        }),
    ...(rs256 === undefined
      ? {}
      : {
          rs256: {
            privateKey: rs256,
            ...(rs256Public === undefined ? {} : { publicKey: rs256Public }),
            ...(rs256Kid === undefined ? {} : { kid: rs256Kid }),
          },
        }),
    ...(mlDsa === undefined
      ? {}
      : { mlDsa: { seed: mlDsa, ...(mlDsaKid === undefined ? {} : { kid: mlDsaKid }) } }),
    // Only a secret the operator set in the environment, as for every key.
    ...(cookieSecret === undefined || cookieSecret.variables.length === 0 ? {} : { cookieSecret }),
  };
}

/**
 * The `kid`s a token without a `kid` may be verified with (#491): the Ed25519
 * key of `JWT_PRIVATE_KEY`, or of `JWT_PUBLIC_KEY` on a process that holds no
 * private key. That key signed every access token before tokens named their
 * key, and the key boot step stores it under its RFC 7638 thumbprint, the
 * `kid` computed here. The key store does not record where a key came from,
 * so the variable is what names it; a key the store generated is never
 * listed.
 *
 * Transitional: removed one release after #491, once the tokens issued
 * before the upgrade have expired. Keep the variable set until then.
 *
 * @returns the thumbprints, none when neither variable holds an Ed25519 key
 */
export async function kidlessTokenKeyIds(
  config: Pick<KeyVariableConfig, 'JWT_PRIVATE_KEY' | 'JWT_PUBLIC_KEY'>
): Promise<string[]> {
  const kids = new Set<string>();
  for (const pem of [config.JWT_PRIVATE_KEY, config.JWT_PUBLIC_KEY]) {
    if (pem === undefined || pem.trim().length === 0) continue;
    let jwk: JWK;
    try {
      jwk = createPublicKey(pem).export({ format: 'jwk' }) as JWK;
    } catch {
      // The key boot step refuses a key that does not parse, with its own message.
      continue;
    }
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') continue;
    kids.add(await calculateJwkThumbprint(jwk, 'sha256'));
  }
  return [...kids];
}
