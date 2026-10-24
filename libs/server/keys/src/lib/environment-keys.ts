import { createPrivateKey, createPublicKey, type KeyObject, randomBytes } from 'node:crypto';

import {
  deriveMlDsaPublicKeyAndZeroize,
  getSignatureBackend,
  PQC_ALG_ML_DSA_65,
  type SignatureAlgorithm,
} from '@qauth-labs/core-crypto';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import { jwkThumbprintKid, RANDOM_KID_BYTES } from './key-generation';

/**
 * The keys a deployment configured in environment variables before the key
 * store (ADR-019 Decision 9 and its answer on existing issuers, issue #485).
 *
 * At its first boot after the upgrade, a deployment imports these keys into
 * the store of its default realm. This module turns the configured values
 * into what the store keeps: the private material in the form key generation
 * produces (`generateKeyMaterial`), the public JWK and the `kid`. It reads no
 * file and no variable itself: the configuration resolves `*_PATH` variables
 * first and hands over the values, with the names of the variables that set
 * them, so every error and warning names a variable and never a value.
 *
 * - `JWT_PRIVATE_KEY` becomes the Ed25519 `token_signing` key, and
 *   `JWT_RS256_PRIVATE_KEY` the RS256 one. Their public halves are derived
 *   from the private keys with `node:crypto`. A configured public key that is
 *   not that half is refused.
 * - `JWT_MLDSA_PRIVATE_KEY`, a 32-byte seed, becomes the ML-DSA-65 key of the
 *   hybrid pair.
 * - `SESSION_COOKIE_SECRET` becomes a `cookie_hmac` key. Its bytes are the
 *   secret's UTF-8 bytes, so an HMAC under the stored key equals one under the
 *   variable.
 *
 * The `kid` of a signing key is `JWT_RS256_KID` or `JWT_MLDSA_KID` when set,
 * and otherwise the RFC 7638 thumbprint of its public key, as for a generated
 * key. The cookie secret gets a random `kid`, as a generated symmetric key
 * does.
 */

/** The smallest RSA modulus an RS256 key may have, in bits (RFC 7518 §3.3). */
export const MIN_RSA_MODULUS_BITS = 2048;

/** The longest `kid` `realm_keys` holds. */
const MAX_KID_LENGTH = 255;

/** The length of an ML-DSA-65 seed, the canonical private form (FIPS 204). */
const ML_DSA_SEED_BYTES = 32;

/** One configured value, and the variables that set it. */
export interface EnvironmentKeySource {
  /** The value as the configuration resolved it: a file variable is already read. */
  readonly value: string;
  /**
   * The variables that are set for this value, such as `['JWT_PRIVATE_KEY_PATH']`.
   * Errors and warnings name them.
   */
  readonly variables: readonly string[];
}

/** The key variables of a deployment, each absent when it is not set. */
export interface EnvironmentKeySettings {
  /** `JWT_PRIVATE_KEY`, with `JWT_PUBLIC_KEY` when set. PEM. */
  readonly ed25519?: {
    readonly privateKey: EnvironmentKeySource;
    readonly publicKey?: EnvironmentKeySource;
  };
  /** `JWT_RS256_PRIVATE_KEY`, with `JWT_RS256_PUBLIC_KEY` and `JWT_RS256_KID` when set. */
  readonly rs256?: {
    readonly privateKey: EnvironmentKeySource;
    readonly publicKey?: EnvironmentKeySource;
    readonly kid?: EnvironmentKeySource;
  };
  /** `JWT_MLDSA_PRIVATE_KEY`, a base64url seed, with `JWT_MLDSA_KID` when set. */
  readonly mlDsa?: {
    readonly seed: EnvironmentKeySource;
    readonly kid?: EnvironmentKeySource;
  };
  /** `SESSION_COOKIE_SECRET`, when the operator set it. */
  readonly cookieSecret?: EnvironmentKeySource;
}

/** A configured key, ready to be sealed and stored. */
export interface EnvironmentKey {
  readonly purpose: 'token_signing' | 'cookie_hmac';
  readonly algorithm: 'EdDSA' | 'RS256' | 'ML-DSA-65' | 'HS256';
  /** The configured `kid`, the thumbprint, or a random id for the cookie secret. */
  readonly kid: string;
  /** The RFC 7638 thumbprint of the public key; `null` for the cookie secret. */
  readonly thumbprint: string | null;
  /** The public JWK with `kid`, `alg` and `use`; absent for the cookie secret. */
  readonly publicJwk?: JWK;
  /**
   * The private material: PKCS#8 DER, the ML-DSA-65 seed, or the secret's
   * bytes. It belongs to the caller, who zeroes it after sealing.
   */
  readonly material: Buffer;
  /** Every variable that set this key: its own, its public key's and its `kid`'s. */
  readonly variables: readonly string[];
}

/** Options of {@link prepareEnvironmentKeys}. */
export interface PrepareEnvironmentKeysOptions {
  /** `cryptoEnv.enabledSignatureAlgorithms`; the ML-DSA-65 backend is gated on it. */
  readonly enabledSignatureAlgorithms: readonly SignatureAlgorithm[];
}

/**
 * Read the configured keys into the form the key store keeps.
 *
 * Nothing is stored here. The material of every returned key belongs to the
 * caller; when this function throws, it has zeroed what it had read.
 *
 * @throws InvalidConfigurationError when a value is not a key of its kind, an
 *   RSA key is shorter than {@link MIN_RSA_MODULUS_BITS}, a configured public
 *   key is not the private key's public half, or a configured `kid` is empty
 *   or longer than 255 characters. The message names the variables, never a
 *   value.
 */
export async function prepareEnvironmentKeys(
  settings: EnvironmentKeySettings,
  options: PrepareEnvironmentKeysOptions
): Promise<EnvironmentKey[]> {
  const keys: EnvironmentKey[] = [];
  try {
    if (settings.ed25519 !== undefined) {
      keys.push(await preparePemKey('EdDSA', settings.ed25519));
    }
    if (settings.rs256 !== undefined) {
      keys.push(await preparePemKey('RS256', settings.rs256));
    }
    if (settings.mlDsa !== undefined) {
      keys.push(await prepareMlDsaKey(settings.mlDsa, options.enabledSignatureAlgorithms));
    }
    if (settings.cookieSecret !== undefined) {
      keys.push(prepareCookieSecret(settings.cookieSecret));
    }
    return keys;
  } catch (error) {
    for (const key of keys) key.material.fill(0);
    throw error;
  }
}

/** How a source is named in a message: its variables, or a description when none is listed. */
export function describeSource(source: EnvironmentKeySource, fallback: string): string {
  return source.variables.length > 0 ? source.variables.join(' and ') : fallback;
}

const PEM_KEY_TYPES = {
  EdDSA: { asymmetricKeyType: 'ed25519', label: 'an Ed25519 private key' },
  RS256: { asymmetricKeyType: 'rsa', label: 'an RSA private key' },
} as const;

async function preparePemKey(
  algorithm: 'EdDSA' | 'RS256',
  source: {
    readonly privateKey: EnvironmentKeySource;
    readonly publicKey?: EnvironmentKeySource;
    readonly kid?: EnvironmentKeySource;
  }
): Promise<EnvironmentKey> {
  const { asymmetricKeyType, label } = PEM_KEY_TYPES[algorithm];
  const name = describeSource(source.privateKey, `the ${algorithm} private key`);
  const details = { variables: source.privateKey.variables };

  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey(source.privateKey.value);
  } catch {
    // The parser's message is dropped: it may quote the value.
    throw new InvalidConfigurationError(
      `${name} does not hold a private key in PEM form. It must hold ${label} as PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----").`,
      details
    );
  }
  if (privateKey.asymmetricKeyType !== asymmetricKeyType) {
    throw new InvalidConfigurationError(`${name} must hold ${label}.`, {
      ...details,
      keyType: privateKey.asymmetricKeyType,
    });
  }
  if (algorithm === 'RS256') {
    const bits = privateKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (bits < MIN_RSA_MODULUS_BITS) {
      throw new InvalidConfigurationError(
        `${name} holds an RSA key shorter than ${MIN_RSA_MODULUS_BITS} bits, which RS256 does not allow (RFC 7518 §3.3). See this error's "details" for its length.`,
        { ...details, bits }
      );
    }
  }

  // The public half, from the private key with node:crypto. jose cannot
  // derive it from the non-extractable key it imports (#359).
  const publicKey = createPublicKey(privateKey);
  if (source.publicKey !== undefined) {
    assertSamePublicKey(publicKey, source.publicKey, name);
  }

  const jwk = publicKey.export({ format: 'jwk' }) as JWK;
  const thumbprint = await jwkThumbprintKid(jwk);
  const kid = configuredKid(source.kid) ?? thumbprint;
  return Object.freeze({
    purpose: 'token_signing',
    algorithm,
    kid,
    thumbprint,
    publicJwk: { ...jwk, alg: algorithm, use: 'sig', kid },
    material: Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })),
    variables: variablesOf(source.privateKey, source.publicKey, source.kid),
  });
}

/**
 * Refuse a configured public key that is not the private key's public half.
 * Signing with one key and publishing another would make every token fail to
 * verify, so the boot stops instead.
 */
function assertSamePublicKey(
  derived: KeyObject,
  configured: EnvironmentKeySource,
  privateName: string
): void {
  const name = describeSource(configured, 'the configured public key');
  let configuredKey: KeyObject;
  try {
    configuredKey = createPublicKey(configured.value);
  } catch {
    throw new InvalidConfigurationError(
      `${name} does not hold a public key in PEM form ("-----BEGIN PUBLIC KEY-----").`,
      { variables: configured.variables }
    );
  }
  if (!configuredKey.equals(derived)) {
    throw new InvalidConfigurationError(
      `${name} does not match ${privateName}: it is not the public half of that private key. Signing with one key and publishing another would make every token fail to verify. Remove ${name}, since the public key is derived from the private key, or set it to that key's public half.`,
      { variables: configured.variables }
    );
  }
}

async function prepareMlDsaKey(
  source: { readonly seed: EnvironmentKeySource; readonly kid?: EnvironmentKeySource },
  enabledSignatureAlgorithms: readonly SignatureAlgorithm[]
): Promise<EnvironmentKey> {
  const name = describeSource(source.seed, 'the ML-DSA-65 seed');
  const seed = source.seed.value;
  const material = Buffer.from(seed, 'base64url');
  if (
    material.length !== ML_DSA_SEED_BYTES ||
    material.toString('base64url') !== seed.replace(/=+$/, '')
  ) {
    material.fill(0);
    throw new InvalidConfigurationError(
      `${name} must be the unpadded base64url encoding of a ${ML_DSA_SEED_BYTES}-byte ML-DSA-65 seed.`,
      { variables: source.seed.variables }
    );
  }
  try {
    // The registry gates the backend on SIGNING_ALGORITHM_MODE.
    const backend = getSignatureBackend('ML-DSA-65', enabledSignatureAlgorithms);
    const publicKey = deriveMlDsaPublicKeyAndZeroize(backend.importKey(seed, 'private'));
    // The member order of a generated ML-DSA-65 key (`generateKeyMaterial`).
    const jwk: JWK = { kty: 'AKP', pub: backend.exportKey(publicKey), use: 'sig' };
    jwk.alg = PQC_ALG_ML_DSA_65;
    const thumbprint = await jwkThumbprintKid(jwk);
    const kid = configuredKid(source.kid) ?? thumbprint;
    return Object.freeze({
      purpose: 'token_signing',
      algorithm: 'ML-DSA-65',
      kid,
      thumbprint,
      publicJwk: { ...jwk, kid },
      material,
      variables: variablesOf(source.seed, source.kid),
    });
  } catch (error) {
    material.fill(0);
    throw error;
  }
}

function prepareCookieSecret(source: EnvironmentKeySource): EnvironmentKey {
  if (source.value.length === 0) {
    throw new InvalidConfigurationError(
      `${describeSource(source, 'the session cookie secret')} is empty.`,
      { variables: source.variables }
    );
  }
  return Object.freeze({
    purpose: 'cookie_hmac',
    algorithm: 'HS256',
    kid: randomBytes(RANDOM_KID_BYTES).toString('base64url'),
    thumbprint: null,
    // The secret's UTF-8 bytes: what `createHmac('sha256', secret)` keys with.
    material: Buffer.from(source.value, 'utf8'),
    variables: [...source.variables],
  });
}

/** A configured `kid`, or `undefined` when none is set. */
function configuredKid(source: EnvironmentKeySource | undefined): string | undefined {
  if (source === undefined) return undefined;
  const kid = source.value;
  if (kid.trim().length === 0 || kid.length > MAX_KID_LENGTH) {
    throw new InvalidConfigurationError(
      `${describeSource(source, 'the configured kid')} must be a non-empty key id of at most ${MAX_KID_LENGTH} characters.`,
      { variables: source.variables }
    );
  }
  return kid;
}

function variablesOf(...sources: (EnvironmentKeySource | undefined)[]): string[] {
  return sources.flatMap((source) => source?.variables ?? []);
}
