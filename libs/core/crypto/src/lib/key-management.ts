/**
 * Classical (jose) key management for the JWT token layer. ML-DSA-65 keys use
 * the raw seed-based import/export on the `SignatureBackend` seem instead —
 * there is no stable PKCS#8/SPKI encoding for ML-DSA (the LAMPS drafts are
 * unsettled), so these PEM importers are intentionally EdDSA-only (#243).
 */
import { exportJWK, generateKeyPair, importJWK, importPKCS8, importSPKI, type JWK } from 'jose';

import { JOSE_P256_CURVE, type JwsAlgorithm } from './algorithms';
import { findPrivateJwkMember, type SigningKey, type SigningKeyPair } from './keys';

/** Options for {@link generateSigningKeyPair}. */
export interface GenerateSigningKeyPairOptions {
  /**
   * Whether the generated private key is extractable (exportable to PEM/JWK).
   * Defaults to `false` — a non-extractable key cannot be serialized out of the
   * runtime, which is the safer default for a production signing key.
   */
  extractable?: boolean;
}

/**
 * Generate an asymmetric signing key pair for the given algorithm.
 *
 * `ES256` (#298) yields an ECDSA P-256 pair. Its WebCrypto key usages are
 * `sign`/`verify`, which is structurally incompatible with the `deriveBits`
 * usage of the ECDH-ES encryption keys in `encryption-keys.ts`: neither key can
 * be fed to the other's primitive, so the signing and key-agreement key sets
 * cannot be confused even though both live on P-256.
 *
 * @param alg - Signature algorithm (`EdDSA`, `RS256`, or `ES256`).
 * @param options - Generation options — see {@link GenerateSigningKeyPairOptions}.
 */
export async function generateSigningKeyPair(
  alg: JwsAlgorithm,
  options: GenerateSigningKeyPairOptions = {}
): Promise<SigningKeyPair> {
  return generateKeyPair(alg, { extractable: options.extractable ?? false });
}

/**
 * Import a PKCS#8 PEM-encoded private key for the given algorithm.
 *
 * @param pem - PKCS#8 PEM string.
 * @param alg - Signature algorithm the key is used with (`EdDSA`, `RS256`, or `ES256`).
 */
export async function importPrivateSigningKey(pem: string, alg: JwsAlgorithm): Promise<SigningKey> {
  return importPKCS8(pem, alg);
}

/**
 * Import an SPKI PEM-encoded public key for the given algorithm.
 *
 * @param pem - SPKI PEM string.
 * @param alg - Signature algorithm the key is used with (`EdDSA`, `RS256`, or `ES256`).
 */
export async function importPublicSigningKey(pem: string, alg: JwsAlgorithm): Promise<SigningKey> {
  return importSPKI(pem, alg);
}

/** Options for {@link exportPublicSigningJwk}. */
export interface ExportPublicSigningJwkOptions {
  /**
   * The algorithm the key is to be used with, stamped as the JWK `alg` member.
   * REQUIRED rather than inferred: a bare `{kty:'EC',crv:'P-256'}` JWK is
   * algorithm-ambiguous by construction (ES256 signing and ECDH-ES key agreement
   * produce the same members), and publishing a fully-specified key is what lets
   * a relying party pin instead of guess.
   */
  alg: JwsAlgorithm;
  /** Optional `kid` stamped into the JWK so a verifier can address this key. */
  kid?: string;
}

/**
 * Export a PUBLIC signing key as a fully-specified JWK (#298).
 *
 * Wallet federation publishes verification keys as JWKs (OID4VP client
 * metadata) rather than as PEM, which is why this exists alongside the PEM
 * importers above.
 *
 * The result always carries `use: 'sig'` and the caller-supplied `alg`, so a
 * consumer never has to infer the algorithm from `kty`/`crv` — the inference
 * that turns an ES256 verification key and an ECDH-ES agreement key into the
 * same-looking object.
 *
 * @param publicKey - Public key to serialize.
 * @param options - Algorithm and optional `kid` — see {@link ExportPublicSigningJwkOptions}.
 * @returns The public JWK. Never contains private material — see the throw below.
 * @throws Error if `publicKey` is a PRIVATE key (fail-closed: exporting a
 * private key from a function named "public" would silently publish `d`).
 */
export async function exportPublicSigningJwk(
  publicKey: SigningKey,
  options: ExportPublicSigningJwkOptions
): Promise<JWK> {
  if (publicKey.type !== 'public') {
    throw new Error(
      `exportPublicSigningJwk requires a public key, got a '${publicKey.type}' key. ` +
        `Exporting a private key here would publish its private material.`
    );
  }
  const jwk = await exportJWK(publicKey);
  return {
    ...jwk,
    alg: options.alg,
    use: 'sig',
    ...(options.kid !== undefined ? { kid: options.kid } : {}),
  };
}

/** The `kty` an `alg` must be published under (fully-specified key, RFC 9864 spirit). */
const EXPECTED_KTY: Record<JwsAlgorithm, string> = {
  EdDSA: 'OKP',
  RS256: 'RSA',
  ES256: 'EC',
};

/**
 * Import a peer-supplied PUBLIC verification key from a JWK, pinned to an
 * algorithm the CALLER chose (#298).
 *
 * The `alg` argument is the whole security story. It comes from the caller's
 * policy — never from the JWK, and never from the header of the token about to
 * be verified — so a wallet cannot steer its own key into a different primitive.
 * Everything the JWK itself claims is treated as untrusted input and checked
 * AGAINST that pin:
 *
 * - `kty` must be the one the algorithm requires ({@link EXPECTED_KTY}), so an
 *   `RSA` JWK can never be imported as an `ES256` key.
 * - for `ES256`, `crv` must be `P-256`. `jose` enforces this itself for `ES256`,
 *   but the check is written here anyway because it does NOT enforce it for
 *   `ECDH-ES` (see `importEncryptionPublicJwk`) — relying on a library's
 *   per-algorithm inconsistency is not a control.
 * - a JWK `alg` member that CONTRADICTS the pin is rejected rather than ignored:
 *   the disagreement means the peer and this deployment do not agree on what the
 *   key is for, and guessing which one is right is exactly the wrong move.
 * - private members (`PRIVATE_JWK_MEMBERS` in `keys.ts`) are refused.
 * - `use: 'enc'` is refused — a key its own publisher marked as an encryption
 *   key must not become a signature verification key.
 *
 * @param jwk - Untrusted JWK, typically from a peer's published key set.
 * @param alg - The algorithm this key will be used with; chosen by the caller.
 * @returns The imported public key.
 * @throws Error if the JWK contradicts the pin or carries private material.
 */
export async function importPublicSigningJwk(jwk: JWK, alg: JwsAlgorithm): Promise<SigningKey> {
  const privateMember = findPrivateJwkMember(jwk);
  if (privateMember !== undefined) {
    throw new Error(
      `Public signing JWK must not carry private key material (found '${privateMember}').`
    );
  }
  const expectedKty = EXPECTED_KTY[alg];
  if (jwk.kty !== expectedKty) {
    throw new Error(`JWK 'kty' must be '${expectedKty}' for ${alg}, got '${String(jwk.kty)}'.`);
  }
  if (alg === 'ES256' && jwk.crv !== JOSE_P256_CURVE) {
    throw new Error(`JWK 'crv' must be '${JOSE_P256_CURVE}' for ES256, got '${String(jwk.crv)}'.`);
  }
  if (jwk.alg !== undefined && jwk.alg !== alg) {
    throw new Error(`JWK declares alg '${jwk.alg}' but is being imported as '${alg}'.`);
  }
  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new Error(`JWK declares use '${jwk.use}'; a signing key must declare 'sig'.`);
  }

  const key = await importJWK(jwk, alg);
  // `importJWK` returns `CryptoKey | Uint8Array` — the byte form is only ever
  // produced for symmetric (`oct`) keys, which the `kty` pin above already
  // excludes. Checked anyway so the impossible case cannot become a cast.
  if (key instanceof Uint8Array || key.type !== 'public') {
    throw new Error(`JWK did not import as an asymmetric public key for ${alg}.`);
  }
  return key;
}
