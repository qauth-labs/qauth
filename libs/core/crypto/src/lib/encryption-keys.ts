/**
 * ECDH-ES (P-256) key-agreement key material for JWE response encryption
 * (#298, HAIP §5).
 *
 * SEPARATE from `key-management.ts` on purpose. Both modules deal in P-256
 * keys, and that similarity is precisely the hazard: an `ES256` verification key
 * and an `ECDH-ES` agreement key serialize to JWKs with identical members
 * (`kty:'EC'`, `crv:'P-256'`, `x`, `y`). Keeping the two key sets in different
 * modules, with different types, different JWK stamps (`use:'sig'` vs
 * `use:'enc'`) and — at the WebCrypto level — different key usages
 * (`sign`/`verify` vs `deriveBits`), means a mix-up is a type error or a runtime
 * refusal from the platform, never a silent cross-use.
 */
import { randomBytes } from 'node:crypto';

import { exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';

import { JOSE_P256_CURVE } from './algorithms';

/**
 * One half of an ECDH-ES key-agreement pair. Aliases the runtime-agnostic
 * `CryptoKey`, exactly as {@link import('./keys').SigningKey} does — but the two
 * aliases are NOT interchangeable in practice: WebCrypto stamps the algorithm
 * (`ECDH` vs `ECDSA`) and the usages onto the key object, so handing one to the
 * other's primitive throws.
 */
export type EncryptionKey = CryptoKey;

/**
 * A per-Authorization-Request ephemeral encryption key pair (#298).
 *
 * HAIP §5 requires the Verifier to publish "ephemeral encryption public keys
 * SPECIFIC TO EACH Authorization Request" in client metadata. That word is the
 * whole design: reusing one static key across requests would let a single
 * compromise decrypt every historical `direct_post.jwt` response, and would let
 * a response captured from one request be replayed into another. So the unit
 * handed around is a pair PLUS its identity ({@link kid}) and its birth time
 * ({@link createdAt}), not a bare key — a key with no identity cannot be
 * addressed in client metadata, and a key with no birth time cannot be expired.
 *
 * LIFECYCLE is the caller's, deliberately. This library generates, serializes,
 * and ages the material; binding a pair to a request id and storing it belongs
 * to the federation layer, which owns the request state to begin with. The
 * contract the caller must honour:
 *
 * 1. generate one pair per Authorization Request,
 * 2. publish only {@link exportEncryptionPublicJwk} in client metadata,
 * 3. keep the private half only until the response arrives or the request
 *    expires — see {@link isEphemeralEncryptionKeyPairExpired},
 * 4. never accept a response decrypted with a pair belonging to another request.
 */
export interface EphemeralEncryptionKeyPair {
  /**
   * Key identifier, unique per pair. Defaults to a fresh 128-bit random value,
   * so uniqueness per request is automatic rather than something a caller has to
   * remember; a caller may supply its own (e.g. the request id) instead.
   */
  readonly kid: string;
  /** Private half — used ONLY to decrypt this request's response. Never published. */
  readonly privateKey: EncryptionKey;
  /** Public half — published to the wallet in client metadata. */
  readonly publicKey: EncryptionKey;
  /** Creation time in epoch milliseconds; the input to expiry decisions. */
  readonly createdAt: number;
}

/** Options for {@link generateEphemeralEncryptionKeyPair}. */
export interface GenerateEphemeralEncryptionKeyPairOptions {
  /** Key identifier. Defaults to a fresh 128-bit `base64url` random value. */
  kid?: string;
  /**
   * Whether the PRIVATE half may be serialized with
   * {@link exportEncryptionPrivateJwk}. Defaults to `false`.
   *
   * Opt in only when the deployment genuinely needs it: a `direct_post.jwt`
   * response arrives on a DIFFERENT HTTP request than the one that generated the
   * key, so a multi-instance deployment has to persist the private half in
   * shared state (encrypted at rest) to decrypt it. A single-instance deployment
   * can keep the pair in memory and leave this `false`, which means the private
   * key cannot leave the runtime at all.
   */
  extractable?: boolean;
  /** Creation time in epoch ms. Defaults to `Date.now()`; injectable for tests. */
  createdAt?: number;
}

/**
 * Generate a fresh ephemeral ECDH-ES P-256 key pair for ONE Authorization
 * Request.
 *
 * @param options - See {@link GenerateEphemeralEncryptionKeyPairOptions}.
 * @returns A pair tagged with a unique `kid` and its creation time.
 * @throws Error if a caller-supplied `kid` is empty.
 */
export async function generateEphemeralEncryptionKeyPair(
  options: GenerateEphemeralEncryptionKeyPairOptions = {}
): Promise<EphemeralEncryptionKeyPair> {
  if (options.kid !== undefined && options.kid.length === 0) {
    throw new Error('Ephemeral encryption key kid must not be empty.');
  }
  const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', {
    crv: JOSE_P256_CURVE,
    extractable: options.extractable ?? false,
  });
  return {
    kid: options.kid ?? randomKid(),
    privateKey,
    publicKey,
    createdAt: options.createdAt ?? Date.now(),
  };
}

/** A fresh 128-bit `base64url` key identifier from the platform CSPRNG. */
function randomKid(): string {
  return randomBytes(16).toString('base64url');
}

/**
 * Default maximum age of an ephemeral encryption key pair, in seconds.
 *
 * Five minutes: long enough for a human to complete a wallet presentation,
 * short enough that a leaked private half has almost no window. Callers should
 * align this with their Authorization Request lifetime rather than treat it as
 * an independent knob.
 */
export const EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS = 300;

/**
 * Whether an ephemeral pair is too old to still decrypt a response.
 *
 * Fails CLOSED in the degenerate cases: a non-positive `maxAgeSeconds` expires
 * everything, and a pair whose `createdAt` is in the future (clock skew, or a
 * tampered persisted record) is treated as expired rather than as valid
 * forever.
 *
 * @param pair - Pair to age.
 * @param options - `maxAgeSeconds` (default
 * {@link EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS}) and `now` in epoch ms.
 */
export function isEphemeralEncryptionKeyPairExpired(
  pair: Pick<EphemeralEncryptionKeyPair, 'createdAt'>,
  options: { maxAgeSeconds?: number; now?: number } = {}
): boolean {
  const maxAgeSeconds = options.maxAgeSeconds ?? EPHEMERAL_ENCRYPTION_KEY_MAX_AGE_SECONDS;
  const now = options.now ?? Date.now();
  const ageMs = now - pair.createdAt;
  if (ageMs < 0) return true;
  return ageMs >= maxAgeSeconds * 1000;
}

/**
 * Serialize the PUBLIC half of an ephemeral pair as the fully-specified JWK to
 * publish in OID4VP client metadata (#298).
 *
 * Always stamps `use: 'enc'`, `alg: 'ECDH-ES'`, `crv: 'P-256'` and the pair's
 * `kid`. Fully specifying the key is what lets the wallet pin the algorithm
 * instead of inferring it from `kty`/`crv` — the inference that makes an ES256
 * verification key and this key look identical.
 *
 * @param pair - Pair whose public half to publish.
 * @returns The public JWK. Cannot contain `d`: a WebCrypto PUBLIC key has no
 * private component to export.
 */
export async function exportEncryptionPublicJwk(
  pair: Pick<EphemeralEncryptionKeyPair, 'kid' | 'publicKey'>
): Promise<JWK> {
  if (pair.publicKey.type !== 'public') {
    throw new Error(
      `exportEncryptionPublicJwk requires a public key, got a '${pair.publicKey.type}' key.`
    );
  }
  const jwk = await exportJWK(pair.publicKey);
  return { ...jwk, alg: 'ECDH-ES', use: 'enc', kid: pair.kid };
}

/**
 * Serialize the PRIVATE half of an ephemeral pair, for deployments that must
 * carry it across HTTP requests (see
 * {@link GenerateEphemeralEncryptionKeyPairOptions.extractable}).
 *
 * The result contains `d`. It is a SECRET: store it encrypted at rest, scoped to
 * the one Authorization Request it belongs to, and delete it as soon as the
 * response is decrypted or the request expires.
 *
 * @throws Error if the private key was generated non-extractable — which is the
 * default, and means the deployment opted out of serializing it.
 */
export async function exportEncryptionPrivateJwk(
  pair: Pick<EphemeralEncryptionKeyPair, 'kid' | 'privateKey'>
): Promise<JWK> {
  if (pair.privateKey.type !== 'private') {
    throw new Error(
      `exportEncryptionPrivateJwk requires a private key, got a '${pair.privateKey.type}' key.`
    );
  }
  if (!pair.privateKey.extractable) {
    throw new Error(
      'Ephemeral encryption private key is not extractable. Generate it with ' +
        '{ extractable: true } if this deployment must persist it across requests.'
    );
  }
  const jwk = await exportJWK(pair.privateKey);
  return { ...jwk, alg: 'ECDH-ES', use: 'enc', kid: pair.kid };
}

/**
 * JWK members carrying private key material — refused by
 * {@link importEncryptionPublicJwk}.
 */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

/**
 * Validate the shared shape of an untrusted `ECDH-ES` P-256 JWK.
 *
 * `jose` does NOT pin the curve when importing for `ECDH-ES` — a `P-384` (or
 * `P-521`) JWK imports without complaint, unlike the `ES256` path where it does
 * check. HAIP §5 mandates P-256, and silently agreeing a key on an unrequested
 * curve is a downgrade this library must refuse itself.
 *
 * @throws Error naming the offending member.
 */
function assertEcdhEsP256Jwk(jwk: JWK): void {
  if (jwk.kty !== 'EC') {
    throw new Error(`JWK 'kty' must be 'EC' for ECDH-ES, got '${String(jwk.kty)}'.`);
  }
  if (jwk.crv !== JOSE_P256_CURVE) {
    throw new Error(
      `JWK 'crv' must be '${JOSE_P256_CURVE}' for ECDH-ES response encryption, got ` +
        `'${String(jwk.crv)}'.`
    );
  }
  if (jwk.alg !== undefined && jwk.alg !== 'ECDH-ES') {
    throw new Error(`JWK declares alg '${jwk.alg}' but is being imported as 'ECDH-ES'.`);
  }
  if (jwk.use !== undefined && jwk.use !== 'enc') {
    throw new Error(`JWK declares use '${jwk.use}'; an encryption key must declare 'enc'.`);
  }
}

/**
 * Import an untrusted PUBLIC `ECDH-ES` P-256 JWK — a wallet's (or peer
 * Verifier's) published encryption key.
 *
 * Every member of the JWK is attacker-controlled, so the curve, key type, and
 * any declared `alg`/`use` are validated against this library's fixed policy
 * before `jose` sees them, and private members are refused outright rather than
 * stripped.
 *
 * @param jwk - Untrusted public JWK.
 * @returns The imported public key, usable as an encryption recipient.
 * @throws Error if the JWK is not a public `ECDH-ES` P-256 key.
 */
export async function importEncryptionPublicJwk(jwk: JWK): Promise<EncryptionKey> {
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (jwk[member] !== undefined) {
      throw new Error(
        `Public encryption JWK must not carry private key material (found '${member}').`
      );
    }
  }
  assertEcdhEsP256Jwk(jwk);
  const key = await importJWK(jwk, 'ECDH-ES');
  if (key instanceof Uint8Array || key.type !== 'public') {
    throw new Error("JWK did not import as an asymmetric public key for 'ECDH-ES'.");
  }
  return key;
}

/**
 * Re-import a PRIVATE `ECDH-ES` P-256 JWK previously produced by
 * {@link exportEncryptionPrivateJwk} — the other half of the
 * persist-across-requests path.
 *
 * The input is this deployment's own stored secret rather than a peer's, but it
 * is validated identically: shared state can be tampered with, and a stored key
 * silently switched to another curve would be a downgrade with no other detector.
 *
 * @param jwk - Private JWK containing `d`.
 * @throws Error if the JWK is not a private `ECDH-ES` P-256 key.
 */
export async function importEncryptionPrivateJwk(jwk: JWK): Promise<EncryptionKey> {
  if (typeof jwk.d !== 'string' || jwk.d.length === 0) {
    throw new Error("Private encryption JWK must carry a 'd' member.");
  }
  assertEcdhEsP256Jwk(jwk);
  const key = await importJWK(jwk, 'ECDH-ES');
  if (key instanceof Uint8Array || key.type !== 'private') {
    throw new Error("JWK did not import as an asymmetric private key for 'ECDH-ES'.");
  }
  return key;
}
