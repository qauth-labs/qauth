import { type MlDsaKey, PQC_ALG_ML_DSA_65 } from '@qauth-labs/core-crypto';
import { exportJWK } from 'jose';

import type { KeyLike } from '../types/key-management';

/**
 * Shape of a single JWK entry exposed on `/.well-known/jwks.json`.
 *
 * We type this as a record with known sig-related fields so that callers
 * (such as the discovery endpoint) can add/override claims like `kid`
 * without fighting a narrow `JWK` type. Raw JWK member names such as
 * `kty`, `crv`, `x` come from {@link exportJWK}.
 */
export interface PublicJwk extends Record<string, unknown> {
  /** Intended use of the key; `sig` = signature verification (RFC 7517 §4.2). */
  use: 'sig';
  /** JWS algorithm (RFC 7518). EdDSA for Ed25519 keys. */
  alg: 'EdDSA';
  /** Optional key identifier used to select a key during verification. */
  kid?: string;
}

/**
 * An `RSA` JWK publishing an RS256 public key on `/.well-known/jwks.json` (#309).
 *
 * `kty: 'RSA'` with the public modulus/exponent (`n`, `e`) per RFC 7518 §6.3.1.
 * Emitted ONLY when an RS256 signing key is configured, alongside the EdDSA
 * `OKP` entry, so an RP that requires `RS256` (OIDC Basic/Config certification,
 * #286) can verify the ID token. It carries a `kid` DISTINCT from the EdDSA key
 * so a verifier resolves `(kid, alg)` unambiguously.
 *
 * NEVER contains private members (`d`, `p`, `q`, `dp`, `dq`, `qi`) — RFC 7517
 * §9.3. {@link exportRs256PublicJwk} constructs the entry from only the public
 * members, so a private component cannot leak even if a private key is passed.
 */
export interface Rs256Jwk extends Record<string, unknown> {
  kty: 'RSA';
  /** base64url RSA public modulus (RFC 7518 §6.3.1.1). */
  n: string;
  /** base64url RSA public exponent (RFC 7518 §6.3.1.2). */
  e: string;
  use: 'sig';
  alg: 'RS256';
  kid?: string;
}

/**
 * RSA JWK members that carry PRIVATE key material (RFC 7518 §6.3.2). None may
 * ever appear in a published JWK; {@link exportRs256PublicJwk} builds its result
 * from the public members only, and additionally asserts none of these leaked.
 */
const RSA_PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const;

/**
 * Export an RS256 public key as an `RSA` JWK for `/.well-known/jwks.json` (#309).
 *
 * Sets `use: 'sig'` and `alg: 'RS256'` so verifiers match the key by algorithm
 * without sniffing. `kid` is attached only when provided, enabling a distinct
 * identifier from the EdDSA key.
 *
 * SECURITY: the returned JWK is constructed from ONLY the public members `n`/`e`
 * read off `jose.exportJWK`. `exportJWK` on a public key already emits just
 * `kty/n/e`, but this function never spreads the raw object — so no private
 * member can ride along — and defensively THROWS if the source somehow carried
 * one (a misconfigured caller passing a private key), rather than silently
 * publishing it.
 *
 * @param publicKey - Imported RS256 public key (see `importRs256PublicKey`).
 * @param kid - Optional stable key identifier; must be distinct from the EdDSA kid.
 * @returns Promise resolving to a public RSA JWK.
 */
export async function exportRs256PublicJwk(publicKey: KeyLike, kid?: string): Promise<Rs256Jwk> {
  const raw = (await exportJWK(publicKey)) as Record<string, unknown>;

  // Fail closed: a private key would expose `d`/`p`/`q`/… here. Never publish it.
  for (const member of RSA_PRIVATE_JWK_MEMBERS) {
    if (member in raw) {
      throw new Error(
        'exportRs256PublicJwk received a key exposing private RSA members; refusing to publish.'
      );
    }
  }

  const { n, e } = raw;
  if (typeof n !== 'string' || typeof e !== 'string') {
    throw new Error('exportRs256PublicJwk requires an RSA public key with `n` and `e` members');
  }

  const jwk: Rs256Jwk = {
    kty: 'RSA',
    n,
    e,
    use: 'sig',
    alg: 'RS256',
  };
  if (kid !== undefined && kid.length > 0) {
    jwk.kid = kid;
  }
  return jwk;
}

/**
 * An `AKP` (Algorithm Key Pair) JWK publishing an ML-DSA public key (#246).
 *
 * `kty: 'AKP'`, the `pub` member and the `ML-DSA-65` `alg` spelling follow
 * **RFC 9964** ("ML-DSA for JOSE and COSE"), pinned as `PQC_JOSE_MLDSA_SPEC`
 * (#274 — this was previously mis-attributed to the composite-signature draft,
 * which specifies a construction QAuth does not implement; the emitted shape
 * was and remains correct). RFC 9964 makes `kty`, `alg` and `pub` REQUIRED and
 * forbids `priv` in a public key.
 *
 * A classical (Ed25519-only) verifier does not understand `kty: 'AKP'` and
 * simply IGNORES this entry — exactly the mixed-key behaviour #246 requires.
 * Only the public key is emitted; there is no private (`priv`/seed) member.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9964.html
 */
export interface AkpJwk extends Record<string, unknown> {
  kty: 'AKP';
  /** base64url raw ML-DSA-65 public key. */
  pub: string;
  use: 'sig';
  alg: typeof PQC_ALG_ML_DSA_65;
  kid?: string;
}

/**
 * Export an ML-DSA-65 public key as an `AKP` JWK for `/.well-known/jwks.json`
 * (#246). NEVER emits private key material — only the raw public key bytes.
 */
export function exportMlDsaPublicJwk(publicKey: MlDsaKey, kid?: string): AkpJwk {
  if (publicKey.alg !== 'ML-DSA-65' || publicKey.kind !== 'public') {
    throw new Error('exportMlDsaPublicJwk requires a public ML-DSA-65 key');
  }
  const jwk: AkpJwk = {
    kty: 'AKP',
    pub: Buffer.from(publicKey.material()).toString('base64url'),
    use: 'sig',
    alg: PQC_ALG_ML_DSA_65,
  };
  if (kid !== undefined && kid.length > 0) {
    jwk.kid = kid;
  }
  return jwk;
}

/**
 * Export an EdDSA public key as a JWK suitable for publication at
 * `/.well-known/jwks.json`.
 *
 * Always sets `use: 'sig'` and `alg: 'EdDSA'` so downstream verifiers can
 * match the key algorithm without sniffing. `kid` is attached only when
 * provided, which lets us support key rotation (multiple keys published
 * simultaneously, JWTs carrying `kid` in their header).
 *
 * The private component (`d`) is stripped by `jose.exportJWK` for public
 * keys, so this is safe to expose publicly.
 *
 * @param publicKey - Imported EdDSA public key (see {@link importPublicKey}).
 * @param kid - Optional stable key identifier.
 * @returns Promise resolving to a public JWK.
 *
 * @example
 * ```typescript
 * const jwk = await exportPublicJwk(publicKey, '2025-04');
 * // { kty: 'OKP', crv: 'Ed25519', x: '...', use: 'sig', alg: 'EdDSA', kid: '2025-04' }
 * ```
 */
export async function exportPublicJwk(publicKey: KeyLike, kid?: string): Promise<PublicJwk> {
  const raw = await exportJWK(publicKey);

  // Defensive: `exportJWK` on a public key should never emit `d`, but we
  // strip anyway so a misconfigured caller passing a private key cannot
  // leak secret material via `/.well-known/jwks.json`.
  if ('d' in raw) {
    delete (raw as Record<string, unknown>)['d'];
  }

  const jwk: PublicJwk = {
    ...(raw as Record<string, unknown>),
    use: 'sig',
    alg: 'EdDSA',
  };

  if (kid !== undefined && kid.length > 0) {
    jwk.kid = kid;
  }

  return jwk;
}
