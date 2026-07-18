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
 * An `AKP` (Algorithm Key Pair) JWK publishing an ML-DSA public key (#246).
 *
 * `kty: 'AKP'` and the `pub` member follow the JOSE PQC composite draft (the
 * same `PQC_JOSE_COMPOSITE_DRAFT` pinned for #245). A classical (Ed25519-only)
 * verifier does not understand `kty: 'AKP'` and simply IGNORES this entry —
 * exactly the mixed-key behaviour #246 requires. Only the public key is
 * emitted; there is no private (`priv`/seed) member.
 *
 * @remarks the exact member names MUST be reconfirmed on the IETF datatracker
 * before the flag is enabled by default.
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
