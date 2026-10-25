/**
 * The JWS algorithms a DPoP proof may be signed with (RFC 9449 §4.2, §4.3
 * step 5 and §11.6).
 *
 * Asymmetric signature algorithms only. `none` and the MAC algorithms
 * (`HS256`, `HS384`, `HS512`) are not in this list, and an allowlist the
 * verifier is given must be a subset of it, so no configuration can accept
 * them.
 */
export const DPOP_SIGNATURE_ALGORITHMS = [
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
  'Ed25519',
  'PS256',
  'PS384',
  'PS512',
  'RS256',
  'RS384',
  'RS512',
] as const;

/** One of {@link DPOP_SIGNATURE_ALGORITHMS}. */
export type DpopAlgorithm = (typeof DPOP_SIGNATURE_ALGORITHMS)[number];

/**
 * The allowlist a verifier uses unless it is given one: every algorithm of
 * {@link DPOP_SIGNATURE_ALGORITHMS} except RSASSA-PKCS1-v1_5 (`RS256`,
 * `RS384`, `RS512`), which an endpoint may still allow explicitly. ECDSA,
 * EdDSA and RSASSA-PSS are the algorithms the FAPI 2.0 Security Profile keeps.
 */
export const DEFAULT_DPOP_ALGORITHMS: readonly DpopAlgorithm[] = Object.freeze([
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
  'Ed25519',
  'PS256',
  'PS384',
  'PS512',
]);

/** The key an algorithm verifies with: its JWK `kty` and, for EC and OKP, its `crv`. */
const KEY_TYPES: Readonly<Record<DpopAlgorithm, { kty: string; crv?: string }>> = {
  ES256: { kty: 'EC', crv: 'P-256' },
  ES384: { kty: 'EC', crv: 'P-384' },
  ES512: { kty: 'EC', crv: 'P-521' },
  EdDSA: { kty: 'OKP', crv: 'Ed25519' },
  Ed25519: { kty: 'OKP', crv: 'Ed25519' },
  PS256: { kty: 'RSA' },
  PS384: { kty: 'RSA' },
  PS512: { kty: 'RSA' },
  RS256: { kty: 'RSA' },
  RS384: { kty: 'RSA' },
  RS512: { kty: 'RSA' },
};

/** Whether `value` names one of {@link DPOP_SIGNATURE_ALGORITHMS}. */
export function isDpopAlgorithm(value: unknown): value is DpopAlgorithm {
  return (
    typeof value === 'string' && (DPOP_SIGNATURE_ALGORITHMS as readonly string[]).includes(value)
  );
}

/** Whether a JWK's `kty` and `crv` are the ones `alg` verifies with. */
export function keyFitsAlgorithm(
  alg: DpopAlgorithm,
  jwk: { readonly kty?: unknown; readonly crv?: unknown }
): boolean {
  const expected = KEY_TYPES[alg];
  if (jwk.kty !== expected.kty) return false;
  return expected.crv === undefined || jwk.crv === expected.crv;
}
