/**
 * Why a DPoP proof was refused (RFC 9449 §4.3).
 *
 * The reason is for the SERVER: logs, metrics, and tests that must show a
 * refusal fired for the right cause. The wire answer is the error code alone
 * ({@link DpopProofError.error}); a response that told a caller which check
 * failed would help an attacker tune a forged proof.
 *
 * - `missing-proof` — the request has no `DPoP` header, or an empty one.
 * - `multiple-proofs` — more than one `DPoP` header (§4.3 step 1), including
 *   two values a proxy or Node joined with a comma.
 * - `malformed` — not one compact JWS, too long, a header or payload that is
 *   not a JSON object, or a `crit` header the verifier cannot honour (§4.3
 *   step 2).
 * - `typ` — the `typ` header is not exactly `dpop+jwt` (§4.3 step 4, §11.5).
 * - `alg` — `none`, a MAC algorithm, an unknown name, or an algorithm the
 *   endpoint does not allow (§4.3 step 5, §11.6).
 * - `jwk` — no `jwk` header, or one that is not a public key of the type
 *   `alg` needs: a member missing or not in canonical base64url, or an RSA
 *   key under 2048 or over 4096 bits.
 * - `private-key` — the `jwk` header carries private key members, or is a
 *   symmetric key (§4.3 step 7).
 * - `signature` — the signature does not verify under the `jwk` (§4.3 step 6).
 * - `htm` — `htm` is missing or is not the request's method (§4.3 step 8).
 * - `htu` — `htu` is missing or is not the request's URL, ignoring query and
 *   fragment (§4.3 step 9); or the request's own path has a dot segment or a
 *   backslash, or its target is not in origin form, so it cannot be compared.
 * - `iat` — `iat` is missing, not a number, or outside the window (§4.3
 *   step 11, §11.1).
 * - `jti` — `jti` is missing, empty or longer than the verifier stores
 *   (§4.2, §11.1).
 * - `ath` — an access token was presented and `ath` is missing or is not its
 *   hash (§4.3 step 12, §7).
 * - `claims-not-allowed` — the proof carries `sub`, `cnf` or `events`, the
 *   claims of the other JWT types a DPoP key may sign (ADR-014 §4).
 * - `key-mismatch` — the key is not the one the token or code is bound to
 *   (§4.3 step 12, §6).
 * - `nonce-required` — the endpoint requires a server-provided nonce and the
 *   proof has none (§8, §9, §11.3).
 * - `nonce-invalid` — the proof's nonce is not one the server provided
 *   recently (§8).
 * - `replayed` — the proof's `jti` was already used by the same key within
 *   the window (§11.1).
 * - `replay-store-unavailable` — the replay store did not answer in time or
 *   failed, so a replay cannot be ruled out. The proof is refused.
 */
export type DpopRejectionReason =
  | 'missing-proof'
  | 'multiple-proofs'
  | 'malformed'
  | 'typ'
  | 'alg'
  | 'jwk'
  | 'private-key'
  | 'signature'
  | 'htm'
  | 'htu'
  | 'iat'
  | 'jti'
  | 'ath'
  | 'claims-not-allowed'
  | 'key-mismatch'
  | 'nonce-required'
  | 'nonce-invalid'
  | 'replayed'
  | 'replay-store-unavailable';

/**
 * The error codes of RFC 9449 §12.2: `invalid_dpop_proof` for a proof that
 * fails a check, `use_dpop_nonce` when the client must retry with the nonce in
 * {@link DpopProofError.nonce}.
 */
export type DpopErrorCode = 'invalid_dpop_proof' | 'use_dpop_nonce';

/** The reasons answered with `use_dpop_nonce`. */
const NONCE_REASONS: ReadonlySet<DpopRejectionReason> = new Set([
  'nonce-required',
  'nonce-invalid',
]);

/**
 * A refused DPoP proof. `message` is fixed text that names no value from the
 * request; `reason` says why, for the server only; `error` is the code for the
 * response.
 *
 * An authorization server answers 400 with `error` (RFC 9449 §5, §8); a
 * resource server answers 401 with a `WWW-Authenticate: DPoP` challenge whose
 * `error` is this code (§7.1, §9). When `error` is `use_dpop_nonce`, `nonce`
 * holds the value for the response's `DPoP-Nonce` header.
 */
export class DpopProofError extends Error {
  readonly error: DpopErrorCode;

  constructor(
    public readonly reason: DpopRejectionReason,
    /** A fresh nonce for the `DPoP-Nonce` header; set only with `use_dpop_nonce`. */
    public readonly nonce?: string,
    options?: { cause?: unknown }
  ) {
    const error: DpopErrorCode = NONCE_REASONS.has(reason)
      ? 'use_dpop_nonce'
      : 'invalid_dpop_proof';
    super(
      error === 'use_dpop_nonce'
        ? 'The DPoP proof must carry the nonce the server provided'
        : 'The DPoP proof was refused',
      options
    );
    this.name = 'DpopProofError';
    this.error = error;
    Object.setPrototypeOf(this, DpopProofError.prototype);
  }
}
