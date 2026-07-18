/**
 * Draft-churn firewall for hybrid PQC signing (ADR-005, #245).
 *
 * Every value that tracks an unstable IETF draft lives HERE and only here, so a
 * draft revision bump is a single reviewed edit rather than a scatter of magic
 * strings. The hybrid feature is also flag-gated (`HYBRID_SIGNING_ENABLED`,
 * default off), so churn cannot affect a running deployment.
 */

/**
 * The governing JOSE binding for ML-DSA composite signatures. QAuth's hybrid
 * construction (a detached PARALLEL Ed25519 + ML-DSA-65 signature — see
 * `hybrid-signing.ts`) deliberately DEVIATES from the strict single-alg-id +
 * concatenated-signature composite this draft specifies, because a strict
 * composite cannot be validated by an unmodified classical (Ed25519-only)
 * verifier — QAuth's hard compatibility requirement (#245 AC#2). This draft is
 * referenced only for the ML-DSA JOSE algorithm spelling and the AKP JWK shape
 * (#246). The deviation is documented for the #248 security review.
 *
 * @remarks The exact revision MUST be reconfirmed on the IETF datatracker
 * before merge — it could not be verified offline at authoring time.
 */
export const PQC_JOSE_COMPOSITE_DRAFT = 'draft-prabel-jose-pq-composite-sigs-02' as const;

/** Protected-header member advertising the parallel PQC algorithm (non-critical). */
export const PQC_HEADER_ALG_MEMBER = 'pqc_alg' as const;

/** Protected-header member carrying the ML-DSA key id, for JWKS resolution (#246). */
export const PQC_HEADER_KID_MEMBER = 'pqc_kid' as const;

/**
 * The `pqc_alg` value for ML-DSA-65. A private QAuth token-header value (never
 * the JWS `alg`, which stays `EdDSA` so stock verifiers accept the token). The
 * spelling follows {@link PQC_JOSE_COMPOSITE_DRAFT}.
 */
export const PQC_ALG_ML_DSA_65 = 'ML-DSA-65' as const;
