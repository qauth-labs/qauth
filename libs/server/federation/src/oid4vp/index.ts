/**
 * OID4VP 1.0 transport and presentation validation (issues #233, #234).
 *
 * Three stages, all profile-gated by #299's `VerifierProfile`:
 *
 * - **Request generation** (#233 Phase B, #377) — `authorization-request`,
 *   `request-object`, `dcql`, `client-identifier`, `credential-format`.
 * - **Response intake** (#233 Phase A) — `request-state`, `direct-post`.
 * - **Presentation validation** (#234) — `presentation-validation`, `sd-jwt-vc`,
 *   `issuer-key-resolution`, `validated-credential`, `presentation-rejection`.
 *
 * Nothing exported from here authenticates anyone — not even the validated
 * credential. Issuer trust (#236) and subject resolution (#300) both still have
 * to run. See `direct-post.ts` and `validated-credential.ts` for the two module
 * JSDocs that state the boundary this whole subdirectory sits behind.
 */

export * from './authorization-request';
export * from './client-identifier';
export * from './credential-format';
export * from './dcql';
export * from './direct-post';
export * from './issuer-key-resolution';
export * from './presentation-rejection';
export * from './presentation-validation';
export * from './request-object';
export * from './request-state';
export * from './sd-jwt-vc';
export * from './validated-credential';
