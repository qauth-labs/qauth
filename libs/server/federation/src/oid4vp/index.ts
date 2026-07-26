/**
 * OID4VP 1.0 transport layer (issue #233).
 *
 * Two halves, both profile-gated by #299's `VerifierProfile`:
 *
 * - **Request generation** (Phase B) — `authorization-request`, `dcql`,
 *   `client-identifier`, `credential-format`.
 * - **Response intake** (Phase A) — `request-state`, `direct-post`.
 *
 * Nothing exported from here authenticates anyone. See `direct-post.ts`'s
 * module JSDoc for the safety boundary this whole subdirectory sits behind.
 */

export * from './authorization-request';
export * from './client-identifier';
export * from './credential-format';
export * from './dcql';
export * from './direct-post';
export * from './request-state';
