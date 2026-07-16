import type { SigningKey } from '@qauth-labs/core-crypto';

/**
 * Cryptographic key type used across the JWT layer.
 *
 * Sourced from the crypto abstraction ({@link SigningKey}) so the JWT layer
 * depends on the algorithm-agnostic seam (ADR-005) rather than a specific
 * crypto backend. Retained under the `KeyLike` name for continuity with
 * existing call sites.
 */
export type KeyLike = SigningKey;
