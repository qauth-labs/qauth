import { z } from 'zod';

/**
 * DPoP settings (RFC 9449; ADR-014 §3, ADR-017 Decision 14 and phase F3,
 * issues #479 and #480).
 *
 * `DPOP_ENABLED` is the one switch for DPoP-bound tokens, shared by the token
 * endpoint, the first-party endpoint and the Authority Tree;
 * `AUTHORITY_TREE_ENABLED` will require it. With it on, the token endpoint
 * binds a token to the key of the request's `DPoP` proof and the protected
 * resources of the auth server accept the `DPoP` scheme. With it off, the
 * server reads no `DPoP` header and answers exactly as it did before DPoP. A
 * plain `z.object`, so the auth server can spread its `.shape`.
 */

/** Same parsing as `REQUIRE_VERIFIED_ACCOUNT`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/**
 * DPoP environment configuration schema.
 */
export const dpopEnvSchema = z.object({
  /**
   * Turn DPoP-bound tokens on (RFC 9449). Default off. While it is off, no
   * client is DPoP-bound, whatever its `dpop_bound_access_tokens` says.
   */
  DPOP_ENABLED: strictBoolean(false),
});

export type DpopEnv = z.infer<typeof dpopEnvSchema>;
