import { z } from 'zod';

/**
 * DPoP settings (RFC 9449; ADR-014 §3, ADR-017 Decision 14 and phase F3,
 * issue #479).
 *
 * `DPOP_ENABLED` is the one switch for DPoP-bound tokens, shared by the token
 * endpoint, the first-party endpoint and the Authority Tree;
 * `AUTHORITY_TREE_ENABLED` will require it. A plain `z.object`, so the auth
 * server can spread its `.shape`.
 */

/**
 * The boot error for `DPOP_ENABLED=true` while no endpoint binds tokens to a
 * DPoP key.
 *
 * The shared verifier (`@qauth-labs/server-dpop`) exists, but nothing calls it
 * yet. Until the change that makes the token endpoint issue DPoP-bound tokens
 * (ADR-017 phase F3, ADR-014 phase P1a), the environment schema refuses the
 * switch, so an operator never believes tokens are sender-constrained while
 * they are still plain bearer tokens. That change removes the refusal.
 */
export const DPOP_ENABLED_REFUSAL =
  'DPOP_ENABLED=true is not available yet. The DPoP verifier is built, but no endpoint binds tokens to a DPoP key until the token endpoint does (ADR-017 phase F3, ADR-014 phase P1a), and this switch is refused until then. Unset DPOP_ENABLED or set it to false.';

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
   * Turn DPoP-bound tokens on (RFC 9449). Default off. REFUSED when `true`
   * until the token endpoint binds tokens to a DPoP key (see
   * {@link DPOP_ENABLED_REFUSAL}).
   */
  DPOP_ENABLED: strictBoolean(false).refine((enabled) => !enabled, {
    message: DPOP_ENABLED_REFUSAL,
  }),
});

export type DpopEnv = z.infer<typeof dpopEnvSchema>;
