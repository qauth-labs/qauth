import { z } from 'zod';

/**
 * Shared Signals Framework transmitter settings (ADR-018 §3, ADR-019
 * Decision 8, issue #410).
 *
 * `SSF_TRANSMITTER_ENABLED` is the deployment's switch. Off, the server
 * registers no SSF route, publishes no SSF metadata and writes no SSF
 * delivery row, and the JWKS is unchanged. On, each realm still needs its
 * own switch (`realms.ssf_transmitter_enabled`) before it serves receivers. A
 * plain `z.object`, so the auth server can spread its `.shape`.
 */

/** Same parsing as `DPOP_ENABLED`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/**
 * SSF transmitter environment configuration schema.
 */
export const ssfEnvSchema = z.object({
  /** Turn the Shared Signals Framework transmitter on. Default off. */
  SSF_TRANSMITTER_ENABLED: strictBoolean(false),
});

export type SsfEnv = z.infer<typeof ssfEnvSchema>;
