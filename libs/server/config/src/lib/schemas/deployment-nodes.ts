import { z } from 'zod';

/**
 * The auth server's node list and configuration digest (ADR-019 Decision 8,
 * issue #499).
 *
 * Every node compares its configuration digest with the running nodes of the
 * same release at boot and refuses to start when it differs.
 * `CONFIG_DIGEST_ROLLOUT=true` turns that refusal into a warning, for the
 * window of a planned change of a deployment-wide setting, during which the
 * nodes run with the old and the new value side by side.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */

/** Same parsing as `ADMIN_API_ENABLED`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/** Deployment node environment configuration schema. */
export const deploymentNodesEnvSchema = z.object({
  /**
   * Boot with a warning, not a refusal, when this node's configuration
   * digest differs from a running node's of the same release. Off by
   * default; on only for the window of a planned settings change.
   */
  CONFIG_DIGEST_ROLLOUT: strictBoolean(false),
});

export type DeploymentNodesEnv = z.infer<typeof deploymentNodesEnvSchema>;
