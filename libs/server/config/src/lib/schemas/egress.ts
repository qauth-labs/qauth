import { z } from 'zod';

/**
 * Egress settings (ADR-019 Decision 8, issue #481).
 *
 * `EGRESS_ALLOWLIST_PATH` names the deployment's allowlist file: the hosts
 * and address ranges an operator lets the egress client reach although they
 * are not public, each for the realms it names. The server reads the file
 * once, at boot (`@qauth-labs/fastify-plugin-egress`); it is not in the
 * database and no API edits it. Unset or blank, the list is empty and every
 * non-public address is refused. A plain `z.object`, so the auth server can
 * spread its `.shape`.
 */
export const egressEnvSchema = z.object({
  /** The allowlist file. Blank, as `docker-compose.yml` forwards an unset one, is unset. */
  EGRESS_ALLOWLIST_PATH: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z.string().optional()
  ),
});

export type EgressEnv = z.infer<typeof egressEnvSchema>;
