import { z } from 'zod';

/**
 * The scheduled key rotation (ADR-019 Decision 9 and its answers on the
 * retired-key lifetime, issue #542): how long a realm's key signs before the
 * rotation job replaces it, how long the next key is published before it
 * signs, and how long a retired key stays published at least. The job runs on
 * the `signer` role; every process reads the keys, and the period is checked
 * against the pre-publication window at boot (`keyRotationProblems`).
 *
 * The defaults are those of `@qauth-labs/server-keys` (90, 7 and 14 days); a
 * test of the auth server holds them equal. A per-realm period is a realm
 * policy, which these keys do not set.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */
export const keyRotationEnvSchema = z.object({
  /** Days a realm's key signs before the rotation job replaces it. */
  KEY_ROTATION_PERIOD_DAYS: z.coerce.number().int().min(1).max(3650).default(90),

  /** Days a new key is published, signing nothing, before it replaces the active key. */
  KEY_PREPUBLISH_DAYS: z.coerce.number().int().min(1).max(365).default(7),

  /**
   * Days a retired key stays published, or keeps verifying cookies and
   * decrypting stored data, at least: never less than the longest lifetime
   * of what it signed or sealed.
   */
  KEY_RETIRED_RETENTION_DAYS: z.coerce.number().int().min(0).max(365).default(14),
});

/** The scheduled key rotation's windows, in days. */
export type KeyRotationEnv = z.infer<typeof keyRotationEnvSchema>;

/**
 * What is wrong with the rotation windows together, one message per problem:
 * a period shorter than the pre-publication window, since a next key must be
 * published for that whole window before it signs, and it is created while
 * the key it replaces signs. Empty when the windows are sound. The auth
 * server refuses to boot with any.
 */
export function keyRotationProblems(
  env: Pick<KeyRotationEnv, 'KEY_ROTATION_PERIOD_DAYS' | 'KEY_PREPUBLISH_DAYS'>
): string[] {
  if (env.KEY_ROTATION_PERIOD_DAYS < env.KEY_PREPUBLISH_DAYS) {
    return [
      `KEY_ROTATION_PERIOD_DAYS (${env.KEY_ROTATION_PERIOD_DAYS}) is shorter than KEY_PREPUBLISH_DAYS (${env.KEY_PREPUBLISH_DAYS}): a next key is published for the whole pre-publication window before it signs, while the key it replaces signs, so the period must be at least as long. Raise KEY_ROTATION_PERIOD_DAYS or lower KEY_PREPUBLISH_DAYS.`,
    ];
  }
  return [];
}
