import type { FastifyInstance } from 'fastify';

/**
 * TEST SUPPORT — the two-admin rule's 7-day window (#521), for suites that
 * run against a real Postgres.
 *
 * An admin may give another admin's request its second approval only when,
 * in the 7 days before the request, its account was not created, it was not
 * granted a role and its credentials did not change. A test makes its admins
 * a moment before it files, so it ages the ones that approve: their account
 * and every grant they hold, as if made {@link PAST_THE_WINDOW_MS} ago.
 *
 * No role may change a grant's times; the trigger `admin_grants_revoke_only`
 * refuses it. The suites connect as the database's owner, which may switch
 * the trigger off for the one update, in a transaction of its own.
 */

/** How far back an aged admin was made: a day past the 7-day window. */
export const PAST_THE_WINDOW_MS = 8 * 24 * 60 * 60 * 1000;

/** Age the account `userId` and its grants by `byMs`, so the two-admin rule finds them old. */
export async function ageAdminAccount(
  pool: FastifyInstance['dbPool'],
  userId: string,
  byMs = PAST_THE_WINDOW_MS
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('ALTER TABLE admin_grants DISABLE TRIGGER admin_grants_revoke_only');
    await client.query(
      `UPDATE admin_grants
          SET created_at = created_at - $2,
              last_security_change_at = last_security_change_at - $2,
              revoked_at = revoked_at - $2
        WHERE user_id = $1`,
      [userId, byMs]
    );
    await client.query('ALTER TABLE admin_grants ENABLE TRIGGER admin_grants_revoke_only');
    await client.query('UPDATE users SET created_at = created_at - $2 WHERE id = $1', [
      userId,
      byMs,
    ]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
