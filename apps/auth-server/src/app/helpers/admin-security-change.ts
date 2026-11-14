import { parseEventType } from '@qauth-labs/shared-events';
import type { FastifyInstance } from 'fastify';

/**
 * THE TWO-ADMIN RULE'S RECORD OF A SECURITY CHANGE (ADR-019 Decision 7,
 * #521).
 *
 * An admin whose credentials, identifier or contact address changed in the 7
 * days before a request cannot approve it, whoever made the change. The rule
 * reads `admin_grants.last_security_change_at`, and
 * {@link recordAdminSecurityChange} moves it: on every live grant of the
 * account, to the database's time, never back (migration 0074). An account
 * that administers nothing has no grant, and nothing moves.
 *
 * Every such change records its event in the change's own transaction, so
 * the event is where the change is recorded too ({@link SECURITY_CHANGE_EVENTS},
 * called by `emitUserEvent`): the account API, the hosted pages, the sign-in
 * flows and the admin API alike, and a later path that makes the change
 * records it by recording its event. The one change whose store keeps its
 * own transaction, a new set of recovery codes, records it before the set
 * is written (`regenerateRecoveryCodes`). The automatic disable of a password or
 * an authenticator app after too many wrong attempts (ADR-017 Decision 7) is
 * not a change of the account's credentials, and records nothing.
 */

/** What changed: one of the three things rule 3 of the two-admin rule watches. */
export type SecurityChangeKind = 'credentials' | 'identifier' | 'contact-address';

/**
 * The events that record a security change, by short name, each with what
 * changed. They are the sources of the account security log's entries for a
 * changed password, a credential added or removed, new recovery codes and an
 * account linked or unlinked (`SECURITY_LOG_KINDS` of the account contract),
 * and `admin/approvals/two-admin.test.ts` keeps the two in step: a source added
 * to one of those entries, `identifier_changed`'s once #690 registers it,
 * fails the test until it is listed here.
 */
export const SECURITY_CHANGE_EVENTS: Readonly<Record<string, SecurityChangeKind>> = Object.freeze({
  'user.password_changed': 'credentials',
  'user.password_reset': 'credentials',
  'user.credential_added': 'credentials',
  'user.credential_removed': 'credentials',
  'user.recovery_codes_regenerated': 'credentials',
  'user.upstream_linked': 'credentials',
  'user.upstream_unlinked': 'credentials',
  'wallet.linked': 'credentials',
});

/** What the change happened to: an account, in its realm. */
export interface SecurityChangeAccount {
  readonly realmId: string;
  readonly accountId: string;
}

/** The transaction a change commits in, as the grants repository takes it. */
export type SecurityChangeTransaction = Parameters<
  FastifyInstance['repositories']['adminGrants']['recordSecurityChange']
>[2];

/**
 * Record that `account`'s credentials, identifier or contact address
 * changed (`kind`): from now on, and for 7 days, it cannot approve another
 * admin's request (#521). Call it in the transaction of the change, so the
 * record commits with it or neither does.
 *
 * @returns how many of the account's grants moved: zero for an account that
 *   administers nothing
 */
export async function recordAdminSecurityChange(
  fastify: FastifyInstance,
  account: SecurityChangeAccount,
  kind: SecurityChangeKind,
  tx?: SecurityChangeTransaction
): Promise<number> {
  const moved = await fastify.repositories.adminGrants.recordSecurityChange(
    account.realmId,
    account.accountId,
    tx
  );
  if (moved > 0) {
    fastify.log.info(
      { realmId: account.realmId, kind, grants: moved },
      'an admin account changed its credentials, identifier or contact address: it cannot approve for 7 days'
    );
  }
  return moved;
}

/**
 * What an event of `type` records of the two-admin rule: the kind of
 * security change it is, or `undefined` for one that is none.
 */
export function securityChangeOfEvent(type: string): SecurityChangeKind | undefined {
  const name = parseEventType(type)?.name;
  return name !== undefined && Object.hasOwn(SECURITY_CHANGE_EVENTS, name)
    ? SECURITY_CHANGE_EVENTS[name]
    : undefined;
}
