/**
 * The rules of a live admin grant (ADR-019 Decision 7, #510): which
 * permissions its role holds now, and which realms it covers. Pure functions
 * of the grant and the account's realm: the admin API's authority stage
 * (`admin-authority.ts`) and the account API's check of an act-chain token
 * (`admin-access.ts`, #523) read one rule.
 */
import type { FastifyInstance } from 'fastify';

import { BUILT_IN_ROLE_NAMES, BUILT_IN_ROLES, type BuiltInRoleName } from './admin-roles';
import type { RealmRow } from './request-realm';

/** The live grants of an account, as the grants repository lists them. */
type LiveAdminGrants = Awaited<
  ReturnType<FastifyInstance['repositories']['adminGrants']['listLive']>
>;

/** One live grant. */
export type LiveAdminGrant = LiveAdminGrants[number];

/** The permission ids a live grant's role holds now. */
export function grantedPermissionIds(live: LiveAdminGrant): readonly string[] {
  if (live.grant.builtInRole !== null) {
    const name = live.grant.builtInRole;
    return (BUILT_IN_ROLE_NAMES as readonly string[]).includes(name)
      ? BUILT_IN_ROLES[name as BuiltInRoleName].permissionIds
      : [];
  }
  return live.role?.permissionIds ?? [];
}

/**
 * Whether a live grant still fits the realm rule for an account of
 * `accountRealm` (`admin_grants_realm_rule` holds it when the grant is
 * written; the operator flag may have moved since):
 *
 * - a grant on every realm only for an account of the operator realm;
 * - a grant on another realm than the account's own only for an account of
 *   the operator realm;
 * - a custom role of the account's realm or of the grant's target realm.
 */
export function grantFitsRealmRule(
  live: LiveAdminGrant,
  accountRealm: Pick<RealmRow, 'id' | 'isOperator'>
): boolean {
  const { targetRealmId } = live.grant;
  if (!accountRealm.isOperator && targetRealmId !== accountRealm.id) return false;
  if (live.grant.roleId !== null) {
    const role = live.role;
    if (role === null || role.disabledAt !== null) return false;
    if (role.realmId !== accountRealm.id && role.realmId !== targetRealmId) return false;
  }
  return true;
}

/**
 * Whether a live grant of an account of `accountRealm` gives its role on the
 * realm `targetRealmId` (rule 3 and the realm rule of
 * {@link resolveAdminAuthority}): it fits the realm rule, and its target is
 * that realm, or every realm for an account of the operator realm. Who may
 * approve a request on a realm is counted with it too
 * (`admin/approvals/eligibility.ts`), so both read one rule.
 */
export function grantCoversRealm(
  live: LiveAdminGrant,
  accountRealm: Pick<RealmRow, 'id' | 'isOperator'>,
  targetRealmId: string
): boolean {
  return (
    grantFitsRealmRule(live, accountRealm) &&
    (live.grant.targetRealmId === targetRealmId ||
      (accountRealm.isOperator && live.grant.targetRealmId === null))
  );
}
