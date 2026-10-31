import type { RealmPolicyStoreOfRealms } from '@qauth-labs/fastify-plugin-realm-policy';

import type { RealmRow } from './request-realm';

/**
 * The realm policies the auth server reads from the realm row (ADR-019
 * Decision 10, #516), by their path in the realm policy schema.
 *
 * Since #516 every realm stores its policies, and the environment only
 * seeds a new realm. The flows move to the stored values one area at a time:
 * the token lifetimes (#527), the verified-account, password and brute-force
 * policy (#528), mail (#529) and CIMD (#534). Until an area has moved, the
 * server still reads its keys from the environment for every realm, so the
 * default realm's boot step says a set key is ignored only for a path listed
 * here; for any other it says the server still applies the key. The issue
 * that moves an area adds its paths.
 */
export const POLICIES_READ_FROM_REALM_ROW: ReadonlySet<string> = new Set([
  // `/oauth/register` and the clients API (`routes/clients/index.ts`) cap a
  // client's scopes with the realm's list; the environment's list fills an
  // empty one only while the realm has no policies.
  'registration.dynamicRegistrationAllowedScopes',
  // `resolveEnvironmentPolicy` (ADR-008): the realm's environment ceiling.
  'posture.maxEnvironmentLaxity',
]);

/**
 * A realm's dynamic registration allowlist (#516), which `/oauth/register`
 * and the clients API cap a client's scopes with. A realm that has its
 * policies keeps the list in its row. One that has none yet (counter 0: from
 * before migration 0046, or created by a node of the previous release during
 * a rolling upgrade) reads as its fill will leave it: the list its row holds
 * when it holds a scope, the environment's seed otherwise.
 *
 * Nothing is written here. The boot step stores the fill, the first node to
 * boot winning, so a request can neither overwrite that fill with its own
 * node's environment nor give an empty list a scope.
 *
 * @throws PolicyValidationError when the fill of a realm with no policies is
 *   not a valid policy document, such as a scope written into its row by hand
 */
export function dynamicRegistrationScopesOf(
  policies: Pick<RealmPolicyStoreOfRealms, 'ofRealm'>,
  realm: RealmRow
): string[] {
  if (realm.policiesVersion !== 0) return [...(realm.dynamicRegistrationAllowedScopes ?? [])];
  return [...policies.ofRealm(realm).policies.registration.dynamicRegistrationAllowedScopes];
}
