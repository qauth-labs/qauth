import type {
  RealmPolicies,
  RealmPolicyStoreOfRealms,
} from '@qauth-labs/fastify-plugin-realm-policy';

import type { RealmRow } from './request-realm';

/**
 * A realm's Client ID Metadata Document policy (#534): the
 * `registration.cimd` group of its policies. Whether an HTTPS URL is
 * accepted as a `client_id` at all (`enabled`), and which hosts such a URL
 * may name (`trustPolicy`, and `trustedDomains` for the `allowlist` policy).
 */
export type CimdPolicy = RealmPolicies['registration']['cimd'];

/**
 * A realm's CIMD policy (ADR-019 Decisions 1 and 10, #534), from the realm
 * row the flow already holds (the realm resolver's): no query. So two realms
 * of one deployment can accept CIMD clients differently, and a change of a
 * realm's policy reaches its next client resolution and discovery document
 * once the row is read again (the resolver's cache time), without a restart.
 *
 * A realm that has its policies keeps the three fields in them;
 * `CIMD_ENABLED`, `CIMD_TRUST_POLICY` and `CIMD_TRUSTED_DOMAINS` only seeded
 * them. One that has none yet (counter 0: created by a node of the previous
 * release during a rolling upgrade, until a boot fills it) reads as its fill
 * will leave it, the environment's seeds of this node, which is what every
 * realm ran on before #534. The fill stores the same values, so the policy
 * does not change when it lands.
 *
 * The cache lifetimes, the document size and the fetch timeout stay
 * deployment settings (`CIMD_CACHE_*`, `CIMD_MAX_DOCUMENT_BYTES`,
 * `CIMD_FETCH_TIMEOUT_MS`): they bound what one node spends on a fetch, not
 * who may be a client of a realm.
 *
 * The store reads the whole document, so a value the schema refuses in any
 * group fails the caller (a server error, logged) rather than let the server
 * guess what the realm meant, as the token lifetimes do (#527). The policy
 * store writes no such value; it comes from a row written by hand, or by a
 * node of another release.
 *
 * This file reads no other decorator than `policyStore`, so the discovery
 * routes can import it without the CIMD fetch's plugins.
 *
 * @throws PolicyValidationError when the realm's stored policies are not a
 *   valid policy document
 */
export function cimdPolicyOf(
  sources: { readonly policyStore: Pick<RealmPolicyStoreOfRealms, 'ofRealm'> },
  realm: RealmRow
): CimdPolicy {
  return sources.policyStore.ofRealm(realm).policies.registration.cimd;
}
