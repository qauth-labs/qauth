import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from './configured-value';
import { canonicalizeIssuerIdentifier } from './issuer-identity';

/**
 * Boot-time agreement between configured trust and RUNTIME trust (issue #236).
 *
 * ## The failure this closes
 *
 * `OID4VP_TRUSTED_ISSUERS` is validated twice, by two different rule sets, and
 * they did not agree. `server-config`'s schema checks that each entry is a
 * syntactically valid HTTPS URL and caps its length; the runtime reduces the
 * SAME entry with {@link canonicalizeIssuerIdentifier}, which additionally
 * refuses userinfo, a query string and a fragment. So
 * `{"master":["https://issuer.example?x=1"]}` parsed cleanly at boot and then
 * failed canonicalization at request time — and because `resolveTrustRegistry`
 * is deliberately ALL-OR-NOTHING, one such entry collapsed the realm's entire
 * allowlist to `DENY_ALL_TRUST_REGISTRY`.
 *
 * The result was the worst shape a security control can take: no boot failure,
 * no log, no signal of any kind, and every Verifiable Presentation to that realm
 * rejected — indistinguishable, by design (`issuer-trust-rejection.ts`), from an
 * untrusted issuer. The operator sees a realm that trusts nobody and a
 * configuration that says otherwise.
 *
 * ## Why here, and why at boot
 *
 * The two rule sets are made to agree by running the RUNTIME one at startup:
 * this module calls the very function the trust registry calls, so there is no
 * second implementation to drift. `server-config` cannot do this itself — it is
 * the lowest server layer and carries no dependency on `server-federation` — so
 * the check lives on this side of the boundary and the bootstrap invokes it,
 * which is also where #299 put its equivalent refusal (a `VerifierProfile`
 * whose Client Identifier Prefix needs a certificate it has not been given
 * refuses the boot rather than serving an unmeetable posture).
 *
 * A deployment that will reject every presentation must not start quietly.
 */

/**
 * Refuse to start on an `OID4VP_TRUSTED_ISSUERS` map the runtime cannot use
 * (#236).
 *
 * Call once from the bootstrap, with the parsed env value. It is NOT gated on
 * `WALLET_FEDERATION_ENABLED`: the operator wrote this configuration, a
 * malformed entry in it is a typo rather than a posture decision, and the env
 * schema already fails the boot on a malformed value regardless of the flag.
 * Discovering the typo only after wallet federation is switched on — by which
 * time the symptom is "every presentation is rejected" — is precisely the delay
 * this function exists to remove.
 *
 * Nothing configured is not a fault: an absent or empty map means no realm
 * trusts any issuer, which is the deliberate fail-closed default (#296 LOCKED),
 * and it starts.
 *
 * @param allowlist - realm name → trusted issuer identifiers, straight from
 * `OID4VP_TRUSTED_ISSUERS`. `null`/`undefined` means "not configured".
 * @throws InvalidConfigurationError when the map, or any entry in it, is
 * something the trust registry would refuse at request time. The offending
 * realm and value are on `details`, never in the message.
 */
export function assertTrustedIssuersUsable(
  allowlist: Readonly<Record<string, readonly string[]>> | null | undefined
): void {
  if (allowlist === null || allowlist === undefined) return;

  if (typeof allowlist !== 'object' || Array.isArray(allowlist)) {
    throw new InvalidConfigurationError(
      'OID4VP_TRUSTED_ISSUERS must be an object mapping realm name to an array of https:// issuer identifiers (#236). Refusing to start on a trust configuration that cannot be read.'
    );
  }

  // Read through `unknown`: the map reaches this function from JSON an operator
  // wrote, so its declared type is a claim rather than a guarantee.
  for (const [realmName, issuers] of Object.entries(allowlist as Record<string, unknown>)) {
    if (!Array.isArray(issuers)) {
      throw new InvalidConfigurationError(
        'OID4VP_TRUSTED_ISSUERS maps a realm to something that is not an array of issuer identifiers (#236). The realm would trust no issuer at all and every Verifiable Presentation to it would be rejected. See this error\'s "details" for the realm.',
        { realm: summarizeConfiguredValue(realmName) }
      );
    }

    for (const [index, entry] of (issuers as readonly unknown[]).entries()) {
      if (canonicalizeIssuerIdentifier(entry) !== undefined) continue;

      throw new InvalidConfigurationError(
        'OID4VP_TRUSTED_ISSUERS contains an entry that is not a usable issuer identity (#236). Entries must be absolute https:// URLs with no userinfo, query string or fragment. Trust is all-or-nothing per realm, so this one entry would make the realm trust NO issuer and reject every Verifiable Presentation — refusing to start instead. See this error\'s "details" for the realm, the position and the value.',
        {
          realm: summarizeConfiguredValue(realmName),
          index,
          entry: summarizeConfiguredValue(entry),
        }
      );
    }
  }
}
