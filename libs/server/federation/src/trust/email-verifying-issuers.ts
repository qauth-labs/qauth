import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from './configured-value';
import { canonicalizeIssuerIdentifier, ValidatedIssuer } from './issuer-identity';

/**
 * Issuers whose `email` claim the OPERATOR accepts as verified
 * (`OID4VP_EMAIL_VERIFYING_ISSUERS`, ANT-2026-BGP7XCR2).
 *
 * A wallet email is verified when the presentation discloses
 * `email_verified: true`. An ABSENT flag cannot count: in SD-JWT VC the holder
 * picks the Disclosures, so a missing flag may be an `email_verified: false`
 * the holder left out. Some issuers (PID-style ones) sign no flag at all and
 * only ever issue verified addresses. For those, the operator can vouch,
 * per issuer, here. The holder's choice of Disclosures can never produce that
 * outcome; only this configuration can.
 */

/**
 * Whether the operator listed this credential's VALIDATED issuer as one whose
 * email counts as verified without a disclosed `email_verified: true`.
 *
 * @param issuer - the credential's issuer; anything but a branded
 * `ValidatedIssuer` is not vouched for.
 * @param configured - `OID4VP_EMAIL_VERIFYING_ISSUERS`, or `undefined` when unset.
 */
export function issuerVouchesForEmail(
  issuer: unknown,
  configured: readonly string[] | undefined
): boolean {
  if (!ValidatedIssuer.isValidated(issuer)) return false;
  if (configured === undefined || configured.length === 0) return false;

  return configured.some((entry) => canonicalizeIssuerIdentifier(entry) === issuer.identifier);
}

/**
 * Refuse to start on an `OID4VP_EMAIL_VERIFYING_ISSUERS` entry the runtime
 * could never match.
 *
 * The env schema checks the list's shape. The runtime additionally reduces
 * each entry with `canonicalizeIssuerIdentifier`, which refuses non-`https:`
 * URLs, userinfo, a query string and a fragment. An entry it refuses would
 * silently vouch for nobody, and that issuer's users would get no `email`
 * claim with nothing in the log naming the cause.
 *
 * @throws InvalidConfigurationError naming the position and a summary of the
 * entry.
 */
export function assertEmailVerifyingIssuersUsable(configured: readonly string[] | undefined): void {
  if (configured === undefined) return;

  for (const [index, entry] of configured.entries()) {
    if (canonicalizeIssuerIdentifier(entry) !== undefined) continue;

    throw new InvalidConfigurationError(
      'OID4VP_EMAIL_VERIFYING_ISSUERS contains an entry that is not a usable issuer identity. Entries must be absolute https:// URLs with no userinfo, query string or fragment. See this error\'s "details" for the position and the value.',
      { index, entry: summarizeConfiguredValue(entry) }
    );
  }
}
