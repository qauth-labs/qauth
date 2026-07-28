import type { VerifierProfile } from '../profiles/verifier-profile.types';

/**
 * The BOOT gate for credential revocation checking (Token Status List, #297).
 *
 * ## Why a boot gate exists at all
 *
 * `VerifierProfile.requireCredentialStatus` is a MANDATE, and a mandate no code
 * can satisfy is a deployment that accepts wallet requests and then refuses
 * every single presentation. `haip-1.0` declares it `true`; a deployment that
 * selected that profile and provisioned neither status-list trust anchors nor a
 * URI allowlist has stated that revocation checking is mandatory and given the
 * checker nothing to check with. An operator must learn that at startup, not
 * from a 100% login-failure rate — which is exactly the shape of defect #378
 * reports one layer up.
 *
 * It is the direct counterpart of `assertKeyStorageAssuranceProvisioned`
 * (`attestation/key-storage-assurance.ts`) and is deliberately built the same
 * way: it reads the DECLARED capability rather than naming a profile, so a
 * future profile that mandates status is gated with no edit here.
 *
 * ## Why it lives beside the checker but not inside it
 *
 * `credential-status-checker.ts` takes the `status` claim as `unknown` on
 * purpose — it depends on no other lane's output and tests standalone. A gate
 * typed on `VerifierProfile` would put a profile import into that module for the
 * sake of a function the request path never calls. Same separation as
 * `trust/assert-trusted-issuers.ts` from `trust/trust-registry.ts`.
 *
 * ## What it does NOT check
 *
 * That the configured anchors PARSE, or that the allowlist entries are usable
 * prefixes. Those are `createStatusListTrustAnchors` and
 * `createStatusListUriAllowlist`'s answers, and both throw
 * `InvalidConfigurationError` on a bad entry rather than dropping it. This gate
 * asks the one question those two cannot: whether the operator provisioned
 * anything at all, against a profile that requires them to.
 */

/**
 * Which halves of the status path an operator has provisioned.
 *
 * TWO booleans rather than one, because the refusal has to name what is missing
 * and the two failures are not the same mistake: no anchors means no Status List
 * Token can ever verify, no allowlist means no status list may ever be fetched.
 * An operator who set one and forgot the other needs to be told which.
 */
export interface CredentialStatusProvisioning {
  /** Whether any status-list trust anchor is configured. */
  readonly trustAnchors: boolean;
  /** Whether any status list URI prefix is permitted. */
  readonly uriAllowlist: boolean;
}

/**
 * Nothing provisioned — the default a caller that forgets to thread the real
 * answer through gets, so it fails closed rather than sails past.
 */
export const NO_CREDENTIAL_STATUS_PROVISIONING: CredentialStatusProvisioning = Object.freeze({
  trustAnchors: false,
  uriAllowlist: false,
});

/**
 * Refuse, at BOOT, a profile that mandates credential status this deployment
 * cannot establish (#297, #378).
 *
 * @param profile - the profile the deployment selected.
 * @param provisioned - what the operator actually configured. Defaults to
 * {@link NO_CREDENTIAL_STATUS_PROVISIONING}, exactly as
 * `assertKeyStorageAssuranceProvisioned` defaults its own parameter to `false`:
 * a caller that forgets to thread it through fails closed.
 * @throws Error naming precisely which half is missing, when the profile
 * requires a status mechanism and either half is absent.
 */
export function assertCredentialStatusProvisioned(
  profile: VerifierProfile,
  provisioned: CredentialStatusProvisioning = NO_CREDENTIAL_STATUS_PROVISIONING
): void {
  if (profile.requireCredentialStatus !== true) return;

  const missing: string[] = [];
  // `!== true`, not falsiness: this is a security gate and the caller may have
  // built the record from something looser than a parsed boolean.
  if (provisioned.trustAnchors !== true) {
    missing.push(
      'status list trust anchors (OID4VP_STATUS_LIST_TRUST_ANCHORS or OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH) — without them no Status List Token can ever verify'
    );
  }
  if (provisioned.uriAllowlist !== true) {
    missing.push(
      'a status list URI allowlist (OID4VP_STATUS_LIST_URI_ALLOWLIST) — without it no status list may ever be fetched, because the URI comes out of the credential and is an SSRF primitive until an operator has named where status lists live'
    );
  }

  if (missing.length === 0) return;

  throw new Error(
    `Verifier profile '${profile.id}' requires credential revocation checking for every presentation (Token Status List, HAIP §6.1, #297), and this deployment has not provisioned ${missing.join(' and ')}. Refusing to start rather than accepting wallet requests and then rejecting every presentation for a status nothing here can establish.`
  );
}
