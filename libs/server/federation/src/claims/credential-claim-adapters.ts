import { SD_JWT_VC_FORMAT } from '../oid4vp/credential-format';
import type { CredentialFormat } from '../profiles/verifier-profile.types';
import type {
  CredentialClaimAdapter,
  CredentialClaimAdapterRegistry,
} from './credential-claims.types';
import { sdJwtVcClaimAdapter } from './sd-jwt-vc-claims';

/**
 * The shipped {@link CredentialClaimAdapter} table and its fail-closed resolver
 * (issue #235).
 *
 * Structurally the twin of `oid4vp/credential-format.ts`'s
 * `CREDENTIAL_FORMAT_ADAPTERS` / `resolveCredentialFormatAdapter`, and
 * deliberately so: an operator reading either one should not have to learn two
 * registration models. What differs is only the phase — that table is the wire
 * lifetime of a format, this one is the identity mapping that runs after
 * validation. See `credential-claims.types.ts` for why the two are separate
 * seams rather than a fourth method on one interface.
 */

/**
 * Every claim adapter QAuth ships.
 *
 * `mso_mdoc` is ABSENT, and that is the seat issue #235 was asked to leave
 * rather than an omission. `haip-1.0` declares `mso_mdoc` as a permitted format,
 * so a deployment on that profile that somehow reached claim normalization with
 * an mdoc credential must be REFUSED here — never handed to the SD-JWT VC
 * adapter, whose claim vocabulary is not mdoc's (see `sd-jwt-vc-claims.ts`), and
 * never quietly served an empty attribute list, which is indistinguishable from
 * a credential that disclosed nothing.
 *
 * The real mdoc adapter therefore lands as ONE new module plus ONE line here.
 * `credential-claim-adapters.mdoc-registration.test.ts` proves that by
 * registering a hypothetical one and running the whole mapping path over it.
 *
 * Frozen, and never mutated.
 */
export const CREDENTIAL_CLAIM_ADAPTERS: CredentialClaimAdapterRegistry = Object.freeze({
  [SD_JWT_VC_FORMAT]: sdJwtVcClaimAdapter,
});

/**
 * Resolve the claim adapter for a Credential Format, fail-closed.
 *
 * Unlike `resolveCredentialFormatAdapter` there is no profile-permitted gate
 * here, and its absence is deliberate rather than an oversight: by the time a
 * credential reaches claim normalization the profile check has ALREADY run twice
 * — once when the DCQL query was built and once inside
 * `PresentationValidationContext.permittedFormats` — and a `ValidatedCredential`
 * cannot exist for a format the active profile forbids. Re-reading the profile
 * here would add a third source of truth for the same posture without adding a
 * gate, and would give this module an opinion about which profile is active.
 *
 * @param format - the validated credential's format.
 * @param adapters - the adapter table; defaults to everything QAuth ships.
 * Overridden ONLY by the test that proves the registration seam is real.
 * @throws Error when QAuth ships no claim adapter for the format.
 */
export function resolveCredentialClaimAdapter(
  format: CredentialFormat,
  adapters: CredentialClaimAdapterRegistry = CREDENTIAL_CLAIM_ADAPTERS
): CredentialClaimAdapter {
  const adapter = adapters[format];

  if (adapter === undefined) {
    throw new Error(
      `No credential claim adapter is implemented for '${format}'. QAuth normalizes '${SD_JWT_VC_FORMAT}' only; 'mso_mdoc' claims arrive as namespaced data elements under a different vocabulary (ADR-009 Finding 1: the PID's mdoc encoding uses 'birth_date' where its SD-JWT VC encoding uses 'birthdate'), so it needs its own adapter behind this same boundary (epic #231) rather than a branch in the SD-JWT VC path.`
    );
  }

  return adapter;
}
