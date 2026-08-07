import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { deriveWalletBinding } from './subject-binding';
import type { SubjectResolutionConfig } from './subject-resolution-strategies';

/**
 * The ENROLMENT half of the `asserted-lookup` proof (issues #300 + #235,
 * ADR-009 §1).
 *
 * ## Why this exists as its own function
 *
 * `asserted-lookup` compares a binding re-derived from the presented credential
 * against the binding STORED for the asserted account. #300 shipped the
 * comparison; nothing shipped the write, because #300 has no enrolment path —
 * `SubjectResolutionStrategy.resolve` returns `no-match` and stops, deliberately
 * (*"strategies never create accounts"*).
 *
 * #235 is the first caller that enrols, so it needs the value to store. It must
 * be derived from the SAME claim set the later comparison will use, or every
 * enrolled user is locked out on their second login — a failure that would
 * surface days later, on a path with a deliberately uninformative error.
 *
 * That claim set lives in the strategy's CONFIGURATION, in a different place per
 * strategy, so this function reads it and the caller does not. The alternative —
 * an app-layer `config.strategy === 'asserted-lookup' ? config.bindingClaims :
 * config.fallback.bindingClaims` — would put the union's internals in
 * `apps/auth-server`, where a strategy added later cannot be seen to have
 * broken it.
 *
 * ## Why `issuer-scoped-claim` deployments store one too
 *
 * ADR-009 §2 makes the `asserted-lookup` fallback structural rather than
 * optional, because the holder may withhold the subject claim on ANY later
 * presentation. If enrolment under `issuer-scoped-claim` recorded no binding,
 * that fallback would meet an account with none — which `asserted-lookup`
 * correctly treats as ADR-009's second bootstrap case and REFUSES. So the
 * binding is written from the fallback's claim set, and the fallback works from
 * the first presentation rather than from the second.
 *
 * @see docs/adr/009-wallet-account-resolution.md
 */

/**
 * Derive the wallet binding to record against a newly enrolled credential.
 *
 * @param config - the resolved strategy configuration
 * (`resolveSubjectResolution`), which owns the binding claim set.
 * @param credential - the validated presentation being enrolled.
 * @returns the binding, or `null` when it cannot be derived — the holder
 * withheld one of the configured claims, or the credential carries no validated
 * issuer. `null` is NOT an error here; the caller decides, and #235's enrolment
 * path refuses rather than storing an account nothing can later prove
 * entitlement to.
 */
export function deriveEnrolmentWalletBinding(
  config: SubjectResolutionConfig,
  credential: ValidatedCredential
): string | null {
  const bindingClaims =
    config?.strategy === 'issuer-scoped-claim'
      ? config.fallback?.bindingClaims
      : config?.bindingClaims;

  if (!Array.isArray(bindingClaims) || bindingClaims.length === 0) return null;

  return deriveWalletBinding(credential, bindingClaims) ?? null;
}
