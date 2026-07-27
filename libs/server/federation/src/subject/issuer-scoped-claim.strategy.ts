import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { createAssertedLookupStrategy } from './asserted-lookup.strategy';
import { deriveIssuerScopedSubject } from './subject-binding';
import {
  AMBIGUOUS,
  matched,
  NO_MATCH,
  REJECTED,
  runAccountLookup,
  selectSoleAccount,
} from './subject-candidates';
import type {
  SubjectResolutionContext,
  SubjectResolutionOutcome,
  SubjectResolutionStrategy,
} from './subject-resolution.types';
import {
  type IssuerScopedClaimConfig,
  normalizeClaimName,
  normalizeIssuerScopedIssuers,
} from './subject-resolution-config';

/**
 * `issuer-scoped-claim` — opt-in, per NAMED issuer (ADR-009 §2).
 *
 * ## Why the key is `(validated issuer, claim)` and never the claim alone
 *
 * The identifier ecosystems do offer is provider-scoped, not person-scoped. CIR
 * (EU) 2024/2977 defines `personal_administrative_number` as *"unique among all
 * personal administrative numbers issued by the provider of person
 * identification data"* — so two Member States may issue the same value to two
 * different humans. The issuer is therefore part of the identifier, and
 * `subject-binding.ts` composes it in.
 *
 * That issuer comes from the `ValidatedIssuer` #234 produced from key
 * resolution, never from a credential-asserted `iss`. #300's constraint 1 states
 * the consequence of getting it wrong: *"an attacker mints a credential claiming
 * any issuer and takes over the corresponding account"*. The nominal type makes
 * that unrepresentable at compile time, and both this module and
 * `subject-binding.ts` re-check the brand at run time, because casts exist.
 *
 * ## Why there is no separate entitlement check here
 *
 * Under `asserted-lookup` the lookup key is unauthenticated user input, so a
 * second, credential-derived value has to prove entitlement. Here the lookup key
 * IS credential-derived: a digest over a validated issuer identity and a claim
 * that issuer signed. Nothing an attacker controls contributes to it, so
 * possession of the key is the proof. Adding a second check over the same
 * material would be ceremony, and ceremony that looks like a security control is
 * worse than none.
 *
 * ## The fallback is mandatory, not a convenience
 *
 * ADR-009 §2 requires *"always with fallback to `asserted-lookup` when the claim
 * is withheld, since the holder may refuse it"* — the EUDI PID Rulebook is
 * explicit that a user may decline even a MANDATORY attribute, so a strategy
 * with no fallback would refuse conformant wallets. Two conditions take the
 * fallback path:
 *
 * - the credential's validated issuer is not one this deployment opted in for;
 * - the subject claim was withheld, or is not a usable primitive.
 *
 * Both are ordinary outcomes, not refusals. A refusal is reserved for a
 * presentation whose issuer identity did not validate at all.
 */

/**
 * Build the `issuer-scoped-claim` strategy.
 *
 * @param config - the subject claim, the opted-in issuers, and the mandatory
 * `asserted-lookup` fallback; all validated eagerly.
 * @returns a stateless, frozen strategy safe to construct once at bootstrap.
 * @throws InvalidConfigurationError when any part of the configuration is
 * unusable.
 */
export function createIssuerScopedClaimStrategy(
  config: IssuerScopedClaimConfig
): SubjectResolutionStrategy {
  const subjectClaim = normalizeClaimName(config?.subjectClaim, 'subjectClaim');
  const issuers = new Set(normalizeIssuerScopedIssuers(config?.issuers));
  // Built here rather than injected so the fallback cannot be omitted, replaced
  // with a permissive stub, or silently left unconfigured.
  const fallback = createAssertedLookupStrategy(config?.fallback ?? { bindingClaims: [] });

  /**
   * The issuer-scoped subject, or `undefined` when this presentation does not
   * qualify for the strategy and must take the fallback path.
   */
  function issuerScopedSubject(credential: ValidatedCredential): string | undefined {
    const issuer: unknown = credential?.issuer;
    if (!ValidatedIssuer.isValidated(issuer)) return undefined;
    if (!issuers.has(issuer.identifier)) return undefined;

    return deriveIssuerScopedSubject(credential, subjectClaim);
  }

  return Object.freeze({
    id: 'issuer-scoped-claim' as const,

    deriveExternalSub(credential: ValidatedCredential, context: SubjectResolutionContext) {
      return issuerScopedSubject(credential) ?? fallback.deriveExternalSub(credential, context);
    },

    async resolve(
      credential: ValidatedCredential,
      context: SubjectResolutionContext
    ): Promise<SubjectResolutionOutcome> {
      const subject = issuerScopedSubject(credential);
      if (subject === undefined) return fallback.resolve(credential, context);

      const candidates = await runAccountLookup(context, () =>
        context.lookup.byWalletSubject(context.realmId, subject)
      );
      if (candidates === undefined) return REJECTED;

      const selection = selectSoleAccount(candidates);
      if (selection.kind === 'invalid') return REJECTED;
      if (selection.kind === 'ambiguous') return AMBIGUOUS;
      // First presentation from this issuer-scoped subject: the caller decides
      // whether it becomes an enrolment. No account exists to be taken over, so
      // unlike `asserted-lookup` there is no second bootstrap case here.
      if (selection.kind === 'none') return NO_MATCH;

      return matched(selection.userId);
    },
  });
}
