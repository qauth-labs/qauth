import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { createAssertedLookupStrategy } from './asserted-lookup.strategy';
import {
  constantTimeEquals,
  deriveIssuerScopedSubject,
  normalizeAssertedIdentifier,
} from './subject-binding';
import {
  AMBIGUOUS,
  matched,
  NO_MATCH,
  REJECTED,
  runAccountLookup,
  selectSoleAccount,
} from './subject-candidates';
import type {
  SubjectAccountCandidate,
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
 * ## The asserted identifier still names the account
 *
 * Wallet sign-in has no usernameless form (ADR-009 §1): the user says which
 * account they are signing in to, and the presentation proves entitlement to
 * it. The credential decides who the holder is; the asserted identifier
 * decides which account the browser asked for. So a subject match is accepted
 * only when the asserted identifier, normalized exactly as `asserted-lookup`
 * normalizes it (`normalizeAssertedIdentifier`) and looked up through the same
 * port (`byAssertedIdentifier`), names the SAME account. An identifier that
 * names another account, or none, is a refusal (`rejected`, as
 * `asserted-lookup` answers an account the presentation is not entitled to),
 * and so is a presentation with no usable identifier at all. Nothing here
 * reads a credential claim to find an account: the comparison is between the
 * account the user named and the account the credential resolved to.
 *
 * Both lookups run on every presentation that takes this path, whatever the
 * first one found, so "subject found, identifier differs" costs the same work
 * as "no such subject" and answers the same refusal on the wire.
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
 * The issuer-scoped subject for a presentation, or `undefined` when this
 * presentation does not qualify and must take the `asserted-lookup` path.
 *
 * Exported because account linking (#238) has to answer the SAME question
 * outside a strategy object: under `issuer-scoped-claim` a linked wallet
 * credential's `external_sub` is the issuer-scoped subject, and the
 * conflict check ADR-009 permits is enforceable only for the presentations
 * this function answers for. Two implementations of "does this credential
 * qualify?" would be two places for the opt-in list to be forgotten.
 *
 * @param credential - the validated presentation.
 * @param subjectClaim - the configured claim name, already normalized.
 * @param issuers - canonicalized issuer identifiers the deployment opted in.
 * @returns the subject, or `undefined` when the issuer is unvalidated, not
 * opted in, or the claim was withheld.
 */
export function deriveOptedInIssuerScopedSubject(
  credential: ValidatedCredential,
  subjectClaim: string,
  issuers: ReadonlySet<string>
): string | undefined {
  const issuer: unknown = credential?.issuer;
  if (!ValidatedIssuer.isValidated(issuer)) return undefined;
  if (!issuers.has(issuer.identifier)) return undefined;

  return deriveIssuerScopedSubject(credential, subjectClaim);
}

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

  const issuerScopedSubject = (credential: ValidatedCredential): string | undefined =>
    deriveOptedInIssuerScopedSubject(credential, subjectClaim, issuers);

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

      // The account the user said they are signing in to (ADR-009 §1). No
      // usable identifier: a refusal before any lookup, as `asserted-lookup`
      // refuses one, so the subject alone never names an account.
      const identifier = normalizeAssertedIdentifier(context?.assertedIdentifier);
      if (identifier === undefined) return REJECTED;

      // BOTH lookups, always, before either result is looked at: see the
      // module JSDoc for why the work must not depend on what the first found.
      const candidates = await runAccountLookup(context, () =>
        context.lookup.byWalletSubject(context.realmId, subject)
      );
      const named = await runAccountLookup(context, () =>
        context.lookup.byAssertedIdentifier(context.realmId, identifier)
      );
      if (candidates === undefined || named === undefined) return REJECTED;

      const selection = selectSoleAccount(candidates);
      if (selection.kind === 'invalid') return REJECTED;
      if (selection.kind === 'ambiguous') return AMBIGUOUS;
      // First presentation from this issuer-scoped subject: the caller decides
      // whether it becomes an enrolment. No account exists to be taken over, so
      // unlike `asserted-lookup` there is no second bootstrap case here.
      if (selection.kind === 'none') return NO_MATCH;

      // The credential resolved to an account; the asserted identifier must
      // name that same account, or the presentation is refused like any other
      // the holder is not entitled to here.
      return identifierNamesAccount(named, selection.userId) ? matched(selection.userId) : REJECTED;
    },
  });
}

/**
 * Whether the accounts an asserted identifier resolved to include `userId`.
 *
 * Membership, not "the sole account": the identifier must name the account the
 * credential resolved to, and another account that also holds a credential on
 * the same identifier does not make that untrue. Nothing is picked — `userId`
 * was already the sole account of the subject lookup. A structurally unusable
 * candidate is a refusal, as `selectSoleAccount` treats one. Every candidate
 * is compared, with no short-circuit, so the count of comparisons does not
 * depend on which candidate matched.
 *
 * @param named - what `byAssertedIdentifier` returned.
 * @param userId - the account the issuer-scoped subject resolved to.
 */
function identifierNamesAccount(
  named: readonly SubjectAccountCandidate[],
  userId: string
): boolean {
  let found = false;
  for (const candidate of named) {
    if (candidate === null || typeof candidate !== 'object') return false;
    if (typeof candidate.userId !== 'string' || candidate.userId.length === 0) return false;
    found = constantTimeEquals(candidate.userId, userId) || found;
  }
  return found;
}
