import type { ValidatedCredential } from '../oid4vp/validated-credential';
import {
  constantTimeEquals,
  deriveWalletBinding,
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
  SubjectResolutionContext,
  SubjectResolutionOutcome,
  SubjectResolutionStrategy,
} from './subject-resolution.types';
import { type AssertedLookupConfig, normalizeBindingClaims } from './subject-resolution-config';

/**
 * `asserted-lookup` — the DEFAULT subject-resolution strategy (ADR-009 §1).
 *
 * ## The shape
 *
 * The user asserts *which* account (an email, a username); the presentation
 * proves *entitlement to it*. Same trade passkeys make between usernameless and
 * username-first flows, and the reason it is the default is that it depends on
 * nothing the ecosystem rotates away: it survives credential re-issuance, key
 * rotation, device change and a holder declining an attribute, because none of
 * those is its lookup key.
 *
 * ## Two lookups' worth of care in one function
 *
 * 1. **Find the account** from the asserted identifier. Unauthenticated input,
 *    so the result is a CANDIDATE, never an answer.
 * 2. **Prove entitlement** by re-deriving the wallet binding from the presented
 *    credential and comparing it, in constant time, with the binding stored when
 *    that account enrolled a wallet credential.
 *
 * Step 2 is the one this whole issue exists for. ADR-009 §1 restates it *"because
 * it is the likeliest way this gets built wrong"*:
 *
 * > Verifying that a presentation is well-formed and issuer-trusted proves only
 * > that the holder has *a* valid credential. … Omitting that check means anyone
 * > holding any valid credential can log in as anyone.
 *
 * `asserted-lookup.strategy.test.ts` proves it as an attack: a real credential
 * from a trusted issuer, validated end to end, asserting someone else's account.
 *
 * ## Bootstrap — the two cases ADR-009 keeps apart
 *
 * At first presentation there is no stored binding to compare, so the rule needs
 * a starting point, and the two cases must not be conflated:
 *
 * - **No account exists for the asserted identifier** → `no-match`. The caller
 *   may establish the account and the binding together.
 * - **An account exists but carries no wallet binding** (typically a password
 *   account on the same email) → `rejected`, NOT `no-match`. Returning
 *   `no-match` here would hand the caller a value it is explicitly allowed to
 *   turn into an enrolment, letting any holder of any trusted credential claim
 *   an existing account by asserting its email. That path is account linking
 *   (#238) and needs an authenticated session — `session-binding`, ADR-009 §5.
 */

/**
 * Build the `asserted-lookup` strategy.
 *
 * @param config - the binding claim set; validated eagerly, see
 * {@link normalizeBindingClaims}.
 * @returns a stateless, frozen strategy safe to construct once at bootstrap.
 * @throws InvalidConfigurationError when the binding claims are unusable.
 */
export function createAssertedLookupStrategy(
  config: AssertedLookupConfig
): SubjectResolutionStrategy {
  const bindingClaims = normalizeBindingClaims(config?.bindingClaims);

  return Object.freeze({
    id: 'asserted-lookup' as const,

    /**
     * The normalized asserted identifier — ADR-009 §1: `external_sub` for a
     * wallet credential holds *"the asserted, normalized identifier — the same
     * column `PasswordProvider` fills"*, which is why wallet federation needs no
     * schema migration under the realm scoping that ships today.
     */
    deriveExternalSub(_credential: ValidatedCredential, context: SubjectResolutionContext) {
      return normalizeAssertedIdentifier(context?.assertedIdentifier) ?? null;
    },

    async resolve(
      credential: ValidatedCredential,
      context: SubjectResolutionContext
    ): Promise<SubjectResolutionOutcome> {
      const identifier = normalizeAssertedIdentifier(context?.assertedIdentifier);
      // No identifier asserted: this strategy has no lookup key at all. A
      // refusal rather than `no-match`, because "the user told us nothing" must
      // not be a route to creating an account.
      if (identifier === undefined) return REJECTED;

      // Derived BEFORE the lookup, and a failure to derive refuses without
      // touching the store — a holder who withheld a binding claim cannot use
      // the request to probe which identifiers exist.
      const presented = deriveWalletBinding(credential, bindingClaims);
      if (presented === undefined) return REJECTED;

      const candidates = await runAccountLookup(context, () =>
        context.lookup.byAssertedIdentifier(context.realmId, identifier)
      );
      if (candidates === undefined) return REJECTED;

      const selection = selectSoleAccount(candidates);
      if (selection.kind === 'invalid') return REJECTED;
      if (selection.kind === 'ambiguous') return AMBIGUOUS;
      if (selection.kind === 'none') return NO_MATCH;

      // ADR-009's second bootstrap case: an account with no wallet binding is a
      // refusal, never an enrolment (see the module JSDoc).
      if (selection.bindings.length === 0) return REJECTED;

      // Every enrolled binding is compared — an account may hold more than one
      // wallet credential. `reduce` rather than `some`, so the comparison count
      // does not depend on WHICH binding matched: a short-circuit here would
      // make the position of the matching credential timeable.
      const entitled = selection.bindings.reduce(
        (found, stored) => constantTimeEquals(stored, presented) || found,
        false
      );

      return entitled ? matched(selection.userId) : REJECTED;
    },
  });
}
