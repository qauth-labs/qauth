import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { matched, REJECTED } from './subject-candidates';
import type {
  SubjectResolutionContext,
  SubjectResolutionOutcome,
  SubjectResolutionStrategy,
} from './subject-resolution.types';

/**
 * `session-binding` — attach a presentation to the account the user is ALREADY
 * authenticated as (ADR-009 §5).
 *
 * ## It answers a different question
 *
 * Not *"which account is this?"* but *"may this credential be attached to the
 * account already in this session?"*. It is therefore **not an alternative to
 * `asserted-lookup`**, and ADR-009 §5 keeps it in the strategy list for one
 * reason: it is the only correct path for attaching a wallet credential to a
 * PRE-EXISTING account, which is #238's flow and the resolution of ADR-009 §1's
 * second bootstrap case.
 *
 * That is also why it is not selectable as a deployment-wide login strategy —
 * see `subject-resolution-strategies.ts`. A deployment that configured it as its
 * login strategy would have a login flow that authenticates only users who are
 * already authenticated.
 *
 * ## It performs no lookup, and that is the point
 *
 * There is nothing to look up: the account is given. So there is no candidate
 * set, no ambiguity, no enumeration surface, and no `no-match` — the session
 * either carries a user or it does not.
 *
 * The presentation is not ignored, but what makes it safe here is not this
 * module: #234 validated it, #236 established that its issuer is trusted, and
 * the SESSION establishes who the user is. Adding a credential-derived check on
 * top would be checking the credential against nothing.
 *
 * ## `deriveExternalSub` returns `null`, deliberately
 *
 * This strategy derives no subject. `user_credentials.external_sub` for a linked
 * wallet credential is the account's own identifier, which the linking flow
 * reads from the authenticated session — not something this strategy can produce
 * from a credential ADR-009 establishes carries no stable subject. Issue #300's
 * sketch has the `| null` branch for exactly this case; #238 owns the column
 * value.
 */

/**
 * Build the `session-binding` strategy.
 *
 * Takes no configuration: there is nothing to configure. Exported as a factory
 * anyway, so it is constructed and held the same way as every other strategy and
 * a caller cannot accidentally share mutable state with one.
 *
 * @returns a stateless, frozen strategy.
 */
export function createSessionBindingStrategy(): SubjectResolutionStrategy {
  return Object.freeze({
    id: 'session-binding' as const,

    deriveExternalSub(): string | null {
      return null;
    },

    async resolve(
      _credential: ValidatedCredential,
      context: SubjectResolutionContext
    ): Promise<SubjectResolutionOutcome> {
      const userId = context?.authenticatedUserId;

      // No session, no link. A refusal rather than `no-match`: `no-match` is the
      // value a caller may turn into an enrolment, and an unauthenticated caller
      // presenting a credential must never be a route to creating or claiming an
      // account — that is the whole reason linking is session-bound.
      if (typeof userId !== 'string' || userId.length === 0) return REJECTED;

      return matched(userId);
    },
  });
}
