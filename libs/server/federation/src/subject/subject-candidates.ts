import type {
  SubjectAccountCandidate,
  SubjectResolutionContext,
  SubjectResolutionOutcome,
} from './subject-resolution.types';

/**
 * Candidate handling shared by every strategy (issue #300).
 *
 * Two rules live here rather than in each strategy, because each is a security
 * property and three near-copies of a security property is two too many:
 *
 * 1. **Ambiguity fails closed.** A lookup that resolves to more than one account
 *    is refused, never disambiguated. #300's constraint 5 is absolute — *"If a
 *    strategy resolves more than one candidate, reject. Never pick one."*
 * 2. **A lookup backend that throws is CONTAINED.** Same containment
 *    `assertIssuerTrusted` applies to a `TrustRegistry` backend, for the same
 *    reason: an uncontained throw becomes a 500 where every other outcome is a
 *    uniform refusal, and that difference is an oracle an attacker can drive by
 *    degrading the store.
 */

/** The single `no-match` value — the caller decides whether it becomes an enrolment. */
export const NO_MATCH: SubjectResolutionOutcome = Object.freeze({ kind: 'no-match' as const });

/** The single `ambiguous` value — always a refusal. */
export const AMBIGUOUS: SubjectResolutionOutcome = Object.freeze({ kind: 'ambiguous' as const });

/** The single `rejected` value — a refusal that must NEVER become an enrolment. */
export const REJECTED: SubjectResolutionOutcome = Object.freeze({ kind: 'rejected' as const });

/** Build a `matched` outcome. */
export function matched(userId: string): SubjectResolutionOutcome {
  return Object.freeze({ kind: 'matched' as const, userId });
}

/**
 * Where a lookup failure goes when the caller wired no reporter.
 *
 * `console.error` rather than nothing, matching `trust-registry.ts`: this lib
 * carries no logger dependency, and a no-op default would let the one failure
 * mode that is invisible on the wire be invisible server-side too.
 */
const DEFAULT_LOOKUP_ERROR_REPORTER = (error: unknown): void => {
  console.error('[subject-resolution] account lookup threw; refusing the presentation', error);
};

/** Report a lookup failure without ever letting the reporter become the fault. */
function reportLookupError(context: SubjectResolutionContext, error: unknown): void {
  try {
    (context.onLookupError ?? DEFAULT_LOOKUP_ERROR_REPORTER)(error);
  } catch {
    // A logger that throws must not convert a contained refusal into an
    // uncontained 500 — the thing that reports a failure may not become one.
  }
}

/**
 * Run an account lookup, containing every way it can fail.
 *
 * @param context - carries the failure reporter.
 * @param run - the lookup to perform.
 * @returns the candidates, or `undefined` when the lookup could not answer —
 * which every caller must treat as a refusal, never as "no account".
 */
export async function runAccountLookup(
  context: SubjectResolutionContext,
  run: () => Promise<readonly SubjectAccountCandidate[]>
): Promise<readonly SubjectAccountCandidate[] | undefined> {
  try {
    const candidates = await run();
    // `undefined`/`null` from a port that promised an array is a broken
    // implementation, not an empty result. Treating it as "no account found"
    // would turn a bug into an enrolment.
    return Array.isArray(candidates) ? candidates : undefined;
  } catch (error) {
    reportLookupError(context, error);
    return undefined;
  }
}

/** What a candidate list reduced to. */
export type CandidateSelection =
  | {
      readonly kind: 'sole';
      /** The one account the lookup resolved to. */
      readonly userId: string;
      /**
       * Every wallet binding recorded against it — one per enrolled wallet
       * credential. Empty when the account has none, which is ADR-009's second
       * bootstrap case and a refusal.
       */
      readonly bindings: readonly string[];
    }
  | { readonly kind: 'none' }
  | { readonly kind: 'ambiguous' }
  /** A candidate was structurally unusable; the caller must refuse. */
  | { readonly kind: 'invalid' };

/**
 * Reduce a candidate list to at most one account.
 *
 * Grouped by `userId` rather than counted: one account may legitimately hold
 * several wallet credentials (a second device, a re-issued credential, a second
 * credential type), and each carries its own binding. Those are one account, not
 * an ambiguity — so they are collapsed, and their bindings are all kept so a
 * presentation matching ANY enrolled credential authenticates.
 *
 * @param candidates - whatever the port returned.
 * @returns the reduction; see {@link CandidateSelection}.
 */
export function selectSoleAccount(
  candidates: readonly SubjectAccountCandidate[]
): CandidateSelection {
  const bindingsByUser = new Map<string, string[]>();

  for (const candidate of candidates) {
    if (candidate === null || typeof candidate !== 'object') return { kind: 'invalid' };

    const { userId, walletBinding } = candidate;
    if (typeof userId !== 'string' || userId.length === 0) return { kind: 'invalid' };

    // `null` is the documented "no wallet binding" value; anything else is a
    // port that did not honour the contract, and guessing what it meant is how
    // an unbound account becomes a matched one.
    if (walletBinding !== null && typeof walletBinding !== 'string') return { kind: 'invalid' };

    const bindings = bindingsByUser.get(userId) ?? [];
    if (typeof walletBinding === 'string' && walletBinding.length > 0) bindings.push(walletBinding);
    bindingsByUser.set(userId, bindings);
  }

  if (bindingsByUser.size === 0) return { kind: 'none' };
  if (bindingsByUser.size > 1) return { kind: 'ambiguous' };

  const [[userId, bindings]] = [...bindingsByUser.entries()];

  return { kind: 'sole', userId, bindings: Object.freeze(bindings) };
}
