import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { issuerTrustRejection } from '../trust/issuer-trust-rejection';
import { createAssertedLookupStrategy } from './asserted-lookup.strategy';
import { createIssuerScopedClaimStrategy } from './issuer-scoped-claim.strategy';
import type {
  SubjectResolutionOutcome,
  SubjectResolutionStrategy,
  SubjectResolutionStrategyId,
} from './subject-resolution.types';
import type { AssertedLookupConfig, IssuerScopedClaimConfig } from './subject-resolution-config';

/**
 * The shipped {@link SubjectResolutionStrategy} table and its factory
 * (issue #300, ADR-009).
 *
 * Structurally this mirrors `VERIFIER_PROFILES` (#299) and `ENVIRONMENT_PROFILES`
 * (ADR-008): a frozen lookup keyed by an id, consumed through a single resolver.
 * Same reasoning — which strategies exist, and which a deployment may select,
 * should be readable in one table rather than reconstructed from conditionals.
 *
 * **The reserved ids are in the table on purpose.** ADR-009 §3: *"Recording it
 * now is the point. When the gates clear, the correct move is to add a strategy
 * — not to rediscover the problem and invent a private identifier."* An operator
 * who selects one gets the gate explained to them; a future implementer who
 * comes looking for `rp-pseudonym` finds a seat rather than a blank page.
 */

/**
 * What a deployment may do with a strategy.
 *
 * - `login` — selectable as the deployment's subject-resolution strategy.
 * - `linking` — real and implemented, but it answers "link", not "log in". The
 *   linking flow (#238) constructs it directly; it is not a deployment-wide
 *   choice.
 * - `gated` — named by ADR-009, deliberately unimplemented, blocked on stated
 *   conditions.
 */
export type SubjectResolutionStrategyUsage = 'login' | 'linking' | 'gated';

/** One row of {@link SUBJECT_RESOLUTION_STRATEGIES}. */
export interface SubjectResolutionStrategyDescriptor {
  readonly id: SubjectResolutionStrategyId;
  readonly usage: SubjectResolutionStrategyUsage;
  /**
   * Why a deployment may not select this as its login strategy — `undefined`
   * exactly when {@link usage} is `login`.
   *
   * Carried as DATA so the refusal message is a property of the strategy rather
   * than of whichever guard happened to reject it, and so adding a strategy
   * cannot ship a refusal that says nothing.
   */
  readonly refusal?: string;
}

/**
 * Every strategy ADR-009 names, with what a deployment may do with it.
 *
 * @see docs/adr/009-wallet-account-resolution.md
 */
export const SUBJECT_RESOLUTION_STRATEGIES = Object.freeze({
  /**
   * ADR-009 §1. The default: the only strategy viable in every ecosystem
   * surveyed, because it depends on nothing the ecosystem rotates away.
   */
  'asserted-lookup': Object.freeze({
    id: 'asserted-lookup',
    usage: 'login',
  }),

  /**
   * ADR-009 §2. Permitted where a specific, named issuer contractually
   * guarantees a stable, disclosed claim — a workforce credential with an
   * employee number, a national scheme that has published a value policy under
   * CIR (EU) 2024/2977 Table 2. Demoted from a plausible default to opt-in
   * because no such Member State policy was found, only the enabling clause.
   */
  'issuer-scoped-claim': Object.freeze({
    id: 'issuer-scoped-claim',
    usage: 'login',
  }),

  /**
   * ADR-009 §5. Real, implemented, and NOT a login strategy — see
   * `session-binding.strategy.ts`.
   */
  'session-binding': Object.freeze({
    id: 'session-binding',
    usage: 'linking',
    refusal:
      "'session-binding' answers 'may this credential be attached to the account already in this session?', not 'which account is this?' (ADR-009 §5). It is the account-linking path (#238) and is constructed by that flow with an authenticated session; selecting it as a deployment-wide login strategy would produce a login that only authenticates users who are already authenticated.",
  }),

  /**
   * ADR-009 §4 — **actively discouraged**, not merely fragile.
   *
   * The PID Rulebook's technical validity period *"typically is short, a few
   * days or weeks at most, if not shorter"*, so an RFC 7638 thumbprint of the
   * `cnf` key is wrong even in ecosystems that do not batch-issue. It is also
   * unimplementable in this library by construction: `ValidatedCredential`
   * carries no holder key material at all, because OID4VP 1.0 §15.5–§15.6 treat
   * it as a linkability defect and #234 strips `cnf` from the claim set rather
   * than merely leaving it unused.
   */
  'key-thumbprint': Object.freeze({
    id: 'key-thumbprint',
    usage: 'gated',
    refusal:
      "'key-thumbprint' is actively discouraged by ADR-009 §4 and is not implemented. Wallet key material rotates by design — OID4VCI 1.0 §3.3.2 has batched credentials carry different cryptographic data for unlinkability, and PID technical validity is days to weeks — so a thumbprint of the `cnf` key identifies a credential, not a person. `ValidatedCredential` deliberately carries no holder key material for exactly this reason (OID4VP 1.0 §15.5–§15.6), so nothing in this library can derive one.",
  }),

  /**
   * ADR-009 §3 — the EU's intended endpoint, reserved and gated.
   *
   * eIDAS Art. 5a(4)(b) and CIR (EU) 2024/2979 Art. 14(2) require wallets to
   * produce a relying-party-specific pseudonym. Three gates, none cleared: QAuth
   * has no WebAuthn workstream; no technical specification for pseudonym
   * generation exists (the ARF's PA_21 is still a forward obligation, and CIR
   * (EU) 2026/1731 deleted the one that named WebAuthn without replacing it);
   * and wallet-side support is a MAY, not a SHALL.
   *
   * ADR-009 §3 also says how the second gate must be read: *"Treat 'the gate
   * cleared' as requiring a published specification, not merely the
   * disappearance of the requirement to write one."*
   */
  'rp-pseudonym': Object.freeze({
    id: 'rp-pseudonym',
    usage: 'gated',
    refusal:
      "'rp-pseudonym' is reserved, not implemented (ADR-009 §3). It is gated on all three of: a WebAuthn workstream in QAuth (not started), a published technical specification for relying-party-specific pseudonym generation (none exists — the obligation to write one is still forward-looking, and the act that named WebAuthn was deleted without a replacement), and wallet-side support surviving as more than a MAY. A gate counts as cleared only when a specification is PUBLISHED, never when the requirement to write one disappears.",
  }),
} satisfies Record<SubjectResolutionStrategyId, SubjectResolutionStrategyDescriptor>);

/**
 * Every strategy id, for exhaustive iteration in tests and config validation.
 *
 * Derived from {@link SUBJECT_RESOLUTION_STRATEGIES} rather than written out
 * again, so a strategy cannot be added to the table and forgotten here.
 */
export const SUBJECT_RESOLUTION_STRATEGY_IDS = Object.freeze(
  Object.keys(SUBJECT_RESOLUTION_STRATEGIES) as SubjectResolutionStrategyId[]
);

/**
 * Narrow an untrusted string to a {@link SubjectResolutionStrategyId}.
 *
 * **Fail-CLOSED.** An unrecognised value yields `undefined` and the caller
 * refuses wallet flows; it never falls back to the default. A realm row meant to
 * run `issuer-scoped-claim` with a typo'd value must not silently run
 * `asserted-lookup` against a binding claim set chosen for a different
 * ecosystem. Same posture as `parseVerifierProfileId` (#299), for the same
 * reason.
 *
 * Recognising a RESERVED id is not accepting it — see
 * {@link assertSubjectResolutionStrategySelectable}, which is what refuses it.
 * Separating the two is what turns "you configured something we do not ship"
 * into an explanation of the gate.
 *
 * @param value - raw config/DB value; `null`/`undefined`/unknown all yield
 * `undefined`.
 */
export function parseSubjectResolutionStrategyId(
  value: string | null | undefined
): SubjectResolutionStrategyId | undefined {
  if (value === null || value === undefined) return undefined;
  return (SUBJECT_RESOLUTION_STRATEGY_IDS as readonly string[]).includes(value)
    ? (value as SubjectResolutionStrategyId)
    : undefined;
}

/**
 * Refuse a strategy a deployment may not select as its login strategy.
 *
 * Throws rather than returning a boolean so a caller cannot proceed by ignoring
 * the result — a gated strategy must make the deployment unstartable, not merely
 * be discouraged in a doc comment.
 *
 * @param id - a recognised strategy id.
 * @throws InvalidConfigurationError carrying the descriptor's explanation when
 * the strategy is `linking` or `gated`.
 */
export function assertSubjectResolutionStrategySelectable(id: SubjectResolutionStrategyId): void {
  const descriptor = SUBJECT_RESOLUTION_STRATEGIES[id];
  if (descriptor.usage === 'login') return;

  throw new InvalidConfigurationError(descriptor.refusal ?? '', { strategy: id });
}

/**
 * Fully-specified strategy configuration — a discriminated union, so a
 * strategy's settings cannot be supplied to a different strategy.
 *
 * Only the `login` strategies appear. `session-binding` takes no configuration
 * and is constructed directly by the flow that owns it, through
 * `createSessionBindingStrategy`; the gated ids have nothing to configure at
 * all.
 */
export type SubjectResolutionConfig =
  | ({ readonly strategy: 'asserted-lookup' } & AssertedLookupConfig)
  | ({ readonly strategy: 'issuer-scoped-claim' } & IssuerScopedClaimConfig);

/**
 * Build the configured strategy.
 *
 * The one construction point, so *"switching the configured strategy changes
 * resolution behaviour without touching protocol code"* (#300 acceptance
 * criterion) is a property of the code rather than an aspiration: protocol code
 * holds a {@link SubjectResolutionStrategy} and never names one.
 *
 * @param config - the discriminated configuration.
 * @returns the strategy, ready to resolve.
 * @throws InvalidConfigurationError when the configuration is unusable, or when
 * `strategy` is not one this factory builds.
 */
export function createSubjectResolutionStrategy(
  config: SubjectResolutionConfig
): SubjectResolutionStrategy {
  switch (config?.strategy) {
    case 'asserted-lookup':
      return createAssertedLookupStrategy(config);
    case 'issuer-scoped-claim':
      return createIssuerScopedClaimStrategy(config);
    default:
      throw new InvalidConfigurationError(
        'Unknown subject-resolution strategy configuration (#300). Only the login strategies are built here; `session-binding` is constructed by the account-linking flow (#238) and the reserved strategies are not implemented.',
        { strategy: String((config as { strategy?: unknown } | undefined)?.strategy) }
      );
  }
}

/**
 * Collapse a resolution outcome into a `users.id` or the single, uniform
 * refusal.
 *
 * The helper that makes #300's constraint 4 — *"A failed lookup must be
 * indistinguishable from a failed proof — one generic error"* — the DEFAULT
 * rather than something each call site has to remember. `no-match`, `ambiguous`
 * and `rejected` all raise the identical `InvalidCredentialsError` #236
 * established for this path, so an attacker probing identifiers learns nothing
 * from the difference between responses.
 *
 * Callers that implement enrolment must branch on `no-match` BEFORE reaching
 * here (ADR-009 §1's first bootstrap case). This function is for the
 * login-only path, where every non-match is a refusal.
 *
 * @param outcome - what the strategy concluded.
 * @returns the resolved `users.id`.
 * @throws InvalidCredentialsError for every other outcome, always the same one.
 */
export function assertSubjectResolved(outcome: SubjectResolutionOutcome): string {
  if (outcome?.kind !== 'matched') throw issuerTrustRejection();
  if (typeof outcome.userId !== 'string' || outcome.userId.length === 0) {
    throw issuerTrustRejection();
  }

  return outcome.userId;
}
