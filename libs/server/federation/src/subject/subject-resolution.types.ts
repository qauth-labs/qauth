/**
 * `SubjectResolutionStrategy` — the CONTRACT (issue #300, ADR-009).
 *
 * ## The question this layer answers, and the one it refuses to answer
 *
 * A Verifiable Presentation has validated (#234) and its issuer is trusted
 * (#236). **Which `users` row is this?** Nothing upstream can say: ADR-009
 * Finding 1 establishes that there is no protocol-guaranteed stable wallet
 * subject identifier, and that this is deliberate rather than an oversight —
 * OID4VCI 1.0 §3.3.2 has batched credentials carry *different* cryptographic
 * data for unlinkability, §15.4.1 tells issuers to discard correlatable key
 * material, SD-JWT VC's `sub` is OPTIONAL and selectively disclosable, and the
 * EUDI PID's mandatory attribute set contains no identifier at all.
 *
 * So the answer cannot fall out of the credential. ADR-009 §1 decides what it
 * falls out of instead:
 *
 * > **The wallet does not need to be the account lookup key. It needs to be the
 * > proof.**
 *
 * The user asserts *which* account; the presentation proves *entitlement to it*.
 * That works in every ecosystem surveyed, because it depends on nothing the
 * ecosystem rotates away.
 *
 * ## What a strategy MUST NOT do
 *
 * - **Create accounts.** {@link SubjectResolutionStrategy.resolve} returns an
 *   outcome; the auth engine decides whether a `no-match` becomes a
 *   registration. Keeping the enrolment decision in one place is what stops two
 *   call sites from disagreeing about when a first presentation may mint a user.
 * - **Distinguish a failed lookup from a failed proof on the wire.** Resolution
 *   runs on attacker-influenced input, so "no such account" and "that credential
 *   does not entitle you to this account" must render identically. See
 *   {@link SubjectResolutionOutcome} and `assertSubjectResolved`.
 * - **Key on anything the credential asserts about its own issuer.** The issuer
 *   component of a composite key comes from the `ValidatedIssuer` that key
 *   resolution produced (#236), never from a raw `iss`. Otherwise an attacker
 *   mints a credential claiming any issuer and takes over the corresponding
 *   account — see `subject-binding.ts`, which re-checks the brand at run time.
 * - **Pick one of several candidates.** Ambiguity fails closed
 *   ({@link SubjectResolutionOutcome} `ambiguous`).
 *
 * ## Type-only, on purpose
 *
 * This module compiles to nothing. Consumers depending on the CONTRACT should
 * not thereby depend on a particular strategy's implementation, the same way
 * `credential-provider.interface.ts` (ADR-003) carries no runtime code.
 *
 * @see docs/adr/009-wallet-account-resolution.md
 */

import type { ValidatedCredential } from '../oid4vp/validated-credential';

/**
 * Every subject-resolution strategy ADR-009 names, including the ones that are
 * reserved rather than implemented.
 *
 * The unimplemented ids are part of the union DELIBERATELY. ADR-009 §3 puts it
 * directly: *"Recording it now is the point. When the gates clear, the correct
 * move is to add a strategy — not to rediscover the problem and invent a private
 * identifier."* An operator who configures one gets a specific, explanatory
 * refusal naming the gate (see `subject-resolution-strategies.ts`) instead of a
 * typo-shaped parse error.
 *
 * - `asserted-lookup` — the user supplies the identifier, the presentation
 *   proves entitlement to it. **The default** (ADR-009 §1), and the only
 *   strategy viable in every ecosystem surveyed.
 * - `issuer-scoped-claim` — keyed on `(validated issuer, claim)`. Opt-in per
 *   NAMED issuer that contractually guarantees a stable disclosed claim, always
 *   with a fallback to `asserted-lookup` when the holder withholds it
 *   (ADR-009 §2).
 * - `session-binding` — bind to the account the user is ALREADY authenticated
 *   as. Answers "link", not "log in" (ADR-009 §5); it is #238's flow and is not
 *   selectable as a deployment-wide login strategy.
 * - `key-thumbprint` — RFC 7638 thumbprint of the `cnf` key. **Actively
 *   discouraged** (ADR-009 §4) and unimplementable here by construction:
 *   `ValidatedCredential` carries no holder key material, because OID4VP 1.0
 *   §15.5–§15.6 treat it as a linkability defect wallets rotate away.
 * - `rp-pseudonym` — the EU's intended endpoint (a WebAuthn-style RP-scoped
 *   pseudonym). Gated on all three of ADR-009 §3's conditions, none cleared.
 */
export type SubjectResolutionStrategyId =
  'asserted-lookup' | 'issuer-scoped-claim' | 'session-binding' | 'key-thumbprint' | 'rp-pseudonym';

/**
 * One account a lookup turned up, with the wallet binding stored against it.
 *
 * Structural rather than a DB row: `server-federation` is `scope:server` and may
 * not import `infra-db` (the same layering that makes `TrustRankedAttribute` a
 * duplicate of `UpsertUserAttributeInput`). The adapter in the app layer maps
 * `user_credentials` onto this shape.
 */
export interface SubjectAccountCandidate {
  /** `users.id`. */
  readonly userId: string;
  /**
   * The wallet binding recorded for this account when its wallet credential was
   * enrolled — the value `subject-binding.ts` derived then, stored verbatim.
   *
   * `null` means **this account has no wallet binding**, which is ADR-009's
   * second bootstrap case and is a REFUSAL, not an invitation to create one:
   *
   * > An account already exists without a wallet binding (typically a password
   * > account on the same email) — the presentation MUST NOT silently create
   * > one. Allowing it would let any holder of any trusted credential claim an
   * > existing account by asserting its email.
   */
  readonly walletBinding: string | null;
}

/**
 * The account-store PORT resolution runs against.
 *
 * Two named lookups rather than one parameterised query, because the two are
 * keyed on different things and confusing them is a bypass: `byAssertedIdentifier`
 * is keyed on UNAUTHENTICATED user input, `byWalletSubject` on a value derived
 * from a validated issuer's signed claim.
 *
 * Implementations MUST:
 *
 * - be realm-scoped — never return an account from another realm;
 * - return **every** account the key resolves to, across every provider type.
 *   Returning only wallet-backed accounts would hide ADR-009's second bootstrap
 *   case and turn a takeover attempt into a `no-match` the caller might register
 *   over;
 * - report "nothing found" as an empty array, never `null` and never a throw.
 *
 * A throw is CONTAINED by the strategies (reported through
 * {@link SubjectResolutionContext.onLookupError}, then refused) rather than
 * trusted not to happen — the same containment `assertIssuerTrusted` applies to
 * a `TrustRegistry` backend, and for the same reason: an uncontained throw is a
 * 500 where every other outcome is a uniform refusal, which is an oracle.
 */
export interface SubjectAccountLookup {
  /**
   * Accounts in `realmId` that the asserted identifier resolves to.
   *
   * @param realmId - the realm the presentation request was created in.
   * @param identifier - the NORMALIZED asserted identifier.
   */
  byAssertedIdentifier(
    realmId: string,
    identifier: string
  ): Promise<readonly SubjectAccountCandidate[]>;
  /**
   * Accounts in `realmId` holding this wallet `external_sub`.
   *
   * @param realmId - the realm the presentation request was created in.
   * @param externalSub - a value produced by
   * {@link SubjectResolutionStrategy.deriveExternalSub}.
   */
  byWalletSubject(
    realmId: string,
    externalSub: string
  ): Promise<readonly SubjectAccountCandidate[]>;
}

/**
 * Everything resolution needs that does not come out of the credential.
 *
 * Mirrors `PresentationValidationContext` (#234) in shape and in discipline:
 * no member has a default that could silently disable a check.
 */
export interface SubjectResolutionContext {
  /** Realm the presentation request was created in. Scopes every lookup. */
  readonly realmId: string;
  /**
   * The identifier the user ASSERTED, as typed (ADR-009 §1). Normalized by the
   * strategy, not by the caller, so two call sites cannot disagree about what
   * "the same account" means.
   *
   * An INPUT to resolution, never its result: unauthenticated user input until
   * a validated presentation is shown to entitle its holder to that account.
   */
  readonly assertedIdentifier?: string;
  /**
   * `users.id` of the account the browser is ALREADY authenticated as, for
   * `session-binding` (ADR-009 §5). Read from a verified session — never from a
   * request parameter.
   */
  readonly authenticatedUserId?: string;
  /** The account store. See {@link SubjectAccountLookup}. */
  readonly lookup: SubjectAccountLookup;
  /**
   * Called when the {@link SubjectAccountLookup} THREW instead of answering.
   *
   * Wire it to the request logger. The refusal is deliberately silent on the
   * wire, so a store that is broken rather than merely unconvinced would
   * otherwise be invisible: the deployment would refuse every presentation and
   * log nothing about why. Defaults to `console.error`.
   */
  readonly onLookupError?: (error: unknown) => void;
}

/**
 * What resolution concluded.
 *
 * Four kinds, where issue #300's sketch had three. The fourth,
 * {@link SubjectResolutionOutcome} `rejected`, is not an embellishment — the
 * sketch's `no-match` carries the comment *"caller decides: register, or
 * reject"*, and there is a case that must NEVER become a registration:
 * ADR-009's second bootstrap case, an account that exists for the asserted
 * identifier but carries no wallet binding (or one that does not match). Folding
 * that into `no-match` would hand the caller a value it is explicitly allowed to
 * turn into an account, which is the takeover ADR-009 §1's security constraint
 * exists to prevent.
 *
 * ## All three failure kinds are ONE thing on the wire
 *
 * `no-match`, `ambiguous` and `rejected` differ only in what the AUTH ENGINE may
 * do next. A client must not be able to tell them apart — see
 * `assertSubjectResolved`, which collapses all three into the single
 * non-enumerating refusal #236 already established for this path.
 *
 * (Whether a caller's *registration policy* re-opens an oracle — "asserting an
 * unknown identifier signed me up, asserting a known one did not" — is a
 * property of that policy, not of this layer. It is the same oracle
 * self-service password registration has, and it is the auth engine's to close.)
 */
export type SubjectResolutionOutcome =
  | {
      readonly kind: 'matched';
      /** `users.id` this presentation resolved to. */
      readonly userId: string;
    }
  /** No account resolved. The caller decides: enrol, or refuse. */
  | { readonly kind: 'no-match' }
  /** More than one account resolved. ALWAYS a refusal — never pick one. */
  | { readonly kind: 'ambiguous' }
  /**
   * An account resolved and the presentation does not entitle its holder to it
   * — or resolution could not run at all. Never a registration.
   */
  | { readonly kind: 'rejected' };

/**
 * The strategy seam (issue #300).
 *
 * One object per configured strategy, built by
 * `createSubjectResolutionStrategy`. Swapping the configured strategy changes
 * resolution behaviour and touches no protocol code — the #300 acceptance
 * criterion, and the same property `VerifierProfile` (#299) gives protocol
 * posture.
 */
export interface SubjectResolutionStrategy {
  /** Which strategy this is. */
  readonly id: SubjectResolutionStrategyId;
  /**
   * The value to write into `user_credentials.external_sub` when the caller
   * turns a `no-match` into an enrolment, or `null` when this strategy produces
   * none.
   *
   * Takes the context as well as the credential — issue #300's sketch had
   * `deriveExternalSub(presentation)` alone, which cannot express the DEFAULT
   * strategy: under `asserted-lookup` the subject is the identifier the user
   * asserted, which by construction is not in the credential (that is the whole
   * point of ADR-009 §1).
   *
   * Pure and side-effect-free: it never consults the account store, so calling
   * it is not a lookup and cannot leak one.
   *
   * @param credential - the validated presentation.
   * @param context - the asserted identifier and the realm it belongs to.
   * @returns the `external_sub` value, or `null`.
   */
  deriveExternalSub(
    credential: ValidatedCredential,
    context: SubjectResolutionContext
  ): string | null;
  /**
   * Resolve the presentation to an account, or refuse.
   *
   * **Never throws for an input reason.** Every refusal is an
   * {@link SubjectResolutionOutcome}, including a lookup backend that failed, so
   * a caller cannot accidentally distinguish refusals by catching different
   * exception types.
   *
   * @param credential - the validated presentation (#234), from a trusted
   * issuer (#236). Both gates run BEFORE this.
   * @param context - see {@link SubjectResolutionContext}.
   */
  resolve(
    credential: ValidatedCredential,
    context: SubjectResolutionContext
  ): Promise<SubjectResolutionOutcome>;
}
