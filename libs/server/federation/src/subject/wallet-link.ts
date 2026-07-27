import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { buildWalletCredentialData, type WalletCredentialData } from '../providers/wallet.provider';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { deriveOptedInIssuerScopedSubject } from './issuer-scoped-claim.strategy';
import { createSessionBindingStrategy } from './session-binding.strategy';
import { deriveWalletBinding, normalizeAssertedIdentifier } from './subject-binding';
import { runAccountLookup } from './subject-candidates';
import type { SubjectAccountLookup, SubjectResolutionStrategyId } from './subject-resolution.types';
import {
  normalizeBindingClaims,
  normalizeClaimName,
  normalizeIssuerScopedIssuers,
} from './subject-resolution-config';
import type { SubjectResolutionConfig } from './subject-resolution-strategies';

/**
 * Account linking — attaching a wallet credential to an ALREADY-AUTHENTICATED
 * account (issue #238, ADR-004 "Account Linking", ADR-009 §5).
 *
 * ## It is a different question, answered by a different strategy
 *
 * Login asks *"which account is this?"*. Linking asks *"may this credential be
 * attached to the account already in this session?"*. ADR-009 §5 keeps
 * `session-binding` in the strategy list for exactly this flow, and calls it
 * *"the only correct path for attaching a wallet credential to a pre-existing
 * account"* — because ADR-009 §1's second bootstrap case forbids the other one:
 *
 * > An account already exists without a wallet binding (typically a password
 * > account on the same email) — the presentation MUST NOT silently create one.
 * > Allowing it would let any holder of any trusted credential claim an existing
 * > account by asserting its email.
 *
 * So `asserted-lookup` refuses that account, and this module is how the account's
 * owner — proven by their existing session, not by the presentation — opts in.
 *
 * ## What this module produces, and what it refuses to do
 *
 * It produces a WRITE PLAN: the `external_sub` and the `credential_data` of the
 * `user_credentials` row a caller should insert. It writes nothing itself and it
 * touches no database — `server-federation` is `scope:server` and may not import
 * `infra-db`, which is the same layering that keeps the account store behind the
 * {@link SubjectAccountLookup} port.
 *
 * ## Two things it insists on, both fail-closed
 *
 * 1. **A derivable binding.** Linking a credential whose binding cannot be
 *    derived — the holder withheld a configured binding claim — would write a
 *    row that proves nothing on the next login. ADR-009 §1's entitlement check
 *    has to have something to check, so a credential that cannot supply one is
 *    refused at link time rather than silently accepted and useless later.
 * 2. **The session, re-asked through the strategy.** The authenticated user id
 *    is not simply copied into the plan: it goes through
 *    `createSessionBindingStrategy()`, whose refusal of an absent session is the
 *    property #238 depends on. Reading `context.authenticatedUserId` directly
 *    here would make the strategy decorative, and a decorative security control
 *    is the one that gets deleted in a refactor.
 *
 * ## The conflict check is STRATEGY-SCOPED, and this is the load-bearing part
 *
 * #238's original acceptance criterion — *"reject linking a wallet already bound
 * to a different `users.id`"* — assumed a stable, unique per-wallet identifier.
 * ADR-009's Negative consequences record that it lost that premise:
 *
 * > **#238's third acceptance criterion loses its premise.** Rejecting a link
 * > when the wallet is "already linked to a different user" assumed a stable,
 * > unique `external_sub` per wallet; there is no such value.
 *
 * So the check runs **only** under `issuer-scoped-claim`, keyed on
 * `(validated issuer, disclosed claim)` — the one configuration that yields such
 * a value. Under `asserted-lookup` there is nothing to key on and the check is
 * NOT performed, NOT approximated, and NOT asserted anywhere. A check that
 * *looks* like duplicate detection but keys on the asserted account identifier
 * would tell an operator their wallets are unique when they are not.
 *
 * (The shipped `uniqueIndex(realm_id, provider_type, external_sub)` still
 * prevents two rows sharing an `external_sub` under either strategy. That is a
 * KEY COLLISION, not wallet duplicate detection, and the caller must not present
 * it as one — see {@link WalletLinkOutcome} `conflict`.)
 *
 * @see docs/adr/009-wallet-account-resolution.md
 * @see docs/adr/004-wallet-agnostic-federation.md
 */

/** Everything linking needs that does not come out of the credential. */
export interface WalletLinkContext {
  /** Realm the presentation request was created in. Scopes every lookup. */
  readonly realmId: string;
  /**
   * `users.id` the browser is ALREADY authenticated as.
   *
   * Read from a VERIFIED session — never from a request parameter, a form field
   * or anything the presentation carries. This value is the entire authority for
   * the link; if it can be influenced by the caller, linking becomes account
   * takeover with extra steps.
   */
  readonly authenticatedUserId: string;
  /**
   * The `external_sub` the authenticated account already owns — the value its
   * existing (password) credential row carries.
   *
   * ADR-009 §1: under `asserted-lookup` a wallet credential's `external_sub` is
   * *"the asserted, normalized identifier — the same column `PasswordProvider`
   * fills"*. Taking it from the account rather than from the user's typing is
   * what makes a later wallet login resolve back to THIS account: the two rows
   * agree on the identifier by construction rather than by the user retyping it
   * identically.
   */
  readonly accountIdentifier: string;
  /** The account store, for the strategy-scoped conflict check only. */
  readonly lookup: SubjectAccountLookup;
  /** Where a lookup backend failure is reported. See `subject-candidates.ts`. */
  readonly onLookupError?: (error: unknown) => void;
}

/** The write plan, or a refusal. */
export type WalletLinkOutcome =
  | {
      readonly kind: 'linkable';
      /** `users.id` the row belongs to — the session's, re-derived. */
      readonly userId: string;
      /** Value for `user_credentials.external_sub`. */
      readonly externalSub: string;
      /**
       * Which strategy produced {@link externalSub}.
       *
       * Carried so the caller can tell a stable, credential-derived subject from
       * an account identifier without re-deriving either — and so an audit entry
       * can record which of ADR-009's two account-keying models a row was
       * written under.
       */
      readonly subjectSource: Extract<
        SubjectResolutionStrategyId,
        'asserted-lookup' | 'issuer-scoped-claim'
      >;
      /** Value for `user_credentials.credential_data`. */
      readonly credentialData: WalletCredentialData;
    }
  /**
   * `issuer-scoped-claim` ONLY: this wallet's stable subject is already bound to
   * a DIFFERENT `users.id`.
   *
   * A distinct outcome rather than a `rejected`, because unlike every refusal on
   * the login path this one is safe to explain: the caller is an authenticated
   * user acting on their own account, so "that wallet belongs to another
   * account" enumerates nothing they could not already establish. It is never
   * produced under `asserted-lookup` — see the module JSDoc.
   */
  | { readonly kind: 'conflict' }
  /** Everything else. One shape, deliberately — see {@link WalletLinkOutcome}. */
  | { readonly kind: 'rejected' };

const CONFLICT: WalletLinkOutcome = Object.freeze({ kind: 'conflict' as const });
const REJECTED: WalletLinkOutcome = Object.freeze({ kind: 'rejected' as const });

/**
 * The binding claims a configuration derives its entitlement check from.
 *
 * `issuer-scoped-claim` carries them on its MANDATORY `asserted-lookup`
 * fallback (ADR-009 §2), so a linked credential is always bound in a way the
 * fallback can later check — which matters precisely because the holder may
 * withhold the subject claim on any future presentation.
 */
function bindingClaimsOf(config: SubjectResolutionConfig): readonly string[] {
  return config.strategy === 'issuer-scoped-claim'
    ? normalizeBindingClaims(config.fallback?.bindingClaims)
    : normalizeBindingClaims(config.bindingClaims);
}

/**
 * Plan the `user_credentials` row for a wallet credential being linked to the
 * session's account.
 *
 * PRECONDITIONS, both enforced by the caller and neither re-checkable here:
 * the presentation has been validated (#234) and its issuer is trusted (#236).
 * A credential that failed either must never reach this function — it would be
 * planned into a row exactly as a good one is, because linking asks nothing of
 * the credential that those two gates do not already answer.
 *
 * @param credential - the validated, issuer-trusted presentation.
 * @param config - the deployment's resolved subject-resolution configuration.
 * It decides how `external_sub` is keyed and therefore whether the conflict
 * check is enforceable at all.
 * @param context - the session, the account, and the lookup port.
 * @returns the write plan, a conflict, or a refusal. Never throws for an input
 * reason; a malformed CONFIGURATION still throws, at the same
 * `InvalidConfigurationError` the strategies throw, because that is an operator
 * error rather than an attacker-reachable outcome.
 */
export async function prepareWalletLink(
  credential: ValidatedCredential,
  config: SubjectResolutionConfig,
  context: WalletLinkContext
): Promise<WalletLinkOutcome> {
  // Configuration first: a deployment whose binding claims are unusable must
  // fail loudly rather than link a credential nothing can later check.
  const bindingClaims = bindingClaimsOf(config);

  // (1) The session, asked through the strategy that owns the question.
  const sessionOutcome = await createSessionBindingStrategy().resolve(credential, {
    realmId: context?.realmId,
    authenticatedUserId: context?.authenticatedUserId,
    lookup: context?.lookup,
    ...(context?.onLookupError === undefined ? {} : { onLookupError: context.onLookupError }),
  });
  if (sessionOutcome.kind !== 'matched') return REJECTED;
  const userId = sessionOutcome.userId;

  // (2) The issuer identity, re-checked at run time. Everything below keys on
  // it — the binding digest, the issuer-scoped subject, the recorded issuer —
  // and ADR-009 §2 makes the rule absolute: the issuer component of any account
  // key comes from the validated chain, never from a credential-asserted `iss`.
  const issuer: unknown = credential?.issuer;
  if (!ValidatedIssuer.isValidated(issuer)) return REJECTED;

  const credentialType = credential?.credentialType;
  if (typeof credentialType !== 'string' || credentialType.length === 0) return REJECTED;

  // (3) The binding this row will be checked against on every later login.
  // Derived BEFORE any lookup: a credential that cannot supply one is refused
  // without the link attempt touching the account store.
  const binding = deriveWalletBinding(credential, bindingClaims);
  if (binding === undefined) return REJECTED;

  // The SAME writer the enrolment path uses (#235). A link and a first-time
  // login must produce byte-identical column shapes, or a credential linked
  // today reads as unbound at the next `asserted-lookup` login.
  const credentialData = buildWalletCredentialData({
    credential,
    walletBinding: binding,
    subjectResolution: config.strategy,
  });

  // (4) `external_sub`, and with it whether duplicate detection is possible.
  const issuerScoped =
    config.strategy === 'issuer-scoped-claim'
      ? deriveOptedInIssuerScopedSubject(
          credential,
          normalizeClaimName(config.subjectClaim, 'subjectClaim'),
          new Set(normalizeIssuerScopedIssuers(config.issuers))
        )
      : undefined;

  if (issuerScoped !== undefined) {
    // The one configuration with a stable, unique per-wallet key — so the one
    // configuration where "already linked to a different account" is a question
    // that can be answered. ADR-009's Negative consequences and #238's
    // conditional acceptance criterion both scope it exactly here.
    const candidates = await runAccountLookup(
      {
        realmId: context.realmId,
        lookup: context.lookup,
        ...(context.onLookupError === undefined ? {} : { onLookupError: context.onLookupError }),
      },
      () => context.lookup.byWalletSubject(context.realmId, issuerScoped)
    );
    // A store that could not answer is a refusal, never a link: writing the row
    // anyway would resolve the conflict in the attacker's favour.
    if (candidates === undefined) return REJECTED;

    for (const candidate of candidates) {
      if (candidate === null || typeof candidate !== 'object') return REJECTED;
      if (typeof candidate.userId !== 'string' || candidate.userId.length === 0) return REJECTED;
      if (candidate.userId !== userId) return CONFLICT;
    }

    return Object.freeze({
      kind: 'linkable' as const,
      userId,
      externalSub: issuerScoped,
      subjectSource: 'issuer-scoped-claim' as const,
      credentialData,
    });
  }

  // `asserted-lookup`, and the `issuer-scoped-claim` fallback path: the subject
  // is the identifier the account already owns, normalized the same way
  // `PasswordProvider` normalizes it so the two rows cannot disagree.
  const externalSub = normalizeAssertedIdentifier(context?.accountIdentifier);
  if (externalSub === undefined) return REJECTED;

  return Object.freeze({
    kind: 'linkable' as const,
    userId,
    externalSub,
    subjectSource: 'asserted-lookup' as const,
    credentialData,
  });
}
