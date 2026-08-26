import type { AttackPotentialResistance } from '../attestation/attack-potential';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import type { AssuranceLevel } from '../providers/credential-provider.interface';
import { canonicalizeIssuerIdentifier, ValidatedIssuer } from '../trust/issuer-identity';
import type { AcrBearingAssuranceLevel } from './acr-value';
import { keyStorageAtFloor } from './key-storage-evidence';

/**
 * Deriving an eIDAS Level of Assurance from a validated credential (ADR-004,
 * ADR-010, issue #237).
 *
 * ## The input is the credential and its ISSUER — never the wallet
 *
 * OID4VP 1.0 §5 makes the response type `vp_token`: there is no wallet-signed
 * identity assertion, so there is nothing for a wallet to claim an assurance
 * level IN. HAIP 1.0 §1 says the same thing from the other end — the profile
 * "fulfils some, but not all, of the requirements to meet the 'High' Level of
 * Assurance … these features must be combined with additional measures outside
 * of the scope of HAIP". LoA is a property of the ECOSYSTEM: who identity-proofed
 * the subject, under which trust anchor, into what kind of key store.
 *
 * None of that arrives in the protocol. It is therefore operator configuration —
 * a statement about which issuers the deployment believes operate at which level
 * — evaluated against evidence #234 actually proved. This module is that
 * evaluation, and nothing in it reads a self-asserted level out of a credential.
 *
 * ## Where it sits relative to issuer TRUST (#236)
 *
 * Trust and assurance are different questions and this module answers only the
 * second. `assertIssuerTrusted` decides *may this realm accept credentials from
 * this issuer at all* and THROWS when the answer is no. This decides *what is a
 * credential from this issuer worth* and returns a level.
 *
 * The gate must run first. Calling this on an untrusted issuer is meaningless:
 * an issuer absent from the assurance policy resolves to `'low'`, which is the
 * same value an untrusted issuer would get, and reading that as "authenticated
 * at low assurance" would be a complete bypass. The ordering is the caller's
 * obligation and is documented on {@link resolveCredentialAssurance}; this
 * module cannot verify it, exactly as `ValidatedIssuer` cannot verify that its
 * evidence came from a real signature check.
 *
 * ## Fail-closed, and `'low'` is the failure
 *
 * Every path that cannot POSITIVELY establish a higher level returns `'low'`,
 * and `'low'` emits no `acr` claim at all (see `acr-value.ts`). There is no
 * throw: a credential from an unlisted issuer is not an error, it is an ordinary
 * authentication that carries no assurance evidence. That makes the degraded
 * state indistinguishable from a password login, which is the correct posture —
 * never an assured session by accident.
 */

/**
 * How the holder's credential-bound private key is stored, in the terms an
 * eIDAS Level of Assurance is expressed in.
 *
 * **The seam for key attestations (HAIP §9.2, issue #308).** eIDAS LoA `high`
 * requires a secure cryptographic device, which is a property of the WALLET's
 * key store, not of the credential — so it cannot come from anything #234 sees.
 * HAIP §9.2 key attestations are how a wallet proves it, and #308 implements
 * their validation.
 *
 * DISTINCT from #308's `KeyStorageAssurance`, deliberately, and the two names are
 * not interchangeable. #308's type answers *which source established anything*
 * (`'none' | 'issuer-attested' | 'key-attested'`) and carries an OID4VCI
 * Appendix D attack-potential grade alongside it. This one answers *what the
 * answer is worth to an eIDAS level*, which is a policy question an operator
 * settles per issuer. Collapsing them would let an attestation's mere presence
 * decide a Level of Assurance.
 *
 * It reaches this module as OPTIONAL {@link AssuranceEvidence} rather than as a
 * field on `ValidatedCredential`, because #234 cannot observe it. The
 * translation from #308's evidence into this vocabulary is `translateKeyStorageAssurance`
 * (`assurance/key-storage-evidence.ts`) and lives THERE rather than here or at a
 * call site — one function, separately tested, so no consumer decides for itself
 * what an attestation is worth (ADR-010 §5, #379).
 *
 * - `software` — the key lives in ordinary application storage.
 * - `hardware` — the key is held in a secure cryptographic device (secure
 *   element, TEE, or an equivalent the attestation vouches for).
 */
export type AssuredKeyStorage = 'software' | 'hardware';

/**
 * Evidence about the authentication that does NOT come from the credential.
 *
 * Separate from {@link ValidatedCredential} on purpose: that type is #234's
 * cryptographic finding and must stay exactly that. This is the extension point
 * for facts established elsewhere in the flow.
 *
 * Absent members are UNKNOWN, never "fine". A policy entry that requires
 * something absent here refuses (returns `'low'`), so adding a requirement can
 * only ever lower the level a deployment reaches, never raise it.
 */
export interface AssuranceEvidence {
  /**
   * Key storage as proven by a validated key attestation (#308). Absent means
   * unproven — see {@link IssuerAssuranceEntry.requiresKeyStorage}.
   *
   * Fill it from `translateKeyStorageAssurance(credential.assurance.keyStorageAssurance)`
   * and from nothing else. Deriving it at a call site is how the same question
   * gets two answers, and reading `assurance !== 'none'` as a level is the exact
   * collapse {@link AssuredKeyStorage} above forbids.
   *
   * What this member deliberately does NOT carry is WHICH #308 source
   * established it. The translation reports that on its own result, for the
   * operator's log; a policy must not be able to branch on it, because D1
   * settled the operator's knob as an attack-potential floor and a second axis
   * here would be an undocumented one (ADR-010 §5).
   */
  readonly keyStorage?: AssuredKeyStorage;
  /**
   * The graded key-storage resistance a #308 source established — SOURCE-FREE,
   * and present only when {@link keyStorage} was read from a recognised source
   * and a recognised grade.
   *
   * Why both members exist: the caller translates ONCE, before the policy has
   * selected an entry, so {@link keyStorage} is necessarily read at the DEFAULT
   * floor. An entry carrying {@link IssuerAssuranceEntry.requiresKeyStorageAttackPotential}
   * states a different floor, and re-reading it needs the grade rather than the
   * already-collapsed `'software' | 'hardware'`.
   *
   * Fill it from `translateKeyStorageAssurance(...).establishedAttackPotential`
   * and from nothing else — in particular never straight off
   * `credential.assurance.keyStorageAssurance.keyStorage`, which has not passed
   * the source gate and could carry a grade under `assurance: 'none'`.
   */
  readonly keyStorageAttackPotential?: AttackPotentialResistance;
}

/**
 * One operator statement: "credentials from this issuer are worth this level".
 *
 * `assuranceLevel` cannot be `'low'`. An entry granting `'low'` would be an
 * entry that does nothing — `'low'` is what an UNLISTED issuer already gets —
 * and a configuration language in which some entries are no-ops invites an
 * operator to believe they disabled something they merely failed to enable.
 */
export interface IssuerAssuranceEntry {
  /**
   * Issuer identifier, canonicalized on construction with the same reduction
   * `ValidatedIssuer` applies, so both sides of the comparison agree.
   */
  readonly issuer: string;
  /** What a credential from this issuer is worth. */
  readonly assuranceLevel: AcrBearingAssuranceLevel;
  /**
   * Credential types (`vct`) this entry covers. **Optional, and omitting it
   * covers every type this issuer signs.**
   *
   * An issuer typically runs one identity-proofing process for its PID and
   * something much weaker for, say, a loyalty credential; naming the types is
   * how an operator says "only the PID is worth `high`". Omitting the list is a
   * deliberate, documented widening — appropriate for an issuer that only ever
   * issues one kind of credential.
   */
  readonly credentialTypes?: readonly string[];
  /**
   * Minimum key storage this entry demands (#308 → #237, ADR-010 §5).
   *
   * When set to `'hardware'`, the entry grants its level ONLY if
   * {@link AssuranceEvidence.keyStorage} proves hardware storage. The wallet
   * login path fills that field from #308's evidence through
   * `translateKeyStorageAssurance`, so the entry is satisfiable — it was not
   * before #379, which is the issue recording that the two halves shipped
   * unconnected and this knob could therefore never grant.
   *
   * `'hardware'` alone means the STRICT reading: the strongest OID4VCI Appendix
   * D §D.2 grade, as {@link import('./key-storage-evidence').DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL}
   * names it. An operator who wants a lower bar states
   * {@link requiresKeyStorageAttackPotential}, because a default may only ever
   * be the reading that refuses more. An eIDAS `high` claim that assumed a
   * secure cryptographic device nobody verified is exactly the unearned
   * assertion this module exists to prevent.
   *
   * Authorable through `OID4VP_ISSUER_ASSURANCE` since #379; before that it was
   * reachable only from a direct {@link createIssuerAssurancePolicy} call, which
   * nothing outside tests made.
   */
  readonly requiresKeyStorage?: AssuredKeyStorage;
  /**
   * The §D.2 attack-potential floor at which this entry reads evidence as
   * `'hardware'` (D1, ADR-010 §5). Meaningful ONLY alongside
   * `requiresKeyStorage: 'hardware'`, and refused by both configuration
   * boundaries in either shape that makes it inert — stated alone, and stated
   * alongside `requiresKeyStorage: 'software'`.
   *
   * The second pairing is inert because the floor decides only whether graded
   * evidence reads as `'hardware'` or as `'software'`, and a `'software'`
   * requirement accepts either reading: every floor in the union then admits
   * exactly the same evidence. Refused rather than ignored, so an operator
   * cannot state a floor and believe it narrowed anything.
   *
   * Absent means {@link import('./key-storage-evidence').DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL} —
   * the STRICT reading. This exists so QAuth stays out of the
   * eIDAS-interpretation business: where `high`'s "secure cryptographic device"
   * begins is a property of the ecosystem a deployment participates in, and the
   * operator is the only party that knows which ecosystems those are — the same
   * reasoning that makes the assurance LEVEL itself configuration.
   *
   * A floor this build does not recognise never grants: `meetsAttackPotential`
   * fails closed on an unrecognised floor, so a typo here refuses rather than
   * disables the check it was written to impose.
   */
  readonly requiresKeyStorageAttackPotential?: AttackPotentialResistance;
}

/**
 * The single assurance decision point, mirroring `TrustRegistry`'s shape.
 *
 * ## Contract for implementations
 *
 * - **Pure, synchronous, no side effects.** Called on the request path.
 * - **Must return `'low'`, never throw,** for anything it cannot vouch for. A
 *   backend that breaks this is CONTAINED by {@link resolveCredentialAssurance},
 *   which converts a throw into `'low'`; containment is a backstop, not a
 *   licence.
 * - **Must re-check {@link ValidatedIssuer.isValidated}.** An assurance policy
 *   is a trust boundary in its own right and cannot assume the compiler's
 *   nominal typing survived every cast on the way in.
 */
export interface AssurancePolicy {
  /**
   * @param credential - #234's validated credential.
   * @param evidence - facts established outside the credential (#308).
   * @returns the level established, or `'low'` when none was.
   */
  levelFor(credential: ValidatedCredential, evidence?: AssuranceEvidence): AssuranceLevel;
}

/**
 * A policy that never grants assurance.
 *
 * The value every unconfigured or unparseable path resolves to, so "we could not
 * work out what this realm assures" and "this realm assures nothing" are the
 * same object rather than two branches one of which might be forgotten. The
 * counterpart of `DENY_ALL_TRUST_REGISTRY`.
 */
export const LOW_ONLY_ASSURANCE_POLICY: AssurancePolicy = Object.freeze({
  levelFor: (): AssuranceLevel => 'low',
});

/**
 * Does the proven key storage satisfy what an entry demands?
 *
 * When the entry states its OWN floor the evidence is re-read at that floor,
 * through the one translation rule, from the source-free grade
 * {@link AssuranceEvidence.keyStorageAttackPotential}. The caller cannot have
 * done that for us: it translates before any entry has been selected, so
 * {@link AssuranceEvidence.keyStorage} is always the reading at the DEFAULT
 * floor.
 */
function keyStorageSatisfied(
  entry: IssuerAssuranceEntry,
  evidence: AssuranceEvidence | undefined
): boolean {
  const required = entry.requiresKeyStorage;
  if (required === undefined) return true;

  const floor = entry.requiresKeyStorageAttackPotential;
  const proven =
    floor === undefined
      ? evidence?.keyStorage
      : keyStorageAtFloor(evidence?.keyStorageAttackPotential, floor);

  // Only an exact `hardware` proof satisfies a `hardware` requirement, and a
  // `software` requirement is satisfied by any PROVEN storage. Absent evidence
  // never satisfies anything — which is what a caller that established nothing,
  // or that never wired the #308 gate at all, passes.
  if (required === 'hardware') return proven === 'hardware';
  if (required === 'software') return proven === 'software' || proven === 'hardware';

  // An ALLOWLIST, for the same reason `resolveCredentialAssurance` uses one on
  // the way out: `IssuerAssuranceEntry` is a nominal promise, not an
  // enforcement, and this policy is a trust boundary in its own right — the
  // module JSDoc says so, and `createIssuerAssurancePolicy` is exported and
  // callable with entries no configuration boundary ever read.
  //
  // Without this line the fall-through carried the failure the wrong way. A
  // requirement outside the union — a mistyped `'HARDWARE'`, a `null` a JSON
  // round trip left behind — missed the `hardware` branch and landed on the
  // `software` one, so the STRICTEST requirement an operator can state was
  // satisfied by a SOFTWARE key. The typo did not disable the check, which would
  // have been bad enough; it silently rewrote it into its opposite.
  //
  // Fail closed instead: an unreadable requirement grants nothing, exactly as an
  // unrecognised FLOOR already grants nothing through `meetsAttackPotential`.
  // The cost is a lost `acr` claim on an entry nobody could author through
  // configuration; the alternative cost was an unearned eIDAS level.
  return false;
}

/**
 * Build the static per-realm issuer assurance policy (#237).
 *
 * ## Matching
 *
 * Entries are canonicalized with `canonicalizeIssuerIdentifier` — the same
 * reduction `ValidatedIssuer` applied to the identity being tested — and stored
 * in a `Map`. An entry that does not canonicalize is DROPPED rather than
 * throwing: unlike the trust allowlist, a dropped assurance entry can only lower
 * the level reached, so failing closed silently is safe here, whereas taking a
 * request down would convert a configuration typo into a 500. Configuration is
 * validated (and rejected loudly) one layer up, in `server-config`.
 *
 * ## Last entry wins, per (issuer, type)
 *
 * Duplicate entries for the same issuer collapse; the LAST one is kept, matching
 * `upsertMany`'s duplicate handling. Type-scoped entries and the issuer-wide
 * entry are stored separately, and a type-scoped entry is preferred when the
 * credential's `vct` matches one — the more specific statement wins, so an
 * operator can say "this issuer is `substantial`, except its PID which is
 * `high`".
 *
 * @param entries - operator statements; may be empty, which assures nothing.
 * @returns a frozen realm-scoped policy.
 */
export function createIssuerAssurancePolicy(
  entries: readonly IssuerAssuranceEntry[]
): AssurancePolicy {
  /** issuer → entry covering every credential type from that issuer. */
  const issuerWide = new Map<string, IssuerAssuranceEntry>();
  /** `issuer vct` → entry covering exactly that credential type. */
  const typeScoped = new Map<string, IssuerAssuranceEntry>();

  if (Array.isArray(entries)) {
    for (const entry of entries) {
      if (entry === null || typeof entry !== 'object') continue;
      const issuer = canonicalizeIssuerIdentifier(entry.issuer);
      if (issuer === undefined) continue;
      if (entry.assuranceLevel !== 'substantial' && entry.assuranceLevel !== 'high') continue;

      const types = entry.credentialTypes;
      if (types === undefined || types === null) {
        issuerWide.set(issuer, entry);
        continue;
      }
      if (!Array.isArray(types)) continue;
      for (const credentialType of types) {
        if (typeof credentialType !== 'string' || credentialType.length === 0) continue;
        typeScoped.set(`${issuer} ${credentialType}`, entry);
      }
    }
  }

  return Object.freeze({
    levelFor(credential: ValidatedCredential, evidence?: AssuranceEvidence): AssuranceLevel {
      // Re-checked here, not only in `resolveCredentialAssurance`: a policy is a
      // trust boundary and must not inherit the caller's assumptions. An issuer
      // identity that never went through key resolution is worth nothing, no
      // matter what string it carries.
      if (credential === null || typeof credential !== 'object') return 'low';
      if (!ValidatedIssuer.isValidated(credential.issuer)) return 'low';

      const { identifier } = credential.issuer;
      const credentialType = credential.credentialType;
      const entry =
        (typeof credentialType === 'string' && credentialType.length > 0
          ? typeScoped.get(`${identifier} ${credentialType}`)
          : undefined) ?? issuerWide.get(identifier);

      if (entry === undefined) return 'low';
      if (!keyStorageSatisfied(entry, evidence)) return 'low';
      return entry.assuranceLevel;
    },
  });
}

/**
 * Derive the assurance level of a validated presentation (#237).
 *
 * ## Call it AFTER `assertIssuerTrusted`, always
 *
 * This function does not gate anything. An untrusted issuer and an unassured
 * trusted issuer both resolve to `'low'`, so a caller that skipped the trust
 * gate would read "authenticated at low assurance" where the correct answer is
 * "not authenticated at all". The gate throws; this returns. Keep them in that
 * order.
 *
 * ## A policy that throws is contained
 *
 * {@link AssurancePolicy} implementations are pluggable, and the contract says
 * they must not throw — but a contract is not an enforcement. A throw here would
 * turn a perfectly valid authentication into a 500, so it is caught and read as
 * `'low'`: the deployment loses the `acr` claim, not the login. That is the only
 * containment direction that can neither grant unearned assurance nor deny a
 * legitimate sign-in.
 *
 * The failure is reported through {@link ResolveAssuranceOptions.onPolicyError}
 * so a broken policy is loud server-side while being invisible on the wire —
 * `acr`'s absence is indistinguishable from an unassured issuer by design.
 *
 * @param policy - the realm's policy, or nothing at all (→ `'low'`).
 * @param credential - the credential #234 validated and #236 accepted.
 * @param evidence - facts proven outside the credential (#308); optional.
 * @param options - optional policy-failure reporting.
 * @returns the established level; `'low'` whenever nothing higher was proven.
 */
export function resolveCredentialAssurance(
  policy: AssurancePolicy | null | undefined,
  credential: ValidatedCredential,
  evidence?: AssuranceEvidence,
  options?: ResolveAssuranceOptions
): AssuranceLevel {
  if (policy === null || policy === undefined) return 'low';

  let level: unknown;
  try {
    level = policy.levelFor(credential, evidence);
  } catch (error) {
    reportPolicyError(error, options?.onPolicyError ?? DEFAULT_POLICY_ERROR_REPORTER);
    return 'low';
  }

  // An ALLOWLIST, not a `!== 'low'` check: a third-party policy returning a
  // truthy non-level ('HIGH', 'eidas-high', `true`) must not be read as a grant.
  if (level !== 'substantial' && level !== 'high') return 'low';
  return level;
}

/** Optional wiring for {@link resolveCredentialAssurance}. */
export interface ResolveAssuranceOptions {
  /**
   * Called when the {@link AssurancePolicy} THREW instead of answering.
   *
   * Wire it to the request logger. The degradation is deliberately silent on the
   * wire, so a policy that is broken rather than merely unconvinced would
   * otherwise be invisible: the deployment would quietly stop emitting `acr` and
   * log nothing about why.
   */
  readonly onPolicyError?: (error: unknown) => void;
}

/**
 * Where a policy failure goes when the caller wired no reporter.
 *
 * `console.error` for the same reason `trust-registry.ts` uses it: this lib has
 * no logger dependency, and a no-op default would let the one failure mode that
 * is invisible on the wire be invisible server-side too.
 */
const DEFAULT_POLICY_ERROR_REPORTER = (error: unknown): void => {
  console.error('[assurance] AssurancePolicy threw; treating the login as low assurance', error);
};

/** Report a policy failure without ever letting the reporter become the fault. */
function reportPolicyError(error: unknown, report: (error: unknown) => void): void {
  try {
    report(error);
  } catch {
    // A logger that throws must not convert a lost `acr` claim into a failed
    // login — the thing that reports a failure may not become one.
  }
}
