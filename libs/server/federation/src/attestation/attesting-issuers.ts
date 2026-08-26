import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { summarizeConfiguredValue } from '../trust/configured-value';
import { canonicalizeIssuerIdentifier, ValidatedIssuer } from '../trust/issuer-identity';
import {
  type AttackPotentialResistance,
  isAttackPotentialResistance,
  meetsAttackPotential,
} from './attack-potential';

/**
 * The TRANSITIVE WSCD assurance path (issue #308, HAIP §4.5.1).
 *
 * ## The finding that shapes this module
 *
 * Reading HAIP §5–§6 (OpenID for Verifiable Presentations) surfaces **no**
 * requirement that a Verifier request or validate a key attestation when it
 * receives a `vp_token`. What a Verifier gets in presentation is CRYPTOGRAPHIC
 * HOLDER BINDING — the KB-JWT and `cnf` prove the presenter possesses the bound
 * key *right now* — which is possession, not storage. The normative key
 * attestation mandate sits somewhere else entirely: §4.5.1, under §4 OpenID for
 * Verifiable Credential ISSUANCE, at the Credential Endpoint, where the ISSUER
 * validates the wallet's attestation before it will issue anything:
 *
 * > Wallets MUST support key attestations.
 *
 * QAuth does not run a Credential Endpoint (ADR-004 puts OID4VCI out of scope),
 * so under HAIP the WSCD assurance QAuth has is assurance it INHERITED: a
 * trusted HAIP Issuer checked the wallet's key attestation at issuance, and the
 * credential QAuth is now looking at exists only because that check passed.
 *
 * That is a real guarantee and it is worth stating in code, because the
 * alternative to stating it is one of two mistakes. Either the verifier invents
 * a verifier↔wallet attestation handshake no specification defines — and then
 * interoperates with nothing — or it quietly treats "the credential parsed" as
 * "the key is in hardware", which is the assumption this whole issue exists to
 * refuse.
 *
 * ## So the reliance is made EXPLICIT, and it is operator-declared
 *
 * The inheritance is only as good as the claim "this issuer validates key
 * attestations per §4.5.1", and nothing in a presentation asserts that claim.
 * Not the credential (an issuer that skips the check does not say so), not the
 * `x5c` chain (a certificate says who signed, not what they verified), not the
 * `vct`. It is an OUT-OF-BAND fact about an issuance ecosystem, which makes it
 * exactly the kind of fact HAIP §3.4 leaves to the operator — the same posture
 * #236 takes for trust anchors.
 *
 * So an operator records it, per issuer, together with the level that issuer's
 * process attests. An issuer absent from that record attests NOTHING, however
 * trusted it is for issuing credentials: trusting an issuer's claims about a
 * PERSON is a different decision from trusting its claims about a DEVICE, and
 * conflating them would hand every allowlisted issuer the ability to mint
 * high-assurance sessions by accident.
 *
 * ## This is a second gate, never a substitute for the first
 *
 * A registry entry here does not make an issuer trusted — {@link
 * import('../trust/trust-registry').assertIssuerTrusted} decides that, from the
 * same {@link ValidatedIssuer}, and it runs on its own. An issuer could
 * plausibly be listed here and not trusted at all (an operator editing one list
 * and not the other), and that combination must authenticate nobody. Keeping
 * the two registries separate is what makes that structural rather than a
 * matter of call order.
 */

/**
 * The per-issuer record of which issuance chains attest key storage.
 *
 * ## Contract for backends
 *
 * - **Pure lookup, no side effects.** Called on the request path.
 * - **Must return `undefined`, never throw,** for an issuer it knows nothing
 *   about. A backend that breaks the rule is CONTAINED by the resolver rather
 *   than trusted to keep it, but containment is a backstop.
 * - **Must re-check {@link ValidatedIssuer.isValidated}.** A backend is a trust
 *   boundary in its own right and cannot assume the compiler's nominal typing
 *   survived every cast on the way in.
 */
export interface KeyStorageAttestingIssuers {
  /**
   * @param issuer - the identity produced by #234's presentation validation.
   * @returns the attack-potential level this issuer's issuance process attests
   * for holder key storage, or `undefined` when the operator has recorded no
   * such claim about it.
   */
  attestedKeyStorage(issuer: ValidatedIssuer): AttackPotentialResistance | undefined;
}

/**
 * A registry in which no issuer attests anything.
 *
 * The value every unconfigured path resolves to, so "we could not work out what
 * this deployment records" and "this deployment records nothing" are the same
 * object rather than two branches, one of which might be forgotten.
 */
export const NO_ATTESTING_ISSUERS: KeyStorageAttestingIssuers = Object.freeze({
  attestedKeyStorage: (): undefined => undefined,
});

/** One operator-declared HAIP issuance chain. */
export interface AttestingIssuerEntry {
  /** The issuer identifier, canonicalized on the way in. */
  readonly issuer: string;
  /**
   * The level this issuer's §4.5.1 validation establishes for holder key
   * storage — the operator's own reading of that ecosystem's certification, not
   * anything QAuth can derive.
   */
  readonly keyStorage: AttackPotentialResistance;
}

/**
 * Build the static attesting-issuer registry (#308).
 *
 * Matching mirrors {@link import('../trust/trust-registry').createStaticIssuerAllowlist}
 * exactly: entries are reduced with {@link canonicalizeIssuerIdentifier}, the
 * same reduction {@link ValidatedIssuer} applies to the identity being tested,
 * and stored in a `Map` so lookup cost does not depend on an issuer's POSITION
 * in the list.
 *
 * A malformed entry throws loudly rather than being dropped. Dropping one would
 * leave the operator believing an ecosystem's key storage is recognised when it
 * is not — which surfaces as every user of that wallet silently failing to
 * reach the assurance their credential should carry, the hardest class of bug
 * to attribute. The offending value goes on `details`, never into the message.
 *
 * @param entries - the issuers this deployment recognises as attesting key
 * storage; may be empty, which yields a registry recording nothing.
 * @returns a frozen registry.
 * @throws InvalidConfigurationError when an entry is not a canonicalizable
 * HTTPS issuer identifier, or names a level this build does not understand.
 */
export function createStaticAttestingIssuers(
  entries: readonly AttestingIssuerEntry[]
): KeyStorageAttestingIssuers {
  if (!Array.isArray(entries)) {
    throw new InvalidConfigurationError(
      'The attesting-issuer registry must be an array of { issuer, keyStorage } entries (#308).'
    );
  }

  const attested = new Map<string, AttackPotentialResistance>();

  for (const [index, entry] of entries.entries()) {
    const canonical = canonicalizeIssuerIdentifier(entry?.issuer);

    if (canonical === undefined) {
      throw new InvalidConfigurationError(
        'An attesting-issuer entry does not name a usable issuer identity (#308). Entries must be absolute https:// URLs with no userinfo, query string or fragment. See this error\'s "details" for the position and the value.',
        { index, entry: summarizeConfiguredValue(entry?.issuer) }
      );
    }

    if (!isAttackPotentialResistance(entry?.keyStorage)) {
      throw new InvalidConfigurationError(
        'An attesting-issuer entry names an attack-potential resistance level this build does not understand (#308). Levels come from OID4VCI Appendix D §D.2. See this error\'s "details" for the position and the value.',
        { index, entry: summarizeConfiguredValue(entry?.keyStorage) }
      );
    }

    attested.set(canonical, entry.keyStorage);
  }

  return Object.freeze({
    attestedKeyStorage(issuer: ValidatedIssuer): AttackPotentialResistance | undefined {
      // Re-checked here, not only in the resolver: a backend is a trust boundary
      // and must not inherit the caller's assumptions.
      if (!ValidatedIssuer.isValidated(issuer)) return undefined;
      return attested.get(issuer.identifier);
    },
  });
}

/**
 * The strongest §D.2 grade a set of entries records, or nothing (#308/#379).
 *
 * ## Why it takes ENTRIES rather than a registry
 *
 * {@link KeyStorageAttestingIssuers} is deliberately opaque — a caller can ask
 * about one issuer and cannot enumerate it, so no message can ever be built from
 * its contents. That property is worth keeping, and this question does not need
 * it broken: the answer is an AGGREGATE over configuration the operator wrote,
 * not a fact about any issuer, and the boot gate that asks it already holds the
 * configured entries.
 *
 * ## What it is for
 *
 * `assertKeyStorageAssuranceProvisioned` compares it against the active
 * profile's `minimumKeyStorageAttackPotential`. A deployment that records only
 * `iso_18045_basic` issuers has provisioned a registry, but not one that can
 * ever clear an `iso_18045_high` floor — so under `haip-1.0` every presentation
 * would be refused with `attack-potential-below-minimum`, which is exactly the
 * 100%-failure shape the boot gate exists to catch. Counting entries answered
 * "is anything recorded"; this answers the question the profile actually asks.
 *
 * The STRONGEST rather than the weakest: the gate is asking whether the
 * deployment can establish the floor for ANY ecosystem it recorded, not for
 * every one. A registry mixing a `high` issuer with a `basic` one is a working
 * deployment with one ecosystem that will not reach the floor, and refusing to
 * start on it would be wrong.
 *
 * Unrecognised grades are SKIPPED rather than throwing: this is an aggregate
 * over already-validated configuration, and `createStaticAttestingIssuers` — run
 * at boot through `assertAttestingIssuersUsable` — is the one place a grade this
 * build cannot read is allowed to take the deployment down. Skipping keeps the
 * two from disagreeing about which error an operator sees.
 *
 * @param entries - the configured entries; may be empty or malformed.
 * @returns the strongest recorded grade, or `undefined` when none is readable.
 */
export function strongestAttestedKeyStorage(
  entries: readonly AttestingIssuerEntry[]
): AttackPotentialResistance | undefined {
  if (!Array.isArray(entries)) return undefined;

  let strongest: AttackPotentialResistance | undefined;

  for (const entry of entries) {
    const keyStorage: unknown = entry?.keyStorage;
    if (!isAttackPotentialResistance(keyStorage)) continue;
    // Delegated, never compared by index: the ordering lives in one table, and
    // re-deriving it here is how a grade added to the union gets ranked twice.
    if (strongest === undefined || meetsAttackPotential(keyStorage, strongest)) {
      strongest = keyStorage;
    }
  }

  return strongest;
}
