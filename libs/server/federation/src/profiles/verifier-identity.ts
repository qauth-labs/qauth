import type { ClientIdPrefix, VerifierProfile } from './verifier-profile.types';

/**
 * Fail-closed guards over the VERIFIER trust direction (issue #299).
 *
 * These are the rules #299 names as MUST-be-unreachable, and the only
 * enforcement primitives with a real consumer today. A bouquet of
 * `isCapabilityPermitted` helpers is deliberately NOT shipped: the profile's
 * readonly arrays already answer those questions directly, and fixing an
 * enforcement API before #233/#234 exist would freeze a contract neither has
 * chosen yet — the same reasoning `wallet.provider.ts` gives for refusing to
 * pin an input schema before #234 selects one.
 *
 * The guards COMPOSE rather than restate each other:
 * {@link assertRequestSigningAllowed} delegates the posture question to
 * {@link assertRequestSigningPosture} and the certificate question to
 * {@link assertPrefixProvisioned}, and {@link assertVerifierIdentityProvisioned}
 * is the boot-time application of that same per-prefix primitive to the
 * preferred prefix. Each rule is therefore written down once, and there is no
 * path that signs with a prefix whose material was never asserted.
 *
 * All throw a plain `Error`, never a `@qauth-labs/shared-errors` domain error.
 * Domain errors carry `statusCode`/`code` and are mapped onto the wire by the
 * global error handler, which would frame a bootstrap misconfiguration or a
 * caller bug as a client-facing outcome with a stable error contract. Neither
 * is one: reaching these means the deployment is mis-provisioned or the caller
 * is mis-wired, and a 500 with a server-side stack trace is the right signal.
 */

/**
 * Kinds of X.509 material an operator can provision, keyed to the `requires`
 * discriminator on `VerifierPrefixBinding`.
 */
export type VerifierMaterialKind = 'leaf-cert' | 'non-self-signed-chain';

/**
 * What the operator has actually provisioned.
 *
 * **Always empty today.** No certificate configuration surface exists: the
 * `x509_san_dns` path needs signed requests (#298 ES256) and `x509_hash` needs a
 * QTSP-issued WRPAC (#296 Q4), so neither is reachable yet. #298/#233 populate
 * this from real config. Modelling it now — rather than inventing env vars for
 * material nothing can consume — is what makes `haip-1.0` refuse to start
 * instead of appearing to work.
 */
export interface ProvisionedVerifierMaterial {
  /** Material kinds the deployment supplied, in no particular order. */
  readonly available: readonly VerifierMaterialKind[];
}

/** Nothing provisioned — the state of every deployment until #298/#233 land. */
export const NO_VERIFIER_MATERIAL: ProvisionedVerifierMaterial = Object.freeze({
  available: Object.freeze([]),
});

/**
 * Assert ONE Client Identifier Prefix has the certificate material it requires
 * (#299).
 *
 * The primitive every other provisioning check is built from. It exists because
 * a profile permits a SET of prefixes, not just its preferred one: checking only
 * `presentedPrefixes[0]` at boot would let `oid4vp-1.0-base` start on its
 * certificate-free `redirect_uri` prefix and then sign an `x509_san_dns` request
 * with no leaf certificate to put in the `x5c` header — an identity QAuth names
 * but cannot prove, which is the exact half-configured verifier #299 forbids.
 *
 * @param profile - the resolved active profile.
 * @param prefix - the prefix about to be presented.
 * @param provisioned - material the operator supplied; defaults to none, so a
 * caller that forgets to thread it through fails closed rather than sails past.
 * @throws Error when the profile declares no binding for the prefix, or when the
 * binding's required material is not configured.
 */
export function assertPrefixProvisioned(
  profile: VerifierProfile,
  prefix: ClientIdPrefix,
  provisioned: ProvisionedVerifierMaterial = NO_VERIFIER_MATERIAL
): void {
  const binding = profile.verifierIdentity.presentedPrefixes.find((b) => b.prefix === prefix);

  if (binding === undefined) {
    throw new Error(
      `Verifier profile '${profile.id}' declares no certificate binding for the '${prefix}' Client Identifier Prefix, so QAuth cannot prove that identity. This is a malformed profile definition (#299): 'clientIdPrefixes' and 'verifierIdentity.presentedPrefixes' must name the same set.`
    );
  }

  // `redirect_uri` is the only binding with no `requires` discriminator.
  if (!('requires' in binding)) return;

  if (!provisioned.available.includes(binding.requires)) {
    throw new Error(
      `Verifier profile '${profile.id}' presents the '${binding.prefix}' Client Identifier Prefix, which requires operator-provisioned '${binding.requires}' X.509 material that is not configured. Refusing rather than running a half-configured verifier (#299). Certificate provisioning lands with #298 (ES256) and #233; until then select 'oid4vp-1.0-base', whose preferred 'redirect_uri' prefix needs no certificate.`
    );
  }
}

/**
 * Assert the profile's preferred Client Identifier Prefix has the certificate
 * material it requires, or refuse (#299).
 *
 * The BOOT-time check, and the reason a deployment fails to start rather than
 * discovering the gap on the first wallet request. The preferred prefix is
 * `presentedPrefixes[0]` — the one a deployment presents unless it selects
 * otherwise — so it is the minimum that must be provisioned for the profile to
 * be operable at all. Per-request use of any OTHER permitted prefix is checked
 * separately by {@link assertPrefixProvisioned}; this is a floor, not the whole
 * story.
 *
 * Consequences today, both intended:
 *   - `oid4vp-1.0-base` prefers `redirect_uri`, which needs no certificate → starts.
 *   - `haip-1.0` requires a non-self-signed chain (WRPAC) → **refuses to start**.
 *
 * @param profile - the resolved active profile.
 * @param provisioned - material the operator supplied; defaults to none.
 * @throws Error when the preferred prefix's required material is missing.
 */
export function assertVerifierIdentityProvisioned(
  profile: VerifierProfile,
  provisioned: ProvisionedVerifierMaterial = NO_VERIFIER_MATERIAL
): void {
  const preferred = profile.verifierIdentity.presentedPrefixes[0];

  if (preferred === undefined) {
    throw new Error(
      `Verifier profile '${profile.id}' presents no Client Identifier Prefix, so QAuth cannot identify itself to a wallet. This is a malformed profile definition (#299), not an operator misconfiguration.`
    );
  }

  assertPrefixProvisioned(profile, preferred.prefix, provisioned);
}

/**
 * The caller's signing decision for one Authorization Request.
 *
 * A single-field object rather than a bare boolean so the call site reads
 * `{ signed: false }` instead of a naked `false` — an unsigned request is the
 * dangerous direction under `haip-1.0`, and it should be impossible to pass it
 * by accident.
 */
export interface RequestSigningDecision {
  /** Whether the request #233 is about to send carries a signature. */
  readonly signed: boolean;
}

/**
 * Assert the caller's signing decision satisfies the profile's posture (#299).
 *
 * `CapabilityPosture` is a triple, and until now only one third of it was
 * enforced: `forbidden` was refused while `required` was decorative. `haip-1.0`
 * declares `requestSigning: 'required'` (HAIP §5.1 signed Authorization
 * Requests), so an unsigned request under that profile is precisely the eIDAS
 * violation the table exists to make impossible — treating `required` as "on by
 * default" is the failure mode `CapabilityPosture` documents.
 *
 * Called by #233 once per Authorization Request, after it has decided whether to
 * sign. {@link assertRequestSigningAllowed} answers the narrower per-prefix
 * question and delegates the `forbidden` half of this rule here, so the posture
 * is written down in exactly one place.
 *
 * @param profile - the resolved active profile.
 * @param decision - whether the request being constructed is signed.
 * @throws Error when the decision contradicts the profile's posture.
 */
export function assertRequestSigningPosture(
  profile: VerifierProfile,
  decision: RequestSigningDecision
): void {
  if (profile.requestSigning === 'required' && !decision.signed) {
    throw new Error(
      `Verifier profile '${profile.id}' requires signed Authorization Requests, but this request is unsigned. Sending it would present the profile's posture to a wallet without honouring it (#299).`
    );
  }

  if (profile.requestSigning === 'forbidden' && decision.signed) {
    throw new Error(`Verifier profile '${profile.id}' forbids request signing.`);
  }
}

/**
 * Render the prefixes under which THIS profile could legitimately sign.
 *
 * Derived from the profile rather than hardcoded: naming `'x509_hash'` in a
 * profile-independent error message would be wrong under `oid4vp-1.0-base`
 * (which does not present it) and would breach the #299 acceptance criterion
 * that no HAIP-specific constant appears outside the `haip-1.0` definition.
 */
function describeSignablePrefixes(profile: VerifierProfile): string {
  const signable = profile.clientIdPrefixes
    .filter((candidate) => candidate !== 'redirect_uri')
    .map((candidate) => `'${candidate}'`);

  if (signable.length === 0) {
    return `Verifier profile '${profile.id}' presents no other prefix, so it cannot sign any request.`;
  }

  const head = signable.slice(0, -1).join(', ');
  const tail = signable.slice(-1).join('');

  return `Present ${head === '' ? tail : `${head} or ${tail}`} to sign under '${profile.id}'.`;
}

/**
 * Assert a request may be signed under this profile with this prefix (#299).
 *
 * The rules, in the order they are checked — and the order matters:
 *
 * 1. **`redirect_uri` can never be signed.** OID4VP 1.0 §5.9.3 — a request using
 *    that prefix is unverifiable, so a signature over it proves nothing. This is
 *    a PROTOCOL rule, so it is checked before anything profile-specific:
 *    refusing `haip-1.0` + `redirect_uri` with "the profile does not present
 *    that prefix" would invite a #233 implementer to widen `haip-1.0`'s prefix
 *    list, which is the HAIP violation the table exists to prevent.
 * 2. **The profile must permit the prefix** — a caller bug otherwise.
 * 3. **The profile must not forbid signing** — delegated to
 *    {@link assertRequestSigningPosture}, with `signed: true` implied by the
 *    call itself.
 * 4. **The prefix's certificate material must be provisioned** — delegated to
 *    {@link assertPrefixProvisioned}. Without this a profile could permit a
 *    prefix whose leaf certificate nobody configured, and #233 would build an
 *    `x5c` header out of nothing.
 *
 * Called by #233 at request construction. Enforcement must make a forbidden
 * capability UNREACHABLE rather than merely undefaulted, so this throws instead
 * of returning a boolean a caller can ignore.
 *
 * @param profile - the resolved active profile.
 * @param prefix - the prefix the request would carry.
 * @param provisioned - material the operator supplied; defaults to none.
 * @throws Error when signing is not allowed for this profile/prefix pair.
 */
export function assertRequestSigningAllowed(
  profile: VerifierProfile,
  prefix: ClientIdPrefix,
  provisioned: ProvisionedVerifierMaterial = NO_VERIFIER_MATERIAL
): void {
  if (prefix === 'redirect_uri') {
    throw new Error(
      `Requests using the 'redirect_uri' Client Identifier Prefix cannot be signed (OID4VP 1.0 §5.9.3) — such a request is unverifiable, so a signature over it asserts nothing. ${describeSignablePrefixes(profile)}`
    );
  }

  // The PERMITTED set, which is a different field from the presented bindings
  // `assertPrefixProvisioned` reads. #299 requires the two to name the same set,
  // and a profile where they drift must be refused by both checks, not one.
  if (!profile.clientIdPrefixes.includes(prefix)) {
    throw new Error(
      `Verifier profile '${profile.id}' does not present the '${prefix}' Client Identifier Prefix (permitted: ${profile.clientIdPrefixes.join(', ')}).`
    );
  }

  assertRequestSigningPosture(profile, { signed: true });
  assertPrefixProvisioned(profile, prefix, provisioned);
}
