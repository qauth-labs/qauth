import type { VerifierProfile, VerifierProfileId } from './verifier-profile.types';

/**
 * The shipped {@link VerifierProfile} table (ADR-004, issue #299).
 *
 * Structurally this mirrors `ENVIRONMENT_PROFILES` in
 * `apps/auth-server/src/app/helpers/environment-policy.ts` (ADR-008): a frozen
 * lookup keyed by an id, consumed through a single resolver. Same reasoning —
 * the posture of a deployment should be readable in one table rather than
 * reconstructed from conditionals scattered across the request path.
 *
 * **Profiles are data.** No entry here may be special-cased downstream. The
 * acceptance criterion is that adding a future profile (`haip-1.1`, a national
 * ecosystem profile) requires editing this file and nothing else.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 */
export const VERIFIER_PROFILES = Object.freeze({
  /**
   * The protocol floor: base OID4VP 1.0 with no ecosystem overlay.
   *
   * For self-contained ecosystems — an enterprise issuing to its own workforce,
   * non-EU deployments, and development/testing. Ships FIRST (#296 Q1) because
   * its preferred path runs on today's EdDSA-only crypto and is testable against
   * the OIDF conformance suite's fake wallet without waiting on #298 or on any
   * regulatory question.
   *
   * `requestSigning: 'permitted'` rather than `'forbidden'`: the profile permits
   * both prefixes, and signing is meaningful for `x509_san_dns` while being
   * impossible for `redirect_uri` (OID4VP §5.9.3). That per-prefix rule is
   * enforced by `assertRequestSigningAllowed`, not expressible in this field.
   */
  'oid4vp-1.0-base': Object.freeze({
    id: 'oid4vp-1.0-base',
    clientIdPrefixes: Object.freeze(['redirect_uri', 'x509_san_dns'] as const),
    requestSigning: 'permitted',
    responseModes: Object.freeze(['direct_post'] as const),
    responseEncryption: 'forbidden',
    signingAlgs: Object.freeze(['EdDSA', 'ES256'] as const),
    credentialFormats: Object.freeze(['dc+sd-jwt'] as const),
    issuerKeyResolution: Object.freeze(['x5c', 'issuer-metadata'] as const),
    requireCredentialStatus: false,
    // ADR-009 §1: the only strategy viable in every ecosystem surveyed. A
    // self-contained deployment whose own issuer guarantees a stable claim opts
    // into `issuer-scoped-claim` per issuer; that is a deployment's contractual
    // knowledge, not something the protocol floor can assert.
    defaultSubjectResolution: 'asserted-lookup',
    // Key attestations (HAIP §9.2, #308) are a high-assurance ecosystem's
    // concern. Base OID4VP 1.0 says nothing about where a holder's key lives, so
    // this profile neither asks for nor evaluates it — which is also what keeps
    // the base profile runnable on today's crypto with no new operator config.
    keyStorageAssurance: 'forbidden',
    verifierIdentity: Object.freeze({
      presentedPrefixes: Object.freeze([
        // Preferred: no certificate, runs today.
        Object.freeze({ prefix: 'redirect_uri' } as const),
        Object.freeze({ prefix: 'x509_san_dns', requires: 'leaf-cert' } as const),
      ]),
    }),
  }),

  /**
   * OpenID4VC High Assurance Interoperability Profile 1.0 — the profile the EUDI
   * ecosystem aligns to, and the falsifiable form of ADR-004's eIDAS claim.
   *
   * **Every HAIP-specific constant in this codebase belongs in this object.** A
   * `'x509_hash'`, an `'ES256'` floor or a `direct_post.jwt` requirement appearing
   * in protocol code is the regression this table exists to prevent (#299 AC).
   *
   * Unusable today, and correctly so — on FOUR counts, each refused by a named
   * guard, because a mandate no code reads is decoration rather than posture:
   * - `x509_hash` needs a WRPAC no deployment has provisioned →
   *   `assertVerifierIdentityProvisioned`, folded into `resolveVerifierProfile`
   *   so no caller can obtain this profile without having been refused.
   * - `signingAlgs: ['ES256']` is not producible until #298 lands ES256, and
   *   `responseEncryption: 'required'` needs the JWE stack from the same issue →
   *   `assertProfileWithinCryptoCapabilities` in
   *   `libs/fastify/plugins/federation/src/lib/configured-providers.ts`. That
   *   check lives in the bootstrap rather than here on purpose: what a build can
   *   actually SIGN is a property of the deployment, not of the profile, and
   *   this lib must not depend on the crypto layer to state a requirement.
   * - `keyStorageAssurance: 'required'` needs an operator-provisioned
   *   attesting-issuer registry or key-attestation trust anchors →
   *   `assertKeyStorageAssuranceProvisioned` (#308), also in the bootstrap and
   *   for the same reason: what an operator has configured is a property of the
   *   deployment.
   *
   * Selecting this profile therefore fails closed at startup, and clearing only
   * some of the four does not make it start.
   *
   * Mandates encoded here, each verified against HAIP 1.0:
   * - §5: response type MUST be `vp_token`; §5.1 response mode `direct_post.jwt`.
   * - §7: ES256 at minimum. EdDSA is NOT in HAIP's mandatory set, so QAuth's
   *   current algorithm does not satisfy the profile.
   * - §6.1: credential status via Token Status List (#297).
   * - §9.2 / §4.5.1: key attestations (#308). The normative mandate is on the
   *   ISSUANCE path, so what this table declares is the Verifier's posture
   *   towards it — assurance is required, at `iso_18045_high` — and the
   *   attestation vocabulary itself lives in `attestation/attack-potential.ts`.
   */
  'haip-1.0': Object.freeze({
    id: 'haip-1.0',
    clientIdPrefixes: Object.freeze(['x509_hash'] as const),
    requestSigning: 'required',
    responseModes: Object.freeze(['direct_post.jwt'] as const),
    responseEncryption: 'required',
    signingAlgs: Object.freeze(['ES256'] as const),
    credentialFormats: Object.freeze(['dc+sd-jwt', 'mso_mdoc'] as const),
    issuerKeyResolution: Object.freeze(['x5c'] as const),
    requireCredentialStatus: true,
    // Also `asserted-lookup`, and that is the finding rather than a copy-paste.
    // ADR-009 Finding 1: the EUDI PID's mandatory attribute set carries NO
    // identifier, `personal_administrative_number` is optional, provider-scoped
    // and refusable, and the Rulebook does not require SD-JWT VC's `sub`. The
    // EU's sanctioned returning-user mechanism is a relying-party pseudonym
    // (`rp-pseudonym`), which is gated on three conditions none of which is
    // cleared. So the flagship regulated profile has the same default as the
    // protocol floor.
    defaultSubjectResolution: 'asserted-lookup',
    // §4.5.1: "Wallets MUST support key attestations." The mandate is on the
    // ISSUANCE path, so what a Verifier enforces is the reliance on it — see
    // `attestation/attesting-issuers.ts`. Declared here as `required` with an
    // explicit floor so the reliance is a posture the code reads rather than an
    // assumption prose makes, and so a deployment that has provisioned neither
    // an attesting-issuer registry nor key-attestation anchors is refused at
    // boot instead of rejecting every presentation in production (#308).
    keyStorageAssurance: 'required',
    minimumKeyStorageAttackPotential: 'iso_18045_high',
    verifierIdentity: Object.freeze({
      presentedPrefixes: Object.freeze([
        Object.freeze({ prefix: 'x509_hash', requires: 'non-self-signed-chain' } as const),
      ]),
    }),
  }),
} satisfies Record<VerifierProfileId, VerifierProfile>);

/**
 * Every profile id, for exhaustive iteration in tests and config validation.
 *
 * Derived from {@link VERIFIER_PROFILES} rather than written out again, so a
 * profile cannot be added to the table and forgotten here.
 */
export const VERIFIER_PROFILE_IDS = Object.freeze(
  Object.keys(VERIFIER_PROFILES) as VerifierProfileId[]
);

/**
 * Narrow an untrusted string to a {@link VerifierProfileId}.
 *
 * **Fail-CLOSED, not fail-safe.** `parseEnvironment` (ADR-008) resolves an
 * unknown value to `production` because a safe default exists there. No such
 * default exists here: `haip-1.0` is not a stricter `oid4vp-1.0-base`, it is a
 * different ecosystem that demands a WRPAC. So an unrecognised value yields
 * `undefined` and the caller refuses wallet flows — #296's locked posture is
 * *"There is never a permissive fallback to the more capable profile."*
 *
 * @param value - raw config/DB value; `null`/`undefined`/unknown all yield `undefined`.
 */
export function parseVerifierProfileId(
  value: string | null | undefined
): VerifierProfileId | undefined {
  if (value === null || value === undefined) return undefined;
  return (VERIFIER_PROFILE_IDS as readonly string[]).includes(value)
    ? (value as VerifierProfileId)
    : undefined;
}
