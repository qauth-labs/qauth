/**
 * `VerifierProfile` capability vocabulary (ADR-004, issue #299).
 *
 * QAuth implements **OID4VP 1.0 Final** as the protocol and expresses ecosystem
 * constraints as configurable profiles (#296, LOCKED 2026-07-20). HAIP is a
 * profile *over* OID4VP, not an alternative to it, so a regulated ecosystem is
 * a CONFIGURATION rather than a fork — which is what ADR-004 decided:
 * *"eIDAS compliance is an emergent property of supporting the right protocols,
 * not a hardcoded feature."*
 *
 * Without this layer every constraint HAIP imposes leaks into the protocol code
 * as an unconditional `MUST`, which is exactly the EUDI lock-in ADR-004 rejects.
 *
 * A profile owns TWO responsibilities, and they must not be confused with each
 * other or with issuer trust:
 *
 * 1. **Protocol posture** — which OID4VP capabilities are REQUIRED / PERMITTED /
 *    FORBIDDEN, enforced fail-closed and bidirectionally (at request
 *    construction AND at response validation).
 * 2. **Verifier identity** — which Client Identifier Prefix QAuth presents *as
 *    the Verifier* to prove who IT is to the wallet, and the X.509 material each
 *    prefix requires.
 *
 * **Not issuer trust.** #236 decides whether a *credential's issuer* is trusted
 * — the opposite trust direction. The two share no config and no code path;
 * conflating them would let "we trust this issuer" answer "who are we?".
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 */

/**
 * Deployment profiles QAuth ships.
 *
 * Order of arrival is LOCKED by #296: `oid4vp-1.0-base` ships first (it runs on
 * today's crypto), `haip-1.0` second, once #298 lands ES256 + JWE.
 */
export type VerifierProfileId = 'oid4vp-1.0-base' | 'haip-1.0';

/**
 * OID4VP Client Identifier Prefixes QAuth implements, carried inside `client_id`.
 *
 * - `redirect_uri` — no certificate. **Cannot be signed** (OID4VP 1.0 §5.9.3:
 *   requests using this prefix are unverifiable, so signing them is meaningless).
 *   The self-contained dev/default path; runs on today's EdDSA-only crypto.
 * - `x509_san_dns` — leaf certificate whose `dNSName` SAN matches QAuth's request
 *   origin. The request IS signed, so this depends on #298 (ES256). A self-signed
 *   certificate is acceptable when testing against the OIDF conformance suite.
 * - `x509_hash` — HAIP-mandated. Non-self-signed chain (in the EU, a QTSP-issued
 *   WRPAC per #296 Q4), trust anchor EXCLUDED from the `x5c` header, and
 *   `client_id` equal to the base64url-encoded SHA-256 of the leaf certificate.
 *
 * Other prefixes in the spec (`decentralized_identifier`, `verifier_attestation`,
 * `openid_federation`) are deliberately unimplemented — #296 Q2 starts with the
 * two ends of the range and adds others as ecosystems demand. ADR-004's refresh
 * flags `openid_federation` as deserving its own ADR.
 */
export type ClientIdPrefix = 'redirect_uri' | 'x509_san_dns' | 'x509_hash';

/**
 * How a profile treats a capability.
 *
 * `forbidden` means UNREACHABLE, not merely undefaulted — a profile that forbids
 * a capability must make it impossible to emit and must reject it on the way in.
 * Treating `forbidden` as "off by default" is the failure mode this triple
 * exists to prevent.
 */
export type CapabilityPosture = 'required' | 'permitted' | 'forbidden';

/**
 * OID4VP Response Modes.
 *
 * `direct_post` is the base OID4VP 1.0 mode. `direct_post.jwt` carries a JWE and
 * is what HAIP §5.1 requires; it is unusable until #298 lands the JWE stack.
 */
export type ResponseMode = 'direct_post' | 'direct_post.jwt';

/** Credential formats a profile may accept. */
export type CredentialFormat = 'dc+sd-jwt' | 'mso_mdoc';

/** How the signing key of a credential (or Status List Token) is resolved. */
export type IssuerKeyResolution = 'x5c' | 'issuer-metadata';

/**
 * JOSE `alg` identifiers a profile may DECLARE.
 *
 * Deliberately NOT `@qauth-labs/core-crypto`'s `JwsAlgorithm` (`'EdDSA' | 'RS256'`).
 * That union is what the crypto layer can actually produce today; this one is what
 * a profile *requires*. `haip-1.0` requires `ES256` (HAIP §7) and no backend
 * produces it until #298 — declaring the requirement is precisely how that gap
 * becomes visible and fail-closed, rather than silently unrepresentable.
 *
 * #298 reconciles the two: when ES256 lands in the crypto layer, this type should
 * be re-derived from `JwsAlgorithm` instead of standing alone.
 */
export type VerifierSigningAlgorithm = 'EdDSA' | 'ES256';

/**
 * One Client Identifier Prefix this profile presents, bound to the certificate
 * material that prefix requires (#299, per #296 Q2/Q4).
 *
 * A discriminated union rather than an optional `cert?` field: `redirect_uri`
 * carrying a certificate is not a valid state, and the type should say so.
 */
export type VerifierPrefixBinding =
  | {
      readonly prefix: 'redirect_uri';
    }
  | {
      readonly prefix: 'x509_san_dns';
      /**
       * Operator-provided leaf certificate whose `dNSName` SAN matches QAuth's
       * request origin. Self-signed is acceptable for conformance testing.
       */
      readonly requires: 'leaf-cert';
    }
  | {
      readonly prefix: 'x509_hash';
      /**
       * Operator-provided NON-self-signed chain — in the EU a QTSP-issued WRPAC.
       * A public CA such as Let's Encrypt does NOT satisfy this: the wallet must
       * recognise the trust anchor.
       */
      readonly requires: 'non-self-signed-chain';
    };

/**
 * The VERIFIER trust direction: how QAuth proves who IT is to the wallet.
 *
 * Distinct from #236 issuer trust in both direction and config. See the module
 * JSDoc.
 */
export interface VerifierIdentityConfig {
  /**
   * One binding per prefix this profile presents. **First entry is preferred** —
   * it is the one a deployment uses unless it selects another, and the one whose
   * material must be provisioned for the deployment to start.
   */
  readonly presentedPrefixes: readonly VerifierPrefixBinding[];
}

/**
 * A declarative profile, consulted at BOTH request construction and response
 * validation.
 *
 * Profiles are DATA, never branching logic — adding `haip-1.1` must require no
 * change to protocol code (a #299 acceptance criterion). Anything that would be
 * written as `if (profile === 'haip-1.0')` in a route belongs in this object.
 */
export interface VerifierProfile {
  readonly id: VerifierProfileId;
  /**
   * PERMITTED prefixes — exactly the set of
   * {@link VerifierIdentityConfig.presentedPrefixes} prefixes, first = preferred.
   */
  readonly clientIdPrefixes: readonly ClientIdPrefix[];
  readonly requestSigning: CapabilityPosture;
  readonly responseModes: readonly ResponseMode[];
  readonly responseEncryption: CapabilityPosture;
  readonly signingAlgs: readonly VerifierSigningAlgorithm[];
  readonly credentialFormats: readonly CredentialFormat[];
  readonly issuerKeyResolution: readonly IssuerKeyResolution[];
  /** Whether credential revocation via Token Status List (#297) is mandatory. */
  readonly requireCredentialStatus: boolean;
  readonly verifierIdentity: VerifierIdentityConfig;
}
