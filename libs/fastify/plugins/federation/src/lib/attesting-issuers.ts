import {
  type AttackPotentialResistance,
  createKeyStorageAssuranceResolver,
  createStaticAttestingIssuers,
  type KeyStorageAssuranceResolver,
} from '@qauth-labs/server-federation';

/**
 * Building the key-storage assurance RESOLVER from configuration — the #308 seam
 * for `apps/auth-server` (issue #379).
 *
 * ## Why this lives in the fastify layer
 *
 * The same boundary reason as `createConfiguredIssuerKeyResolver` and
 * `createConfiguredCredentialStatusChecker` next door: `apps/auth-server` is
 * `scope:app` and may not import `scope:server` libraries directly, while
 * `libs/server/federation` is a pure library with no configuration. Turning one
 * environment variable into a wired resolver needs a home in between.
 *
 * It is also why `createStaticAttestingIssuers` and
 * `createKeyStorageAssuranceResolver` are not re-exported from this package's
 * index: like the trust allowlist and the status checker, a resolver must be
 * obtained through a configuration-driven factory rather than assembled at a
 * call site, so there is exactly one place that decides what a deployment
 * provisioned.
 *
 * ## What it decides, and what it deliberately does not
 *
 * It decides only whether a resolver EXISTS and which issuance ecosystems it
 * recognises. Every question about whether a particular presentation clears a
 * floor stays inside `keyStorageAssuranceGateFor` and the profile's posture, and
 * every question about what the resulting evidence is WORTH stays in #237's
 * assurance policy. This layer never turns evidence into a level.
 *
 * ## The transitive path only, for now
 *
 * `OID4VP_ATTESTING_ISSUERS` provisions #308's TRANSITIVE path — the operator's
 * record that an issuer validates key attestations at issuance per HAIP §4.5.1.
 * The DIRECT path (verifying an Appendix D attestation conveyed into the
 * presentation against anchored trust) needs a certificate configuration surface
 * that does not exist yet, the same one #233 owes `provisionedVerifierMaterial`.
 * A deployment that records no attesting issuer therefore provisions nothing,
 * and {@link keyStorageAssuranceProvisioningOf} says so — which is what keeps
 * `assertKeyStorageAssuranceProvisioned` refusing a `haip-1.0` boot rather than
 * letting it accept wallet requests and reject every presentation.
 */

/** Issuer identifier → the §D.2 grade its issuance process attests. */
export type ConfiguredAttestingIssuers = Readonly<Record<string, string>>;

/**
 * Whether an attesting-issuer map records anything at all.
 *
 * Own-property enumeration on a possibly prototype-less object, so a map built
 * with `Object.create(null)` — which is what `server-config` hardens to — reads
 * correctly.
 */
function recordsAnything(configured: ConfiguredAttestingIssuers | null | undefined): boolean {
  if (configured === null || configured === undefined || typeof configured !== 'object') {
    return false;
  }
  return Object.keys(configured).length > 0;
}

/**
 * Whether this deployment has provisioned what key-storage assurance needs
 * (#308/#379).
 *
 * Threaded into `createConfiguredProviders` as `keyStorageAssuranceProvisioned`,
 * where `assertKeyStorageAssuranceProvisioned` turns it into a boot refusal for
 * a profile whose `keyStorageAssurance` posture is `required`. Before #379 that
 * option was never passed, so the assertion sat permanently in its refusing
 * state and was a constant rather than a predicate.
 *
 * `false` for an empty or absent map, which is the honest answer AND the
 * fail-closed one: a deployment recording no attesting issuer and holding no
 * key-attestation anchors can establish key storage by no path at all.
 *
 * @param configured - the parsed `OID4VP_ATTESTING_ISSUERS` map.
 * @returns whether a mandating profile may start here.
 */
export function keyStorageAssuranceProvisioningOf(
  configured: ConfiguredAttestingIssuers | null | undefined
): boolean {
  return recordsAnything(configured);
}

/**
 * Build the deployment's key-storage assurance resolver, or nothing (#308/#379).
 *
 * `undefined` rather than an empty resolver for an unconfigured deployment, so
 * "provisioned nothing" reaches `keyStorageAssuranceGateFor` as an absent
 * resolver and becomes `DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER` — the posture
 * is kept and the evidence is refused. Returning a resolver that recognises no
 * issuer would be observably identical today and would quietly stop being so the
 * moment the direct path lands.
 *
 * @param configured - the parsed `OID4VP_ATTESTING_ISSUERS` map.
 * @returns a resolver, or `undefined` when nothing is provisioned.
 * @throws InvalidConfigurationError when an entry is not a canonicalizable
 * HTTPS issuer identity or names a grade this build does not understand.
 * `server-config` has already validated both, so reaching this throw means
 * configuration changed under a running process — an operator error, never a
 * permissive fallback.
 */
export function createConfiguredKeyStorageAssuranceResolver(
  configured: ConfiguredAttestingIssuers | null | undefined
): KeyStorageAssuranceResolver | undefined {
  if (!recordsAnything(configured)) return undefined;

  const entries = Object.entries(configured as ConfiguredAttestingIssuers).map(
    ([issuer, keyStorage]) => ({
      issuer,
      // Cast rather than re-validated: `createStaticAttestingIssuers` runs the
      // membership test itself and THROWS on a grade it does not understand, so
      // narrowing here would only move the same refusal earlier while adding a
      // second copy of the §D.2 vocabulary to this layer.
      keyStorage: keyStorage as AttackPotentialResistance,
    })
  );

  return createKeyStorageAssuranceResolver({
    attestingIssuers: createStaticAttestingIssuers(entries),
  });
}

/**
 * Refuse to start on an `OID4VP_ATTESTING_ISSUERS` map the runtime cannot use
 * (#308/#379).
 *
 * ## The failure this closes
 *
 * The variable is validated twice by two rule sets that do not agree.
 * `server-config`'s `issuerIdentifierSchema` checks each key with
 * `z.url({ protocol: /^https$/ })` and a length cap; the runtime reduces the
 * SAME key with `canonicalizeIssuerIdentifier`, which additionally refuses
 * userinfo, a query string and a fragment. So
 * `{"https://pid.issuer.example?x=1":"iso_18045_high"}` parses cleanly at boot.
 *
 * {@link createConfiguredKeyStorageAssuranceResolver} does throw on it — but it
 * is built LAZILY, at the first wallet presentation, and that throw is caught on
 * the request path, logged as an operator error and rendered as the same uniform
 * refusal a forged credential gets. The operator's only discovery channel is a
 * log line behind a request nobody may make for days, and until then every
 * credential from that ecosystem silently resolves to `assurance: 'none'` — so a
 * policy entry demanding hardware key storage refuses a wallet that satisfies
 * it, and the deployment grants `'low'` where it was configured to grant `'high'`.
 *
 * That is the same shape #236 closed with `assertTrustedIssuersUsable`, and this
 * is its counterpart for the attestation half.
 *
 * ## Why it delegates rather than re-checks
 *
 * It calls the very function the request path calls and discards the result, so
 * there is no second copy of the canonicalization or the §D.2 vocabulary to
 * drift out of agreement — the failure mode this gate exists to prevent.
 *
 * Not gated on `WALLET_FEDERATION_ENABLED`: the operator wrote this
 * configuration, a malformed entry is a typo rather than a posture decision, and
 * finding it only once wallet federation is switched on is exactly the delay
 * being removed. Nothing configured is not a fault — an absent or empty map
 * means no ecosystem is recorded as attesting, the fail-closed default, and it
 * starts.
 *
 * @param configured - the parsed `OID4VP_ATTESTING_ISSUERS` map, or
 * `null`/`undefined` when not configured.
 * @throws InvalidConfigurationError when an entry is not a canonicalizable
 * HTTPS issuer identity or names a grade this build does not understand.
 */
export function assertAttestingIssuersUsable(
  configured: ConfiguredAttestingIssuers | null | undefined
): void {
  createConfiguredKeyStorageAssuranceResolver(configured);
}
