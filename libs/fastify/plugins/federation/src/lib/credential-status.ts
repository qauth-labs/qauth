import {
  createCredentialStatusChecker,
  createStatusEndpointBreaker,
  createStatusListTrustAnchors,
  createStatusListUriAllowlist,
  type CredentialStatusAuditEvent,
  type CredentialStatusChecker,
  type CredentialStatusProvisioning,
} from '@qauth-labs/server-federation';

/**
 * Building the credential-revocation checker from CONFIGURATION — the #297 seam
 * for `apps/auth-server` (issue #378).
 *
 * ## Why this lives in the fastify layer
 *
 * The same boundary reason as `createConfiguredIssuerKeyResolver` next door:
 * `apps/auth-server` is `scope:app` and may not import `scope:server` libraries
 * directly, while `libs/server/federation` is a pure library with no
 * configuration and no logger. Turning two environment variables into a wired
 * checker needs a home in between, and this is it.
 *
 * ## What it decides, and what it deliberately does not
 *
 * It decides only whether a checker EXISTS and what it is anchored to. Every
 * question about whether a particular credential passes — fail-closed on an
 * unreachable endpoint, cache freshness, the breaker, the SSRF refusals — is
 * settled inside the checker and must not be re-litigated here or at any call
 * site (`credential-status-checker.ts`: *"There is no timeout fallback, no
 * stale-cache-on-error path, no 'the endpoint is down so carry on'"*).
 *
 * ## Three configurations, three different answers
 *
 * | anchors | allowlist | result |
 * | --- | --- | --- |
 * | absent | absent | NO checker. `statusChecked` is `'not-required'`, nothing is fetched, and a profile that MANDATES status refuses to boot (`assertCredentialStatusProvisioned`). |
 * | present | present | a checker, anchored and bounded. |
 * | one of the two | | REFUSAL. |
 *
 * The third row is the one worth spelling out. A deployment with anchors and no
 * allowlist would build a checker that refuses every credential carrying a
 * `status` claim, because no URI is fetchable; a deployment with an allowlist
 * and no anchors would build one that refuses every credential too, because no
 * Status List Token can chain to anything. Both are silent — the operator sees
 * logins fail, not configuration fail — and both are the exact defect class #378
 * exists to close: configuration that says one thing while the code does
 * another. Half-configured is therefore an operator error, raised where operator
 * errors belong.
 */

/** The configuration a {@link CredentialStatusChecker} is built from. */
export interface ConfiguredCredentialStatusOptions {
  /**
   * PEM-encoded X.509 anchors a Status List Token's `x5c` chain must terminate
   * at — `OID4VP_STATUS_LIST_TRUST_ANCHORS` and its `_PATH` sibling, already
   * unioned by `resolveStatusListTrustAnchorPems`.
   *
   * Structural (`readonly string[]`) rather than a `server-config` type, for the
   * same reason {@link createConfiguredIssuerKeyResolver}'s parameter is: this
   * layer must not force a config-library type on a deployment that supplies
   * anchors from a secrets manager instead.
   */
  readonly trustAnchorPems: readonly string[];
  /** `https://` URI prefixes status lists may be fetched from (the SSRF boundary). */
  readonly uriAllowlist: readonly string[];
  /**
   * Audit sink. Wire it to the SERVER logger.
   *
   * Every check reports here, accepted ones included, so a revocation-rejection
   * counter has a denominator. The event carries the status list URI and index —
   * both attacker-influenced — so it is a server-side record and must never
   * reach a response.
   */
  readonly onAudit?: (event: CredentialStatusAuditEvent) => void;
}

/** Whether a list holds at least one non-blank entry. */
function isProvisioned(entries: readonly string[]): boolean {
  return Array.isArray(entries) && entries.some((entry) => entry.trim().length > 0);
}

/**
 * Report which halves of the status path this configuration provisions (#297).
 *
 * Handed to `assertCredentialStatusProvisioned` at boot, which turns it into a
 * refusal when the active profile mandates status and a half is missing.
 *
 * @param options - the status configuration; only the two lists are read.
 * @returns one boolean per half.
 */
export function credentialStatusProvisioningOf(
  options: Pick<ConfiguredCredentialStatusOptions, 'trustAnchorPems' | 'uriAllowlist'>
): CredentialStatusProvisioning {
  return Object.freeze({
    trustAnchors: isProvisioned(options.trustAnchorPems),
    uriAllowlist: isProvisioned(options.uriAllowlist),
  });
}

/**
 * Refuse a half-configured or unusable status configuration, at BOOT (#297).
 *
 * Runs the runtime's OWN compilation — `createStatusListTrustAnchors` parses
 * every certificate and `createStatusListUriAllowlist` compiles every prefix,
 * and both throw `InvalidConfigurationError` on an entry they refuse rather than
 * dropping it — so a bad entry fails the boot instead of surfacing as "every
 * presentation is rejected". The same posture, and the same reasoning, as
 * `assertTrustedIssuersUsable` for `OID4VP_TRUSTED_ISSUERS`.
 *
 * NOT gated on `WALLET_FEDERATION_ENABLED` or on the active profile: a typo is a
 * typo whether or not wallet flows are switched on today, and finding it at boot
 * beats finding it when the first presentation arrives.
 *
 * @param options - the status configuration, straight from the parsed env.
 * @throws Error when exactly one of the two halves is configured.
 * @throws InvalidConfigurationError when an anchor will not parse or a prefix is
 * not a usable `https://` prefix. The offending value is on `details`, never in
 * the message.
 */
export function assertCredentialStatusConfigUsable(
  options: ConfiguredCredentialStatusOptions
): void {
  const provisioning = credentialStatusProvisioningOf(options);

  if (provisioning.trustAnchors !== provisioning.uriAllowlist) {
    throw new Error(
      provisioning.trustAnchors
        ? 'OID4VP_STATUS_LIST_TRUST_ANCHORS is configured but OID4VP_STATUS_LIST_URI_ALLOWLIST is not (#297). A status checker with no permitted URI refuses every credential that carries a `status` claim, silently — configure where status lists may be fetched from, or unset the anchors to run without revocation checking.'
        : 'OID4VP_STATUS_LIST_URI_ALLOWLIST is configured but no status list trust anchors are (#297). A status checker with no anchors refuses every Status List Token, silently — set OID4VP_STATUS_LIST_TRUST_ANCHORS or OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH, or unset the allowlist to run without revocation checking.'
    );
  }

  if (!provisioning.trustAnchors) return;

  // Compiled and discarded: the point is the throw, not the value. The checker
  // itself is built once, later, by the wallet verification setup.
  createStatusListTrustAnchors(options.trustAnchorPems);
  createStatusListUriAllowlist(options.uriAllowlist);
}

/**
 * Build this deployment's credential status checker (#297, #378).
 *
 * Call ONCE per process and share the result. The verified-list cache, the
 * in-flight coalescing map and the per-origin breaker are properties of the
 * INSTANCE: a per-request checker has a cold cache, a breaker that never trips,
 * and turns every login into an outbound round-trip.
 *
 * The breaker is passed EXPLICITLY. `createCredentialStatusChecker` defaults to
 * `ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER`, which never intervenes — a real
 * deployment wants the 5-consecutive-failures-per-origin breaker, which does not
 * make an outage permissive (an open circuit is the same refusal a failed fetch
 * produces) but does make it cheap to absorb.
 *
 * @param options - see {@link ConfiguredCredentialStatusOptions}.
 * @returns the checker, or `undefined` when this deployment configured no status
 * checking at all. `undefined` is not a permissive value: presentation
 * validation reports `statusChecked: 'not-required'` for it, and a profile whose
 * `requireCredentialStatus` is `true` never reaches this code because
 * `assertCredentialStatusProvisioned` already refused the boot.
 * @throws Error / InvalidConfigurationError — see
 * {@link assertCredentialStatusConfigUsable}, which this runs first.
 */
export function createConfiguredCredentialStatusChecker(
  options: ConfiguredCredentialStatusOptions
): CredentialStatusChecker | undefined {
  assertCredentialStatusConfigUsable(options);

  if (!credentialStatusProvisioningOf(options).trustAnchors) return undefined;

  return createCredentialStatusChecker({
    trustAnchors: createStatusListTrustAnchors(options.trustAnchorPems),
    uriAllowlist: createStatusListUriAllowlist(options.uriAllowlist),
    breaker: createStatusEndpointBreaker(),
    ...(options.onAudit !== undefined ? { onAudit: options.onAudit } : {}),
  });
}
