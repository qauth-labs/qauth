import { AsyncLocalStorage } from 'node:async_hooks';

import {
  createConfiguredCredentialStatusChecker,
  createConfiguredIssuerKeyResolver,
  type CredentialStatusAuditEvent,
  type CredentialStatusChecker,
  type IssuerKeyResolver,
  resolveSubjectResolution,
  resolveTrustRegistry,
  type SubjectResolutionConfig,
  type TrustRegistry,
  type VerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';
import { resolveStatusListTrustAnchorPems } from '@qauth-labs/server-config';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveWalletLoginCapability } from './wallet-login-request';

/**
 * The deployment's wallet VERIFICATION posture, resolved per request
 * (issue #238; composes #234, #236, #299 and #300).
 *
 * Three independent decisions have to line up before a presented credential can
 * become anything, and each one is configured separately on purpose:
 *
 * | question | source |
 * | --- | --- |
 * | what protocol posture do we run? | `VerifierProfile` (#299) |
 * | which key does an issuer sign with? | `OID4VP_ISSUER_JWKS` (#234) |
 * | which issuers does this realm accept? | `OID4VP_TRUSTED_ISSUERS` (#236) |
 * | is the credential still live? | `OID4VP_STATUS_LIST_*` (#297) |
 * | which account does a credential belong to? | `OID4VP_SUBJECT_RESOLUTION` (#300) |
 *
 * Resolving them in ONE place is what keeps the login flow and the linking flow
 * (#238) from drifting into two different postures — the drift that
 * `resolveVerifierProfile` and `resolveTrustRegistry` each exist to prevent
 * within their own question.
 *
 * ## Fail-closed, and two distinguishable ways
 *
 * `undefined` means *this deployment cannot serve wallet flows* — no profile, no
 * requested `vct`, a posture needing capabilities that are not there. Callers
 * turn it into "wallet sign-in is not available", never into a permissive
 * fallback (#296, LOCKED).
 *
 * A THROW means the deployment is half-configured: a strategy was selected and
 * its settings are missing or unusable. `resolveSubjectResolution` is explicit
 * about where that lands — a deployment that configures nothing gets
 * `asserted-lookup` from the profile and then a throw, because it named no
 * binding claims, and *"`asserted-lookup` without an entitlement check is
 * ADR-009 §1's total authentication bypass"*. Callers surface it as an operator
 * error; they must not degrade it to "no wallet login today", because that would
 * make a misconfiguration look like an intentional opt-out.
 */

/** Everything the verification path needs, resolved together. */
export interface WalletVerificationSetup {
  /** The active `VerifierProfile` (#299). */
  readonly profile: VerifierProfile;
  /** The realm's subject-resolution configuration (#300). */
  readonly subjectResolution: SubjectResolutionConfig;
  /** The configured issuer key backend (#234). */
  readonly resolveIssuerKey: IssuerKeyResolver;
  /**
   * The deployment's credential-revocation checker (#297), or `undefined` when
   * no status checking is configured.
   *
   * REQUIRED-but-nullable rather than optional: a caller assembling this object
   * must state the answer, and typecheck — not a code review — is what enforces
   * that. `undefined` is a decision ("this deployment configured none"), and it
   * is safe only because a profile that MANDATES status has already been refused
   * at boot by `assertCredentialStatusProvisioned`.
   */
  readonly credentialStatus: CredentialStatusChecker | undefined;
}

/**
 * The issuer key resolver, built ONCE.
 *
 * `createStaticIssuerKeyResolver` validates every entry eagerly and throws on a
 * malformed one, which is right at bootstrap and wrong per request. Memoized
 * rather than module-initialised so importing this file cannot take the process
 * down for a deployment that never enables wallet federation — and so the tests
 * that stub `env` are not fighting an import-time side effect.
 */
let cachedIssuerKeyResolver: IssuerKeyResolver | undefined;

function issuerKeyResolver(): IssuerKeyResolver {
  cachedIssuerKeyResolver ??= createConfiguredIssuerKeyResolver(env.OID4VP_ISSUER_JWKS);
  return cachedIssuerKeyResolver;
}

/**
 * Where credential-status audit events are written (#297).
 *
 * A module-level indirection rather than a logger captured inside the checker's
 * closure, because the two have different lifetimes: the checker is built ONCE
 * per process (it owns the verified-list cache, the in-flight coalescing map and
 * the endpoint breaker) while a `FastifyInstance` is not guaranteed to be —
 * tests build several. Capturing the first instance's logger would send every
 * later audit record to a closed one. Refreshed on each
 * {@link resolveWalletVerificationSetup} call, so events always land on the
 * logger of the server that is actually serving.
 */
let auditLogger: FastifyBaseLogger | undefined;

/**
 * Write one status-check outcome to the SERVER log (#297, #378).
 *
 * ## Every check, not only the refusals
 *
 * A revocation-rejection counter with no denominator cannot tell "we started
 * rejecting everything" from "traffic grew", so accepted checks are recorded
 * too — and at `info`, not `debug`, because `debug` is off in every deployment
 * that would want the metric and a denominator nobody records is not a
 * denominator. Refusals go to `warn` so they stand out without the operator
 * having to query.
 *
 * ## Server-side only, and that is a hard rule
 *
 * The event carries `statusListUri` and `idx`, which the WALLET chose: they are
 * attacker-influenced strings. They are exactly what an operator needs to tell a
 * revoked credential from a dead status endpoint, and exactly what a client must
 * never be told — the client-visible refusal is the single non-enumerating
 * `InvalidCredentialsError` and stays that way. Nothing here may be copied into
 * a response body, an error, or a header.
 *
 * Never throws: the sink is invoked from inside the checker, and a logger that
 * threw would turn a contained 401 into a 500. The checker contains it as well,
 * so neither end is load-bearing alone.
 */
function recordCredentialStatusAudit(event: CredentialStatusAuditEvent): void {
  // Prefer the request-scoped correlation established by
  // `runWithCredentialStatusAuditContext`; fall back to the server logger, which
  // still records the event but cannot say which login produced it.
  const scope = credentialStatusAuditScope.getStore();
  const log = scope?.log ?? auditLogger;
  if (log === undefined) return;

  const record = scope === undefined ? { ...event } : { ...event, realmId: scope.realmId };

  if (event.decision === 'rejected') {
    log.warn(record, 'credential status check refused a credential');
    return;
  }
  log.info(record, 'credential status check accepted a credential');
}

/**
 * Request-scoped correlation for {@link recordCredentialStatusAudit} (#378).
 *
 * ## Why an async store rather than a parameter
 *
 * The audit sink is bound ONCE, when the checker is constructed, because the
 * checker is a process-wide singleton that owns the verified-list cache, the
 * in-flight coalescing map and the endpoint breaker. There is therefore no
 * parameter path from a route to `onAudit` — the same lifetime mismatch that
 * made {@link auditLogger} a module-level indirection in the first place.
 * `AsyncLocalStorage` closes it without widening `CredentialStatusCheckOptions`,
 * so #297's checker keeps taking the `status` claim as `unknown` and keeps
 * testing standalone.
 *
 * ## Why it matters
 *
 * Status refusals deliberately bypass `onRefusal` — the checker's fine-grained
 * reason must never reach the wire, so `onAudit` is the ONLY server-side channel
 * that carries it. An operator reading `credential status check refused a
 * credential` with no request id and no realm cannot tie it to the login attempt
 * that produced it, which makes the one diagnostic the design leaves them
 * unusable for diagnosis.
 *
 * Safe when unset: an unwrapped caller falls back to the server logger and loses
 * only the correlation, never the event.
 */
const credentialStatusAuditScope = new AsyncLocalStorage<CredentialStatusAuditScope>();

/** Request-scoped correlation carried alongside a status audit event. */
interface CredentialStatusAuditScope {
  /** The request logger, so audit lines carry Fastify's `reqId`. */
  readonly log: FastifyBaseLogger;
  /** The realm the presentation was made in. */
  readonly realmId: string;
}

/**
 * Run `fn` with status audit events correlated to one request.
 *
 * Wrap the narrowest scope that can emit a status check — the presentation
 * verification call, not the whole handler — so no unrelated event inherits the
 * correlation.
 *
 * @param scope - the request logger and realm to stamp onto each event.
 * @param fn - the work to run; its result is returned unchanged.
 * @returns whatever `fn` returns.
 */
export function runWithCredentialStatusAuditContext<T>(
  scope: CredentialStatusAuditScope,
  fn: () => T
): T {
  return credentialStatusAuditScope.run(scope, fn);
}

/**
 * Whether a request-scoped audit correlation is already established.
 *
 * Lets an inner seam supply a coarser fallback scope without overwriting a
 * richer one a route already set.
 */
export function hasCredentialStatusAuditContext(): boolean {
  return credentialStatusAuditScope.getStore() !== undefined;
}

/**
 * The credential status checker, built ONCE (#297).
 *
 * Memoized for a stronger reason than the issuer key resolver above: this object
 * OWNS state. The verified-list cache, the single-flight map that coalesces
 * concurrent lookups of the same URI, and the per-origin circuit breaker are all
 * properties of the instance. Rebuilding it per request would give every login a
 * cold cache, a breaker that can never reach its threshold, and an outbound
 * round-trip — turning a defence into a latency tax and a thundering herd.
 *
 * `undefined` is a legitimate memoized value ("this deployment configured no
 * status checking"), so the built flag is separate from the value — `??=` would
 * re-run the factory on every call for exactly the deployments that configured
 * nothing.
 */
let cachedCredentialStatusChecker: CredentialStatusChecker | undefined;
let credentialStatusCheckerBuilt = false;

function credentialStatusChecker(): CredentialStatusChecker | undefined {
  if (!credentialStatusCheckerBuilt) {
    // Throws on a half-configured or unparseable status configuration. The boot
    // already ran the same assertion (`assertCredentialStatusConfigUsable` in
    // `app.ts`), so reaching a throw here means configuration changed under a
    // running process; it surfaces as an operator error, never as a permissive
    // fallback.
    cachedCredentialStatusChecker = createConfiguredCredentialStatusChecker({
      trustAnchorPems: resolveStatusListTrustAnchorPems(env),
      uriAllowlist: env.OID4VP_STATUS_LIST_URI_ALLOWLIST,
      onAudit: recordCredentialStatusAudit,
    });
    credentialStatusCheckerBuilt = true;
  }
  return cachedCredentialStatusChecker;
}

/**
 * Resolve the deployment's wallet verification posture.
 *
 * @param fastify - server instance, for logging.
 * @returns the setup, or `undefined` when wallet flows must not be served.
 * @throws InvalidConfigurationError when a subject-resolution strategy is
 * selected but half-configured, or when the status-list configuration is
 * half-configured or unusable (#297) — both are operator errors, and neither may
 * degrade into "wallet sign-in is not available today".
 */
export function resolveWalletVerificationSetup(
  fastify: FastifyInstance
): WalletVerificationSetup | undefined {
  // Point the status audit sink at THIS server's logger before anything can
  // emit an event. See {@link auditLogger} for why it is not captured once.
  auditLogger = fastify.log;

  const capability = resolveWalletLoginCapability(fastify);
  if (capability === undefined) return undefined;

  // The realm argument is null because `realms.subject_resolution` does not
  // exist yet (#300) — the same call shape `resolveVerifierProfile` is given
  // everywhere else, so per-realm selection lands in one edit.
  const subjectResolution = resolveSubjectResolution(null, env, capability.profile);
  if (subjectResolution === undefined) {
    fastify.log.warn(
      'wallet flows unavailable: no usable subject-resolution strategy is selected (#300)'
    );
    return undefined;
  }

  return {
    profile: capability.profile,
    subjectResolution,
    resolveIssuerKey: issuerKeyResolver(),
    credentialStatus: credentialStatusChecker(),
  };
}

/**
 * Resolve the issuer allowlist in force for a realm (#236).
 *
 * Keyed by `realms.name`, which is what `OID4VP_TRUSTED_ISSUERS` is authored
 * against — realm ids are database-minted UUIDs an operator cannot know when
 * writing configuration.
 *
 * @param fastify - server instance, for its repositories.
 * @param realmId - the realm the presentation request was created in.
 * @returns the realm's registry. NEVER `undefined` and never permissive: a realm
 * that cannot be read at all resolves to trusting nobody, which refuses every
 * presentation rather than accepting one from an unknown policy.
 */
export async function resolveRealmTrustRegistry(
  fastify: FastifyInstance,
  realmId: string
): Promise<TrustRegistry> {
  let realmName: string | null = null;
  try {
    const realm = await fastify.repositories.realms.findById(realmId);
    realmName = realm?.name ?? null;
  } catch (error) {
    // Contained: an unreadable realm must land on deny-all, not on a 500 that
    // an attacker can tell apart from a refusal.
    fastify.log.error({ err: error, realmId }, 'failed to read the realm for its issuer allowlist');
  }

  return resolveTrustRegistry(
    { name: realmName },
    { OID4VP_TRUSTED_ISSUERS: env.OID4VP_TRUSTED_ISSUERS }
  );
}
