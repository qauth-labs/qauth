import type { InvalidCredentialsError } from '@qauth-labs/shared-errors';

import type { TrustRegistry } from '../trust/trust-registry';
import {
  credentialStatusRejection,
  type CredentialStatusRejectionReason,
} from './credential-status-rejection';
import {
  ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER,
  type StatusEndpointBreaker,
} from './status-endpoint-breaker';
import { readStatusListEntry } from './status-list-bits';
import {
  type CachedStatusList,
  createInMemoryStatusListCache,
  type StatusListCache,
} from './status-list-cache';
import { NO_STATUS_LIST_TRUST_ANCHORS, type StatusListTrustAnchors } from './status-list-chain';
import {
  createHttpsStatusListFetch,
  type StatusListFetch,
  type StatusListFetchResult,
} from './status-list-fetch';
import { parseStatusListReference, type StatusListReference } from './status-list-reference';
import { CREDENTIAL_STATUS, TOKEN_STATUS_LIST_DRAFT } from './status-list-spec';
import { type VerifiedStatusList, verifyStatusListToken } from './status-list-token';
import { DENY_ALL_STATUS_LIST_URI_ALLOWLIST, type StatusListUriAllowlist } from './status-list-uri';

/**
 * Credential revocation via Token Status List — the orchestrator (issue #297).
 *
 * ## The one thing this module must never do
 *
 * Return "valid" for a credential whose status it did not establish. Every
 * branch below either reaches a bit that says `VALID`, or refuses. There is no
 * timeout fallback, no stale-cache-on-error path, no "the endpoint is down so
 * carry on" — because each of those is, in effect, a way for an attacker who
 * can degrade a third party's availability to un-revoke credentials. #297 puts
 * it as an acceptance criterion: *"a credential whose status cannot be verified
 * is rejected (fail closed), never accepted."*
 *
 * The cost is real and is accepted deliberately: a status endpoint outage
 * blocks logins for that issuer's users. The circuit breaker makes that outage
 * cheap to absorb; it does not make it permissive.
 *
 * ## Why it takes `unknown`
 *
 * The input is the credential's `status` claim and nothing else. #234 owns
 * SD-JWT VC presentation validation in a parallel lane, and a status checker
 * that consumed its output would couple two parsers and could not be tested
 * without constructing a whole presentation. `unknown` in, a decision out.
 *
 * ## Pipeline
 *
 * 1. parse the `status` claim into `{ idx, uri }` — absent is a policy decision
 *    (`statusRequired`), malformed is always a refusal;
 * 2. SSRF allowlist on the URI, BEFORE any socket is opened;
 * 3. cache lookup — the common path, and the reason a login is not an HTTP
 *    round-trip;
 * 4. circuit breaker;
 * 5. single-flight fetch + full verification (signature, anchored `x5c`, `typ`,
 *    `sub`, `iss` binding);
 * 6. bounded decompression and the bit lookup;
 * 7. `VALID` accepts, everything else refuses.
 *
 * Every outcome — accepting ones included — is reported to
 * {@link CredentialStatusCheckerConfig.onAudit}, so revocation rejections are
 * countable and an operator can tell a revoked credential from a dead endpoint
 * even though a client cannot.
 */

/** Default outbound budget for one status fetch. */
const DEFAULT_REQUEST_TIMEOUT_MS = 3_000;

/**
 * Default ceiling on how long a verified status list may be reused.
 *
 * Five minutes. This is the revocation-freshness knob: it bounds the window in
 * which an already-revoked credential is still accepted, and it is capped here
 * rather than left to the issuer because `ttl` is the ISSUER's claim and an
 * issuer that publishes `ttl: 86400` would be choosing QAuth's freshness for
 * it. The effective TTL is always the minimum of this, `ttl` and `exp`.
 */
const DEFAULT_MAX_CACHE_TTL_SECONDS = 300;

/**
 * The result of loading (fetching + verifying) a status list.
 *
 * Internal. It exists so the single-flight promise carries its own failure
 * reason instead of the orchestrator keeping one in a shared variable, which
 * would be a race between coalesced callers.
 */
type StatusListLoad =
  | { readonly outcome: 'loaded'; readonly statusList: VerifiedStatusList }
  | { readonly outcome: 'failed'; readonly reason: CredentialStatusRejectionReason };

/** The decision a status check reached. */
export type CredentialStatusDecision =
  | { readonly decision: 'valid' }
  | { readonly decision: 'rejected'; readonly reason: CredentialStatusRejectionReason };

/**
 * One status-check outcome, for audit and metrics (#297).
 *
 * Emitted for accepted checks too, not only refusals: a revocation-rejection
 * counter with no denominator cannot distinguish "we started rejecting
 * everything" from "traffic grew".
 *
 * Carries the status list URI and index. Both are attacker-influenced strings
 * and belong in a server-side log, NEVER in a response — see
 * `credential-status-rejection.ts`.
 */
export interface CredentialStatusAuditEvent {
  /** `accepted` only when the bit read `VALID`. */
  readonly decision: 'accepted' | 'rejected';
  /** Present on every refusal; the closed server-side vocabulary. */
  readonly reason?: CredentialStatusRejectionReason;
  /** The `status_list.uri` consulted, when one could be parsed. */
  readonly statusListUri?: string;
  /** The `status_list.idx` consulted, when one could be parsed. */
  readonly idx?: number;
  /** The raw bit value read, when a list was successfully decoded. */
  readonly statusValue?: number;
  /** Whether the list came from cache. */
  readonly cacheHit: boolean;
  /** Whether a network request was actually issued. */
  readonly fetched: boolean;
  /** Wall-clock duration of the check, in milliseconds. */
  readonly durationMs: number;
  /** The pinned specification revision, so audit records self-describe. */
  readonly spec: typeof TOKEN_STATUS_LIST_DRAFT;
}

/** Wiring for {@link createCredentialStatusChecker}. */
export interface CredentialStatusCheckerConfig {
  /**
   * Anchors the Status List Token's `x5c` chain must terminate at. Defaults to
   * none, which refuses every token — an unconfigured deployment must not be a
   * permissive one.
   */
  readonly trustAnchors?: StatusListTrustAnchors;
  /**
   * Where status lists may be fetched from (SSRF boundary). Defaults to
   * permitting nothing.
   */
  readonly uriAllowlist?: StatusListUriAllowlist;
  /** Outbound transport. Defaults to the platform HTTPS implementation. */
  readonly fetch?: StatusListFetch;
  /** Verified-list cache. Defaults to a bounded in-process cache. */
  readonly cache?: StatusListCache;
  /** Endpoint breaker. Defaults to one that never intervenes. */
  readonly breaker?: StatusEndpointBreaker;
  /** Optional extra identity constraint on the status issuer (#236). */
  readonly issuerTrustRegistry?: TrustRegistry;
  /** Per-fetch abort budget in milliseconds. */
  readonly requestTimeoutMs?: number;
  /** Ceiling on cache reuse in seconds; see {@link DEFAULT_MAX_CACHE_TTL_SECONDS}. */
  readonly maxCacheTtlSeconds?: number;
  /** Clock skew tolerance in seconds applied to the token's `exp`. */
  readonly clockToleranceSeconds?: number;
  /** Epoch-millisecond clock; injectable for deterministic tests. */
  readonly now?: () => number;
  /** Audit sink. Must not throw; a throw is contained and ignored. */
  readonly onAudit?: (event: CredentialStatusAuditEvent) => void;
}

/** Per-check policy, supplied by the profile layer. */
export interface CredentialStatusCheckOptions {
  /**
   * Whether a credential MUST carry a status mechanism — i.e.
   * `VerifierProfile.requireCredentialStatus`. When `true`, a credential with
   * no `status` claim is refused; when `false`, it is accepted unchecked,
   * because base OID4VP 1.0 does not mandate a revocation mechanism and there
   * is nothing to consult.
   *
   * Defaults to `true`. The safe default is the one that refuses: a caller that
   * forgets to pass the profile's posture gets the stricter behaviour, not the
   * looser one.
   */
  readonly statusRequired?: boolean;
}

/** The status gate #234 (and any other credential consumer) calls. */
export interface CredentialStatusChecker {
  /**
   * Decide, without throwing.
   *
   * @param status - the credential's `status` claim, as parsed JSON.
   * @param options - per-check policy.
   */
  resolveCredentialStatus(
    status: unknown,
    options?: CredentialStatusCheckOptions
  ): Promise<CredentialStatusDecision>;

  /**
   * Assert the credential is not revoked, throwing the single non-enumerating
   * refusal otherwise.
   *
   * Throws rather than returning a boolean for the same reason
   * `assertIssuerTrusted` does: a caller must not be able to proceed by
   * ignoring the result.
   *
   * @throws InvalidCredentialsError whenever `VALID` is not positively
   * established.
   */
  assertCredentialNotRevoked(
    status: unknown,
    options?: CredentialStatusCheckOptions
  ): Promise<void>;
}

/**
 * A checker that refuses everything with a status claim and requires one.
 *
 * The value an unconfigured deployment should hold, so "status checking is not
 * wired up" is an object that fails closed rather than a `null` a call site
 * might skip past — the same role `DENY_ALL_TRUST_REGISTRY` plays for issuer
 * trust.
 */
export const DENY_ALL_CREDENTIAL_STATUS_CHECKER: CredentialStatusChecker = Object.freeze({
  resolveCredentialStatus: async (): Promise<CredentialStatusDecision> => ({
    decision: 'rejected',
    reason: 'uri-not-permitted',
  }),
  assertCredentialNotRevoked: async (): Promise<void> => {
    throw credentialStatusRejection('uri-not-permitted');
  },
});

/** Report an audit event without ever letting the sink become the fault. */
function reportAudit(
  sink: ((event: CredentialStatusAuditEvent) => void) | undefined,
  event: CredentialStatusAuditEvent
): void {
  if (sink === undefined) return;
  try {
    sink(event);
  } catch {
    // A logger that throws must not convert a contained 401 into a 500.
  }
}

/** Map a decoded bit value onto a decision. */
function decideFromStatusValue(value: number): CredentialStatusDecision {
  if (value === CREDENTIAL_STATUS.VALID) return { decision: 'valid' };
  if (value === CREDENTIAL_STATUS.INVALID) return { decision: 'rejected', reason: 'revoked' };
  if (value === CREDENTIAL_STATUS.SUSPENDED) return { decision: 'rejected', reason: 'suspended' };
  // Application-specific and reserved values: this deployment has not been told
  // what they mean, and "unknown" is not "valid".
  return { decision: 'rejected', reason: 'status-unknown' };
}

/**
 * Build a credential status checker (#297).
 *
 * @param config - see {@link CredentialStatusCheckerConfig}.
 * @returns a checker; safe to share across requests and concurrency-safe.
 */
export function createCredentialStatusChecker(
  config: CredentialStatusCheckerConfig = {}
): CredentialStatusChecker {
  const anchors: StatusListTrustAnchors = config.trustAnchors ?? NO_STATUS_LIST_TRUST_ANCHORS;
  const allowlist: StatusListUriAllowlist =
    config.uriAllowlist ?? DENY_ALL_STATUS_LIST_URI_ALLOWLIST;
  const fetchToken: StatusListFetch = config.fetch ?? createHttpsStatusListFetch();
  const now = config.now ?? ((): number => Date.now());
  // The default cache is handed the SAME clock, so a deployment (or a test)
  // that injects one cannot end up with expiry decided by a different notion
  // of time than the TTL that produced it.
  const cache: StatusListCache = config.cache ?? createInMemoryStatusListCache({ now });
  const breaker: StatusEndpointBreaker = config.breaker ?? ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER;
  const requestTimeoutMs =
    config.requestTimeoutMs !== undefined &&
    Number.isFinite(config.requestTimeoutMs) &&
    config.requestTimeoutMs > 0
      ? config.requestTimeoutMs
      : DEFAULT_REQUEST_TIMEOUT_MS;
  const maxCacheTtlSeconds =
    config.maxCacheTtlSeconds !== undefined &&
    Number.isFinite(config.maxCacheTtlSeconds) &&
    config.maxCacheTtlSeconds >= 0
      ? config.maxCacheTtlSeconds
      : DEFAULT_MAX_CACHE_TTL_SECONDS;

  /**
   * In-flight fetch+verify per URI.
   *
   * Without it, N concurrent logins against a cold cache produce N identical
   * outbound requests — the thundering herd that makes a cache useless exactly
   * when it matters most (start-up, cache expiry, an issuer's peak). Entries
   * are removed when the promise settles, so the map is bounded by concurrency
   * rather than by anything an attacker chooses.
   *
   * The promise resolves to a RESULT rather than to `VerifiedStatusList |
   * undefined` so the failure reason travels with it. Carrying the reason in a
   * closure variable instead would be shared mutable state across coalesced
   * callers, and a race there would mislabel an audit record.
   */
  const inFlight = new Map<string, Promise<StatusListLoad>>();

  /**
   * Compute how long a verified list may be cached.
   *
   * The minimum of the operator ceiling, the issuer's `ttl`, and the time left
   * before `exp`. Zero or less means "do not cache" rather than "cache
   * briefly": storing an entry that is already stale only evicts a live one.
   */
  const cacheTtlMs = (statusList: VerifiedStatusList, at: number): number => {
    let ttlMs = maxCacheTtlSeconds * 1000;
    if (statusList.ttlSeconds !== undefined) {
      ttlMs = Math.min(ttlMs, statusList.ttlSeconds * 1000);
    }
    if (statusList.expiresAtMs !== undefined) {
      ttlMs = Math.min(ttlMs, statusList.expiresAtMs - at);
    }
    return ttlMs;
  };

  const fetchAndVerify = async (reference: StatusListReference): Promise<StatusListLoad> => {
    // The transport contract says it must never throw, and a contract is not
    // an enforcement — a caller-supplied transport is third-party code on the
    // login path. Containing the throw is the fail-closed reading: a transport
    // that could not answer has not established status, which is the same
    // refusal as an endpoint that answered badly. Letting it escape would turn
    // a contained 401 into a 500 and make a network condition observable in
    // QAuth's own response code.
    let result: StatusListFetchResult;
    try {
      result = await fetchToken({ uri: reference.uri, timeoutMs: requestTimeoutMs });
    } catch {
      breaker.recordFailure(reference.uri);
      return { outcome: 'failed', reason: 'endpoint-unavailable' };
    }

    if (result.outcome !== 'ok') {
      breaker.recordFailure(reference.uri);
      return { outcome: 'failed', reason: 'endpoint-unavailable' };
    }

    const verification = await verifyStatusListToken({
      token: result.token,
      expectedUri: reference.uri,
      anchors,
      now: new Date(now()),
      ...(config.clockToleranceSeconds !== undefined
        ? { clockToleranceSeconds: config.clockToleranceSeconds }
        : {}),
      ...(config.issuerTrustRegistry !== undefined
        ? { issuerTrustRegistry: config.issuerTrustRegistry }
        : {}),
    });

    if (verification.outcome !== 'verified') {
      // A token that will not verify is an endpoint problem as much as a
      // credential one: it counts toward the breaker so a misconfigured or
      // compromised endpoint stops being dialled on every login.
      breaker.recordFailure(reference.uri);
      return { outcome: 'failed', reason: verification.reason };
    }

    breaker.recordSuccess(reference.uri);

    const at = now();
    const ttlMs = cacheTtlMs(verification.statusList, at);
    if (ttlMs > 0) {
      const entry: CachedStatusList = {
        statusList: verification.statusList,
        expiresAtMs: at + ttlMs,
      };
      cache.set(reference.uri, entry);
    }

    return { outcome: 'loaded', statusList: verification.statusList };
  };

  const loadStatusList = async (reference: StatusListReference): Promise<StatusListLoad> => {
    const existing = inFlight.get(reference.uri);
    if (existing !== undefined) return existing;

    const pending = fetchAndVerify(reference).finally(() => {
      inFlight.delete(reference.uri);
    });
    inFlight.set(reference.uri, pending);
    return pending;
  };

  const resolveCredentialStatus = async (
    status: unknown,
    options?: CredentialStatusCheckOptions
  ): Promise<CredentialStatusDecision> => {
    const startedAt = now();
    let cacheHit = false;
    let fetched = false;

    const finish = (
      decision: CredentialStatusDecision,
      extra: { reference?: StatusListReference; statusValue?: number }
    ): CredentialStatusDecision => {
      reportAudit(config.onAudit, {
        decision: decision.decision === 'valid' ? 'accepted' : 'rejected',
        ...(decision.decision === 'rejected' ? { reason: decision.reason } : {}),
        ...(extra.reference !== undefined
          ? { statusListUri: extra.reference.uri, idx: extra.reference.idx }
          : {}),
        ...(extra.statusValue !== undefined ? { statusValue: extra.statusValue } : {}),
        cacheHit,
        fetched,
        durationMs: Math.max(0, now() - startedAt),
        spec: TOKEN_STATUS_LIST_DRAFT,
      });
      return decision;
    };

    const statusRequired = options?.statusRequired ?? true;

    if (status === undefined || status === null) {
      return statusRequired
        ? finish({ decision: 'rejected', reason: 'status-required-but-absent' }, {})
        : finish({ decision: 'valid' }, {});
    }

    const reference = parseStatusListReference(status);
    if (reference === undefined) {
      // A `status` claim that is present but unusable is ALWAYS a refusal, even
      // when the profile does not require status: HAIP §6.1 says a credential
      // that carries `status` must carry `status_list`, and a mechanism we
      // cannot evaluate is a status we have not established.
      return finish({ decision: 'rejected', reason: 'malformed-status-claim' }, {});
    }

    if (!allowlist.permits(reference.uri)) {
      return finish({ decision: 'rejected', reason: 'uri-not-permitted' }, { reference });
    }

    let statusList = cache.get(reference.uri)?.statusList;
    if (statusList !== undefined) {
      cacheHit = true;
    } else {
      if (!breaker.allows(reference.uri)) {
        return finish({ decision: 'rejected', reason: 'circuit-open' }, { reference });
      }
      fetched = true;
      const loaded = await loadStatusList(reference);
      if (loaded.outcome !== 'loaded') {
        return finish({ decision: 'rejected', reason: loaded.reason }, { reference });
      }
      statusList = loaded.statusList;
    }

    const lookup = readStatusListEntry(statusList.lst, statusList.bits, reference.idx);
    if (lookup.outcome === 'out-of-range') {
      return finish({ decision: 'rejected', reason: 'index-out-of-range' }, { reference });
    }
    if (lookup.outcome === 'unreadable') {
      return finish({ decision: 'rejected', reason: 'list-unreadable' }, { reference });
    }

    return finish(decideFromStatusValue(lookup.status), {
      reference,
      statusValue: lookup.status,
    });
  };

  return {
    resolveCredentialStatus,
    async assertCredentialNotRevoked(
      status: unknown,
      options?: CredentialStatusCheckOptions
    ): Promise<void> {
      const outcome = await resolveCredentialStatus(status, options);
      if (outcome.decision !== 'valid') {
        const rejection: InvalidCredentialsError = credentialStatusRejection(outcome.reason);
        throw rejection;
      }
    },
  };
}
