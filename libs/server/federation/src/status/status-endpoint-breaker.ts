/**
 * The circuit breaker in front of the status endpoint (issue #297).
 *
 * ## What it protects against
 *
 * A status endpoint that is down does not fail fast. It hangs until the request
 * timeout, and it does so for EVERY login, so an outage at one credential
 * issuer converts into saturated outbound sockets, exhausted request-handler
 * concurrency, and a login path that is slow for users of every OTHER issuer
 * too. The breaker turns the second and subsequent failures into an immediate
 * refusal, so the blast radius of someone else's outage is bounded by the
 * failure threshold rather than by traffic volume.
 *
 * ## Opening the circuit is NOT a fallback to "assume valid"
 *
 * This is the trap a breaker invites — the usual pattern is "trip, then serve
 * degraded", and degraded here would mean accepting credentials whose status is
 * unknown. It does the opposite: an open circuit is an immediate REJECTION, the
 * same one a failed fetch produces. It makes the failure cheaper, never more
 * permissive. Availability of the login path is deliberately traded away in
 * favour of not accepting revoked credentials, which is the whole point of
 * checking status.
 *
 * ## Keyed by origin, not by URI
 *
 * The thing that fails is a host, not a path. Keying by full URI would let an
 * attacker keep the circuit closed by varying the path — each URI accumulating
 * its own failure count, none ever reaching the threshold — and would grow one
 * counter per attacker-chosen string. Keying by origin also means an outage
 * observed on one list protects logins that reference a different list on the
 * same host.
 */

/** Options for {@link createStatusEndpointBreaker}. */
export interface StatusEndpointBreakerOptions {
  /** Consecutive failures that open the circuit. Defaults to 5. */
  readonly failureThreshold?: number;
  /** How long the circuit stays open, in milliseconds. Defaults to 30 000. */
  readonly openDurationMs?: number;
  /** Hard cap on tracked origins; least-recently-touched is dropped. */
  readonly maxTrackedOrigins?: number;
  /** Epoch-millisecond clock; injectable for deterministic tests. */
  readonly now?: () => number;
}

/** The breaker seam. */
export interface StatusEndpointBreaker {
  /**
   * @param uri - the status list URI about to be fetched.
   * @returns whether a request may be attempted right now.
   */
  allows(uri: string): boolean;
  /** Record a successful fetch; closes the circuit for that origin. */
  recordSuccess(uri: string): void;
  /** Record a failed fetch; may open the circuit for that origin. */
  recordFailure(uri: string): void;
}

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_OPEN_DURATION_MS = 30_000;
const DEFAULT_MAX_TRACKED_ORIGINS = 256;

/** Per-origin breaker state. */
interface OriginState {
  consecutiveFailures: number;
  /** Epoch ms until which the circuit is open; 0 when closed. */
  openUntilMs: number;
}

/** Reduce a URI to the origin the breaker counts against. */
function originOf(uri: string): string | undefined {
  try {
    return new URL(uri).origin;
  } catch {
    return undefined;
  }
}

/**
 * Build a per-origin circuit breaker (#297).
 *
 * After `failureThreshold` consecutive failures the origin is refused for
 * `openDurationMs`. When that elapses the NEXT call is allowed through as a
 * probe — a half-open state — and its outcome either closes the circuit or
 * re-opens it for another full duration. The probe is what stops a recovered
 * endpoint from staying dark, and allowing exactly one is what stops recovery
 * from arriving as a thundering herd.
 *
 * A URI that does not parse is refused rather than tracked: it cannot be
 * fetched anyway, and creating a counter for it would let an attacker allocate
 * one map entry per malformed string.
 *
 * @param options - see {@link StatusEndpointBreakerOptions}.
 * @returns a breaker with bounded state.
 */
export function createStatusEndpointBreaker(
  options: StatusEndpointBreakerOptions = {}
): StatusEndpointBreaker {
  const failureThreshold =
    options.failureThreshold !== undefined &&
    Number.isSafeInteger(options.failureThreshold) &&
    options.failureThreshold > 0
      ? options.failureThreshold
      : DEFAULT_FAILURE_THRESHOLD;
  const openDurationMs =
    options.openDurationMs !== undefined &&
    Number.isFinite(options.openDurationMs) &&
    options.openDurationMs > 0
      ? options.openDurationMs
      : DEFAULT_OPEN_DURATION_MS;
  const maxTrackedOrigins =
    options.maxTrackedOrigins !== undefined &&
    Number.isSafeInteger(options.maxTrackedOrigins) &&
    options.maxTrackedOrigins > 0
      ? options.maxTrackedOrigins
      : DEFAULT_MAX_TRACKED_ORIGINS;
  const now = options.now ?? ((): number => Date.now());
  const states = new Map<string, OriginState>();

  const touch = (origin: string): OriginState => {
    const existing = states.get(origin);
    if (existing !== undefined) {
      states.delete(origin);
      states.set(origin, existing);
      return existing;
    }

    const created: OriginState = { consecutiveFailures: 0, openUntilMs: 0 };
    states.set(origin, created);
    while (states.size > maxTrackedOrigins) {
      const oldest = states.keys().next();
      if (oldest.done === true) break;
      states.delete(oldest.value);
    }
    return created;
  };

  return {
    allows(uri: string): boolean {
      const origin = originOf(uri);
      if (origin === undefined) return false;

      const state = states.get(origin);
      if (state === undefined || state.openUntilMs === 0) return true;
      if (now() < state.openUntilMs) return false;

      // Half-open: let exactly ONE probe through. The open window is RE-ARMED
      // rather than cleared, which is what makes "exactly one" true — clearing
      // it would admit every caller that arrived before the probe reported
      // back, i.e. deliver recovery as the thundering herd the probe exists to
      // avoid, and would leave the circuit permanently closed if a probe never
      // reported back at all. `recordSuccess` clears the window on a good
      // probe; the counter is left at the threshold so a failing probe re-opens
      // on its own `recordFailure`.
      state.openUntilMs = now() + openDurationMs;
      return true;
    },

    recordSuccess(uri: string): void {
      const origin = originOf(uri);
      if (origin === undefined) return;
      const state = touch(origin);
      state.consecutiveFailures = 0;
      state.openUntilMs = 0;
    },

    recordFailure(uri: string): void {
      const origin = originOf(uri);
      if (origin === undefined) return;
      const state = touch(origin);
      state.consecutiveFailures += 1;
      if (state.consecutiveFailures >= failureThreshold) {
        state.openUntilMs = now() + openDurationMs;
      }
    },
  };
}

/** A breaker that never intervenes. For tests and single-issuer deployments. */
export const ALWAYS_CLOSED_STATUS_ENDPOINT_BREAKER: StatusEndpointBreaker = Object.freeze({
  allows: (): boolean => true,
  recordSuccess: (): void => undefined,
  recordFailure: (): void => undefined,
});
