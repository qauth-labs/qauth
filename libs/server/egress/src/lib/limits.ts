/** The caps of one egress call. */
export interface EgressLimits {
  /**
   * Time to open the TCP connection and finish the TLS handshake, in
   * milliseconds. It applies to each connection, so to each redirect hop.
   */
  connectTimeoutMs: number;
  /**
   * Time for the whole call, in milliseconds: name resolution, every redirect
   * and the last byte of the response.
   */
  totalTimeoutMs: number;
  /** Largest request body, in bytes. */
  maxRequestBytes: number;
  /** Largest response body, in bytes. Reading stops at the cap. */
  maxResponseBytes: number;
  /** Redirects followed. `0` follows none. */
  maxRedirects: number;
}

/** The caps a call gets unless the client or the call sets its own. */
export const DEFAULT_EGRESS_LIMITS: Readonly<EgressLimits> = Object.freeze({
  connectTimeoutMs: 5_000,
  totalTimeoutMs: 10_000,
  maxRequestBytes: 1024 * 1024,
  maxResponseBytes: 1024 * 1024,
  maxRedirects: 3,
});

const POSITIVE: readonly (keyof EgressLimits)[] = ['connectTimeoutMs', 'totalTimeoutMs'];

/**
 * `base` with `overrides` applied. Every value must be a non-negative integer,
 * and the timeouts must be positive; anything else is a programming error and
 * throws a `TypeError`.
 */
export function mergeLimits(
  base: Readonly<EgressLimits>,
  overrides: Partial<EgressLimits> | undefined
): EgressLimits {
  const limits: EgressLimits = { ...base };
  for (const key of Object.keys(DEFAULT_EGRESS_LIMITS) as (keyof EgressLimits)[]) {
    const value = overrides?.[key];
    if (value === undefined) continue;
    const min = POSITIVE.includes(key) ? 1 : 0;
    if (!Number.isSafeInteger(value) || value < min) {
      throw new TypeError(`egress limit ${key} must be an integer of at least ${min}`);
    }
    limits[key] = value;
  }
  return limits;
}
