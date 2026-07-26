/**
 * Outbound presentation-request state (issue #233, Phase A).
 *
 * Every OID4VP Authorization Request QAuth sends carries two unguessable
 * values, and this module mints them:
 *
 *   - `state` — the CORRELATOR. The wallet posts it back to the `response_uri`,
 *     and it is the ONLY thing tying that unauthenticated POST to a request we
 *     made. It is therefore a bearer secret: whoever holds it can consume the
 *     request exactly once.
 *   - `nonce` — the FRESHNESS binding, replayed inside the Key Binding JWT so a
 *     Presentation cannot be captured and replayed against a later request
 *     (OID4VP 1.0 §14.1). This layer only STORES it; comparing it against a
 *     KB-JWT is #234's job.
 *
 * ## Why `state` is stored HASHED and `nonce` is not
 *
 * They are not the same kind of value even though they are minted the same way.
 *
 * `state` is presented to us as a credential — the DB row is looked up BY it —
 * so a read-only leak of the table would otherwise hand an attacker everything
 * needed to consume a pending request. Storing SHA-256 and looking up by digest
 * removes that, exactly as `email_verification_tokens.token_hash` and
 * `refresh_tokens.token_hash` already do. Lookup is a unique-index probe on the
 * digest, never a comparison, so there is no timing channel to close.
 *
 * `nonce` is never presented to us and never looked up; it must be handed to
 * #234 VERBATIM to be compared against the KB-JWT's `nonce` claim. Hashing it
 * would make it useless for the one job it has. It is not a lookup key, so a
 * leaked nonce alone consumes nothing.
 */

import { createHash, randomBytes } from 'node:crypto';

/**
 * Entropy for `state` and `nonce`, in bytes.
 *
 * 256 bits, matching the workspace's other unguessable-token sizes. OID4VP 1.0
 * §14.1 requires the `nonce` to have "sufficient entropy"; `state` needs the
 * same because it is the single-use consumption key.
 */
export const OID4VP_SECRET_BYTES = 32;

/**
 * Default lifetime of a presentation request.
 *
 * Five minutes: long enough for a human to pick up a phone, open a wallet and
 * approve a presentation; short enough that a leaked `state` is worth little.
 * The redemption path treats expiry as a hard rejection, so this is a real
 * bound rather than a hint.
 */
export const DEFAULT_OID4VP_REQUEST_TTL_MS = 5 * 60 * 1000;

/**
 * Ceiling on a caller-supplied TTL.
 *
 * A request-state row is an unauthenticated-consumption primitive that lives
 * until it expires; letting a caller pick an arbitrary lifetime would let one
 * misconfiguration keep thousands of them redeemable for a day.
 */
export const MAX_OID4VP_REQUEST_TTL_MS = 15 * 60 * 1000;

/** Hex-encoded SHA-256 digest length — the `state_hash` column width. */
export const OID4VP_STATE_HASH_LENGTH = 64;

/**
 * The two secrets bound to one Authorization Request.
 *
 * `state` and `nonce` are returned in the CLEAR because both go on the wire in
 * the request. Only `stateHash` is ever persisted (see the module JSDoc).
 */
export interface Oid4vpRequestSecrets {
  /** Sent as the request's `state`; the wallet posts it back. */
  readonly state: string;
  /** Sent as the request's `nonce`; the wallet echoes it inside the KB-JWT. */
  readonly nonce: string;
  /** SHA-256 of {@link state}, hex — the value the store is keyed by. */
  readonly stateHash: string;
}

/**
 * Mint the `state`/`nonce` pair for one Authorization Request.
 *
 * `randomBytes` (CSPRNG) rather than anything derived from a request, a clock or
 * a counter: `state` is a consumption credential and `nonce` is a replay
 * defence, and both fail completely if predictable.
 */
export function generateOid4vpRequestSecrets(): Oid4vpRequestSecrets {
  const state = randomBytes(OID4VP_SECRET_BYTES).toString('base64url');
  const nonce = randomBytes(OID4VP_SECRET_BYTES).toString('base64url');

  return { state, nonce, stateHash: hashOid4vpState(state) };
}

/**
 * Digest a `state` for storage or lookup.
 *
 * The SAME function must be used on both sides — mint and redeem — or a
 * legitimate response will never correlate. A plain SHA-256 (not a password
 * hash) is correct here: `state` carries 256 bits of CSPRNG entropy, so there is
 * no dictionary to slow down, and redemption sits on the request path.
 *
 * @param state - the raw `state` value, as it appears on the wire.
 */
export function hashOid4vpState(state: string): string {
  return createHash('sha256').update(state, 'utf8').digest('hex');
}

/**
 * Resolve an absolute expiry from a TTL, clamped fail-closed.
 *
 * @param ttlMs - requested lifetime; defaults to {@link DEFAULT_OID4VP_REQUEST_TTL_MS}.
 * @param now - injectable clock, in epoch milliseconds.
 * @throws Error when the TTL is not a positive integer or exceeds the ceiling.
 */
export function resolveOid4vpExpiry(
  ttlMs: number = DEFAULT_OID4VP_REQUEST_TTL_MS,
  now: number = Date.now()
): number {
  if (!Number.isInteger(ttlMs) || ttlMs <= 0) {
    throw new Error(
      `An OID4VP request TTL must be a positive whole number of milliseconds; received ${ttlMs}.`
    );
  }

  if (ttlMs > MAX_OID4VP_REQUEST_TTL_MS) {
    throw new Error(
      `An OID4VP request TTL of ${ttlMs}ms exceeds the ${MAX_OID4VP_REQUEST_TTL_MS}ms ceiling. A pending request state is redeemable by whoever holds its 'state', so its lifetime is bounded deliberately.`
    );
  }

  return now + ttlMs;
}
