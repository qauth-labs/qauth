import { SELF_REPORTED_SOURCE } from '../providers/password.provider';

/**
 * Trust-ordered attribute selection (ADR-002, issue #229).
 *
 * Claim resolution reads `user_attributes` rows and must decide which source's
 * value QAuth asserts downstream. The trust order is APP-CODE POLICY (per the
 * schema JSDoc in `identity.ts` — deliberately not a DB constraint), and this
 * module is its single implementation: `wallet > oidc_* > self_reported`.
 *
 * Design decisions (adjudicated, #229):
 *
 * - **Unknown sources rank 0 but stay ELIGIBLE** — `verified=true` is the real
 *   trust gate (set only by first-party code paths), so a verified attribute
 *   from a source this ranking does not yet know loses every tie but is still
 *   emitted when it is the only verified value. Silent claim loss when a
 *   future provider (#231) forgets to extend the ranking would be the worse
 *   failure mode. Extend {@link rankAttributeSource} when adding a source
 *   family.
 * - **Intra-rank ties break lexicographically by `source` (ascending)** — two
 *   verified `oidc_*` providers yield a winner that changes only when the SET
 *   of sources changes, never with write activity (an `updated_at`-based rule
 *   would flap on every #228 upsert). Deterministic but worth revisiting when
 *   #231 links real multi-provider accounts: linking an alphabetically
 *   earlier provider (e.g. `oidc_apple` next to `oidc_google`) changes the
 *   emitted email.
 * - **Expiry is excluded HERE, not in SQL** — the whole "may this attribute be
 *   asserted" decision lives in one pure function with an injected clock, so
 *   the `expiresAt === now` boundary is unit-testable and the repository
 *   stays policy-free.
 */

/** Structural input for {@link selectTrustedAttribute} — satisfied by the
 * infra `UserAttributeRow` without this lib importing the infra layer. */
export interface TrustRankedAttribute {
  /** Attribute origin, e.g. `'wallet' | 'oidc_google' | 'self_reported'`. */
  source: string;
  attrValue: string;
  /** Epoch-ms expiry for VC-derived attributes; null/undefined never expires. */
  expiresAt?: number | null;
}

/**
 * ADR-002 trust rank: `wallet` (3) > `oidc_*` family (2) >
 * `self_reported` (1) > unknown (0, eligible — see module JSDoc).
 */
export function rankAttributeSource(source: string): number {
  if (source === 'wallet') return 3;
  if (source.startsWith('oidc_')) return 2;
  if (source === SELF_REPORTED_SOURCE) return 1;
  return 0;
}

/**
 * Pick the attribute QAuth asserts: highest trust rank among non-expired rows,
 * lexicographic `source` ascending within a rank. Returns undefined when no
 * eligible row remains — the caller then OMITS the claim entirely (never
 * null), per ADR-002 / OIDC Core 1.0.
 *
 * @param rows - Candidate rows; callers pass only `verified = true` rows
 * (the repository read enforces that filter).
 * @param now - Epoch-ms clock; a row with `expiresAt <= now` is excluded.
 */
export function selectTrustedAttribute<T extends TrustRankedAttribute>(
  rows: readonly T[],
  now: number
): T | undefined {
  const eligible = rows.filter((row) => row.expiresAt == null || row.expiresAt > now);
  if (eligible.length === 0) return undefined;

  return [...eligible].sort((a, b) => {
    const byRank = rankAttributeSource(b.source) - rankAttributeSource(a.source);
    if (byRank !== 0) return byRank;
    return a.source < b.source ? -1 : a.source > b.source ? 1 : 0;
  })[0];
}
