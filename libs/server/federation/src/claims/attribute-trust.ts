import { SELF_REPORTED_SOURCE } from '../providers/password.provider';

/**
 * Trust-ordered attribute selection (ADR-002, issue #229).
 *
 * Claim resolution reads `user_attributes` rows and must decide which source's
 * value QAuth asserts downstream. The trust order is APP-CODE POLICY (per the
 * schema JSDoc in `identity.ts` — deliberately not a DB constraint), and this
 * module is its single implementation: `wallet > oidc_* > self_reported`,
 * where a row a method the plugin loader built from an upstream OpenID
 * Connect preset wrote (#671) ranks with `oidc_*`: the server's own client
 * checked its ID token, as it does a configured `oidc_*` provider's. The core
 * names no provider (ADR-018 §3): the host records how the writing method was
 * built in the row's `provenance` when it writes the row
 * ({@link UPSTREAM_PRESET_PROVENANCE}), so every role ranks it alike, with or
 * without the plugins loaded, and a type another package serves later does
 * not re-rank what an earlier one wrote.
 *
 * Design decisions (adjudicated, #229):
 *
 * - **Unknown sources rank 0 but stay ELIGIBLE** — `verified=true` is the real
 *   trust gate (set by QAuth's own code paths, and by an AuthMethod (#599):
 *   operator-installed code that runs in-process and that ADR-019 Decision 12
 *   trusts, which may write attributes only under its own `type` as their
 *   source, never `wallet` or `self_reported`), so a verified attribute
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
  /** The row's `provenance`, as the host wrote it; null/undefined for none. */
  provenance?: unknown;
}

/**
 * The `user_attributes.provenance` the host writes on every row of a method
 * the plugin loader built from an upstream OpenID Connect preset (#671): the
 * rows that rank with `oidc_*`. Written by the server's code only, never by a
 * plugin, and only under the plugin's own `type` as the source.
 */
export const UPSTREAM_PRESET_PROVENANCE: Readonly<{ builtFrom: 'upstream-oidc-preset' }> =
  Object.freeze({ builtFrom: 'upstream-oidc-preset' });

/** Whether `provenance` is {@link UPSTREAM_PRESET_PROVENANCE}. */
export function isUpstreamPresetProvenance(provenance: unknown): boolean {
  return (
    typeof provenance === 'object' &&
    provenance !== null &&
    !Array.isArray(provenance) &&
    (provenance as Record<string, unknown>)['builtFrom'] === UPSTREAM_PRESET_PROVENANCE.builtFrom
  );
}

/**
 * ADR-002 trust rank: `wallet` (3) > `oidc_*` family and a row of a
 * preset-built method ({@link UPSTREAM_PRESET_PROVENANCE}) (2) >
 * `self_reported` (1) > unknown (0, eligible — see module JSDoc). A
 * provenance never changes the rank of QAuth's own sources.
 */
export function rankAttributeSource(source: string, provenance?: unknown): number {
  if (source === 'wallet') return 3;
  if (source.startsWith('oidc_')) return 2;
  if (source === SELF_REPORTED_SOURCE) return 1;
  if (isUpstreamPresetProvenance(provenance)) return 2;
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
    const byRank =
      rankAttributeSource(b.source, b.provenance) - rankAttributeSource(a.source, a.provenance);
    if (byRank !== 0) return byRank;
    return a.source < b.source ? -1 : a.source > b.source ? 1 : 0;
  })[0];
}
