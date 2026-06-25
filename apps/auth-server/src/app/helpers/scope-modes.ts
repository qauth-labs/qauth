/**
 * Agent scope modes (ADR-007 §2, issue #184).
 *
 * A small, opinionated taxonomy that bounds what an agent token can do,
 * layered over raw OAuth scopes. Operators get a coarse, legible control
 * (ReadOnly / Admin / Exec) instead of hand-curating scope strings.
 *
 * The modes are expressed as **reserved scopes** so the EXISTING scope
 * machinery enforces them unchanged — `validateScopes` / the realm allowlist
 * / `filterRequestedScopes` / `mcp-guard`'s scope checks all keep working
 * with no parallel claim system. This module only adds the agent-mode CAP
 * check that sits in front of that machinery.
 *
 * Mapping (reserved scope → mode):
 *   - `agent:readonly` → ReadOnly  (read-only access)
 *   - `agent:admin`    → Admin     (administrative; ⊇ ReadOnly)
 *   - `agent:exec`     → Exec      (action-taking; the most privileged)
 *
 * Ordering (cap semantics): readonly < admin < exec. A client capped at
 * mode N may request reserved-mode scopes of rank ≤ N. `Admin` therefore
 * also permits `agent:readonly` (ReadOnly ⊂ Admin), and `Exec` permits all
 * three. A cap is the MAXIMUM mode, not an exact match.
 *
 * TRUST BOUNDARY / DEFAULT-DENY (epic #181 security requirement):
 * `oauth_clients.is_agent` is self-asserted, unverified client input. Agent
 * scope modes therefore must NOT trust that flag alone. Enforcement here is
 * fail-closed:
 *   - A reserved-mode scope is granted ONLY when the client is BOTH
 *     classified as an agent (the fail-closed `isAgentClient` accessor) AND
 *     has a server-side `maxAgentMode` cap that covers the requested mode.
 *   - An omitted / unknown / null cap grants NOTHING (least privilege),
 *     never Exec/Admin — and never ReadOnly without an explicit cap.
 *   - A client omitting `is_agent` to dodge these controls just loses access
 *     to every `agent:*` scope (it is not an agent), which is the safe
 *     outcome.
 */

/** Canonical agent scope-mode identifiers, lowest → highest privilege. */
export const AGENT_MODES = ['readonly', 'admin', 'exec'] as const;

export type AgentMode = (typeof AGENT_MODES)[number];

/** Reserved scope prefix for agent modes. */
export const AGENT_SCOPE_PREFIX = 'agent:';

/** The reserved scope string for each mode (e.g. `agent:readonly`). */
export const AGENT_MODE_SCOPES: Readonly<Record<AgentMode, string>> = {
  readonly: 'agent:readonly',
  admin: 'agent:admin',
  exec: 'agent:exec',
} as const;

/**
 * Cap ordering rank: higher rank ⇒ more privilege. A cap permits every
 * reserved-mode scope whose rank is ≤ the cap's rank (ReadOnly ⊂ Admin ⊂
 * Exec for cap purposes). Kept as an explicit map (not array index) so the
 * ordering is intentional and survives reordering of `AGENT_MODES`.
 */
const AGENT_MODE_RANK: Readonly<Record<AgentMode, number>> = {
  readonly: 1,
  admin: 2,
  exec: 3,
} as const;

/** Map of reserved scope string → its mode, for reverse lookup. */
const SCOPE_TO_MODE: ReadonlyMap<string, AgentMode> = new Map(
  AGENT_MODES.map((mode) => [AGENT_MODE_SCOPES[mode], mode] as const)
);

/**
 * Parse a string into a known {@link AgentMode}, or `null` for anything
 * unrecognised. Fail-closed: an unknown / empty / malformed value is NOT a
 * mode (callers must treat `null` as "no agent privilege"), never silently
 * upgraded to a default mode.
 */
export function parseAgentMode(value: string | null | undefined): AgentMode | null {
  if (typeof value !== 'string') return null;
  return (AGENT_MODES as readonly string[]).includes(value) ? (value as AgentMode) : null;
}

/** True iff `scope` is one of the reserved agent-mode scopes. */
export function isAgentModeScope(scope: string): boolean {
  return SCOPE_TO_MODE.has(scope);
}

/**
 * The {@link AgentMode} a reserved scope maps to, or `null` if `scope` is not
 * a reserved agent-mode scope. (A scope merely starting with `agent:` that is
 * not one of the three reserved scopes returns `null` — it is treated as an
 * ordinary scope subject to the normal allowlist, not a mode.)
 */
export function agentModeForScope(scope: string): AgentMode | null {
  return SCOPE_TO_MODE.get(scope) ?? null;
}

/**
 * True iff `mode` is within the privilege ceiling `cap` — i.e. a client
 * capped at `cap` may be granted `mode`. Fail-closed: a `null` cap (no agent
 * mode configured, or unknown value) permits NOTHING.
 *
 * `isModeWithinCap('readonly', 'admin')` → true   (ReadOnly ⊂ Admin)
 * `isModeWithinCap('exec', 'admin')`     → false  (Exec exceeds the cap)
 * `isModeWithinCap('readonly', null)`    → false  (no cap ⇒ deny)
 */
export function isModeWithinCap(mode: AgentMode, cap: AgentMode | null): boolean {
  if (cap === null) return false;
  return AGENT_MODE_RANK[mode] <= AGENT_MODE_RANK[cap];
}

/**
 * The HIGHEST agent scope mode present in a granted scope set, or `null` when
 * the set carries no reserved agent-mode scope. Used for audit attribution
 * (#186): records the effective mode an agent acted under (e.g. a token
 * granting both `agent:readonly` and `agent:exec` is attributed as `exec`).
 *
 * This is a read-only summarizer over an ALREADY-AUTHORISED scope set — it
 * does not gate anything (the cap is enforced upstream); it only labels the
 * audit row. Returns `null` (not a default mode) when no mode scope is present.
 *
 * Recording only the single highest mode is intentional: it is the effective
 * privilege ceiling the action ran under (and matches the cap rank used by
 * `enforceAgentScopeCap`). No information is lost — the FULL granted scope set,
 * including every `agent:*` scope, is preserved verbatim in the audit row's
 * `metadata.scope`; `scope_mode` is the queryable rollup over that detail.
 */
export function highestAgentModeInScopes(scopes: readonly string[]): AgentMode | null {
  let highest: AgentMode | null = null;
  for (const scope of scopes) {
    const mode = agentModeForScope(scope);
    if (mode === null) continue;
    if (highest === null || AGENT_MODE_RANK[mode] > AGENT_MODE_RANK[highest]) {
      highest = mode;
    }
  }
  return highest;
}

/**
 * Enforce the agent scope-mode cap against a set of already-parsed scopes,
 * BEFORE the ordinary allowlist machinery runs.
 *
 * For every reserved agent-mode scope present in `scopes`, the request is
 * permitted only when the caller is a verified agent (`isAgent === true`,
 * fail-closed) AND the requested mode is within `cap`. Non-mode scopes are
 * ignored here (the normal allowlist handles them).
 *
 * Returns the list of reserved-mode scopes that exceed the cap (or are
 * present on a non-agent / un-capped client). An empty array means the
 * request is within policy. Callers map a non-empty result to
 * `invalid_scope` (RFC 6749 §5.2), consistent with `validateScopes`.
 *
 * @param scopes      Requested scopes (already split/parsed).
 * @param isAgent     The fail-closed agent classification (`isAgentClient`).
 * @param cap         The client's server-side max agent mode (NULL = none).
 */
export function findExceedingAgentScopes(
  scopes: readonly string[],
  isAgent: boolean,
  cap: AgentMode | null
): string[] {
  const exceeding: string[] = [];
  for (const scope of scopes) {
    const mode = agentModeForScope(scope);
    if (mode === null) continue; // not a reserved-mode scope
    // Default-deny: a non-agent client (incl. one that omitted is_agent) or
    // a client with no cap can never hold an agent-mode scope.
    if (!isAgent || !isModeWithinCap(mode, cap)) {
      exceeding.push(scope);
    }
  }
  return exceeding;
}
