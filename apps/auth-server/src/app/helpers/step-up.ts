import { AGENT_MODE_SCOPES } from './scope-modes';

/**
 * Step-up authentication before dangerous operations (ADR-007 §2, issue #185).
 *
 * `mcp-guard` already emits the runtime `403 insufficient_scope` +
 * `WWW-Authenticate` challenge when a resource needs a scope the presented
 * token lacks (shipped in T1). THIS module is the **authorization-server**
 * half of that loop: when a client comes back to `/oauth/authorize` asking for
 * an *increased* scope set (e.g. `mcp:read` → `mcp:read mcp:write`, or
 * `agent:readonly` → `agent:exec`), QAuth must NOT silently widen an existing
 * grant from a prior consent / live session. Crossing into a more-privileged
 * scope set is treated as a step-up: it requires a **fresh authentication**
 * and/or an **explicit re-consent**, per MCP 2025-11-25 incremental consent.
 *
 * The policy is deliberately small and legible, and DEFAULT-DENY in the spirit
 * of epic #181: we never trust a self-asserted client signal to decide whether
 * an elevation is "safe". The decision is driven only by (a) the scopes being
 * newly requested versus what a prior consent already covers, (b) whether any
 * newly-requested scope is classified dangerous server-side, and (c) the
 * standard OIDC `prompt` / `max_age` request parameters.
 */

/**
 * OIDC `prompt` values we honour (OIDC Core §3.1.2.1). `select_account` is not
 * meaningful for QAuth (single account per session) and is treated as absent.
 *   - `login`   — force a fresh end-user authentication.
 *   - `consent` — force the consent screen even if a prior grant would cover
 *     the request (used to re-affirm an elevation).
 *   - `none`    — caller asserts no UI; we still fail-closed and refuse to
 *     silently elevate (the route maps this to an interaction-required style
 *     error rather than auto-widening).
 */
export type PromptMode = 'login' | 'consent' | 'none';

/** Parse the raw `prompt` query param into a known {@link PromptMode} or null. */
export function parsePromptMode(value: string | undefined): PromptMode | null {
  if (value === 'login' || value === 'consent' || value === 'none') return value;
  return null;
}

/**
 * Scopes that are "dangerous" — performing or enabling a state-changing /
 * privileged action — and therefore require step-up (a fresh authentication)
 * before a token carrying them may be issued through an *elevation*.
 *
 * The classification is intentionally conservative and server-side only:
 *   - any `write:*` scope (mutating access),
 *   - the higher agent scope modes `agent:admin` and `agent:exec` (Admin can
 *     administer; Exec takes actions — both are action-taking per
 *     scope-modes.ts). `agent:readonly` is NOT dangerous.
 *
 * This is the single policy hook for "what counts as dangerous": extend
 * {@link DANGEROUS_EXACT_SCOPES} or {@link DANGEROUS_SCOPE_PREFIXES} here and
 * every step-up decision picks it up. Deployments that need a different policy
 * override this one function rather than sprinkling scope checks across routes.
 */
const DANGEROUS_SCOPE_PREFIXES: readonly string[] = ['write:'];

const DANGEROUS_EXACT_SCOPES: ReadonlySet<string> = new Set<string>([
  AGENT_MODE_SCOPES.admin,
  AGENT_MODE_SCOPES.exec,
]);

/** True iff `scope` is classified dangerous (see {@link DANGEROUS_SCOPE_PREFIXES}). */
export function isDangerousScope(scope: string): boolean {
  if (DANGEROUS_EXACT_SCOPES.has(scope)) return true;
  return DANGEROUS_SCOPE_PREFIXES.some((prefix) => scope.startsWith(prefix));
}

/**
 * The subset of `requested` scopes that are NOT already covered by a prior
 * consent — i.e. the scopes this request would *newly* grant (the elevation).
 * Order-preserving, de-duplicated. An empty result means the request is fully
 * within an existing grant (no elevation).
 */
export function elevatedScopes(
  requested: readonly string[],
  priorConsent: readonly string[]
): string[] {
  const have = new Set(priorConsent);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const s of requested) {
    if (have.has(s)) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

/** Inputs to {@link evaluateStepUp}. All times are epoch milliseconds. */
export interface StepUpInput {
  /** Scopes requested now (already filtered to the client's allowlist). */
  requestedScopes: readonly string[];
  /** Scopes an active, non-revoked prior consent already covers (empty if none). */
  priorConsentScopes: readonly string[];
  /** Parsed OIDC `prompt`, or null when absent. */
  prompt: PromptMode | null;
  /**
   * Parsed OIDC `max_age` in SECONDS, or null when absent. `0` demands a
   * brand-new authentication (re-auth on every elevation), matching the
   * `max_age=0` step-up idiom.
   */
  maxAgeSeconds: number | null;
  /** When the current session authenticated (session.createdAt), epoch ms. */
  authTimeMs: number;
  /** "Now", epoch ms — injected for deterministic tests. */
  nowMs: number;
  /**
   * Freshness window in MILLISECONDS for the `prompt=login` / dangerous-scope
   * step-up: an authentication newer than this is accepted as "fresh", so a
   * user who just re-authenticated for the elevation is not bounced back to
   * the login page again (which would loop forever). `max_age` is handled
   * separately and exactly — it is NOT widened by this window.
   */
  freshAuthWindowMs: number;
}

/** The step-up decision. */
export interface StepUpDecision {
  /** The newly-requested (elevated) scopes that drove the decision. */
  elevated: string[];
  /** The elevated scopes classified dangerous (subset of `elevated`). */
  dangerous: string[];
  /**
   * The current session must re-authenticate before a code is issued. Driven
   * by `prompt=login`, a `max_age` the session age exceeds, OR a dangerous
   * elevation (default-deny: a dangerous new scope always forces fresh auth,
   * regardless of any client-supplied signal).
   */
  requiresFreshLogin: boolean;
  /**
   * The consent screen must be shown (the skip-consent fast path is forbidden).
   * Driven by `prompt=consent` OR any elevation at all — a new scope set must
   * be explicitly re-consented, never silently widened from a prior grant.
   */
  requiresConsent: boolean;
}

/**
 * Decide whether this authorization request is an elevation that needs
 * step-up, and if so what kind. Pure + deterministic (time is injected).
 *
 * Rules (all default-deny / fail-closed):
 *  1. Any scope newly requested beyond the prior consent is an `elevated`
 *     scope ⇒ `requiresConsent` (re-affirm the wider set; never auto-widen).
 *  2. `prompt=consent` ⇒ `requiresConsent` even with no elevation.
 *  3. A dangerous elevated scope ⇒ `requiresFreshLogin` — a state-changing /
 *     privileged capability is only granted right after the user proves
 *     presence. This is the "dangerous operation" gate and needs no client
 *     opt-in.
 *  4. `prompt=login` ⇒ `requiresFreshLogin`.
 *  5. `max_age` present and the session is older than it ⇒ `requiresFreshLogin`
 *     (`max_age=0` ⇒ always, since any positive age exceeds 0).
 *
 * A request that is fully within an existing grant, with no prompt/max_age and
 * no dangerous scope, yields no step-up (`requiresFreshLogin=false`,
 * `requiresConsent=false`) and the ordinary skip-consent fast path applies.
 */
export function evaluateStepUp(input: StepUpInput): StepUpDecision {
  const elevated = elevatedScopes(input.requestedScopes, input.priorConsentScopes);
  const dangerous = elevated.filter(isDangerousScope);

  const requiresConsent = elevated.length > 0 || input.prompt === 'consent';

  const authAgeMs = input.nowMs - input.authTimeMs;

  // `prompt=login` and dangerous elevations demand a *fresh* authentication,
  // but one performed within the freshness window counts — otherwise the
  // post-login return trip would re-trigger the same requirement and loop.
  const authIsFresh = authAgeMs <= input.freshAuthWindowMs;
  const loginRequirement = (dangerous.length > 0 || input.prompt === 'login') && !authIsFresh;

  // `max_age` is enforced exactly against the request value (not widened by
  // the freshness window). `max_age=0` ⇒ any positive age fails.
  const maxAgeExceeded = input.maxAgeSeconds !== null && authAgeMs > input.maxAgeSeconds * 1000;

  const requiresFreshLogin = loginRequirement || maxAgeExceeded;

  return { elevated, dangerous, requiresFreshLogin, requiresConsent };
}
