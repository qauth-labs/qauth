/**
 * Environment-aware authorization posture (ADR-008, issue #196).
 *
 * QAuth treats **environment** (`development` | `staging` | `production`) as a
 * first-class, policy-profile dimension: one attribute that flips a coordinated
 * bundle of security and operational defaults instead of N independent knobs.
 *
 * Two columns drive it:
 *   - `oauth_clients.environment` — the client's DECLARED environment.
 *   - `realms.max_environment_laxity` — a realm-level CEILING on how lax any
 *     client in that realm may be.
 *
 * The **effective** environment is the STRICTER of the two (strictness order:
 * `production` > `staging` > `development`). A realm pinned to `production`
 * forces every client to the production profile regardless of its own field.
 *
 * FAIL-SAFE: both inputs default to `production`; an absent / unknown value on
 * either side is treated as `production`. The relaxed posture is therefore
 * opt-in and bounded, and misconfiguration fails closed.
 *
 * OPERATOR-SET: the relaxation direction is never self-asserted — it is set by
 * an operator (seed/manifest, admin API, realm config), never by a client's own
 * DCR request or CIMD metadata document. This mirrors the `max_agent_mode` /
 * `dynamic_registration_allowed_scopes` precedent from ADR-007 §2.
 *
 * This module is the single resolver ADR-008 §7 calls for. Policy checkpoints —
 * token issuance, the static-API-key gate, redirect-URI validation, DCR, agent
 * step-up, T3 hardening (issues #197 / #97 / #98) — consult
 * {@link resolveEnvironmentPolicy} rather than re-deriving rules, exactly as the
 * `toAgentScopeContext` / `enforceAgentScopeCap` pattern centralises the agent
 * scope-mode cap. It is intentionally PURE and depends on no DB row types: it
 * accepts minimal structural inputs so it is trivial to import and unit-test.
 */

/** Canonical environments, ordered laxest → strictest. */
export const ENVIRONMENTS = ['development', 'staging', 'production'] as const;

export type Environment = (typeof ENVIRONMENTS)[number];

/**
 * Strictness rank: higher ⇒ stricter (more hardened). The effective
 * environment is the MAX rank of the client value and the realm ceiling, so a
 * realm at `production` always wins. Kept as an explicit map (not array index)
 * so the ordering is intentional and survives reordering of {@link ENVIRONMENTS}.
 */
const ENVIRONMENT_STRICTNESS_RANK: Readonly<Record<Environment, number>> = {
  development: 1,
  staging: 2,
  production: 3,
} as const;

/**
 * Parse a value into a known {@link Environment}, or `production` for anything
 * unrecognised. FAIL-SAFE: an unknown / empty / null / malformed value is NOT
 * silently downgraded to a laxer profile — it resolves to the strictest
 * (`production`), matching the NOT NULL `production` column defaults.
 */
export function parseEnvironment(value: string | null | undefined): Environment {
  if (typeof value !== 'string') return 'production';
  return (ENVIRONMENTS as readonly string[]).includes(value)
    ? (value as Environment)
    : 'production';
}

/**
 * The STRICTER of two environments (ADR-008 §2). `production` beats `staging`
 * beats `development`. Used to bound a client's declared environment by its
 * realm's ceiling: `stricterEnvironment(clientEnv, realmCeiling)`.
 *
 * `stricterEnvironment('development', 'production')` → `'production'`
 * `stricterEnvironment('development', 'staging')`    → `'staging'`
 * `stricterEnvironment('development', 'development')`→ `'development'`
 */
export function stricterEnvironment(a: Environment, b: Environment): Environment {
  return ENVIRONMENT_STRICTNESS_RANK[a] >= ENVIRONMENT_STRICTNESS_RANK[b] ? a : b;
}

/**
 * Access-token lifespan tier (ADR-008 §5). Coarse, legible label rather than a
 * concrete number of seconds — the token-issuance checkpoint (#197) maps a tier
 * to its configured lifespan so the realm's `access_token_lifespan` and any
 * per-environment override live in one place, not scattered across callers.
 */
export type AccessTokenLifespanTier = 'long' | 'short';

/**
 * Rate-limit tier (ADR-008 §5). `staging` keeps lenient limits for load
 * testing, so it shares the `lenient` tier with `development`; `production` is
 * `strict`. The rate-limit plugin maps a tier to concrete window/max values.
 */
export type RateLimitTier = 'lenient' | 'strict';

/**
 * The effective environment policy profile (ADR-008 §5). The resolved bundle of
 * security and operational knobs a policy checkpoint consults. Every field is a
 * resolved DEFAULT for the effective environment; an operator may later override
 * an individual knob, but only WITHIN the realm ceiling and never below the hard
 * security floors (client secrets are always hashed, audience binding always
 * holds, etc.).
 *
 * Security-relevant relaxations apply to `development` ONLY. `staging` keeps
 * production-grade security (`pkceRequired`, `refreshRotationRequired`,
 * `agentStepUpEnforced`, `t3SecurityEnforced`, https-only redirects, no static
 * keys) and relaxes only operational conveniences (rate limits, token lifespan).
 */
export interface EnvironmentPolicy {
  /** The effective environment (stricter of client vs realm ceiling). */
  readonly environment: Environment;
  /**
   * Static, long-lived developer API keys (#97/#98) may be issued/accepted.
   * `development` only; `staging` and `production` use OAuth `client_credentials`.
   */
  readonly staticApiKeysAllowed: boolean;
  /**
   * `http://localhost` (loopback) redirect URIs are permitted. `development`
   * only; `staging`/`production` are https-only. (Loopback exceptions for native
   * apps per RFC 8252 are handled by redirect validation, not this flag.)
   */
  readonly localhostRedirectAllowed: boolean;
  /**
   * PKCE (`S256`) is REQUIRED. True for `staging`/`production`; in `development`
   * it is recommended but not forced. Note QAuth's project-wide floor still sets
   * `oauth_clients.require_pkce=true` by default — this only governs whether the
   * environment profile additionally hard-requires it.
   */
  readonly pkceRequired: boolean;
  /** Access-token lifespan tier: `long` in `development`, else `short`. */
  readonly accessTokenLifespanTier: AccessTokenLifespanTier;
  /** Refresh-token rotation is REQUIRED. True for `staging`/`production`. */
  readonly refreshRotationRequired: boolean;
  /** Rate-limit tier: `lenient` for `development`/`staging`, `strict` for `production`. */
  readonly rateLimitTier: RateLimitTier;
  /**
   * Open dynamic client registration / CIMD. `development` is open; `staging`
   * and `production` are gated. (This describes posture only — DCR security
   * caps such as the realm scope allowlist always apply regardless.)
   */
  readonly openDynamicRegistration: boolean;
  /** Agent step-up before dangerous ops is enforced. True for `staging`/`production`. */
  readonly agentStepUpEnforced: boolean;
  /**
   * T3 hardening (security headers / CSRF / secure cookies, #108/#109/#113) is
   * enforced. True for `staging`/`production`; relaxed in `development`.
   */
  readonly t3SecurityEnforced: boolean;
}

/**
 * The static policy-profile table (ADR-008 §5), keyed by environment. Exported
 * so downstream checkpoints (#197/#97/#98) can consume the per-environment
 * defaults directly when they already know the effective environment, without
 * re-running the resolver. Frozen to prevent accidental mutation of shared state.
 *
 * Security relaxations live in `development` ONLY; `staging` matches
 * `production` on every security knob and differs only on operational
 * conveniences (`rateLimitTier`, `accessTokenLifespanTier`).
 */
export const ENVIRONMENT_PROFILES: Readonly<Record<Environment, EnvironmentPolicy>> = Object.freeze(
  {
    development: Object.freeze({
      environment: 'development',
      staticApiKeysAllowed: true,
      localhostRedirectAllowed: true,
      pkceRequired: false,
      accessTokenLifespanTier: 'long',
      refreshRotationRequired: false,
      rateLimitTier: 'lenient',
      openDynamicRegistration: true,
      agentStepUpEnforced: false,
      t3SecurityEnforced: false,
    }),
    staging: Object.freeze({
      environment: 'staging',
      staticApiKeysAllowed: false,
      localhostRedirectAllowed: false,
      pkceRequired: true,
      accessTokenLifespanTier: 'short',
      refreshRotationRequired: true,
      rateLimitTier: 'lenient',
      openDynamicRegistration: false,
      agentStepUpEnforced: true,
      t3SecurityEnforced: true,
    }),
    production: Object.freeze({
      environment: 'production',
      staticApiKeysAllowed: false,
      localhostRedirectAllowed: false,
      pkceRequired: true,
      accessTokenLifespanTier: 'short',
      refreshRotationRequired: true,
      rateLimitTier: 'strict',
      openDynamicRegistration: false,
      agentStepUpEnforced: true,
      t3SecurityEnforced: true,
    }),
  } satisfies Record<Environment, EnvironmentPolicy>
);

/**
 * Minimal structural view of a client for the resolver. Accepts a bare
 * `{ environment }` rather than a full DB row so the resolver stays pure and
 * easy to import/test. `environment` is optional and may arrive as a raw string
 * from the DB column; {@link parseEnvironment} fails safe to `production` for
 * any absent / unknown value.
 */
export interface EnvironmentClientLike {
  environment?: Environment | string | null;
}

/**
 * Minimal structural view of a realm for the resolver. `maxEnvironmentLaxity`
 * is the realm-level ceiling; absent / unknown ⇒ `production` (fail-safe).
 */
export interface EnvironmentRealmLike {
  maxEnvironmentLaxity?: Environment | string | null;
}

/**
 * Resolve the effective {@link EnvironmentPolicy} for a client within its realm
 * (ADR-008 §7). The single entry point every policy checkpoint should call.
 *
 * The effective environment is the STRICTER of the client's declared
 * `environment` and the realm's `maxEnvironmentLaxity` ceiling, each parsed
 * fail-safe to `production`. The returned profile is the corresponding frozen
 * entry from {@link ENVIRONMENT_PROFILES}.
 *
 * Fail-safe behaviour:
 *   - `resolveEnvironmentPolicy({}, {})` → production profile (both unset).
 *   - `resolveEnvironmentPolicy({ environment: 'development' }, { maxEnvironmentLaxity: 'production' })`
 *     → production profile (realm ceiling caps the laxer client).
 *   - A `null`/unknown value on either side resolves to `production`.
 *
 * @param client A `{ environment }` view of the OAuth client (may be null/undefined).
 * @param realm  A `{ maxEnvironmentLaxity }` view of the realm (may be null/undefined).
 */
export function resolveEnvironmentPolicy(
  client: EnvironmentClientLike | null | undefined,
  realm: EnvironmentRealmLike | null | undefined
): EnvironmentPolicy {
  const clientEnv = parseEnvironment(client?.environment ?? null);
  const realmCeiling = parseEnvironment(realm?.maxEnvironmentLaxity ?? null);
  const effective = stricterEnvironment(clientEnv, realmCeiling);
  return ENVIRONMENT_PROFILES[effective];
}

// ---------------------------------------------------------------------------
// Tier → concrete-value mappers (ADR-008 §5, issue #197).
//
// The profile table above is deliberately COARSE: it carries legible tier
// labels (`accessTokenLifespanTier`, `rateLimitTier`), not magic numbers. The
// concrete seconds / request caps stay in realm/env config so an operator
// tunes one place. These two pure mappers are the SINGLE point where a tier is
// turned into a number — every policy checkpoint (#197) calls them instead of
// re-deriving its own `dev ? x : y` arithmetic, mirroring how
// `enforceAgentScopeCap` centralises the agent cap decision.
// ---------------------------------------------------------------------------

/**
 * Concrete access-token lifespans (seconds) the two tiers map to. Both numbers
 * come from configuration — the resolver only SELECTS between them by tier:
 *   - `short` — the production/staging baseline (`ACCESS_TOKEN_LIFESPAN`).
 *   - `long`  — the `development` convenience (`DEV_ACCESS_TOKEN_LIFESPAN`).
 */
export interface AccessTokenLifespanConfig {
  /** The `short` tier value in seconds (production/staging baseline). */
  readonly shortSeconds: number;
  /** The `long` tier value in seconds (development convenience). */
  readonly longSeconds: number;
}

/**
 * Map an {@link AccessTokenLifespanTier} to a concrete number of seconds using
 * the supplied config (ADR-008 §5). `short` (production/staging) returns the
 * baseline lifespan; `long` (development) returns the dev-convenience lifespan.
 *
 * FAIL-SAFE: the `long` value is clamped to be at LEAST the `short` baseline is
 * NOT applied here on purpose — `long` is a development relaxation and a
 * misconfigured `longSeconds < shortSeconds` simply yields a shorter dev token,
 * which is the safe direction. The strict tiers always get exactly the baseline.
 */
export function resolveAccessTokenLifespanSeconds(
  tier: AccessTokenLifespanTier,
  config: AccessTokenLifespanConfig
): number {
  return tier === 'long' ? config.longSeconds : config.shortSeconds;
}

/**
 * Concrete per-window request caps the two rate-limit tiers map to. Both come
 * from configuration; the resolver only SELECTS by tier.
 */
export interface RateLimitTierConfig {
  /** The `lenient` tier cap (development / staging, e.g. load testing). */
  readonly lenientMax: number;
  /** The `strict` tier cap (production). */
  readonly strictMax: number;
}

/**
 * Map a {@link RateLimitTier} to a concrete per-window request cap (ADR-008
 * §5). `strict` (production) returns the tight cap; `lenient`
 * (development/staging) returns the relaxed cap. The window itself is unchanged
 * by environment — only the cap moves, matching the profile table.
 */
export function resolveRateLimitMax(tier: RateLimitTier, config: RateLimitTierConfig): number {
  return tier === 'strict' ? config.strictMax : config.lenientMax;
}
