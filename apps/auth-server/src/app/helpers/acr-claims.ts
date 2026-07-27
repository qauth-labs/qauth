import {
  type AssuranceLevel,
  parseAcrValueStyle,
  parseAssuranceLevel,
  resolveAcrValue,
} from '@qauth-labs/fastify-plugin-federation';

import { env } from '../../config/env';

/**
 * OIDC `acr` claim resolution (ADR-004, ADR-010, issue #237).
 *
 * The single place a stored assurance level becomes an ID-token claim. Every
 * emission site consumes it as a one-line spread, exactly like
 * `resolveEmailClaims`, so the claim can never be assembled two different ways
 * within one issuance.
 *
 * ## The value is rendered HERE, not stored rendered
 *
 * `authorization_codes.assurance_level` holds the internal level
 * (`'substantial'` / `'high'` / NULL). The eIDAS LoA → `acr` VOCABULARY is
 * deployment configuration (`ACR_VALUE_STYLE`), so rendering at mint time would
 * freeze every in-flight code into whichever vocabulary happened to be
 * configured when it was issued — and a config change would then be observable
 * as two different `acr` values for the same level, for the length of a code's
 * TTL.
 *
 * ## Absence is the signal
 *
 * `'low'`, NULL, and anything unrecognised all produce `{}` — no `acr` claim at
 * all. Password logins are `'low'` by ADR-003 and therefore never carry `acr`
 * (#240 asserts the same invariant from the other side). OIDC Core treats `acr`
 * as an optional higher-assurance indicator, so a Relying Party may gate on its
 * PRESENCE; emitting a "low" value for ordinary logins would destroy that
 * signal, not merely add noise.
 *
 * ## Fail-closed on an unreadable value
 *
 * The stored level arrives as an untrusted string — a database column, a Redis
 * payload — so it is narrowed with `parseAssuranceLevel` rather than cast. An
 * unrecognised value yields no claim: an assurance assertion QAuth cannot read
 * is one it must not make.
 */
export type AcrClaims = { acr: string } | Record<string, never>;

/**
 * Resolve the `acr` claim for an authentication whose assurance level was
 * recorded as `stored`.
 *
 * @param stored - the persisted level (authorization code column or session
 * field). `null`/`undefined`/`'low'`/unparseable all mean "no claim".
 * @returns a spreadable `{ acr }`, or `{}` when no `acr` may be emitted.
 */
export function resolveAcrClaims(stored: string | null | undefined): AcrClaims {
  const level: AssuranceLevel | undefined = parseAssuranceLevel(stored);
  const acr = resolveAcrValue(level, parseAcrValueStyle(env.ACR_VALUE_STYLE));
  if (acr === undefined) return {};
  return { acr };
}

/**
 * Narrow a session's assurance level to what `authorization_codes.assurance_level`
 * may hold.
 *
 * The counterpart of {@link resolveAcrClaims}, applied at code-mint time. Only
 * the two levels that BEAR an `acr` claim are storable — `'low'`, absent and
 * unrecognised all collapse to NULL — which is what makes NULL the single
 * representation of "no assurance established" from the browser session all the
 * way to the ID token. The database enforces the same rule with a CHECK
 * constraint, so a value that slipped past here still cannot be persisted.
 *
 * @param level - the level carried on the browser session, if any.
 * @returns the column value: `'substantial'`, `'high'`, or `null`.
 */
export function toStoredAssuranceLevel(level: unknown): string | null {
  const parsed = parseAssuranceLevel(level);
  if (parsed !== 'substantial' && parsed !== 'high') return null;
  return parsed;
}
