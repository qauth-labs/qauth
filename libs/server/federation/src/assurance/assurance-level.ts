import type { AssuranceLevel } from '../providers/credential-provider.interface';

/**
 * Runtime handling of {@link AssuranceLevel} values (ADR-004, issue #237).
 *
 * `AssuranceLevel` is declared in `providers/credential-provider.interface.ts`,
 * which is a TYPE-ONLY module (ADR-003's contract, re-exported with
 * `export type *`). The moment a level is persisted — on an authorization code,
 * in a session record, in a JSON column — it comes back as an untrusted string,
 * and something has to narrow it without widening what the type means. That
 * narrowing lives here rather than next to the type, so the contract module
 * stays free of runtime code.
 */

/**
 * Every level, in ASCENDING order of assurance.
 *
 * Ordered because the order is meaningful (eIDAS LoA / ISO 29115) and because a
 * `Set` would have made it look arbitrary. Nothing here compares levels today:
 * a comparison helper would invite `>= 'substantial'` policy checks at call
 * sites, and which levels a deployment accepts is a policy question that belongs
 * in configuration, not in an inequality.
 */
export const ASSURANCE_LEVELS: readonly AssuranceLevel[] = Object.freeze([
  'low',
  'substantial',
  'high',
]);

/**
 * Narrow an untrusted value to an {@link AssuranceLevel}, fail-closed.
 *
 * Returns `undefined` — never `'low'` — for anything unrecognised. The two are
 * behaviourally identical downstream (neither emits an `acr` claim), but they
 * mean different things: `'low'` is a level that was established, `undefined` is
 * a value that was not understood. A caller that wants to treat the second as
 * the first says so with `?? 'low'`, which is visible in review.
 *
 * @param value - candidate level; `unknown` because DB columns, Redis payloads
 * and JSON bodies all reach this function.
 * @returns the level, or `undefined` when the value is not one.
 */
export function parseAssuranceLevel(value: unknown): AssuranceLevel | undefined {
  if (value !== 'low' && value !== 'substantial' && value !== 'high') return undefined;
  return value;
}
