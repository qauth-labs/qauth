/**
 * Subject resolution — which account does a validated presentation belong to
 * (issue #300, ADR-009).
 *
 * The last gate between a cryptographic finding and an authenticated user, and
 * the one with no protocol answer behind it: ADR-009 Finding 1 establishes that
 * there is no protocol-guaranteed stable wallet subject identifier and that the
 * ecosystem is built to keep it that way. So the strategy decides, per
 * deployment, and `asserted-lookup` is the fail-closed default.
 *
 * Nothing here authenticates anyone on its own. Presentation validation (#234)
 * and issuer trust (#236) both run FIRST; a strategy handed an unvalidated
 * credential or an untrusted issuer's credential will happily resolve it, which
 * is why the order is stated in `subject-resolution.types.ts` rather than left
 * to the caller to infer.
 */

export * from './asserted-lookup.strategy';
export * from './issuer-scoped-claim.strategy';
export * from './resolve-subject-resolution';
export * from './session-binding.strategy';
export * from './subject-binding';
export type * from './subject-resolution.types';
export * from './subject-resolution-config';
export * from './subject-resolution-strategies';
