/**
 * The effects that make an admin operation a security operation (ADR-019
 * Decision 7, "security operations, defined by effect"; issue #508).
 *
 * An admin API operation needs `qauth:admin:security` because of what it
 * does, not because of the screen it sits on. Each tag below names one such
 * effect. An operation with at least one effect is a security operation, and
 * an operation with none is not. The auth server's operation registry
 * (`apps/auth-server/src/app/helpers/admin-operations.ts`) enforces that rule,
 * and the realm policy schema names the effect of each security-relevant
 * field from this list.
 *
 * CLOSED LIST. A value outside it is not an effect: the operation registry
 * refuses it at boot, and a request whose classification names one counts as
 * a security operation (fail closed). The names are published in OpenAPI as
 * `x-qauth-effects` and on the docs site's `reference/security-operations.md`.
 * Like every QAuth-defined identifier they are promised from 1.0.0 on
 * (ADR-018 §5).
 *
 * `realm-lifecycle` is not in ADR-019's effect list: its credentials
 * paragraph names realm deletion and ownership transfer as security
 * operations, and #508 gives them this tag.
 */

/** Every effect tag, in the order the docs page lists them. */
export const SECURITY_EFFECTS = Object.freeze([
  'credential-path',
  'token-content',
  'issue-for-other',
  'administration',
  'import',
  'federation-operator',
  'key-custody',
  'realm-lifecycle',
  'authority-tree-power',
  'posture-loosening',
  'bulk-revocation',
] as const);

export type SecurityEffect = (typeof SECURITY_EFFECTS)[number];

/** One sentence per effect: what an operation with it changes. */
export const SECURITY_EFFECT_DESCRIPTIONS: Readonly<Record<SecurityEffect, string>> = Object.freeze(
  {
    'credential-path':
      'Changes which credentials, links or addresses can authenticate or recover an account.',
    'token-content': 'Changes what a token asserts or who receives it.',
    'issue-for-other': 'Issues a token or session for someone other than the caller.',
    administration: 'Changes who administers.',
    import:
      'Imports a realm file, or promotes a sandbox configuration, whose diff holds any other effect.',
    'federation-operator': 'Acts as a federation operator.',
    'key-custody': 'Rotates a key, rotates the KEK or retires a key.',
    'realm-lifecycle': 'Deletes a realm or transfers its ownership.',
    'authority-tree-power': 'Revokes by agent or disables a transmitter.',
    'posture-loosening':
      'Loosens the environment posture, lengthens a token or session lifetime or the key rotation interval, or shortens or switches off audit-event retention.',
    'bulk-revocation': 'Revokes sessions or refresh-token families in bulk.',
  }
);

const EFFECTS: ReadonlySet<string> = new Set(SECURITY_EFFECTS);

/** Whether `value` is one of the effect tags, exactly (case-sensitive). */
export function isSecurityEffect(value: unknown): value is SecurityEffect {
  return typeof value === 'string' && EFFECTS.has(value);
}
