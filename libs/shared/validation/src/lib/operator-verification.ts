/**
 * An operator's verification of an account (ADR-015 Decision 8, amended
 * 2026-11-08; issue #1052): who verified it, as `users.operator_verified_by`
 * stores it and the `user.verified` event names its method.
 *
 * Two ways record one:
 *
 * - `operator`: the admin security operation `users.verify`, approved like
 *   every security operation. The operator is the admin account that filed
 *   it, by its id.
 * - `operator_cli`: the migration runner's `verify-account` command, run on
 *   the server host where no admin API is set up. The operator is the
 *   operating-system user that ran it, when the host names one.
 *
 * The stored form is `<method>` or `<method>:<operator>`: `operator:<account
 * id>`, `operator_cli:<os user>` or `operator_cli`. The database holds the
 * column to {@link OPERATOR_VERIFIED_BY_PATTERN} (migration 0070), so a value
 * of any other form is never stored.
 */

/** The ways an operator verifies an account. The set may grow in a minor release. */
export const OPERATOR_VERIFICATION_METHODS = ['operator', 'operator_cli'] as const;

export type OperatorVerificationMethod = (typeof OPERATOR_VERIFICATION_METHODS)[number];

/** The longest operating-system user name the CLI's form records. */
export const OPERATOR_CLI_USER_MAX_LENGTH = 255;

/**
 * The form of `users.operator_verified_by`, as the CHECK of migration 0070
 * spells it: an admin account id in lower case, or the CLI with an optional
 * operating-system user of 1 to 255 characters and no control character.
 */
export const OPERATOR_VERIFIED_BY_PATTERN =
  /^(operator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|operator_cli(:[^\p{Cc}]{1,255})?)$/u;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Who verified an account, as {@link parseOperatorVerifiedBy} reads it. */
export type OperatorVerifier =
  /** An admin through `users.verify`: the account that filed it. */
  | { readonly method: 'operator'; readonly accountId: string }
  /** The command on the host: the operating-system user, or `null` when it named none. */
  | { readonly method: 'operator_cli'; readonly osUser: string | null };

/**
 * The stored form of `verifier`.
 *
 * @throws {TypeError} when it cannot be stored: an account id that is not a
 *   UUID, or an operating-system user that is empty, too long or holds a
 *   control character
 */
export function operatorVerifiedBy(verifier: OperatorVerifier): string {
  const value =
    verifier.method === 'operator'
      ? `operator:${verifier.accountId.toLowerCase()}`
      : verifier.osUser === null
        ? 'operator_cli'
        : `operator_cli:${verifier.osUser}`;
  if (verifier.method === 'operator' && !UUID.test(verifier.accountId)) {
    throw new TypeError('operatorVerifiedBy: the admin account id is not a UUID');
  }
  if (!OPERATOR_VERIFIED_BY_PATTERN.test(value)) {
    throw new TypeError('operatorVerifiedBy: the operator cannot be recorded in this form');
  }
  return value;
}

/**
 * The verifier `value`, a stored `users.operator_verified_by`, names, or
 * `null` when it is not one of the forms.
 */
export function parseOperatorVerifiedBy(value: string): OperatorVerifier | null {
  if (!OPERATOR_VERIFIED_BY_PATTERN.test(value)) return null;
  if (value.startsWith('operator:')) {
    return { method: 'operator', accountId: value.slice('operator:'.length) };
  }
  return {
    method: 'operator_cli',
    osUser: value === 'operator_cli' ? null : value.slice('operator_cli:'.length),
  };
}

/**
 * Whether an account carries an operator's verification: what its
 * `users.operator_verified_at` holds. The rules that decide whether an
 * account is verified count it beside the proof of its primary identity.
 */
export function isOperatorVerified(account: {
  readonly operatorVerifiedAt?: number | null;
}): boolean {
  return typeof account.operatorVerifiedAt === 'number';
}
