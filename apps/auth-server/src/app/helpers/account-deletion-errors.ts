/**
 * The refusal of an admin's deletion of an account (`users.delete`, ADR-020
 * §3, issue #681), answered as a problem document
 * (`api-conventions/error-classes.ts`).
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load it without loading a route.
 */

/**
 * Why an account is not deleted through `users.delete`:
 *
 * - `service_account`: it is a service account's account (#522), marked or
 *   bound. The service account is disabled or removed through its own path,
 *   and its account goes with it.
 * - `administrator`: it holds an admin grant that is not revoked. Removing an
 *   admin is the administration's own operation, under the two-admin rule
 *   (ADR-019 Decision 7, #521), which deleting the account would bypass.
 */
export type AccountDeletionRefusal = 'service_account' | 'administrator';

const MESSAGES: Readonly<Record<AccountDeletionRefusal, string>> = Object.freeze({
  service_account:
    "The account is a service account's: disable or remove the service account instead, and its account goes with it.",
  administrator:
    'The account holds an admin grant: remove its grants through the admin operations first, under the two-admin rule.',
});

/**
 * An account `users.delete` does not delete as it stands: `409`, the
 * `conflict` problem document. Nothing is deleted, and no approval is filed
 * for it.
 */
export class AccountDeletionConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(readonly refusal: AccountDeletionRefusal) {
    super(MESSAGES[refusal]);
    this.name = 'AccountDeletionConflictError';
  }
}
