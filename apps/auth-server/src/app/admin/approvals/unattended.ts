import type { AdminCaller } from '../pipeline';

/**
 * A SECURITY OPERATION RUN WITH NO APPROVAL (ADR-019 Decision 7, amended
 * 2026-11-16; issue #1090). Pure: the admin pipeline's approval gate asks
 * {@link runsUnattended} before it asks the call for its approval.
 *
 * A relying party that closes a person's account on its own side deletes
 * the account on its realm the moment the person confirms, as a service
 * account (#522). Had a human to approve each deletion, the account would
 * stay alive and signed in until one did, while the relying party has
 * already told the person it is gone. So the operator gives that one service
 * account the built-in role `account-closer` on that one realm, on the host
 * (`service-accounts create --grant account-closer@<realm>`), and its
 * `users.delete` there runs with no approval. Its call is otherwise the call
 * any admin makes: the permission check, `If-Match`, the account's refusals
 * (a service account's and an admin's are never deleted) and the audit row,
 * which records no approval and names the service account as the actor.
 *
 * A call runs unattended only when all of these hold:
 *
 * 1. The caller is a service account, whose client the operator made: a
 *    service account whose client registered itself runs nothing unattended,
 *    and a person never does (`unattendedOperations` of the authority stage,
 *    `helpers/admin-authority.ts`).
 * 2. One of its live grants names `account-closer` on exactly the realm the
 *    call acts on; a grant on every realm gives none.
 * 3. The operation is one of `UNATTENDED_OPERATION_IDS` (`users.delete`).
 * 4. The realm needs one approval for the request: where it makes a second
 *    admin mandatory for `users.delete` (the two-admin rule, #521), the grant
 *    stands in for nothing, and the call needs every approval the rule asks,
 *    as any other. One admin can always add `users.delete` to that list, so a
 *    realm's admins can switch the unattended deletion off; removing it again
 *    takes two.
 * 5. The call names no approval in `QAuth-Approval`: a call that names one
 *    is judged by it.
 *
 * Every other security operation, and `users.delete` for any other caller,
 * runs only with its approval.
 */
export function runsUnattended(
  caller: Pick<AdminCaller, 'kind' | 'unattendedOperations'>,
  operationId: string,
  approvalsRequired: number
): boolean {
  return (
    caller.kind === 'service_account' &&
    approvalsRequired === 1 &&
    (caller.unattendedOperations?.has(operationId) ?? false)
  );
}
