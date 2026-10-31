import type { AdminApproval } from '@qauth-labs/fastify-plugin-db';

import { sameDigest } from './canonical-request';

/**
 * THE APPROVAL GATE'S DECISION (ADR-019 Decision 7, issue #512). Pure: the
 * admin pipeline's stage 7 reads the approval the retried call names and
 * asks {@link approvalRefusal} whether it approves that call; the conditional
 * consumption in the operation's transaction then makes sure it does so once.
 */

/** The header a retried security operation names its approval in. */
export const APPROVAL_HEADER = 'qauth-approval';

/**
 * Why an approval does not approve a call. Logged, never sent: every refusal
 * answers the same `approval_required`.
 *
 * - `malformed-header`: `QAuth-Approval` is not one UUID.
 * - `uncanonical-request`: the call has no canonical form, such as a binary body.
 * - `not-found`: no approval of the realm has that id.
 * - `request-mismatch`: the approval was filed for another request: another
 *   operation, method, path parameter, query, body, realm or requester.
 * - `expired`: its five minutes are over.
 * - `pending`, `denied`, `cancelled`, `consumed`: where it stands instead of
 *   `approved`.
 * - `used-meanwhile`: it was approved when the gate read it, and used or
 *   withdrawn before the operation's transaction could consume it.
 */
export type ApprovalRefusal =
  | 'malformed-header'
  | 'uncanonical-request'
  | 'not-found'
  | 'request-mismatch'
  | 'expired'
  | 'pending'
  | 'denied'
  | 'cancelled'
  | 'consumed'
  | 'used-meanwhile';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The approval id `QAuth-Approval` names, or `null` when it is not exactly one UUID. */
export function approvalIdOf(header: string | string[] | undefined): string | null {
  if (typeof header !== 'string') return null;
  const value = header.trim();
  return UUID.test(value) ? value.toLowerCase() : null;
}

/**
 * Why `approval` does not approve the call whose `request_hash` is
 * `requestHash` at `now`, or `null` when it does: it exists in the realm, was
 * filed for exactly this request by this requester, has not expired, and is
 * `approved`.
 */
export function approvalRefusal(
  approval: Pick<AdminApproval, 'requestHash' | 'status' | 'expiresAt'> | undefined,
  requestHash: Buffer,
  now: number
): ApprovalRefusal | null {
  if (approval === undefined) return 'not-found';
  if (!sameDigest(approval.requestHash, requestHash)) return 'request-mismatch';
  if (now >= approval.expiresAt) return 'expired';
  if (approval.status !== 'approved') return approval.status;
  return null;
}
