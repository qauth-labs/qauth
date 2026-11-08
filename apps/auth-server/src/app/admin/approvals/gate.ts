import type { AdminApproval } from '@qauth-labs/fastify-plugin-db';

import { type CanonicalRequest, opHashOf, sameDigest } from './canonical-request';

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
 * - `denied`, `cancelled`, `consumed`, `expired`: the approval is closed. Its
 *   nonce was overwritten then, so no call matches it any more.
 * - `request-mismatch`: the approval was filed for another request: another
 *   operation, method, path parameter, query, body, realm or requester, or
 *   against another version of the state the operation reads.
 * - `pending`: it still lacks an approval.
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

/** What the gate reads of a stored approval. */
export type GatedApprovalRecord = Pick<AdminApproval, 'opHash' | 'nonce' | 'status' | 'expiresAt'>;

/**
 * Why `approval` does not approve the call whose canonical request is
 * `request` at `now`, or `null` when it does: it exists in the realm, is open,
 * the call's `op_hash` with the approval's nonce is the stored one (exactly
 * this request, by this requester), it has not expired, and it is `approved`.
 */
export function approvalRefusal(
  approval: GatedApprovalRecord | undefined,
  request: CanonicalRequest,
  now: number
): ApprovalRefusal | null {
  if (approval === undefined) return 'not-found';
  // A closed approval's nonce is not the one its op_hash was computed with:
  // every call would be a mismatch, so its status is the reason.
  if (approval.status !== 'pending' && approval.status !== 'approved') return approval.status;
  if (!sameDigest(opHashOf(request, approval.nonce), approval.opHash)) return 'request-mismatch';
  if (now >= approval.expiresAt) return 'expired';
  if (approval.status !== 'approved') return approval.status;
  return null;
}
