import { createHash } from 'node:crypto';

import { canonicalizeJson } from '@qauth-labs/fastify-plugin-db';

/**
 * THE FACTOR THAT APPROVES (ADR-019 Decision 7, ADR-014 §14, issue #512).
 *
 * The approval engine does not know which factor approves. A factor makes a
 * challenge for one approver and one approval, and verifies the approver's
 * answer to it, returning the id of the credential that gave it. The engine
 * stores that id with the approval and in the admin audit row.
 *
 * The passkey factor (WebAuthn, #623) is the only one a deployment will use.
 * Until it ships, only the test factor exists
 * (`apps/auth-server/src/testing/approval-factor.ts`), which is built only
 * in a test run and never under `NODE_ENV=production`, so no production
 * process can approve.
 *
 * Binding: a factor's challenge is derived from the approval's `op_hash`
 * ({@link approvalChallengeOf}), with the approval id, the approver and a
 * nonce of the factor's, so an answer given for one approval, or by one
 * approver, approves nothing else. A factor makes each challenge single use.
 */

/** The account that approves: a human admin, of the realm it lives in. */
export interface Approver {
  /** The realm the approver's account lives in. */
  readonly realmId: string;
  readonly accountId: string;
}

/** What a factor sees of the approval it makes a challenge for. */
export interface ApprovalForFactor {
  readonly id: string;
  /** The realm the operation acts on. */
  readonly realmId: string;
  /** SHA-256 of the canonical request with the server's nonce. */
  readonly opHash: Buffer;
}

/** A challenge for the approver's credential to sign. */
export interface ApprovalChallenge {
  /** The challenge bytes, base64url, as the page hands them to the authenticator. */
  readonly challenge: string;
}

/** An approver's answer to a challenge, with what it was meant for. */
export interface ApprovalAssertion {
  readonly approval: ApprovalForFactor;
  readonly approver: Approver;
  /** The factor's own answer, such as a WebAuthn assertion. Untrusted. */
  readonly response: unknown;
}

/** A factor of the approval engine. */
export interface ApprovalFactor {
  /** Its name, stored with each approval it verified: `webauthn`, `test`. */
  readonly name: string;
  /** A fresh challenge for `approver` to answer for `approval`. */
  createChallenge(approval: ApprovalForFactor, approver: Approver): Promise<ApprovalChallenge>;
  /**
   * Verify an answer to a challenge this factor made for the same approval
   * and approver, once: the challenge cannot be answered again.
   *
   * @returns the id of the credential that answered
   * @throws {ApprovalFactorError} when the answer does not verify
   */
  verify(assertion: ApprovalAssertion): Promise<string>;
}

/** An answer a factor refused. Its message is logged, never sent. */
export class ApprovalFactorError extends Error {
  override readonly name = 'ApprovalFactorError';
}

/** What the challenge digest is for: a versioned QAuth identifier (ADR-018 §5). */
export const APPROVAL_CHALLENGE_PURPOSE = 'qauth-approval-challenge/1-rc.0';

/**
 * The challenge a factor has an approver sign: SHA-256 over the RFC 8785 form
 * of the purpose, the approval id, its realm, its `op_hash`, the approver and
 * the factor's own nonce. A factor that cannot sign arbitrary bytes derives
 * its own challenge from this.
 */
export function approvalChallengeOf(
  approval: ApprovalForFactor,
  approver: Approver,
  nonce: Buffer
): Buffer {
  return createHash('sha256')
    .update(
      canonicalizeJson({
        purpose: APPROVAL_CHALLENGE_PURPOSE,
        approvalId: approval.id,
        realmId: approval.realmId,
        opHash: approval.opHash.toString('base64url'),
        approver: { realmId: approver.realmId, accountId: approver.accountId },
        nonce: nonce.toString('base64url'),
      }),
      'utf8'
    )
    .digest();
}
