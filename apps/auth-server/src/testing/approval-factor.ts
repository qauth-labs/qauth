import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import {
  type ApprovalAssertion,
  type ApprovalChallenge,
  approvalChallengeOf,
  type ApprovalFactor,
  ApprovalFactorError,
  type ApprovalForFactor,
  type Approver,
} from '../app/admin/approvals/factor';

/**
 * TEST SUPPORT — the test-only approval factor (#512).
 *
 * It stands in for the passkey factor (#623) in tests: one credential per
 * account, whose "signature" is an HMAC under a key only this factor and its
 * authenticator hold. It keeps the passkey factor's rules: a challenge is
 * derived from the approval's `op_hash` (`approvalChallengeOf`) and made for
 * one approval and one approver, it is answered once, and an answer verifies
 * only for the approval and approver it was made for.
 *
 * Refuses to be built under `NODE_ENV=production`, so a production process
 * can never approve with it.
 */

/** What the test authenticator answers a challenge with. */
export interface TestApprovalResponse {
  readonly challenge: string;
  readonly credentialId: string;
  readonly signature: string;
}

/** The test factor and the authenticator that answers its challenges. */
export interface TestApprovalFactor {
  readonly factor: ApprovalFactor;
  /** Answer `challenge` with `approver`'s credential, as its authenticator would. */
  answer(challenge: ApprovalChallenge, approver: Approver): TestApprovalResponse;
  /** The credential id the authenticator holds for `approver`. */
  credentialOf(approver: Approver): string;
}

/** Build a test factor with a key of its own. */
export function createTestApprovalFactor(): TestApprovalFactor {
  if (process.env['NODE_ENV'] === 'production') {
    throw new Error('The test approval factor is never built in production');
  }
  const key = randomBytes(32);
  const challenges = new Map<string, { readonly challenge: string; used: boolean }>();
  const slot = (approval: ApprovalForFactor, approver: Approver) =>
    JSON.stringify([approval.id, approver.realmId, approver.accountId]);
  const credentialOf = (approver: Approver) => `test-credential:${approver.accountId}`;
  const sign = (challenge: string, credentialId: string) =>
    createHmac('sha256', key).update(`${challenge}.${credentialId}`).digest('base64url');

  const factor: ApprovalFactor = {
    name: 'test',
    async createChallenge(approval, approver) {
      const challenge = approvalChallengeOf(approval, approver, randomBytes(32)).toString(
        'base64url'
      );
      challenges.set(slot(approval, approver), { challenge, used: false });
      return { challenge };
    },
    async verify(assertion: ApprovalAssertion) {
      const response = assertion.response as Partial<TestApprovalResponse> | null;
      const stored = challenges.get(slot(assertion.approval, assertion.approver));
      if (
        stored === undefined ||
        stored.used ||
        typeof response?.challenge !== 'string' ||
        response.challenge !== stored.challenge ||
        typeof response.credentialId !== 'string' ||
        response.credentialId !== credentialOf(assertion.approver) ||
        typeof response.signature !== 'string'
      ) {
        throw new ApprovalFactorError('the answer is not for a challenge of this approval');
      }
      const expected = Buffer.from(sign(response.challenge, response.credentialId));
      const given = Buffer.from(response.signature);
      if (expected.length !== given.length || !timingSafeEqual(expected, given)) {
        throw new ApprovalFactorError('the signature does not verify');
      }
      stored.used = true;
      return response.credentialId;
    },
  };

  return {
    factor,
    credentialOf,
    answer(challenge, approver) {
      const credentialId = credentialOf(approver);
      return {
        challenge: challenge.challenge,
        credentialId,
        signature: sign(challenge.challenge, credentialId),
      };
    },
  };
}
