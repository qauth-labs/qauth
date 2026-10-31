import { randomBytes } from 'node:crypto';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApprovalFactorError } from '../app/admin/approvals/factor';
import { createTestApprovalFactor } from './approval-factor';

/**
 * The test-only approval factor (#512) keeps the passkey factor's rules: an
 * answer approves only the approval and the approver its challenge was made
 * for, once, and the factor is never built in production.
 */

const approvalA = { id: 'approval-a', realmId: 'realm', opHash: randomBytes(32) };
const approvalB = { id: 'approval-b', realmId: 'realm', opHash: randomBytes(32) };
const alice = { realmId: 'realm', accountId: 'alice' };
const bob = { realmId: 'realm', accountId: 'bob' };

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('the test approval factor (#512)', () => {
  it("verifies an answer once, and names the approver's credential", async () => {
    const { factor, answer, credentialOf } = createTestApprovalFactor();
    const challenge = await factor.createChallenge(approvalA, alice);
    const response = answer(challenge, alice);
    await expect(factor.verify({ approval: approvalA, approver: alice, response })).resolves.toBe(
      credentialOf(alice)
    );
    await expect(
      factor.verify({ approval: approvalA, approver: alice, response })
    ).rejects.toBeInstanceOf(ApprovalFactorError);
  });

  it('refuses an answer for another approval, or by another approver', async () => {
    const { factor, answer } = createTestApprovalFactor();
    const challenge = await factor.createChallenge(approvalA, alice);
    await factor.createChallenge(approvalB, alice);
    await factor.createChallenge(approvalA, bob);
    const response = answer(challenge, alice);
    await expect(
      factor.verify({ approval: approvalB, approver: alice, response })
    ).rejects.toBeInstanceOf(ApprovalFactorError);
    await expect(
      factor.verify({ approval: approvalA, approver: bob, response })
    ).rejects.toBeInstanceOf(ApprovalFactorError);
  });

  it('derives each challenge afresh, and refuses a forged signature', async () => {
    const { factor, answer } = createTestApprovalFactor();
    const first = await factor.createChallenge(approvalA, alice);
    const second = await factor.createChallenge(approvalA, alice);
    expect(first.challenge).not.toBe(second.challenge);
    // The first challenge was replaced by the second.
    await expect(
      factor.verify({ approval: approvalA, approver: alice, response: answer(first, alice) })
    ).rejects.toBeInstanceOf(ApprovalFactorError);
    const forged = { ...answer(second, alice), signature: 'forged' };
    await expect(
      factor.verify({ approval: approvalA, approver: alice, response: forged })
    ).rejects.toBeInstanceOf(ApprovalFactorError);
  });

  it('is never built in production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    expect(() => createTestApprovalFactor()).toThrow(/never built in production/);
  });
});
