import {
  type CredentialStatusChecker,
  type DcqlQuery,
  type PresentationValidationContext,
  type PresentedCredential,
  type TrustRegistry,
  validatePresentations,
  VERIFIER_PROFILES,
} from '@qauth-labs/server-federation';
import { describe, expect, it, type Mock, vi } from 'vitest';

import { verifyWalletPresentations } from './wallet-credential-verification';

/**
 * What actually reaches `PresentationValidationContext` — the seam #297 was
 * lost at (issue #378).
 *
 * ## Why this file exists, and why it mocks the callee
 *
 * `wallet-credential-verification.test.ts` next door tests the COMPOSITION
 * against the real validator, and every case there refuses at parse time — so
 * nothing in it ever observes what the deployment gates were set to. That is
 * precisely how #378 shipped: the Token Status List checker was complete,
 * exported and tested with ZERO production call sites, and a revoked credential
 * authenticated a user exactly like a live one.
 *
 * The failure mode is a FORWARDING that silently stops forwarding. Replacing
 * `options.credentialStatus` with a literal `undefined` here still type-checks —
 * the context member is nullable, because a deployment may legitimately consult
 * no status list — still passes every other suite in this package, and re-inerts
 * the whole feature. So the callee is mocked and the context it received is
 * asserted directly: there is no cheaper observation of this property, and a
 * property with no observation is the one that regresses.
 *
 * Asserted by IDENTITY (`toBe`) rather than by shape, which catches the second
 * failure mode as well: a seam that rebuilt a checker locally instead of passing
 * the caller's would look correct field-by-field while owning a cold cache, a
 * breaker that never trips, and an outbound round-trip per login.
 */

vi.mock('@qauth-labs/server-federation', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@qauth-labs/server-federation')>();
  return { ...actual, validatePresentations: vi.fn(async () => []) };
});

const PROFILE = VERIFIER_PROFILES['oid4vp-1.0-base'];

const QUERY: DcqlQuery = {
  credentials: [
    {
      id: 'qauth_wallet_login',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['https://credentials.example.com/pid'] },
    },
  ],
};

const TRUST_EVERYTHING: TrustRegistry = { isTrusted: () => true };

/**
 * One structurally-shaped presentation.
 *
 * Its bytes are never read — the validator is mocked — but the batch must be
 * non-empty, because `verifyWalletPresentations` refuses an empty one BEFORE it
 * builds a context at all.
 */
function onePresentation(): PresentedCredential[] {
  return [
    { queryId: 'qauth_wallet_login', format: 'dc+sd-jwt', presentation: 'not-a-presentation' },
  ];
}

/** The context the seam handed the validator, for the most recent call. */
function contextOf(): PresentationValidationContext {
  const call = (validatePresentations as unknown as Mock).mock.calls.at(-1);
  if (call === undefined) throw new Error('validatePresentations was never called');
  return call[2] as PresentationValidationContext;
}

describe('verifyWalletPresentations — the deployment gates reach the validator', () => {
  it('forwards the status checker and the profile posture beside it (#297/#378)', async () => {
    const credentialStatus = {
      checkStatus: async () => ({ outcome: 'valid' }),
    } as unknown as CredentialStatusChecker;

    await verifyWalletPresentations(onePresentation(), {
      profile: PROFILE,
      clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
      nonce: 'n-0S6_WzA2Mj',
      dcqlQuery: QUERY,
      resolveIssuerKey: async () => undefined,
      trustRegistry: TRUST_EVERYTHING,
      credentialStatus,
    }).catch(() => undefined);

    const context = contextOf();

    // The same object, not an equal one. The checker owns the verified-list
    // cache, the in-flight coalescing map and the per-origin breaker, so a
    // rebuilt-here instance would be the same defect wearing the right shape.
    expect(context.credentialStatus).toBe(credentialStatus);
    // Copied off the resolved profile rather than re-decided at the seam — the
    // #299 rule that profiles are data, not branches.
    expect(context.requireCredentialStatus).toBe(PROFILE.requireCredentialStatus);
  });

  it('states an absent checker EXPLICITLY rather than omitting the member', async () => {
    // A deployment that configured no status checking legitimately answers
    // `undefined`. What must never happen is the member being absent: an
    // omitted key is indistinguishable from a caller that forgot, which is the
    // exact state #378 found the auth-server in.
    await verifyWalletPresentations(onePresentation(), {
      profile: PROFILE,
      clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
      nonce: 'n-0S6_WzA2Mj',
      dcqlQuery: QUERY,
      resolveIssuerKey: async () => undefined,
      trustRegistry: TRUST_EVERYTHING,
      credentialStatus: undefined,
    }).catch(() => undefined);

    expect('credentialStatus' in contextOf()).toBe(true);
  });
});
