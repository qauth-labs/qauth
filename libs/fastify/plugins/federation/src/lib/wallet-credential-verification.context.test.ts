import {
  type CredentialStatusChecker,
  type DcqlQuery,
  keyStorageAssuranceGateFor,
  type PresentationValidationContext,
  type PresentedCredential,
  type TrustRegistry,
  validatePresentations,
  VERIFIER_PROFILES,
} from '@qauth-labs/server-federation';
import { describe, expect, it, type Mock, vi } from 'vitest';

import { verifyWalletPresentations } from './wallet-credential-verification';

/**
 * What actually reaches `PresentationValidationContext` — the seam #308 and
 * #297 were BOTH lost at (issues #378, #379).
 *
 * ## Why this file exists, and why it mocks the callee
 *
 * `wallet-credential-verification.test.ts` next door tests the COMPOSITION
 * against the real validator, and every case there refuses at parse time — so
 * nothing in it ever observes what the deployment gates were set to. That is
 * precisely how both defects shipped: the Token Status List checker was
 * complete, exported and tested with ZERO production call sites while a revoked
 * credential authenticated a user exactly like a live one; and
 * `keyStorageAssuranceGateFor`, `createKeyStorageAssuranceResolver` and
 * `createStaticAttestingIssuers` were likewise complete with zero non-test
 * callers, so every `ValidatedCredential` the auth-server produced carried
 * `assurance.keyStorageAssurance === { assurance: 'none' }` unconditionally.
 *
 * The failure mode is a FORWARDING that silently stops forwarding. Replacing
 * either member with a literal `undefined` here still type-checks — both context
 * members are nullable, because a deployment may legitimately consult no status
 * list and evaluate no key storage — still passes every other suite in this
 * package, and re-inerts the whole feature. So the callee is mocked and the
 * context it received is asserted directly: there is no cheaper observation of
 * this property, and a property with no observation is the one that regresses.
 *
 * Asserted by IDENTITY (`toBe`) rather than by shape, which catches the second
 * failure mode as well: a seam that rebuilt either object locally instead of
 * passing the caller's would look correct field-by-field while answering a
 * question the caller already answered.
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
  it('forwards the key-storage gate VERBATIM (#308/#379)', async () => {
    // Built the way a real caller builds it: from the resolved profile, so the
    // posture survives even when no resolver is provisioned.
    const keyStorageAssurance = keyStorageAssuranceGateFor(PROFILE);

    await verifyWalletPresentations(onePresentation(), {
      profile: PROFILE,
      clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
      nonce: 'n-0S6_WzA2Mj',
      dcqlQuery: QUERY,
      resolveIssuerKey: async () => undefined,
      trustRegistry: TRUST_EVERYTHING,
      credentialStatus: undefined,
      keyStorageAssurance,
    }).catch(() => undefined);

    // The same object, not an equal one. #379's Break 1 was that this member
    // never arrived at all; a rebuilt-here gate would be the same defect wearing
    // the right shape, with a profile or a resolver it guessed at.
    expect(contextOf().keyStorageAssurance).toBe(keyStorageAssurance);
  });

  it('forwards the status checker and the profile posture beside it (#297/#378)', async () => {
    // The neighbouring gate, asserted here because it was lost the same way and
    // because a suite that pins one forwarding and not the other invites the
    // next edit to drop the unpinned one.
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
      keyStorageAssurance: keyStorageAssuranceGateFor(PROFILE),
    }).catch(() => undefined);

    const context = contextOf();

    // The same object, not an equal one. The checker owns the verified-list
    // cache, the in-flight coalescing map and the per-origin breaker, so a
    // rebuilt-here instance would look correct while giving every login a cold
    // cache, a breaker that never trips, and an outbound round-trip.
    expect(context.credentialStatus).toBe(credentialStatus);
    // Copied off the resolved profile rather than re-decided at the seam — the
    // #299 rule that profiles are data, not branches.
    expect(context.requireCredentialStatus).toBe(PROFILE.requireCredentialStatus);
  });

  it('states an absent gate EXPLICITLY rather than omitting the member', async () => {
    // A deployment with no profile resolved may legitimately answer `undefined`.
    // What must never happen is the member being absent: an omitted key is how a
    // `required` posture silently reads as `forbidden`, which is the exact state
    // #379 found the auth-server in, and is indistinguishable from a caller that
    // simply forgot — the state #378 found it in.
    await verifyWalletPresentations(onePresentation(), {
      profile: PROFILE,
      clientId: 'redirect_uri:https://auth.example.com/oid4vp/response',
      nonce: 'n-0S6_WzA2Mj',
      dcqlQuery: QUERY,
      resolveIssuerKey: async () => undefined,
      trustRegistry: TRUST_EVERYTHING,
      credentialStatus: undefined,
      keyStorageAssurance: undefined,
    }).catch(() => undefined);

    expect('keyStorageAssurance' in contextOf()).toBe(true);
    expect('credentialStatus' in contextOf()).toBe(true);
  });
});
