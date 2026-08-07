import { describe, expect, it } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { deriveEnrolmentWalletBinding } from './enrolment-binding';
import type { SubjectAccountCandidate, SubjectResolutionContext } from './subject-resolution.types';
import {
  createSubjectResolutionStrategy,
  type SubjectResolutionConfig,
} from './subject-resolution-strategies';

/**
 * The enrolment binding (#235 closing #300's write half, ADR-009 §1).
 *
 * The property that matters is a ROUND TRIP, not a shape: the value stored when
 * an account is enrolled must be the value `asserted-lookup` re-derives and
 * accepts on the next presentation. Asserting the digest's format would pass
 * while the two halves quietly disagreed — and the symptom would be every
 * wallet user locked out on their SECOND login, days later, behind a
 * deliberately uninformative refusal.
 */

const ASSERTED_LOOKUP: SubjectResolutionConfig = {
  strategy: 'asserted-lookup',
  bindingClaims: ['family_name', 'given_name'],
};

const ISSUER_SCOPED: SubjectResolutionConfig = {
  strategy: 'issuer-scoped-claim',
  subjectClaim: 'personal_administrative_number',
  issuers: ['https://issuer.example.com'],
  fallback: { bindingClaims: ['family_name', 'given_name'] },
};

/** A resolution context whose lookup answers with exactly these candidates. */
function contextFor(candidates: readonly SubjectAccountCandidate[]): SubjectResolutionContext {
  return {
    realmId: 'realm-1',
    assertedIdentifier: 'alice@example.com',
    lookup: {
      byAssertedIdentifier: async () => candidates,
      byWalletSubject: async () => candidates,
    },
    onLookupError: () => undefined,
  };
}

describe('deriveEnrolmentWalletBinding', () => {
  it('produces the binding asserted-lookup will accept on the NEXT presentation', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe' },
    });

    // Enrolment: derive and "store" the binding.
    const stored = deriveEnrolmentWalletBinding(ASSERTED_LOOKUP, credential);
    expect(stored).not.toBeNull();

    // A later login: the same credential is presented against the account that
    // binding was stored on.
    const strategy = createSubjectResolutionStrategy(ASSERTED_LOOKUP);
    const outcome = await strategy.resolve(
      credential,
      contextFor([{ userId: 'user-1', walletBinding: stored }])
    );

    expect(outcome).toEqual({ kind: 'matched', userId: 'user-1' });
  });

  it('produces a binding NO OTHER credential satisfies', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe' },
    });
    const stored = deriveEnrolmentWalletBinding(ASSERTED_LOOKUP, credential);

    // A different person, same issuer, same credential type, fully valid.
    const attacker = await validatedFixtureCredential({
      claims: { given_name: 'Mallory', family_name: 'Doe' },
    });

    const outcome = await createSubjectResolutionStrategy(ASSERTED_LOOKUP).resolve(
      attacker,
      contextFor([{ userId: 'user-1', walletBinding: stored }])
    );

    expect(outcome).toEqual({ kind: 'rejected' });
  });

  it('binds under issuer-scoped-claim too, from the MANDATORY fallback claim set', async () => {
    // ADR-009 §2 makes the fallback structural because the holder may withhold
    // the subject claim on any later presentation. An enrolment that stored no
    // binding would meet an account with none — which `asserted-lookup`
    // correctly refuses — so the fallback would never work.
    const credential = await validatedFixtureCredential({
      claims: {
        given_name: 'Alice',
        family_name: 'Doe',
        personal_administrative_number: 'PA-42',
      },
    });

    const stored = deriveEnrolmentWalletBinding(ISSUER_SCOPED, credential);
    expect(stored).not.toBeNull();

    // The holder withholds the subject claim next time; the fallback runs.
    const withheld = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe' },
    });

    const outcome = await createSubjectResolutionStrategy(ISSUER_SCOPED).resolve(
      withheld,
      contextFor([{ userId: 'user-1', walletBinding: stored }])
    );

    expect(outcome).toEqual({ kind: 'matched', userId: 'user-1' });
  });

  it('returns null when the holder withheld a configured binding claim', async () => {
    // Fail-closed, and the caller must refuse: enrolling here would create an
    // account nothing could later prove entitlement to.
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    expect(deriveEnrolmentWalletBinding(ASSERTED_LOOKUP, credential)).toBeNull();
  });

  it('returns null for a credential whose issuer is not the branded ValidatedIssuer', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe' },
    });
    const forged = {
      ...credential,
      issuer: { identifier: 'https://issuer.example.com', keyResolution: 'issuer-metadata' },
    };

    expect(deriveEnrolmentWalletBinding(ASSERTED_LOOKUP, forged as never)).toBeNull();
  });

  it.each([
    ['no configuration', undefined],
    ['an empty binding claim set', { strategy: 'asserted-lookup', bindingClaims: [] }],
    [
      'an issuer-scoped configuration with no fallback claims',
      { strategy: 'issuer-scoped-claim', subjectClaim: 'x', issuers: [], fallback: undefined },
    ],
  ] as ReadonlyArray<readonly [string, unknown]>)(
    'returns null for %s rather than a binding derived from nothing',
    async (_label, config) => {
      const credential = await validatedFixtureCredential({
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });

      expect(
        deriveEnrolmentWalletBinding(config as SubjectResolutionConfig, credential)
      ).toBeNull();
    }
  );
});
