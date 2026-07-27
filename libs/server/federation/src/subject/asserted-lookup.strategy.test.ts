import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { createAssertedLookupStrategy } from './asserted-lookup.strategy';
import { deriveWalletBinding } from './subject-binding';
import type {
  SubjectAccountCandidate,
  SubjectAccountLookup,
  SubjectResolutionContext,
} from './subject-resolution.types';

/**
 * `asserted-lookup` (#300, ADR-009 §1) — the default strategy, and the one whose
 * entitlement check ADR-009 restates *"because it is the likeliest way this gets
 * built wrong"*.
 *
 * Every credential below is REAL: issued with a real signature, presented with a
 * real Key Binding JWT, and run through #234's validator. So when a test says a
 * presentation must not authenticate an account, it is saying that about a
 * credential that is valid in every respect — which is the only version of the
 * claim worth making.
 */

const BINDING_CLAIMS = ['birth_date', 'family_name', 'given_name'];
const REALM = 'realm-1';
const VICTIM = 'victim@example.com';

const ALICE_CLAIMS = { given_name: 'Alice', family_name: 'Doe', birth_date: '1990-01-01' };
const MALLORY_CLAIMS = { given_name: 'Mallory', family_name: 'Kray', birth_date: '1985-06-02' };

interface LookupTables {
  readonly asserted?: Record<string, readonly SubjectAccountCandidate[]>;
  readonly wallet?: Record<string, readonly SubjectAccountCandidate[]>;
}

/** An in-memory {@link SubjectAccountLookup}, with call recording. */
function lookupOf(tables: LookupTables): SubjectAccountLookup & {
  readonly assertedCalls: string[][];
} {
  const assertedCalls: string[][] = [];

  return {
    assertedCalls,
    async byAssertedIdentifier(realmId, identifier) {
      assertedCalls.push([realmId, identifier]);
      return tables.asserted?.[identifier] ?? [];
    },
    async byWalletSubject(_realmId, externalSub) {
      return tables.wallet?.[externalSub] ?? [];
    },
  };
}

function contextOf(
  lookup: SubjectAccountLookup,
  overrides: Partial<SubjectResolutionContext> = {}
): SubjectResolutionContext {
  return { realmId: REALM, assertedIdentifier: VICTIM, lookup, ...overrides };
}

describe('createAssertedLookupStrategy (ADR-009 §1)', () => {
  describe('the attack — a valid credential must not authenticate an account it is not bound to', () => {
    it('refuses a genuine, issuer-trusted credential asserting someone else’s account', async () => {
      // The whole issue in one test. Mallory holds a REAL credential from the
      // SAME issuer the victim's account was enrolled with — validated end to
      // end by #234, so every property #234 guarantees holds — and asserts the
      // victim's identifier. ADR-009 §1: "Omitting that check means anyone
      // holding any valid credential can log in as anyone."
      const victimCredential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const malloryCredential = await validatedFixtureCredential({ claims: MALLORY_CLAIMS });

      const victimBinding = deriveWalletBinding(victimCredential, BINDING_CLAIMS);
      expect(victimBinding).toBeDefined();

      const lookup = lookupOf({
        asserted: { [VICTIM]: [{ userId: 'user-victim', walletBinding: victimBinding as string }] },
      });
      const strategy = createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS });

      const attack = await strategy.resolve(malloryCredential, contextOf(lookup));

      expect(attack).toEqual({ kind: 'rejected' });

      // And the test is not passing for an uninteresting reason: the SAME
      // strategy, the same account, the same lookup — with the credential the
      // account is actually bound to — authenticates.
      const legitimate = await strategy.resolve(victimCredential, contextOf(lookup));
      expect(legitimate).toEqual({ kind: 'matched', userId: 'user-victim' });
    });

    it('refuses rather than reporting no-match, so the caller cannot enrol over the account', async () => {
      // The distinction matters: `no-match` is the one outcome a caller is
      // allowed to turn into a registration. A binding mismatch that reported
      // `no-match` would hand a takeover attempt to the enrolment path.
      const victimCredential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const malloryCredential = await validatedFixtureCredential({ claims: MALLORY_CLAIMS });

      const lookup = lookupOf({
        asserted: {
          [VICTIM]: [
            {
              userId: 'user-victim',
              walletBinding: deriveWalletBinding(victimCredential, BINDING_CLAIMS) as string,
            },
          ],
        },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(malloryCredential, contextOf(lookup));

      expect(outcome.kind).not.toBe('no-match');
      expect(outcome.kind).toBe('rejected');
    });

    it('refuses an account that exists but carries NO wallet binding (ADR-009 bootstrap case 2)', async () => {
      // "An account already exists without a wallet binding (typically a
      // password account on the same email) — the presentation MUST NOT
      // silently create one." Reporting `no-match` here would let any holder of
      // any trusted credential claim an existing account by asserting its email.
      const credential = await validatedFixtureCredential({ claims: MALLORY_CLAIMS });
      const lookup = lookupOf({
        asserted: { [VICTIM]: [{ userId: 'user-victim', walletBinding: null }] },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup));

      expect(outcome).toEqual({ kind: 'rejected' });
    });
  });

  describe('resolution outcomes', () => {
    it('matches the account the presented credential is bound to', async () => {
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const lookup = lookupOf({
        asserted: {
          'alice@example.com': [
            {
              userId: 'user-alice',
              walletBinding: deriveWalletBinding(credential, BINDING_CLAIMS) as string,
            },
          ],
        },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup, { assertedIdentifier: 'alice@example.com' }));

      expect(outcome).toEqual({ kind: 'matched', userId: 'user-alice' });
    });

    it('reports no-match when the asserted identifier resolves to no account', async () => {
      // ADR-009's FIRST bootstrap case: the caller may establish the account and
      // the binding together. This is the one outcome that may become an
      // enrolment.
      const credential = await validatedFixtureCredential();

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookupOf({})));

      expect(outcome).toEqual({ kind: 'no-match' });
    });

    it('reports ambiguous when two accounts share the asserted identifier — never picks one', async () => {
      // #300 constraint 5. Two users on one email is possible today: a password
      // account and an OIDC account both normalize to it.
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const binding = deriveWalletBinding(credential, BINDING_CLAIMS) as string;
      const lookup = lookupOf({
        asserted: {
          [VICTIM]: [
            { userId: 'user-a', walletBinding: binding },
            { userId: 'user-b', walletBinding: binding },
          ],
        },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup));

      expect(outcome).toEqual({ kind: 'ambiguous' });
    });

    it('treats several wallet credentials on ONE account as one account, not an ambiguity', async () => {
      // A second device, a re-issued credential or a second credential type all
      // produce a second binding row for the same user. Refusing those as
      // "ambiguous" would break every user who ever re-enrolled.
      const enrolled = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const other = await validatedFixtureCredential({
        vct: 'https://credentials.example.com/loyalty-card',
        claims: ALICE_CLAIMS,
      });

      const lookup = lookupOf({
        asserted: {
          [VICTIM]: [
            {
              userId: 'user-alice',
              walletBinding: deriveWalletBinding(other, BINDING_CLAIMS) as string,
            },
            {
              userId: 'user-alice',
              walletBinding: deriveWalletBinding(enrolled, BINDING_CLAIMS) as string,
            },
          ],
        },
      });

      const strategy = createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS });

      await expect(strategy.resolve(enrolled, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-alice',
      });
      await expect(strategy.resolve(other, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-alice',
      });
    });

    it('normalizes the asserted identifier before looking anything up', async () => {
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const lookup = lookupOf({
        asserted: {
          [VICTIM]: [
            {
              userId: 'user-victim',
              walletBinding: deriveWalletBinding(credential, BINDING_CLAIMS) as string,
            },
          ],
        },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup, { assertedIdentifier: '  Victim@Example.COM ' }));

      expect(outcome).toEqual({ kind: 'matched', userId: 'user-victim' });
      expect(lookup.assertedCalls).toEqual([[REALM, VICTIM]]);
    });
  });

  describe('refusals that never touch the account store', () => {
    it('refuses when no identifier was asserted, without querying', async () => {
      // "The user told us nothing" must not be a route to an account — and must
      // not be a way to make the server run a lookup either.
      const credential = await validatedFixtureCredential();
      const lookup = lookupOf({});

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup, { assertedIdentifier: undefined }));

      expect(outcome).toEqual({ kind: 'rejected' });
      expect(lookup.assertedCalls).toEqual([]);
    });

    it('refuses a withheld binding claim BEFORE querying, so it cannot probe identifiers', async () => {
      // Deriving after the lookup would let a holder with no usable credential
      // drive one database read per guessed identifier.
      const credential = await validatedFixtureCredential({
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });
      const lookup = lookupOf({});

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup));

      expect(outcome).toEqual({ kind: 'rejected' });
      expect(lookup.assertedCalls).toEqual([]);
    });
  });

  describe('a broken account store is contained, never propagated', () => {
    it('refuses and reports when the lookup throws', async () => {
      // Same containment `assertIssuerTrusted` applies to a TrustRegistry
      // backend: an uncontained throw is a 500 where every other outcome is a
      // uniform refusal, which is an oracle an attacker can drive by degrading
      // the store.
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const onLookupError = vi.fn();
      const lookup: SubjectAccountLookup = {
        byAssertedIdentifier: () => Promise.reject(new Error('connection reset')),
        byWalletSubject: async () => [],
      };

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup, { onLookupError }));

      expect(outcome).toEqual({ kind: 'rejected' });
      expect(onLookupError).toHaveBeenCalledTimes(1);
    });

    it('refuses when the lookup returns something that is not an array', async () => {
      // `undefined` from a port that promised an array is a bug, not an empty
      // result. Reading it as "no account" would turn the bug into an enrolment.
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const lookup = {
        byAssertedIdentifier: async () => undefined,
        byWalletSubject: async () => [],
      } as unknown as SubjectAccountLookup;

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup, { onLookupError: vi.fn() }));

      expect(outcome).toEqual({ kind: 'rejected' });
    });

    it.each([
      ['an empty userId', [{ userId: '', walletBinding: 'wb1:x' }]],
      ['a non-string userId', [{ userId: 7, walletBinding: 'wb1:x' }]],
      ['a non-string, non-null binding', [{ userId: 'u', walletBinding: 42 }]],
      ['a null candidate', [null]],
    ])('refuses a candidate list carrying %s', async (_label, candidates) => {
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const lookup = lookupOf({
        asserted: { [VICTIM]: candidates as unknown as readonly SubjectAccountCandidate[] },
      });

      const outcome = await createAssertedLookupStrategy({
        bindingClaims: BINDING_CLAIMS,
      }).resolve(credential, contextOf(lookup));

      expect(outcome).toEqual({ kind: 'rejected' });
    });
  });

  describe('deriveExternalSub', () => {
    it('is the normalized asserted identifier — the column PasswordProvider fills', async () => {
      // ADR-009 §1's zero-migration property: `external_sub` holds the asserted,
      // normalized identifier under the realm scoping that ships today.
      const credential = await validatedFixtureCredential();
      const strategy = createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS });

      expect(
        strategy.deriveExternalSub(
          credential,
          contextOf(lookupOf({}), { assertedIdentifier: 'Alice@Example.com' })
        )
      ).toBe('alice@example.com');
    });

    it('is null when nothing was asserted', async () => {
      const credential = await validatedFixtureCredential();
      const strategy = createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS });

      expect(
        strategy.deriveExternalSub(
          credential,
          contextOf(lookupOf({}), { assertedIdentifier: '  ' })
        )
      ).toBeNull();
    });
  });

  describe('configuration is validated once, loudly', () => {
    it.each([
      ['an empty list', []],
      ['a non-array', 'given_name'],
      ['undefined', undefined],
    ])('refuses %s of binding claims — there would be nothing to match', (_label, claims) => {
      // `asserted-lookup` without an entitlement check is not a degraded version
      // of the strategy; it is the total authentication bypass.
      expect(() =>
        createAssertedLookupStrategy({ bindingClaims: claims as unknown as string[] })
      ).toThrow(InvalidConfigurationError);
    });

    it.each(['iss', 'cnf', '_sd', '_sd_alg'])('refuses %s as a binding claim', (claim) => {
      // ADR-009 §2 forbids keying on a self-asserted issuer; OID4VP §15.5–§15.6
      // forbid keying on holder key material. #234 strips all four, so
      // configuring one would silently never match — which is why this refuses
      // at construction rather than failing quietly at run time.
      expect(() => createAssertedLookupStrategy({ bindingClaims: [claim] })).toThrow(
        InvalidConfigurationError
      );
    });

    it('is insensitive to the ORDER the operator listed the claims in', async () => {
      // A config edit that reorders the list must not invalidate every stored
      // binding in the deployment.
      const credential = await validatedFixtureCredential({ claims: ALICE_CLAIMS });
      const forward = createAssertedLookupStrategy({ bindingClaims: BINDING_CLAIMS });
      const reversed = createAssertedLookupStrategy({
        bindingClaims: [...BINDING_CLAIMS].reverse(),
      });
      const lookup = lookupOf({
        asserted: {
          [VICTIM]: [
            {
              userId: 'user-victim',
              walletBinding: deriveWalletBinding(credential, [...BINDING_CLAIMS].sort()) as string,
            },
          ],
        },
      });

      await expect(forward.resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-victim',
      });
      await expect(reversed.resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-victim',
      });
    });
  });
});
