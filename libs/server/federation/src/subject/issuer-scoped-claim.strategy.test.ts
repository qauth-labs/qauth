import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { createIssuerScopedClaimStrategy } from './issuer-scoped-claim.strategy';
import { deriveIssuerScopedSubject, deriveWalletBinding } from './subject-binding';
import type {
  SubjectAccountCandidate,
  SubjectAccountLookup,
  SubjectResolutionContext,
} from './subject-resolution.types';

/**
 * `issuer-scoped-claim` (#300, ADR-009 §2) — opt-in, per NAMED issuer, with a
 * mandatory `asserted-lookup` fallback.
 */

const REALM = 'realm-1';
const OPTED_IN_ISSUER = 'https://hr.example.com';
const OTHER_ISSUER = 'https://issuer.example.com';
const SUBJECT_CLAIM = 'employee_number';
const BINDING_CLAIMS = ['family_name', 'given_name'];

const EMPLOYEE_CLAIMS = { given_name: 'Alice', family_name: 'Doe', employee_number: 'E-12345' };

interface LookupTables {
  readonly asserted?: Record<string, readonly SubjectAccountCandidate[]>;
  readonly wallet?: Record<string, readonly SubjectAccountCandidate[]>;
}

function lookupOf(tables: LookupTables): SubjectAccountLookup & {
  readonly walletCalls: string[];
  readonly assertedCalls: string[];
} {
  const walletCalls: string[] = [];
  const assertedCalls: string[] = [];

  return {
    walletCalls,
    assertedCalls,
    async byAssertedIdentifier(_realmId, identifier) {
      assertedCalls.push(identifier);
      return tables.asserted?.[identifier] ?? [];
    },
    async byWalletSubject(_realmId, externalSub) {
      walletCalls.push(externalSub);
      return tables.wallet?.[externalSub] ?? [];
    },
  };
}

function contextOf(
  lookup: SubjectAccountLookup,
  overrides: Partial<SubjectResolutionContext> = {}
): SubjectResolutionContext {
  return { realmId: REALM, assertedIdentifier: 'alice@example.com', lookup, ...overrides };
}

function strategy() {
  return createIssuerScopedClaimStrategy({
    subjectClaim: SUBJECT_CLAIM,
    issuers: [OPTED_IN_ISSUER],
    fallback: { bindingClaims: BINDING_CLAIMS },
  });
}

describe('createIssuerScopedClaimStrategy (ADR-009 §2)', () => {
  describe('the composite key, and where its issuer half comes from', () => {
    it('matches an account keyed on the derived (validated issuer, claim) subject', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;
      const lookup = lookupOf({
        wallet: { [subject]: [{ userId: 'user-1', walletBinding: null }] },
      });

      await expect(strategy().resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-1',
      });
      expect(lookup.walletCalls).toEqual([subject]);
    });

    it('does not match an account keyed by a DIFFERENT issuer asserting the same claim value', async () => {
      // The account below was enrolled from the opted-in issuer. A credential
      // carrying the identical `employee_number` from another issuer must not
      // reach it — CIR (EU) 2024/2977 scopes such identifiers to the provider,
      // so the same string is a different person.
      const enrolled = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const impostor = await validatedFixtureCredential({
        issuer: OTHER_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const subject = deriveIssuerScopedSubject(enrolled, SUBJECT_CLAIM) as string;

      const lookup = lookupOf({
        wallet: { [subject]: [{ userId: 'user-1', walletBinding: null }] },
      });

      // The other issuer is not opted in, so it takes the fallback path — and
      // the fallback finds nothing, because the account has no wallet binding
      // recorded against the asserted identifier.
      const outcome = await strategy().resolve(impostor, contextOf(lookup));

      expect(outcome).not.toEqual({ kind: 'matched', userId: 'user-1' });
      expect(lookup.walletCalls).toEqual([]);
    });

    it('never keys on a forged issuer identity', async () => {
      // ADR-009 §2: "an attacker mints a credential claiming any issuer and
      // takes over the corresponding account". The cast is the only way to
      // express it; the run-time brand check is what stops it.
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const forged = {
        ...credential,
        issuer: { identifier: OPTED_IN_ISSUER, keyResolution: 'x5c' },
      } as unknown as typeof credential;

      const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;
      const lookup = lookupOf({
        wallet: { [subject]: [{ userId: 'user-1', walletBinding: null }] },
      });

      const outcome = await strategy().resolve(forged, contextOf(lookup));

      expect(outcome).not.toEqual({ kind: 'matched', userId: 'user-1' });
      expect(lookup.walletCalls).toEqual([]);
    });
  });

  describe('the mandatory fallback (ADR-009 §2 — the holder may refuse the claim)', () => {
    it('falls back to asserted-lookup when the subject claim is WITHHELD', async () => {
      // The EUDI PID Rulebook is explicit that a user may refuse even a
      // mandatory attribute. A strategy with no fallback would refuse
      // conformant wallets.
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });
      const lookup = lookupOf({
        asserted: {
          'alice@example.com': [
            {
              userId: 'user-1',
              walletBinding: deriveWalletBinding(credential, [...BINDING_CLAIMS].sort()) as string,
            },
          ],
        },
      });

      await expect(strategy().resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'matched',
        userId: 'user-1',
      });
      expect(lookup.walletCalls).toEqual([]);
      expect(lookup.assertedCalls).toEqual(['alice@example.com']);
    });

    it('falls back for an issuer the deployment did not opt in for', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OTHER_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const lookup = lookupOf({});

      await expect(strategy().resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'no-match',
      });
      expect(lookup.walletCalls).toEqual([]);
      expect(lookup.assertedCalls).toEqual(['alice@example.com']);
    });

    it('keeps the fallback as STRONG as the primary strategy — its binding check still runs', async () => {
      // The fallback is not a relaxation. A credential from the opted-in issuer
      // that withholds the subject claim still has to satisfy the asserted
      // account's binding.
      const enrolled = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });
      const impostor = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: { given_name: 'Mallory', family_name: 'Kray' },
      });
      const lookup = lookupOf({
        asserted: {
          'alice@example.com': [
            {
              userId: 'user-1',
              walletBinding: deriveWalletBinding(enrolled, [...BINDING_CLAIMS].sort()) as string,
            },
          ],
        },
      });

      await expect(strategy().resolve(impostor, contextOf(lookup))).resolves.toEqual({
        kind: 'rejected',
      });
    });
  });

  describe('outcomes on the primary path', () => {
    it('reports no-match for a first presentation from an unknown subject', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });

      await expect(strategy().resolve(credential, contextOf(lookupOf({})))).resolves.toEqual({
        kind: 'no-match',
      });
    });

    it('reports ambiguous when the derived subject resolves to two accounts', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const subject = deriveIssuerScopedSubject(credential, SUBJECT_CLAIM) as string;
      const lookup = lookupOf({
        wallet: {
          [subject]: [
            { userId: 'user-1', walletBinding: null },
            { userId: 'user-2', walletBinding: null },
          ],
        },
      });

      await expect(strategy().resolve(credential, contextOf(lookup))).resolves.toEqual({
        kind: 'ambiguous',
      });
    });

    it('contains a lookup that throws', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const onLookupError = vi.fn();
      const lookup: SubjectAccountLookup = {
        byAssertedIdentifier: async () => [],
        byWalletSubject: () => Promise.reject(new Error('store down')),
      };

      await expect(
        strategy().resolve(credential, contextOf(lookup, { onLookupError }))
      ).resolves.toEqual({ kind: 'rejected' });
      expect(onLookupError).toHaveBeenCalledTimes(1);
    });
  });

  describe('deriveExternalSub', () => {
    it('is the issuer-scoped subject when the presentation qualifies', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });

      expect(strategy().deriveExternalSub(credential, contextOf(lookupOf({})))).toBe(
        deriveIssuerScopedSubject(credential, SUBJECT_CLAIM)
      );
    });

    it('falls back to the asserted identifier when it does not', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OTHER_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });

      expect(strategy().deriveExternalSub(credential, contextOf(lookupOf({})))).toBe(
        'alice@example.com'
      );
    });
  });

  describe('configuration is validated once, loudly', () => {
    it.each([
      ['no issuers', []],
      ['a non-array', 'https://hr.example.com'],
      ['an unusable issuer identity', ['not-a-url']],
      ['an http:// issuer', ['http://hr.example.com']],
      ['an issuer with a query string', ['https://hr.example.com?x=1']],
    ])('refuses %s', (_label, issuers) => {
      expect(() =>
        createIssuerScopedClaimStrategy({
          subjectClaim: SUBJECT_CLAIM,
          issuers: issuers as unknown as string[],
          fallback: { bindingClaims: BINDING_CLAIMS },
        })
      ).toThrow(InvalidConfigurationError);
    });

    it('refuses iss as the subject claim', () => {
      expect(() =>
        createIssuerScopedClaimStrategy({
          subjectClaim: 'iss',
          issuers: [OPTED_IN_ISSUER],
          fallback: { bindingClaims: BINDING_CLAIMS },
        })
      ).toThrow(InvalidConfigurationError);
    });

    it('refuses a configuration with no usable fallback — ADR-009 §2 makes it mandatory', () => {
      // "Always with fallback to asserted-lookup when the claim is withheld."
      // Structural, not optional: there is no way to express the strategy
      // without one.
      expect(() =>
        createIssuerScopedClaimStrategy({
          subjectClaim: SUBJECT_CLAIM,
          issuers: [OPTED_IN_ISSUER],
        } as never)
      ).toThrow(InvalidConfigurationError);
    });

    it('canonicalizes the opted-in issuer list, so a trailing slash still matches', async () => {
      const credential = await validatedFixtureCredential({
        issuer: OPTED_IN_ISSUER,
        claims: EMPLOYEE_CLAIMS,
      });
      const configured = createIssuerScopedClaimStrategy({
        subjectClaim: SUBJECT_CLAIM,
        issuers: [`${OPTED_IN_ISSUER}/`],
        fallback: { bindingClaims: BINDING_CLAIMS },
      });

      expect(configured.deriveExternalSub(credential, contextOf(lookupOf({})))).toBe(
        deriveIssuerScopedSubject(credential, SUBJECT_CLAIM)
      );
    });
  });
});
