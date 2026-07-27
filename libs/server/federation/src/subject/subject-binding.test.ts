import { describe, expect, it } from 'vitest';

import { TEST_ISSUER } from '../../testing/sd-jwt-vc.fixture';
import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import {
  constantTimeEquals,
  deriveIssuerScopedSubject,
  deriveWalletBinding,
  ISSUER_SCOPED_SUBJECT_PREFIX,
  MAX_ASSERTED_IDENTIFIER_LENGTH,
  MAX_BINDING_CLAIM_VALUE_LENGTH,
  normalizeAssertedIdentifier,
  readBindingClaim,
  WALLET_BINDING_PREFIX,
} from './subject-binding';

const BINDING_CLAIMS = ['birth_date', 'family_name', 'given_name'] as const;

/**
 * A credential whose `issuer` is a plausible-looking object rather than a
 * `ValidatedIssuer`.
 *
 * This is the attack ADR-009 §2 names — *"an attacker mints a credential
 * claiming any issuer and takes over the corresponding account"* — expressed as
 * the only way it can actually reach this layer: a cast. The compiler forbids it
 * outright, so the cast is the test.
 */
function withForgedIssuer(credential: ValidatedCredential): ValidatedCredential {
  return {
    ...credential,
    issuer: { identifier: TEST_ISSUER, keyResolution: 'issuer-metadata' },
  } as unknown as ValidatedCredential;
}

describe('subject binding derivation (#300, ADR-009)', () => {
  describe('deriveWalletBinding — the entitlement half of asserted-lookup', () => {
    it('is deterministic for the same issuer, type and claim values', async () => {
      // Two credentials, separately issued and separately signed, asserting the
      // same person. The binding MUST survive re-issuance: ADR-009 Finding 1
      // records that PID technical validity is days to weeks with silent
      // re-issuance, so a binding that changed with the signature would lock out
      // every returning user within a fortnight.
      const first = await validatedFixtureCredential();
      const second = await validatedFixtureCredential();

      expect(deriveWalletBinding(first, [...BINDING_CLAIMS])).toBe(
        deriveWalletBinding(second, [...BINDING_CLAIMS])
      );
    });

    it('carries the version prefix and a fixed-length digest', async () => {
      const credential = await validatedFixtureCredential();
      const binding = deriveWalletBinding(credential, [...BINDING_CLAIMS]);

      // Fixed length is what lets `constantTimeEquals` compare without falling
      // out early, and what stops the stored value's length from describing the
      // claims behind it.
      expect(binding).toMatch(new RegExp(`^${WALLET_BINDING_PREFIX}[0-9a-f]{64}$`));
    });

    it('differs when the VALIDATED issuer differs, same claims', async () => {
      // Without the issuer in the composite, a credential from any other trusted
      // issuer asserting the same attributes would satisfy a binding one of them
      // established.
      const ours = await validatedFixtureCredential({ issuer: 'https://issuer.example.com' });
      const theirs = await validatedFixtureCredential({ issuer: 'https://other.example.com' });

      expect(deriveWalletBinding(ours, [...BINDING_CLAIMS])).not.toBe(
        deriveWalletBinding(theirs, [...BINDING_CLAIMS])
      );
    });

    it('differs when the credential type differs, same issuer and claims', async () => {
      const pid = await validatedFixtureCredential();
      const other = await validatedFixtureCredential({
        vct: 'https://credentials.example.com/loyalty-card',
      });

      expect(deriveWalletBinding(pid, [...BINDING_CLAIMS])).not.toBe(
        deriveWalletBinding(other, [...BINDING_CLAIMS])
      );
    });

    it('differs when a single bound claim value differs', async () => {
      const alice = await validatedFixtureCredential();
      const bob = await validatedFixtureCredential({
        claims: { given_name: 'Bob', family_name: 'Doe', birth_date: '1990-01-01' },
      });

      expect(deriveWalletBinding(alice, [...BINDING_CLAIMS])).not.toBe(
        deriveWalletBinding(bob, [...BINDING_CLAIMS])
      );
    });

    it('refuses when a configured binding claim was WITHHELD', async () => {
      // Selective disclosure must not be able to weaken the check the more it is
      // exercised: deriving from the subset a holder chose to reveal would let a
      // holder pick the weakest binding available to them.
      const credential = await validatedFixtureCredential({
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });

      expect(deriveWalletBinding(credential, [...BINDING_CLAIMS])).toBeUndefined();
    });

    it('refuses when the issuer identity is not a genuine ValidatedIssuer', async () => {
      // ADR-009 §2, run-time half: `as unknown as ValidatedIssuer` compiles.
      // `#validated in value` does not survive it.
      const credential = await validatedFixtureCredential();

      expect(
        deriveWalletBinding(withForgedIssuer(credential), [...BINDING_CLAIMS])
      ).toBeUndefined();
    });

    it('refuses an empty claim list rather than deriving a claim-free binding', async () => {
      // A binding over (issuer, vct) alone would be satisfied by every holder of
      // that credential type from that issuer — i.e. by everyone.
      const credential = await validatedFixtureCredential();

      expect(deriveWalletBinding(credential, [])).toBeUndefined();
    });
  });

  describe('deriveIssuerScopedSubject — the lookup key that is also the proof', () => {
    it('is stable across re-issuance and carries the version prefix', async () => {
      const first = await validatedFixtureCredential({
        claims: { ...{ given_name: 'Alice' }, employee_number: 'E-12345' },
      });
      const second = await validatedFixtureCredential({
        claims: { given_name: 'Alice', employee_number: 'E-12345' },
      });

      const subject = deriveIssuerScopedSubject(first, 'employee_number');

      expect(subject).toMatch(new RegExp(`^${ISSUER_SCOPED_SUBJECT_PREFIX}[0-9a-f]{64}$`));
      expect(subject).toBe(deriveIssuerScopedSubject(second, 'employee_number'));
    });

    it('scopes the value to the issuer — the same number from two issuers is two people', async () => {
      // CIR (EU) 2024/2977 scopes `personal_administrative_number` uniqueness to
      // "the provider of person identification data", so two Member States may
      // issue the same value to two different humans. Keying on the value alone
      // would merge them into one account.
      const first = await validatedFixtureCredential({
        issuer: 'https://pid.member-state-a.example',
        claims: { personal_administrative_number: '12345' },
      });
      const second = await validatedFixtureCredential({
        issuer: 'https://pid.member-state-b.example',
        claims: { personal_administrative_number: '12345' },
      });

      expect(deriveIssuerScopedSubject(first, 'personal_administrative_number')).not.toBe(
        deriveIssuerScopedSubject(second, 'personal_administrative_number')
      );
    });

    it('refuses when the claim was withheld, so the caller can fall back', async () => {
      // ADR-009 §2: the holder may refuse to present even a mandatory attribute,
      // so a withheld claim is an ordinary outcome the caller answers with
      // `asserted-lookup` — never a value derived from what was left.
      const credential = await validatedFixtureCredential();

      expect(deriveIssuerScopedSubject(credential, 'employee_number')).toBeUndefined();
    });

    it('refuses a forged issuer identity', async () => {
      const credential = await validatedFixtureCredential({
        claims: { employee_number: 'E-12345' },
      });

      expect(
        deriveIssuerScopedSubject(withForgedIssuer(credential), 'employee_number')
      ).toBeUndefined();
    });

    it('never collides with a wallet binding, even over identical inputs', async () => {
      // The two values live in different columns and are compared by different
      // code paths. A value that leaked from one into the other must not be
      // usable there.
      const credential = await validatedFixtureCredential();

      expect(deriveIssuerScopedSubject(credential, 'given_name')).not.toBe(
        deriveWalletBinding(credential, ['given_name'])
      );
    });
  });

  describe('readBindingClaim — what may take part in a derivation', () => {
    it('reads own string, number and boolean claims', () => {
      const claims = Object.freeze({ s: 'value', n: 42, b: true });

      expect(readBindingClaim(claims, 's')).toBe('value');
      expect(readBindingClaim(claims, 'n')).toBe(42);
      expect(readBindingClaim(claims, 'b')).toBe(true);
    });

    it('never reads an INHERITED property', () => {
      // #234 builds the claim set with `Object.defineProperty` precisely so a
      // `__proto__` claim name cannot reach the prototype; reading it back with
      // `name in claims` would undo that defence at the consumer.
      const claims = Object.create({ inherited: 'from-prototype' }) as Record<string, unknown>;

      expect(readBindingClaim(claims, 'inherited')).toBeUndefined();
      expect(readBindingClaim({}, 'toString')).toBeUndefined();
      expect(readBindingClaim({}, '__proto__')).toBeUndefined();
    });

    it.each([
      ['a structured object', { nested: { a: 1 } }],
      ['an array', { nested: [1, 2] }],
      ['null', { nested: null }],
      ['an empty string', { nested: '' }],
      ['NaN', { nested: Number.NaN }],
      ['Infinity', { nested: Number.POSITIVE_INFINITY }],
      ['an over-long string', { nested: 'x'.repeat(MAX_BINDING_CLAIM_VALUE_LENGTH + 1) }],
    ])('refuses %s', (_label, claims) => {
      // Objects and arrays have no canonical string form this module can commit
      // to (JSON key order), and the numeric edge cases do not round-trip
      // through JSON as themselves — a binding derived from `NaN` would collide
      // with one derived from `null`.
      expect(readBindingClaim(claims as Record<string, unknown>, 'nested')).toBeUndefined();
    });
  });

  describe('normalizeAssertedIdentifier', () => {
    it('lowercases and trims, exactly as PasswordProvider does', () => {
      // ADR-009 §1 puts the asserted identifier in the same `external_sub`
      // column `PasswordProvider` fills. Two normalizations would mean two
      // definitions of "the same account".
      expect(normalizeAssertedIdentifier('  Alice@Example.COM ')).toBe('alice@example.com');
    });

    it.each([
      ['a non-string', 42],
      ['null', null],
      ['undefined', undefined],
      ['empty', ''],
      ['whitespace only', '   '],
      ['over-long', `${'a'.repeat(MAX_ASSERTED_IDENTIFIER_LENGTH)}@example.com`],
    ])('refuses %s', (_label, raw) => {
      expect(normalizeAssertedIdentifier(raw)).toBeUndefined();
    });
  });

  describe('constantTimeEquals', () => {
    it('is true only for byte-identical values', () => {
      expect(constantTimeEquals('wb1:abc', 'wb1:abc')).toBe(true);
      expect(constantTimeEquals('wb1:abc', 'wb1:abd')).toBe(false);
    });

    it('returns false on a length mismatch rather than throwing', () => {
      // `timingSafeEqual` throws on unequal lengths; a throw here would turn a
      // refusal into a 500 and hand back an oracle.
      expect(constantTimeEquals('short', 'considerably-longer')).toBe(false);
      expect(constantTimeEquals('', 'x')).toBe(false);
    });
  });
});
