import { describe, expect, it } from 'vitest';

import { SD_JWT_VC_FORMAT } from '../oid4vp/credential-format';
import { EMAIL_ATTR_KEY } from '../providers/password.provider';
import type { CredentialClaimSet } from './credential-claims.types';
import {
  SD_JWT_VC_ATTRIBUTE_CLAIMS,
  SD_JWT_VC_UNMAPPED_CLAIMS,
  sdJwtVcClaimAdapter,
} from './sd-jwt-vc-claims';

/**
 * The SD-JWT VC claim mapping (issue #235).
 *
 * The mapping is an ALLOWLIST, so most of these tests are about what does NOT
 * become an attribute. That asymmetry is the point: a `user_attributes` row is
 * an assertion QAuth emits downstream, and the failure mode worth testing is a
 * trusted issuer widening QAuth's claim vocabulary — not a claim being missed.
 */

/** A claim set in the shape #234 hands over. */
function claimSet(claims: Record<string, unknown>): CredentialClaimSet {
  return {
    format: SD_JWT_VC_FORMAT,
    credentialType: 'https://credentials.example.com/pid',
    claims,
  };
}

/** The mapped keys of a normalization run, for order-sensitive assertions. */
function keysOf(claims: Record<string, unknown>): string[] {
  return sdJwtVcClaimAdapter.normalizeClaims(claimSet(claims)).map((claim) => claim.attrKey);
}

/** The single value normalization produced for `attrKey`, or undefined. */
function valueOf(claims: Record<string, unknown>, attrKey: string): string | undefined {
  return sdJwtVcClaimAdapter
    .normalizeClaims(claimSet(claims))
    .find((claim) => claim.attrKey === attrKey)?.attrValue;
}

describe('sdJwtVcClaimAdapter (VC claims normalization, #235)', () => {
  it('registers under the SD-JWT VC format', () => {
    expect(sdJwtVcClaimAdapter.format).toBe(SD_JWT_VC_FORMAT);
    expect(sdJwtVcClaimAdapter.format).toBe('dc+sd-jwt');
  });

  describe('the mapped vocabulary', () => {
    it.each(Object.entries(SD_JWT_VC_ATTRIBUTE_CLAIMS))(
      "maps '%s' onto attr_key '%s'",
      (claimName, attrKey) => {
        expect(valueOf({ [claimName]: 'a-value' }, attrKey)).toBeDefined();
      }
    );

    it('maps a disclosed email onto the key PasswordProvider writes', () => {
      // The whole point of #229's trust order: `wallet` outranks
      // `self_reported` ONLY if both land on the same attr_key. A drift here
      // would leave a verified wallet email invisible to `resolveEmailClaims`.
      expect(SD_JWT_VC_ATTRIBUTE_CLAIMS['email']).toBe(EMAIL_ATTR_KEY);
      expect(valueOf({ email: 'alice@example.com' }, EMAIL_ATTR_KEY)).toBe('alice@example.com');
    });

    it('normalizes the email value the same way PasswordProvider does', () => {
      // `normalizeEmail` is idempotent and applied on both sides, so the two
      // sources compare as the same address rather than two spellings of it.
      expect(valueOf({ email: '  Alice@Example.COM ' }, EMAIL_ATTR_KEY)).toBe('alice@example.com');
    });

    it('records every other value VERBATIM — an issuer-signed assertion, not QAuth’s opinion of it', () => {
      expect(valueOf({ family_name: 'de la Cruz-Öztürk' }, 'family_name')).toBe(
        'de la Cruz-Öztürk'
      );
      expect(valueOf({ birthdate: '1990-01-01' }, 'birthdate')).toBe('1990-01-01');
    });

    it('carries the professional-attestation claims (#235: professional credentials)', () => {
      const mapped = sdJwtVcClaimAdapter.normalizeClaims(
        claimSet({
          title: 'Registered Nurse',
          organization: 'Universitair Ziekenhuis',
          employee_number: 40219,
          given_name: 'Alice',
        })
      );

      expect(mapped).toEqual([
        { attrKey: 'given_name', attrValue: 'Alice' },
        { attrKey: 'title', attrValue: 'Registered Nurse' },
        { attrKey: 'organization', attrValue: 'Universitair Ziekenhuis' },
        // A numeric employee number renders as its decimal string; the column
        // is `text` and every reader expects one shape.
        { attrKey: 'employee_number', attrValue: '40219' },
      ]);
    });

    it('emits in TABLE order, not in the holder’s disclosure order', () => {
      // `upsertMany` collapses duplicate (source, attr_key) pairs LAST-WINS. A
      // holder-controlled emission order would make "which value won" a
      // holder-controlled outcome.
      const forward = keysOf({ email: 'a@example.com', given_name: 'Alice', title: 'Dr' });
      const reversed = keysOf({ title: 'Dr', given_name: 'Alice', email: 'a@example.com' });

      expect(forward).toEqual(reversed);
      expect(forward).toEqual(['email', 'given_name', 'title']);
    });
  });

  describe('the claims it refuses to record', () => {
    it('produces nothing for a claim outside the table', () => {
      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ salary: '90000' }))).toEqual([]);
    });

    it.each(Object.keys(SD_JWT_VC_UNMAPPED_CLAIMS))(
      "never records '%s', however it is disclosed",
      (claimName) => {
        for (const value of ['a-string', 42, true, ['DE', 'FR'], { formatted: 'x' }]) {
          expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ [claimName]: value }))).toEqual([]);
        }
      }
    );

    it('keeps the mapped and unmapped tables disjoint', () => {
      // Adding a claim to the mapping means DELETING its refusal reason — a
      // visible act. Two tables that overlapped would let a claim be mapped
      // while the reason it must not be still stood next to it.
      const mapped = Object.keys(SD_JWT_VC_ATTRIBUTE_CLAIMS);
      const unmapped = Object.keys(SD_JWT_VC_UNMAPPED_CLAIMS);

      expect(mapped.filter((claim) => unmapped.includes(claim))).toEqual([]);
    });

    it('refuses the PID nationalities ARRAY rather than joining it', () => {
      // ADR-009 Finding 1 records `nationalities` (plural, an array) in the
      // Rulebook's SD-JWT VC encoding. `selectTrustedAttribute` hands its
      // winner's value straight to a token claim, so `"DE,FR"` would ship where
      // a scalar is expected.
      expect(
        sdJwtVcClaimAdapter.normalizeClaims(claimSet({ nationalities: ['DE', 'FR'] }))
      ).toEqual([]);
      // The singular form, which non-PID SD-JWT VCs do use, IS recorded.
      expect(valueOf({ nationality: 'DE' }, 'nationality')).toBe('DE');
    });

    it('refuses the mdoc spelling of a claim it maps', () => {
      // `birth_date` is the mdoc data identifier; the SD-JWT VC encoding uses
      // `birthdate`. Accepting both here would erase the reason the format
      // boundary exists — see `credential-claims.types.ts`.
      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ birth_date: '1990-01-01' }))).toEqual(
        []
      );
    });

    it.each([
      ['an object', { formatted: 'Musterstraße 1' }],
      ['an array', ['a', 'b']],
      ['null', null],
      ['undefined', undefined],
      ['a NaN', Number.NaN],
      ['an Infinity', Number.POSITIVE_INFINITY],
      ['an empty string', ''],
      ['a whitespace-only string', '   '],
    ] as ReadonlyArray<readonly [string, unknown]>)(
      'records no row when a mapped claim carries %s',
      (_label, value) => {
        expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ given_name: value }))).toEqual([]);
      }
    );

    it('records no row for an over-long value', () => {
      expect(
        sdJwtVcClaimAdapter.normalizeClaims(claimSet({ given_name: 'x'.repeat(513) }))
      ).toEqual([]);
      expect(valueOf({ given_name: 'x'.repeat(512) }, 'given_name')).toHaveLength(512);
    });

    it('records no email row for a value that does not survive normalization', () => {
      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ email: '   ' }))).toEqual([]);
      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({ email: 42 }))).toEqual([]);
    });
  });

  describe('hostile shapes', () => {
    it('does not reach the prototype for a claim named __proto__', () => {
      // #234 builds the claim object with `Object.defineProperty` precisely so a
      // `__proto__` claim name cannot reach the prototype; reading it back with
      // a bare property access would undo that at the consumer.
      const claims = Object.create(null) as Record<string, unknown>;
      Object.defineProperty(claims, '__proto__', {
        value: { given_name: 'Mallory' },
        enumerable: true,
        configurable: true,
        writable: true,
      });

      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet(claims))).toEqual([]);
    });

    it('inherits nothing from Object.prototype', () => {
      // `constructor` and `toString` exist on every plain object. A bare
      // property read would find them; `Object.hasOwn` does not.
      expect(sdJwtVcClaimAdapter.normalizeClaims(claimSet({}))).toEqual([]);
    });

    it.each([
      ['null claims', null],
      ['a string instead of a claim object', 'given_name=Alice'],
      ['undefined claims', undefined],
    ] as ReadonlyArray<readonly [string, unknown]>)(
      'returns an empty list for %s rather than throwing',
      (_label, claims) => {
        expect(
          sdJwtVcClaimAdapter.normalizeClaims({
            format: SD_JWT_VC_FORMAT,
            credentialType: 'x',
            claims: claims as Readonly<Record<string, unknown>>,
          })
        ).toEqual([]);
      }
    );
  });

  it('keeps both tables frozen', () => {
    expect(Object.isFrozen(SD_JWT_VC_ATTRIBUTE_CLAIMS)).toBe(true);
    expect(Object.isFrozen(SD_JWT_VC_UNMAPPED_CLAIMS)).toBe(true);
  });
});
