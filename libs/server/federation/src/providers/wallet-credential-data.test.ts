import { describe, expect, it } from 'vitest';

import {
  buildWalletCredentialData,
  MAX_WALLET_BINDING_LENGTH,
  readWalletBinding,
  walletCredentialDataSchema,
} from './wallet-credential-data';

/**
 * `credential_data` for `provider_type='wallet'` (#238).
 *
 * The shape is the stored half of ADR-009 §1's entitlement check, so the tests
 * that matter are the ones proving an unusable row degrades to "no binding" —
 * which the strategies treat as a REFUSAL — rather than to something that
 * accidentally compares equal.
 */

const BINDING = `wb1:${'a'.repeat(64)}`;

describe('buildWalletCredentialData (#238)', () => {
  it('produces the snake_case shape the database column carries', () => {
    expect(buildWalletCredentialData(BINDING, 'https://issuer.example.com', 'https://vct')).toEqual(
      {
        wallet_binding: BINDING,
        issuer: 'https://issuer.example.com',
        vct: 'https://vct',
      }
    );
  });

  it('round-trips through the schema and back out of readWalletBinding', () => {
    const data = buildWalletCredentialData(BINDING, 'https://issuer.example.com', 'https://vct');

    expect(walletCredentialDataSchema.safeParse(data).success).toBe(true);
    expect(readWalletBinding(data)).toBe(BINDING);
  });

  it('carries no holder key material and no claim values', () => {
    // OID4VP 1.0 §15.5–§15.6 and ADR-009 §4: a `cnf` key identifies a
    // credential, not a person, and ADR-009 Finding 2 is about keeping claim
    // values out of columns like this one. The shape has exactly three keys.
    const data = buildWalletCredentialData(BINDING, 'https://issuer.example.com', 'https://vct');

    expect(Object.keys(data).sort()).toEqual(['issuer', 'vct', 'wallet_binding']);
  });
});

describe('readWalletBinding — degrades to null, never to a usable value (#238)', () => {
  it.each([
    ['a password credential row', { password_hash: 'x', email_verified: true }],
    ['an empty object', {}],
    ['null', null],
    ['a string', 'wb1:deadbeef'],
    ['an array', [BINDING]],
    ['a camelCase drift', { walletBinding: BINDING, issuer: 'https://i', vct: 'v' }],
    ['a non-string binding', { wallet_binding: 42, issuer: 'https://i', vct: 'v' }],
    ['an empty binding', { wallet_binding: '', issuer: 'https://i', vct: 'v' }],
    [
      'an over-long binding',
      { wallet_binding: 'a'.repeat(MAX_WALLET_BINDING_LENGTH + 1), issuer: 'https://i', vct: 'v' },
    ],
  ] as const)('returns null for %s', (_label, value) => {
    expect(readWalletBinding(value)).toBeNull();
  });

  it('tolerates sibling keys a future issue adds', () => {
    // Deliberately not `.strict()`: a reader of today's binary must keep parsing
    // rows written by tomorrow's.
    expect(
      readWalletBinding({
        wallet_binding: BINDING,
        issuer: 'https://issuer.example.com',
        vct: 'https://vct',
        linked_at: 1,
      })
    ).toBe(BINDING);
  });
});
