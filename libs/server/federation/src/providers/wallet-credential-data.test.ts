import { describe, expect, it } from 'vitest';

import { ValidatedIssuer } from '../trust/issuer-identity';
import { buildWalletCredentialData, walletCredentialDataSchema } from './wallet.provider';
import { MAX_WALLET_BINDING_LENGTH, readWalletBinding } from './wallet-credential-data';

/**
 * Reading `credential_data` back out of a `provider_type='wallet'` row
 * (#235 writes it, #238 reads it).
 *
 * The stored binding is the stored half of ADR-009 §1's entitlement check, so
 * the tests that matter are the ones proving an unusable row degrades to "no
 * binding" — which the strategies treat as a REFUSAL — rather than to something
 * that accidentally compares equal.
 */

const BINDING = `wb1:${'a'.repeat(64)}`;

/** A row exactly as `buildWalletCredentialData` writes it. */
const ENROLLED_ROW = {
  credential_format: 'dc+sd-jwt',
  credential_type: 'https://credentials.example.com/pid',
  issuer: 'https://issuer.example.com',
  wallet_binding: BINDING,
  subject_resolution: 'asserted-lookup',
  enrolled_at: 1_700_000_000_000,
  credential_expires_at: null,
} as const;

describe('readWalletBinding — the reader and the writer agree (#235/#238)', () => {
  it('reads back what the write shape stores', () => {
    // The pairing that matters: the ONE writer and the ONE reader, checked
    // against each other rather than each against its own fixture. A key rename
    // on either side has to fail here.
    expect(walletCredentialDataSchema.safeParse(ENROLLED_ROW).success).toBe(true);
    expect(readWalletBinding(ENROLLED_ROW)).toBe(BINDING);
  });

  it('is not coupled to the rest of the write shape', () => {
    // The reader asks for the one field it consumes. A row that gained a sibling
    // key, or lost one this binary no longer writes, must still yield its
    // binding: `null` means "no wallet binding", which ADR-009's second
    // bootstrap case turns into a refusal for a legitimate account.
    expect(readWalletBinding({ wallet_binding: BINDING })).toBe(BINDING);
    expect(readWalletBinding({ ...ENROLLED_ROW, linked_at: 1, some_future_key: 'x' })).toBe(
      BINDING
    );
  });

  it('never reports holder key material or a claim value as a binding', () => {
    // OID4VP 1.0 §15.5–§15.6 and ADR-009 §4: a `cnf` key identifies a
    // credential, not a person, and ADR-009 Finding 2 is about keeping claim
    // values out of columns like this one. Neither is reachable through this
    // reader even if a hand-edited row carried them.
    expect(readWalletBinding({ cnf: { jwk: { kty: 'EC' } } })).toBeNull();
    expect(readWalletBinding({ birthdate: '1990-01-01' })).toBeNull();
  });
});

describe('readWalletBinding — degrades to null, never to a usable value (#238)', () => {
  it.each([
    ['a password credential row', { password_hash: 'x', email_verified: true }],
    ['an empty object', {}],
    ['null', null],
    ['undefined', undefined],
    ['a string', 'wb1:deadbeef'],
    ['an array', [BINDING]],
    ['a camelCase drift', { ...ENROLLED_ROW, wallet_binding: undefined, walletBinding: BINDING }],
    ['a non-string binding', { ...ENROLLED_ROW, wallet_binding: 42 }],
    ['an empty binding', { ...ENROLLED_ROW, wallet_binding: '' }],
    ['a null binding (a strategy that stores none)', { ...ENROLLED_ROW, wallet_binding: null }],
    [
      'an over-long binding',
      { ...ENROLLED_ROW, wallet_binding: 'a'.repeat(MAX_WALLET_BINDING_LENGTH + 1) },
    ],
  ] as const)('returns null for %s', (_label, value) => {
    expect(readWalletBinding(value)).toBeNull();
  });

  it('never throws, whatever the column holds', () => {
    // A corrupt row must make its account unclaimable by a presentation, never
    // turn a login into a 500 — and never let a caller distinguish the two.
    const hostile: unknown[] = [
      Object.create(null),
      { wallet_binding: { toString: () => BINDING } },
      Symbol('x'),
      123n,
    ];

    for (const value of hostile) {
      expect(() => readWalletBinding(value)).not.toThrow();
      expect(readWalletBinding(value)).toBeNull();
    }
  });
});

describe('buildWalletCredentialData → readWalletBinding round trip', () => {
  it('a row the enrolment path wrote reads back its binding', () => {
    const data = buildWalletCredentialData({
      credential: {
        queryId: 'pid',
        format: 'dc+sd-jwt',
        credentialType: 'https://credentials.example.com/pid',
        issuer: issuerFor('https://issuer.example.com'),
        claims: {},
        validity: {},
        assurance: {
          credentialType: 'https://credentials.example.com/pid',
          issuerKeyResolution: 'issuer-metadata',
          issuerSignatureAlgorithm: 'ES256',
          keyBindingAlgorithm: 'ES256',
          disclosedClaimCount: 0,
          statusChecked: 'not-required',
          keyStorageAssurance: { assurance: 'none' },
        },
      },
      walletBinding: BINDING,
      subjectResolution: 'asserted-lookup',
    });

    expect(readWalletBinding(data)).toBe(BINDING);
  });
});

/** A genuine branded issuer — `buildWalletCredentialData` refuses anything else. */
function issuerFor(identifier: string) {
  return ValidatedIssuer.fromValidatedPresentation({
    identifier,
    keyResolution: 'issuer-metadata',
  });
}
