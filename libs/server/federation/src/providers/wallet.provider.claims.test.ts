import { describe, expect, it } from 'vitest';

import {
  fixtureValidationContext,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_CREDENTIAL_QUERY,
} from '../../testing/sd-jwt-vc.fixture';
import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { validateSdJwtVcPresentation } from '../oid4vp/sd-jwt-vc';
import { deriveWalletBinding } from '../subject/subject-binding';
import { EMAIL_ATTR_KEY } from './password.provider';
import {
  buildWalletCredentialData,
  buildWalletVerifiedIdentity,
  createWalletProvider,
  extractWalletAttributes,
  WALLET_SOURCE,
  walletCredentialDataSchema,
} from './wallet.provider';

/**
 * VC claims normalization into `user_attributes` (issue #235, ADR-004).
 *
 * Every credential here is REAL: issued, presented and run through #234's
 * validator by `validatedFixtureCredential`. A mapping test could be written
 * against object literals — `sd-jwt-vc-claims.test.ts` is — but the rows this
 * file asserts about are the ones a deployment actually writes, so they are
 * derived from a credential that survived signature verification, disclosure
 * digests, the validity window and holder binding. That also means the claim set
 * under test is one a holder genuinely disclosed, not one a test invented.
 */

/** Far enough out that no clock skew makes it expire mid-suite. */
const FAR_FUTURE_SECONDS = Math.floor(Date.now() / 1000) + 3600;

describe('extractWalletAttributes (#235)', () => {
  it('writes every disclosed identity claim as a verified wallet attribute', async () => {
    const credential = await validatedFixtureCredential({
      claims: {
        given_name: 'Alice',
        family_name: 'Doe',
        birthdate: '1990-01-01',
        nationality: 'DE',
      },
    });

    expect(extractWalletAttributes(credential)).toEqual([
      { source: 'wallet', attrKey: 'given_name', attrValue: 'Alice', verified: true },
      { source: 'wallet', attrKey: 'family_name', attrValue: 'Doe', verified: true },
      { source: 'wallet', attrKey: 'birthdate', attrValue: '1990-01-01', verified: true },
      { source: 'wallet', attrKey: 'nationality', attrValue: 'DE', verified: true },
    ]);
  });

  it("stamps source='wallet' — the top of ADR-002's trust order", async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    for (const attribute of extractWalletAttributes(credential)) {
      expect(attribute.source).toBe(WALLET_SOURCE);
    }
  });

  it('marks rows verified because the ISSUER signed them and #236 accepted the issuer', async () => {
    const credential = await validatedFixtureCredential({
      claims: { email: 'alice@example.com', email_verified: true, given_name: 'Alice' },
    });

    expect(extractWalletAttributes(credential)).toEqual([
      { source: 'wallet', attrKey: EMAIL_ATTR_KEY, attrValue: 'alice@example.com', verified: true },
      { source: 'wallet', attrKey: 'given_name', attrValue: 'Alice', verified: true },
    ]);
  });

  // The issuer signed "this is the holder's address, and it is NOT verified".
  // Storing it verified would claim more than the issuer did, and
  // resolveEmailClaims would emit email_verified: true downstream.
  it('writes the email row UNVERIFIED when the issuer itself signed email_verified: false', async () => {
    const credential = await validatedFixtureCredential({
      claims: { email: 'alice@example.com', email_verified: false, given_name: 'Alice' },
    });

    expect(extractWalletAttributes(credential)).toEqual([
      {
        source: 'wallet',
        attrKey: EMAIL_ATTR_KEY,
        attrValue: 'alice@example.com',
        verified: false,
      },
      // Only the email row: the flag says nothing about any other claim.
      { source: 'wallet', attrKey: 'given_name', attrValue: 'Alice', verified: true },
    ]);
  });

  it.each([
    ['the string "true"', 'true'],
    ['the string "false"', 'false'],
    ['null', null],
  ])(
    'treats email_verified=%s as no assertion (only a signed boolean true verifies the row)',
    async (_label, value) => {
      const credential = await validatedFixtureCredential({
        claims: { email: 'alice@example.com', email_verified: value },
      });

      expect(extractWalletAttributes(credential)).toEqual([
        {
          source: 'wallet',
          attrKey: EMAIL_ATTR_KEY,
          attrValue: 'alice@example.com',
          verified: false,
        },
      ]);
    }
  );

  // The holder chooses the Disclosures. A credential whose issuer signed
  // `email_verified: false` as its own Disclosure can be presented with that
  // Disclosure left out, and the validator rightly accepts the subset. The
  // claim set then says nothing about verification, and nothing is what QAuth
  // must assert: absence must read exactly like the denial the holder withheld.
  it('keeps the email row UNVERIFIED when the holder withholds the email_verified Disclosure', async () => {
    const issued = await issueSdJwtVc({
      selectiveClaims: { email: 'alice@example.com', email_verified: false },
    });
    const [emailDisclosure] = issued.disclosures;
    const nonce = 'nonce-withheld-email-verified';
    const presentation = await presentSdJwtVc(issued, { nonce, disclosures: [emailDisclosure] });

    const credential = await validateSdJwtVcPresentation(
      presentation,
      TEST_CREDENTIAL_QUERY.id,
      TEST_CREDENTIAL_QUERY,
      fixtureValidationContext(issued, nonce)
    );

    expect(credential.claims).not.toHaveProperty('email_verified');
    expect(extractWalletAttributes(credential)).toEqual([
      {
        source: 'wallet',
        attrKey: EMAIL_ATTR_KEY,
        attrValue: 'alice@example.com',
        verified: false,
      },
    ]);
  });

  describe('an issuer the operator lists in OID4VP_EMAIL_VERIFYING_ISSUERS (ANT-2026-BGP7XCR2)', () => {
    // A PID-style issuer that only ever issues verified addresses and signs no
    // `email_verified` flag. The operator, not the holder, decides that its
    // email counts as verified.
    it('verifies an email that arrives with no email_verified claim', async () => {
      const credential = await validatedFixtureCredential({
        claims: { email: 'alice@example.com' },
      });

      expect(
        extractWalletAttributes(credential, undefined, { issuerVouchesForEmail: true })
      ).toEqual([
        {
          source: 'wallet',
          attrKey: EMAIL_ATTR_KEY,
          attrValue: 'alice@example.com',
          verified: true,
        },
      ]);
    });

    it('still honours a disclosed email_verified: false from that issuer', async () => {
      const credential = await validatedFixtureCredential({
        claims: { email: 'alice@example.com', email_verified: false },
      });

      expect(
        extractWalletAttributes(credential, undefined, { issuerVouchesForEmail: true })
      ).toEqual([
        {
          source: 'wallet',
          attrKey: EMAIL_ATTR_KEY,
          attrValue: 'alice@example.com',
          verified: false,
        },
      ]);
    });
  });

  describe('expiry (ADR-002: an attribute must not outlive the credential asserting it)', () => {
    it("carries the credential's exp onto every row", async () => {
      const credential = await validatedFixtureCredential({
        claims: { given_name: 'Alice', family_name: 'Doe' },
        issue: { exp: FAR_FUTURE_SECONDS },
      });

      const attributes = extractWalletAttributes(credential);

      expect(attributes).toHaveLength(2);
      for (const attribute of attributes) {
        expect(attribute.expiresAt).toEqual(new Date(FAR_FUTURE_SECONDS * 1000));
      }
    });

    it('omits expiry entirely when the credential carries none', async () => {
      const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

      // Absent, never null: `UserAttribute.expiresAt` is optional and the
      // register-path conversion (`attr.expiresAt ? getTime() : null`) turns
      // absence into the DB's NULL, which `selectTrustedAttribute` reads as
      // "never expires".
      expect(extractWalletAttributes(credential)[0]).not.toHaveProperty('expiresAt');
    });
  });

  describe('email present vs absent (#235 test matrix)', () => {
    it('emits an email row when the holder disclosed one', async () => {
      const credential = await validatedFixtureCredential({
        claims: { email: 'Alice@Example.COM', given_name: 'Alice' },
      });

      // Present, normalized, and UNVERIFIED: no `email_verified: true` was
      // disclosed alongside it, so the row must not reach `resolveEmailClaims`.
      expect(
        extractWalletAttributes(credential).find((attr) => attr.attrKey === EMAIL_ATTR_KEY)
      ).toEqual({
        source: 'wallet',
        attrKey: 'email',
        attrValue: 'alice@example.com',
        verified: false,
      });
    });

    it('emits no email row — and still emits the rest — when the holder withheld it', async () => {
      // Selective disclosure is the normal case, not an error: withholding one
      // claim must not cost the user the claims they did disclose.
      const credential = await validatedFixtureCredential({
        claims: { given_name: 'Alice', family_name: 'Doe' },
      });

      const attributes = extractWalletAttributes(credential);

      expect(attributes.map((attr) => attr.attrKey)).toEqual(['given_name', 'family_name']);
    });
  });

  it('returns an empty list for a credential that asserts nothing QAuth maps', async () => {
    // An age-attestation EAA is a legitimate login that carries no identity
    // attribute. Empty is the honest answer here — and it is reachable ONLY
    // through a real credential, never from a malformed input (see below).
    const credential = await validatedFixtureCredential({ claims: { age_over_18: true } });

    expect(extractWalletAttributes(credential)).toEqual([]);
  });

  it('throws rather than returning [] for a malformed source', () => {
    expect(() => extractWalletAttributes(null as never)).toThrow(/validated credential/);
  });
});

describe('buildWalletVerifiedIdentity (#235 consumes #300’s external_sub)', () => {
  it('carries the resolved external_sub through unchanged', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    const identity = buildWalletVerifiedIdentity(credential, 'alice@example.com');

    expect(identity.externalSub).toBe('alice@example.com');
    // ADR-003: 'low' emits no `acr`. #237 supplies a higher level; this
    // function never guesses one.
    expect(identity.assuranceLevel).toBe('low');
  });

  it('refuses to invent an external_sub when none was resolved', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    expect(() => buildWalletVerifiedIdentity(credential, '')).toThrow(/SubjectResolutionStrategy/);
  });

  it('derives NOTHING from wallet cryptography (ADR-009, OID4VP §15.5–§15.6)', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    const surface = JSON.stringify(buildWalletVerifiedIdentity(credential, 'alice@example.com'));

    expect(surface).not.toContain('cnf');
    expect(surface).not.toContain('"kty"');
    expect(surface).not.toContain('thumbprint');
    expect(surface).not.toContain('did:');
  });

  it('refuses a credential whose issuer is not the branded ValidatedIssuer', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });
    const forged = {
      ...credential,
      issuer: { identifier: 'https://evil.example', keyResolution: 'x5c' },
    };

    expect(() => buildWalletVerifiedIdentity(forged as never, 'alice@example.com')).toThrow(
      /ValidatedIssuer/
    );
  });

  it('round-trips through WalletProvider.extractAttributes to the same rows', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', email: 'alice@example.com' },
      issue: { exp: FAR_FUTURE_SECONDS },
    });

    const identity = buildWalletVerifiedIdentity(credential, 'alice@example.com');

    expect(createWalletProvider().extractAttributes(identity)).toEqual(
      extractWalletAttributes(credential)
    );
  });
});

describe('buildWalletCredentialData (#235 writes the wallet credential row)', () => {
  it('records what a later presentation must be matched against', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe' },
      issue: { exp: FAR_FUTURE_SECONDS },
    });
    const binding = deriveWalletBinding(credential, ['family_name', 'given_name']);

    const data = buildWalletCredentialData({
      credential,
      walletBinding: binding as string,
      subjectResolution: 'asserted-lookup',
      enrolledAt: 1_700_000_000_000,
    });

    expect(data).toEqual({
      credential_format: 'dc+sd-jwt',
      credential_type: 'https://credentials.example.com/pid',
      issuer: 'https://issuer.example.com',
      wallet_binding: binding,
      subject_resolution: 'asserted-lookup',
      enrolled_at: 1_700_000_000_000,
      credential_expires_at: FAR_FUTURE_SECONDS,
    });
    expect(walletCredentialDataSchema.safeParse(data).success).toBe(true);
  });

  it('takes the issuer from the VALIDATED identity, never from a credential-asserted iss', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice' },
      issuer: 'https://issuer.example.com/',
    });

    // Canonicalized: the trailing slash is stripped, so the value stored is the
    // same one `assertIssuerTrusted` and the binding derivation compare.
    expect(
      buildWalletCredentialData({
        credential,
        walletBinding: 'wb1:deadbeef',
        subjectResolution: 'asserted-lookup',
      }).issuer
    ).toBe('https://issuer.example.com');
  });

  it('refuses a credential whose issuer is not the branded ValidatedIssuer', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });
    const forged = {
      ...credential,
      issuer: { identifier: 'https://evil.example', keyResolution: 'x5c' },
    };

    expect(() =>
      buildWalletCredentialData({
        credential: forged as never,
        walletBinding: 'wb1:deadbeef',
        subjectResolution: 'asserted-lookup',
      })
    ).toThrow(/ValidatedIssuer/);
  });

  it('stores no claim VALUES, no holder key and no DID (ADR-009 Finding 2)', async () => {
    const credential = await validatedFixtureCredential({
      claims: { given_name: 'Alice', family_name: 'Doe', personal_administrative_number: 'PA-42' },
    });

    const surface = JSON.stringify(
      buildWalletCredentialData({
        credential,
        walletBinding: deriveWalletBinding(credential, ['family_name']) as string,
        subjectResolution: 'asserted-lookup',
      })
    );

    // The binding is a digest, so the person's attributes are matchable without
    // being kept a second time in the clear.
    expect(surface).not.toContain('Alice');
    expect(surface).not.toContain('PA-42');
    expect(surface).not.toContain('cnf');
    expect(surface).not.toContain('"kty"');
  });

  it('records null expiry for a credential with no exp', async () => {
    const credential = await validatedFixtureCredential({ claims: { given_name: 'Alice' } });

    expect(
      buildWalletCredentialData({
        credential,
        walletBinding: 'wb1:deadbeef',
        subjectResolution: 'asserted-lookup',
      }).credential_expires_at
    ).toBeNull();
  });
});
