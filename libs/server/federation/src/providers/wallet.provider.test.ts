import { describe, expect, it } from 'vitest';

import { rankAttributeSource } from '../claims/attribute-trust';
import type { VerifiedIdentity } from './credential-provider.interface';
import { createWalletProvider, WALLET_PROVIDER_TYPE, WALLET_SOURCE } from './wallet.provider';

/**
 * WalletProvider is a REGISTRATION-ONLY skeleton (#232). These tests pin the
 * two things the skeleton actually promises — its `type` discriminator and that
 * every method fails closed — so a future contributor cannot quietly turn the
 * stubs into no-ops (which would be an authentication-bypass primitive, see the
 * module JSDoc) without a red test.
 */
describe('WalletProvider (ADR-004 skeleton, #232)', () => {
  const provider = createWalletProvider();

  it('registers under the wallet type', () => {
    expect(provider.type).toBe(WALLET_PROVIDER_TYPE);
    expect(provider.type).toBe('wallet');
  });

  it("declares 'wallet' as the attribute source ranked highest by ADR-002 trust order", () => {
    // Pins WALLET_SOURCE to the literal `rankAttributeSource` special-cases —
    // a drift here would silently demote every VC-derived attribute to rank 0.
    expect(WALLET_SOURCE).toBe('wallet');
    expect(rankAttributeSource(WALLET_SOURCE)).toBe(3);
  });

  describe('verify (must fail closed)', () => {
    /** Inputs a future OID4VP caller might plausibly hand this provider. */
    const plausibleInputs: ReadonlyArray<readonly [string, unknown]> = [
      ['no input', undefined],
      ['empty object', {}],
      [
        // KEPT DELIBERATELY as a negative case. SIOPv2 is NOT the mechanism
        // (ADR-004 § "Spec status (2026-07-20)", #295): HAIP 1.0 §5 mandates
        // `response_type=vp_token`, which excludes the self-issued `id_token`.
        // This fixture is the shape a contributor who read the pre-correction
        // ADR would wire up, so it must keep failing closed rather than being
        // deleted along with the error that inspired it.
        'SIOPv2-shaped id_token response (superseded shape — must never be accepted)',
        {
          id_token: 'eyJhbGciOiJFZERTQSJ9.e30.sig',
          state: 'abc123',
        },
      ],
      [
        'OID4VP-shaped presentation response',
        {
          // OID4VP 1.0 Final response shape: `vp_token` is a JSON OBJECT keyed
          // by the `id` of each DCQL Credential Query, each value an array of
          // presentations. There is no `dcql_query_id` response parameter (the
          // REQUEST carries `dcql_query`), `credential_sets` is a separate DCQL
          // construct, and the flat-string `vp_token` of the pre-1.0 drafts is
          // superseded. #234 must build against this shape — see ADR-004
          // § "Spec status (2026-07-19)" and the module JSDoc.
          vp_token: { pid_credential: ['eyJhbGciOiJFZERTQSJ9.e30.sig~disclosure~'] },
          state: 'abc123',
        },
      ],
      [
        'a fully-formed VerifiedIdentity (the shape an attacker would want back)',
        {
          externalSub: 'did:example:123',
          assuranceLevel: 'high',
          rawClaims: { given_name: 'Alice' },
        },
      ],
      [
        // #234 landed presentation validation, so this is now a shape a caller
        // could genuinely hold: a credential that verified in every respect.
        // It still authenticates nobody — issuer trust (#236) and subject
        // resolution (#300) have not run, and neither has anything here.
        'a ValidatedCredential (#234) — validated is not authenticated',
        {
          queryId: 'pid',
          format: 'dc+sd-jwt',
          credentialType: 'https://credentials.example.com/pid',
          claims: { given_name: 'Alice' },
          assurance: { statusChecked: false },
        },
      ],
    ];

    it.each(plausibleInputs)('rejects for %s', async (_label, input) => {
      await expect(provider.verify(input)).rejects.toThrow(/not implemented/);
    });

    it.each(plausibleInputs)('never resolves a VerifiedIdentity for %s', async (_label, input) => {
      // Stronger than `.rejects`: proves the promise settles as a rejection
      // rather than resolving anything at all (an empty or placeholder identity
      // would authenticate whoever presented it).
      const settled = await provider.verify(input).then(
        (value) => ({ status: 'resolved' as const, value }),
        (reason: unknown) => ({ status: 'rejected' as const, value: reason })
      );

      expect(settled.status).toBe('rejected');
      expect(settled.value).toBeInstanceOf(Error);
    });

    it('names this issue and the follow-ups that implement verification', async () => {
      const error = await provider.verify({}).then(
        () => null,
        (reason: unknown) => reason as Error
      );

      expect(error?.message).toContain('#232');
      expect(error?.message).toContain('#233');
      expect(error?.message).toContain('#234');
      expect(error?.message).toContain('WalletProvider.verify()');
    });

    it('names the gates that remain OPEN now that validation (#234) has landed', async () => {
      const error = await provider.verify({}).then(
        () => null,
        (reason: unknown) => reason as Error
      );

      // Issuer trust and subject resolution. Until both are wired, a validated
      // credential is a cryptographic finding and nothing more.
      expect(error?.message).toContain('#236');
      expect(error?.message).toContain('#300');
    });
  });

  /**
   * IMPLEMENTED as of #235 — and #232's reason for making it throw survives.
   *
   * The original skeleton test read *"never returns an empty attribute list
   * (silent claim loss)"*, because a stub returning `[]` would be
   * indistinguishable from a working provider handed a credential carrying no
   * claims. That property is still asserted below, in the only form it can now
   * take: a malformed input THROWS, and `[]` is reachable only from a
   * well-formed envelope whose credential genuinely disclosed nothing mappable.
   *
   * The mapping itself is exercised against real, validated credentials in
   * `wallet.provider.claims.test.ts`.
   */
  describe('extractAttributes (#235)', () => {
    /** What `buildWalletVerifiedIdentity` produces — the only accepted shape. */
    const identity: VerifiedIdentity = {
      externalSub: 'alice@example.com',
      assuranceLevel: 'low',
      rawClaims: {
        credential_format: 'dc+sd-jwt',
        credential_type: 'https://credentials.example.com/pid',
        issuer: 'https://issuer.example.com',
        claims: { given_name: 'Alice', family_name: 'Doe' },
      },
    };

    it('normalizes the envelope’s claims into verified wallet attributes', () => {
      expect(provider.extractAttributes(identity)).toEqual([
        { source: WALLET_SOURCE, attrKey: 'given_name', attrValue: 'Alice', verified: true },
        { source: WALLET_SOURCE, attrKey: 'family_name', attrValue: 'Doe', verified: true },
      ]);
    });

    it('still fails LOUDLY on an envelope verify() would never have produced', () => {
      // #232's silent-claim-loss guard, in its post-#235 form. A bare claim set
      // (the shape a caller who skipped `buildWalletVerifiedIdentity` would
      // pass) carries no format, so there is no vocabulary to read it with —
      // and returning `[]` would look exactly like an empty credential.
      expect(() =>
        provider.extractAttributes({
          externalSub: 'alice@example.com',
          assuranceLevel: 'low',
          rawClaims: { given_name: 'Alice', family_name: 'Doe' },
        })
      ).toThrow(/buildWalletVerifiedIdentity did not produce/);
    });

    it.each([
      ['a password-shaped rawClaims', { email: 'a@example.com', email_verified: true }],
      ['an unknown credential format', { ...identity.rawClaims, credential_format: 'mso_mdoc' }],
      ['a missing issuer', { ...identity.rawClaims, issuer: '' }],
      ['an unexpected sibling key', { ...identity.rawClaims, sub: 'did:example:123' }],
      ['claims that are not an object', { ...identity.rawClaims, claims: 'given_name=Alice' }],
    ] as ReadonlyArray<readonly [string, Record<string, unknown>]>)(
      'throws for %s',
      (_label, rawClaims) => {
        expect(() =>
          provider.extractAttributes({ externalSub: 'x', assuranceLevel: 'low', rawClaims })
        ).toThrow();
      }
    );

    it('returns [] only for a credential that genuinely disclosed nothing mappable', () => {
      expect(
        provider.extractAttributes({
          ...identity,
          rawClaims: { ...identity.rawClaims, claims: { age_over_18: true } },
        })
      ).toEqual([]);
    });

    it('authenticates nobody: the rows carry no subject and no user id', () => {
      const surface = JSON.stringify(provider.extractAttributes(identity));

      expect(surface).not.toContain('externalSub');
      expect(surface).not.toContain('external_sub');
      expect(surface).not.toContain('userId');
    });
  });

  it('is stateless — each factory call yields an independent, inert instance', () => {
    const other = createWalletProvider();
    expect(other).not.toBe(provider);
    expect(other.type).toBe(provider.type);
  });
});
