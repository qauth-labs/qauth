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
    /** Inputs a future SIOPv2/OID4VP caller might plausibly hand this provider. */
    const plausibleInputs: ReadonlyArray<readonly [string, unknown]> = [
      ['no input', undefined],
      ['empty object', {}],
      [
        'SIOPv2-shaped id_token response',
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
  });

  describe('extractAttributes (must fail closed)', () => {
    const identity: VerifiedIdentity = {
      externalSub: 'did:example:123',
      assuranceLevel: 'high',
      rawClaims: { given_name: 'Alice', family_name: 'Doe' },
    };

    it('throws instead of returning attributes', () => {
      expect(() => provider.extractAttributes(identity)).toThrow(/not implemented/);
    });

    it('never returns an empty attribute list (silent claim loss)', () => {
      let returned: unknown = 'sentinel';
      try {
        returned = provider.extractAttributes(identity);
      } catch {
        // expected — the assertion below proves nothing was produced.
      }
      expect(returned).toBe('sentinel');
    });

    it('names this issue and the follow-up that implements claim normalization', () => {
      const error = (() => {
        try {
          provider.extractAttributes(identity);
          return null;
        } catch (e: unknown) {
          return e as Error;
        }
      })();

      expect(error?.message).toContain('#232');
      expect(error?.message).toContain('#235');
      expect(error?.message).toContain('WalletProvider.extractAttributes()');
    });
  });

  it('is stateless — each factory call yields an independent, inert instance', () => {
    const other = createWalletProvider();
    expect(other).not.toBe(provider);
    expect(other.type).toBe(provider.type);
  });
});
