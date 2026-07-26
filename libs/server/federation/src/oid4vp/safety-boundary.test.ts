import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import { createWalletProvider } from '../providers/wallet.provider';
import { assertIssuerTrusted } from '../trust/trust-registry';
import { buildOid4vpAuthorizationRequest } from './authorization-request';
import { parseVpToken } from './direct-post';
import { validatePresentations } from './presentation-validation';
import { generateOid4vpRequestSecrets } from './request-state';
import {
  fixtureValidationContext,
  issueSdJwtVc,
  presentSdJwtVc,
  TEST_VCT,
} from './sd-jwt-vc.fixture';

/**
 * The safety boundary of issue #233, asserted rather than merely documented.
 *
 * #233 ships the OID4VP TRANSPORT: a wallet can now receive a presentation
 * request from QAuth and post a `vp_token` back, and QAuth will correlate the
 * `state`/`nonce` and structurally parse the response. That proves key
 * possession and freshness. It proves NOTHING about who the holder is.
 *
 * Under ADR-003 the auth engine mints a QAuth token for whatever `externalSub` a
 * `CredentialProvider` returns. So the moment `WalletProvider.verify()` resolves
 * a subject on the strength of this transport, any party able to round-trip the
 * endpoint self-registers as a user. Identity requires the credential to be
 * validated (#234) and its issuer to be trusted (#236) — and even then there is
 * no protocol-guaranteed stable wallet subject identifier (ADR-009 / #300).
 *
 * If a change makes this file fail, the change is wrong until #234 and #236 have
 * both landed. Do not soften the assertions to make it pass.
 */
describe('#233 safety boundary — the transport authenticates nobody', () => {
  it('WalletProvider.verify() STILL throws after the transport layer landed', async () => {
    const provider = createWalletProvider();

    await expect(provider.verify({ anything: 'a structurally valid response' })).rejects.toThrow(
      /not implemented/
    );
  });

  it('WalletProvider.extractAttributes() still throws', () => {
    expect(() => createWalletProvider().extractAttributes({} as never)).toThrow(/not implemented/);
  });

  it('a full request → response round-trip yields no identity of any kind', () => {
    const { state, nonce } = generateOid4vpRequestSecrets();

    const request = buildOid4vpAuthorizationRequest({
      profile: VERIFIER_PROFILES['oid4vp-1.0-base'],
      responseUri: 'https://auth.example.com/oid4vp/response',
      credentials: [
        { id: 'pid', format: 'dc+sd-jwt', typeValues: ['https://credentials.example.com/pid'] },
      ],
      state,
      nonce,
    });

    const presentations = parseVpToken(
      JSON.stringify({ pid: ['eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJwaWQifQ.c2ln~'] }),
      request.dcql_query,
      VERIFIER_PROFILES['oid4vp-1.0-base'].credentialFormats
    );

    // Everything the transport produced, flattened. None of it names a person.
    const surface = JSON.stringify(presentations);

    expect(presentations).toHaveLength(1);
    expect(surface).not.toContain('externalSub');
    expect(surface).not.toContain('external_sub');
    expect(surface).not.toContain('subject');
    expect(surface).not.toContain('userId');

    for (const presented of presentations) {
      expect(Object.keys(presented).sort()).toEqual(['format', 'presentation', 'queryId']);
    }
  });

  /**
   * A grep, deliberately. The types above cannot stop a future edit from adding
   * a subject-derivation helper next to them, and ADR-009 is explicit that this
   * layer must not derive or persist any `external_sub` — not from a JWK
   * thumbprint, not from a DID, not from an unverified `iss`.
   */
  it('no module in oid4vp/ derives an external_sub or a wallet subject', () => {
    const dir = __dirname;
    const sources = readdirSync(dir).filter(
      (file) => file.endsWith('.ts') && !file.endsWith('.test.ts')
    );

    expect(sources.length).toBeGreaterThan(0);

    const forbidden = [/externalSub\s*[:=]/, /external_sub\s*[:=]/, /thumbprint/i, /\bdid:/];

    for (const file of sources) {
      const contents = readFileSync(path.join(dir, file), 'utf8');
      // Strip block comments: the boundary is DESCRIBED in the JSDoc on purpose.
      const code = contents.replace(/\/\*[\s\S]*?\*\//g, '');

      for (const pattern of forbidden) {
        expect(
          pattern.test(code),
          `${file} appears to derive a wallet subject (${pattern}); identity is #234/#236, not #233.`
        ).toBe(false);
      }
    }
  });
});

/**
 * The safety boundary of issue #234, which moved but did not soften.
 *
 * #234 ships CRYPTOGRAPHIC VALIDATION: a `vp_token` is now checked for issuer
 * signature, disclosure-digest integrity, validity window and holder binding to
 * this exact request. That is a real, hard-won guarantee — and it is still not
 * authentication:
 *
 *  - a validly-signed credential from an issuer this realm does not trust is a
 *    forgery with extra steps (#236 decides, from the identity #234 surfaces);
 *  - there is no protocol-guaranteed stable wallet subject identifier, so there
 *    is nothing to key an account on (ADR-009 / #300).
 *
 * If a change makes this block fail, the change is wrong until #236 AND #300
 * have both landed. Do not soften the assertions to make it pass.
 */
describe('#234 safety boundary — a VALID credential authenticates nobody', () => {
  /** The whole flow, from a request we built to a fully validated credential. */
  async function validateRealPresentation() {
    const { state, nonce } = generateOid4vpRequestSecrets();

    const request = buildOid4vpAuthorizationRequest({
      profile: VERIFIER_PROFILES['oid4vp-1.0-base'],
      responseUri: 'https://auth.example.com/oid4vp/response',
      credentials: [{ id: 'pid', format: 'dc+sd-jwt', typeValues: [TEST_VCT] }],
      state,
      nonce,
    });

    const issued = await issueSdJwtVc();
    // Bound to the `client_id` and `nonce` of the request QAuth actually sent —
    // the Key Binding JWT is what ties this Presentation to this exchange.
    const presentation = await presentSdJwtVc(issued, {
      nonce: request.nonce,
      audience: request.client_id,
    });

    const parsed = parseVpToken(
      JSON.stringify({ pid: [presentation] }),
      request.dcql_query,
      VERIFIER_PROFILES['oid4vp-1.0-base'].credentialFormats
    );

    const validated = await validatePresentations(
      parsed,
      request.dcql_query,
      fixtureValidationContext(issued, request.nonce, { clientId: request.client_id })
    );

    return { validated, presentation, issued };
  }

  it('produces a ValidatedCredential carrying no subject of any kind', async () => {
    const { validated } = await validateRealPresentation();

    expect(validated).toHaveLength(1);

    const surface = JSON.stringify(validated);

    expect(surface).not.toContain('externalSub');
    expect(surface).not.toContain('external_sub');
    expect(surface).not.toContain('userId');
    // The holder key and the raw `iss` are consumed and dropped — ADR-009 and
    // OID4VP §15.5–§15.6 both forbid keying an account on wallet cryptography.
    expect(surface).not.toContain('cnf');
    expect(surface).not.toContain('"kty"');
    expect(Object.keys(validated[0]).sort()).toEqual([
      'assurance',
      'claims',
      'credentialType',
      'format',
      'issuer',
      'queryId',
      'validity',
    ]);
  });

  it('is NOT a VerifiedIdentity — it carries no assuranceLevel and no rawClaims', async () => {
    const { validated } = await validateRealPresentation();

    expect(validated[0]).not.toHaveProperty('assuranceLevel');
    expect(validated[0]).not.toHaveProperty('rawClaims');
    // The eIDAS LoA is derived downstream from the credential AND its trusted
    // issuer (#237); this layer reports evidence only.
    expect(validated[0].assurance.statusChecked).toBe(false);
  });

  it('surfaces the issuer WITHOUT treating it as trusted', async () => {
    const { validated } = await validateRealPresentation();

    // The gate #236 owns still refuses: a realm with no configured registry
    // trusts nobody, however well the credential validated.
    expect(() => assertIssuerTrusted(undefined, validated[0].issuer)).toThrow(
      /Verifiable Presentation rejected/
    );
  });

  it('WalletProvider.verify() STILL throws when handed a fully valid Presentation', async () => {
    const { presentation } = await validateRealPresentation();
    const provider = createWalletProvider();

    const settled = await provider
      .verify({ vp_token: { pid: [presentation] }, state: 'anything' })
      .then(
        (value) => ({ status: 'resolved' as const, value }),
        (reason: unknown) => ({ status: 'rejected' as const, value: reason })
      );

    expect(settled.status).toBe('rejected');
    expect((settled.value as Error).message).toMatch(/not implemented/);
  });

  it('names the two gates that still have to land before a wallet can authenticate', async () => {
    const error = await createWalletProvider()
      .verify({})
      .then(
        () => null,
        (reason: unknown) => reason as Error
      );

    expect(error?.message).toContain('#236');
    expect(error?.message).toContain('#300');
  });

  it('no module in oid4vp/ produces a VerifiedIdentity', () => {
    const dir = __dirname;
    const sources = readdirSync(dir).filter(
      (file) => file.endsWith('.ts') && !file.endsWith('.test.ts')
    );

    for (const file of sources) {
      const code = readFileSync(path.join(dir, file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');

      expect(
        /VerifiedIdentity/.test(code),
        `${file} references VerifiedIdentity; validation produces a ValidatedCredential, and only #236 + #300 can turn one into an identity.`
      ).toBe(false);
      expect(
        /assuranceLevel/.test(code),
        `${file} emits an assuranceLevel; #234 reports an assurance SIGNAL and #237 derives the level.`
      ).toBe(false);
    }
  });
});
