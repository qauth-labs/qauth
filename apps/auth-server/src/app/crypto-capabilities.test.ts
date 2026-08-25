/**
 * The bootstrap's answer to "what can this deployment ACTUALLY sign and
 * encrypt", and what the #299 fail-closed gate does with it.
 *
 * This file is the home of the claim because `apps/auth-server` is the only
 * place that can see both halves: the capability descriptor it builds, and
 * `createConfiguredProviders`, the gate that consumes it. The plugin lib's own
 * tests exercise the gate against FIXTURES (`CRYPTO_TODAY`, `CRYPTO_AFTER_298`,
 * …) — necessarily, since it does not depend on the crypto layer — so nothing
 * there can catch a bootstrap that hands the gate a descriptor claiming more
 * than the deployment can do. That is exactly the regression these tests exist
 * to catch: a capability claimed on the strength of a library function existing,
 * rather than of key material being provisioned, silently LIFTS the gate.
 */
import { createConfiguredProviders } from '@qauth-labs/fastify-plugin-federation';
import { describe, expect, it } from 'vitest';

import { deriveCryptoCapabilities, type ProvisionedSigningKeys } from './crypto-capabilities';

/** A PEM-shaped placeholder. Nothing here parses it; only presence is read. */
const PEM = (label: string) => `-----BEGIN ${label}-----\nplaceholder\n-----END ${label}-----`;

/** The default posture: EdDSA only, no RS256 key, no verifier identity. */
const NOTHING_OPTIONAL: ProvisionedSigningKeys = {
  rs256PrivateKey: undefined,
  verifierEs256PrivateKey: undefined,
  verifierCertificateChainPems: [],
};

/** A deployment with the optional RS256 ID-token key configured (#309). */
const WITH_RS256: ProvisionedSigningKeys = {
  ...NOTHING_OPTIONAL,
  rs256PrivateKey: PEM('PRIVATE KEY'),
};

/**
 * A deployment that provisioned the OID4VP verifier identity (#377): an ES256
 * key AND the certificate chain a wallet establishes that identity from.
 *
 * Both halves, because the ES256 predicate reads both. That is the point of the
 * two single-half fixtures below.
 */
const WITH_VERIFIER_IDENTITY: ProvisionedSigningKeys = {
  ...NOTHING_OPTIONAL,
  verifierEs256PrivateKey: PEM('PRIVATE KEY'),
  verifierCertificateChainPems: [PEM('CERTIFICATE'), PEM('CERTIFICATE')],
};

/**
 * The certificate state a HAIP deployment provisions — the non-self-signed chain
 * (QTSP-issued WRPAC) that the `x509_hash` prefix requires.
 *
 * Provisioned in the gate tests below on purpose: it takes the CERTIFICATE half
 * of the fail-closed gate out of the picture, so what is measured is the CRYPTO
 * half alone. Without it a passing test would prove only that the certificate is
 * missing, which is not the control under test.
 */
const WRPAC_PROVISIONED = { available: ['non-self-signed-chain'] } as const;

describe('deriveCryptoCapabilities (#298 F1, #377)', () => {
  it('always claims EdDSA — the env schema refuses to parse without that key', () => {
    expect(deriveCryptoCapabilities(NOTHING_OPTIONAL).signingAlgs).toContain('EdDSA');
  });

  it('claims RS256 only when an RS256 key is provisioned', () => {
    expect(deriveCryptoCapabilities(WITH_RS256).signingAlgs).toContain('RS256');
    expect(deriveCryptoCapabilities(NOTHING_OPTIONAL).signingAlgs).not.toContain('RS256');
  });

  it('treats a blank RS256 key as unprovisioned', () => {
    // `resolveKey` can hand back an empty string from an empty env var or an
    // empty key file. Fail closed: an empty key signs nothing.
    expect(
      deriveCryptoCapabilities({ ...NOTHING_OPTIONAL, rs256PrivateKey: '   ' }).signingAlgs
    ).not.toContain('RS256');
  });

  // The #377 acceptance criterion, stated as a test on the pure function.
  it('claims ES256 when an ES256 key AND a certificate chain are provisioned', () => {
    expect(deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY).signingAlgs).toContain('ES256');
  });

  it('does NOT claim ES256 on a key with no certificate chain', () => {
    // The half that a "does the key exist" predicate would get wrong. A P-256
    // key with no chain produces a signature a wallet cannot attribute to
    // anyone: OID4VP 1.0 §5.9.3 establishes the Verifier identity from the `x5c`
    // header, so claiming ES256 here would lift the gate for a deployment that
    // still cannot present a verifiable request.
    expect(
      deriveCryptoCapabilities({
        ...WITH_VERIFIER_IDENTITY,
        verifierCertificateChainPems: [],
      }).signingAlgs
    ).not.toContain('ES256');
  });

  it('does NOT claim ES256 on a certificate chain with no key', () => {
    expect(
      deriveCryptoCapabilities({
        ...WITH_VERIFIER_IDENTITY,
        verifierEs256PrivateKey: undefined,
      }).signingAlgs
    ).not.toContain('ES256');
  });

  it('treats a blank ES256 key as unprovisioned', () => {
    expect(
      deriveCryptoCapabilities({
        ...WITH_VERIFIER_IDENTITY,
        verifierEs256PrivateKey: '   ',
      }).signingAlgs
    ).not.toContain('ES256');
  });

  it('does NOT claim ES256 for a deployment that provisioned no verifier identity', () => {
    // The default posture, and the one the gate must keep refusing: core-crypto
    // can compute an ES256 signature (#298), but a deployment with no key and no
    // chain cannot sign a request with one.
    expect(deriveCryptoCapabilities(WITH_RS256).signingAlgs).not.toContain('ES256');
  });

  it('keeps the verifier key OUT of the token-issuance algorithms it claims', () => {
    // #298's risk note: "the two key sets must not be interchangeable." A
    // deployment that provisioned ONLY the verifier identity gains `ES256` — the
    // algorithm it can sign an OID4VP request with — and gains nothing for the
    // tokens it issues, which stay EdDSA. If this ever started claiming RS256 or
    // widening the token algorithms, the verifier key would have leaked into the
    // issuance path.
    const capabilities = deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY);

    expect(capabilities.signingAlgs).toEqual(['EdDSA', 'ES256']);
    expect(capabilities.signingAlgs).not.toContain('RS256');
  });

  it('does NOT claim response encryption, even though core-crypto ships encryptJwe/decryptJwe', () => {
    // The distinction the module exists for, now visible in one descriptor: the
    // JWE primitives exist and are tested, but nothing in the workspace calls
    // them. There is no `direct_post.jwt` response mode, no published
    // client_metadata encryption JWK and no intake route to decrypt at, so this
    // deployment cannot operate an encrypted Authorization Response. Phase C of
    // #377 flips it.
    expect(deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY).responseEncryption).toBe(false);
  });
});

describe('the #299 boot gate over the REAL bootstrap capabilities (#298 F1, #377)', () => {
  it('no longer refuses haip-1.0 on the ES256 signing count once the verifier identity is provisioned', () => {
    // What #377 Phase A cleared. The refusal is still there — see the next test
    // — but it is no longer THIS one, and asserting the absence of the old
    // message is what stops the suite passing for the old reason.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY),
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).not.toThrow(/accepts 'ES256' for request signing/);
  });

  it('still refuses haip-1.0 on the response-encryption count (Phase C of #377)', () => {
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY),
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/requires encrypted Authorization Responses/);
  });

  it('refuses haip-1.0 on the ES256 count again for a deployment with no verifier identity', () => {
    // The control for the two tests above: the crypto refusal is a real
    // predicate over configuration, not a check that was simply deleted.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: deriveCryptoCapabilities(WITH_RS256),
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/accepts 'ES256' for request signing/);
  });

  it('lands on the key-storage assurance count once the encryption half is hypothetically met (#379)', () => {
    // The count `haip-1.0` refuses on AFTER Phase C of #377 lands, asserted now
    // so the ordering is proven rather than assumed. `responseEncryption` is
    // forced true here — this is the ONE thing Phase C changes about this
    // descriptor — and with the crypto half fully met the next guard in
    // `createConfiguredProviders` is the #308/#379 one. Naming it specifically is
    // what makes the boot-refusal suite honest: a test that merely asserted
    // "haip-1.0 refuses" would pass for the counts #377 has already cleared.
    const real = deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY);

    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: { signingAlgs: real.signingAlgs, responseEncryption: true },
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/requires key-storage assurance for every presentation/);
  });

  it("still boots oid4vp-1.0-base — the profile that runs on today's crypto", () => {
    // The gate must be a real intersection, not a ban: `oid4vp-1.0-base`
    // declares ['EdDSA', 'ES256'] and needs only ONE of them, with its preferred
    // `redirect_uri` prefix needing no certificate at all.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'oid4vp-1.0-base',
        cryptoCapabilities: deriveCryptoCapabilities(NOTHING_OPTIONAL),
      })
    ).not.toThrow();
  });

  it('still boots oid4vp-1.0-base for a deployment that DID provision a verifier identity', () => {
    // Provisioning the verifier key must not change the base profile's outcome:
    // it declares both algorithms and needs one, and its preferred prefix needs
    // no certificate. A deployment that provisions a chain and keeps the base
    // profile keeps the base profile's behaviour.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'oid4vp-1.0-base',
        cryptoCapabilities: deriveCryptoCapabilities(WITH_VERIFIER_IDENTITY),
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).not.toThrow();
  });
});
