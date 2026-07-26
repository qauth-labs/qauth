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

import { deriveCryptoCapabilities } from './crypto-capabilities';

/** A deployment with the optional RS256 ID-token key configured (#309). */
const WITH_RS256 = {
  rs256PrivateKey: '-----BEGIN PRIVATE KEY-----\nrsa\n-----END PRIVATE KEY-----',
};

/** The default posture: EdDSA only, no RS256 key. */
const WITHOUT_RS256 = { rs256PrivateKey: undefined };

/**
 * The certificate state #233 will deliver for a HAIP deployment — the
 * non-self-signed chain (QTSP-issued WRPAC) that the `x509_hash` prefix
 * requires.
 *
 * Provisioned in the gate tests below on purpose: it takes the CERTIFICATE half
 * of the fail-closed gate out of the picture, so what is measured is the CRYPTO
 * half alone. Without it a passing test would prove only that the certificate is
 * missing, which is not the control under test.
 */
const WRPAC_PROVISIONED = { available: ['non-self-signed-chain'] } as const;

describe('deriveCryptoCapabilities (#298 F1)', () => {
  it('always claims EdDSA — the env schema refuses to parse without that key', () => {
    expect(deriveCryptoCapabilities(WITHOUT_RS256).signingAlgs).toContain('EdDSA');
  });

  it('claims RS256 only when an RS256 key is provisioned', () => {
    expect(deriveCryptoCapabilities(WITH_RS256).signingAlgs).toContain('RS256');
    expect(deriveCryptoCapabilities(WITHOUT_RS256).signingAlgs).not.toContain('RS256');
  });

  it('treats a blank RS256 key as unprovisioned', () => {
    // `resolveKey` can hand back an empty string from an empty env var or an
    // empty key file. Fail closed: an empty key signs nothing.
    expect(deriveCryptoCapabilities({ rs256PrivateKey: '   ' }).signingAlgs).not.toContain('RS256');
  });

  it('does NOT claim ES256, even though core-crypto can compute an ES256 signature', () => {
    // The distinction the whole module exists for. `sign(..., 'ES256', ...)`
    // works — but no env var, schema field or code path provisions a P-256
    // signing key, so this deployment cannot sign a request with it. Claiming it
    // would lift the gate for `haip-1.0`.
    expect(deriveCryptoCapabilities(WITH_RS256).signingAlgs).not.toContain('ES256');
  });

  it('does NOT claim response encryption, even though core-crypto ships encryptJwe/decryptJwe', () => {
    // Same distinction: the JWE primitives exist and are tested, but nothing in
    // the workspace calls them. There is no `direct_post.jwt` response mode, no
    // published client_metadata encryption JWK and no intake route to decrypt
    // at, so this deployment cannot operate an encrypted Authorization Response.
    expect(deriveCryptoCapabilities(WITH_RS256).responseEncryption).toBe(false);
  });
});

describe('the #299 boot gate over the REAL bootstrap capabilities (#298 F1)', () => {
  it('refuses haip-1.0 on this build, even with the WRPAC provisioned', () => {
    // The regression under guard. `haip-1.0` declares `signingAlgs: ['ES256']`
    // (HAIP §7) and `responseEncryption: 'required'` (§5.1). If the bootstrap
    // descriptor claims either capability before #233 provisions the key
    // material and the response path, an operator selects `haip-1.0`, boots
    // clean, advertises an ES256 posture and `direct_post.jwt` to wallets — and
    // 100% of presentations fail at runtime.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: deriveCryptoCapabilities(WITH_RS256),
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/accepts 'ES256' for request signing/);
  });

  it('still refuses haip-1.0 on the encryption count once ES256 is hypothetically added', () => {
    // Belt-and-braces on the SECOND half of the gate: the signing refusal fires
    // first, so a descriptor that regained only `responseEncryption: true` would
    // be caught by the test above and this one would not run. Assert the
    // encryption refusal directly, so both fail-closed checks stay proven and a
    // future descriptor that lifts only one of them cannot pass unnoticed.
    const real = deriveCryptoCapabilities(WITH_RS256);
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: {
          signingAlgs: [...real.signingAlgs, 'ES256'],
          responseEncryption: real.responseEncryption,
        },
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/requires encrypted Authorization Responses/);
  });

  it("still boots oid4vp-1.0-base — the profile that runs on today's crypto", () => {
    // The gate must be a real intersection, not a ban: `oid4vp-1.0-base`
    // declares ['EdDSA', 'ES256'] and needs only ONE of them, with its preferred
    // `redirect_uri` prefix needing no certificate at all.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'oid4vp-1.0-base',
        cryptoCapabilities: deriveCryptoCapabilities(WITHOUT_RS256),
      })
    ).not.toThrow();
  });
});
