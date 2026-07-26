import {
  PASSWORD_PROVIDER_TYPE,
  type ProvisionedVerifierMaterial,
  type VerifierProfileId,
  WALLET_PROVIDER_TYPE,
} from '@qauth-labs/server-federation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { createConfiguredProviders, type VerifierCryptoCapabilities } from './configured-providers';
import { federationPlugin } from './federation-plugin';

/**
 * The crypto layer as it exists TODAY, transcribed from `JwsAlgorithm`
 * (`libs/core/crypto/src/lib/algorithms.ts`) and from the absence of any JWE
 * encrypter in the workspace.
 *
 * `apps/auth-server` builds the same descriptor and pins it to `JwsAlgorithm`
 * exhaustively with `satisfies`; this lib cannot (it does not depend on
 * `core-crypto`, and deliberately does not — see
 * {@link VerifierCryptoCapabilities}). Here the values are the fixture, and what
 * is under test is what the gate DOES with them.
 */
const CRYPTO_TODAY: VerifierCryptoCapabilities = {
  signingAlgs: ['EdDSA', 'RS256'],
  responseEncryption: false,
};

/** The crypto layer once #298 lands ES256 and the JWE stack. */
const CRYPTO_AFTER_298: VerifierCryptoCapabilities = {
  signingAlgs: ['EdDSA', 'RS256', 'ES256'],
  responseEncryption: true,
};

/** #298 has landed ES256 but not the JWE stack — the halfway state. */
const CRYPTO_ES256_WITHOUT_JWE: VerifierCryptoCapabilities = {
  signingAlgs: ['EdDSA', 'RS256', 'ES256'],
  responseEncryption: false,
};

/**
 * The certificate state #298/#233 will deliver for a HAIP deployment: a
 * QTSP-issued WRPAC, i.e. the non-self-signed chain `x509_hash` requires.
 *
 * Nothing can produce this today; it is written down so the crypto gate can be
 * tested in the world where the certificate gate no longer fires.
 */
const WRPAC_PROVISIONED: ProvisionedVerifierMaterial = {
  available: ['non-self-signed-chain'],
};

/**
 * Acceptance criteria of issue #232, proved without Postgres or Redis: the
 * whole flag→registry decision is a pure function feeding the plugin, so the
 * only thing that has to boot is Fastify itself.
 *
 * - AC1: WalletProvider is registered and resolvable when the flag is on.
 * - AC2: NO behaviour change to any existing auth flow when the flag is off.
 */
describe('createConfiguredProviders (WALLET_FEDERATION_ENABLED wiring, #232)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  /**
   * Boot the real plugin over the real configured provider set.
   *
   * Defaults to `oid4vp-1.0-base` because a flag-ON boot now REQUIRES a profile
   * (#299) — the protocol floor is the profile that runs on today's crypto, so
   * it is the one that keeps these #232 assertions about the flag itself.
   */
  async function bootWithFlag(
    walletFederationEnabled: boolean,
    verifierProfileId: VerifierProfileId | undefined = 'oid4vp-1.0-base'
  ): Promise<FastifyInstance> {
    app = Fastify({ logger: false });
    await app.register(federationPlugin, {
      providers: createConfiguredProviders({
        walletFederationEnabled,
        verifierProfileId,
        cryptoCapabilities: CRYPTO_TODAY,
      }),
    });
    await app.ready();
    return app;
  }

  describe('AC1 — flag ON', () => {
    it("registers the wallet provider and resolves 'wallet' to it", async () => {
      const fastify = await bootWithFlag(true);

      expect(fastify.providerRegistry.has(WALLET_PROVIDER_TYPE)).toBe(true);
      const provider = fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE);
      expect(provider.type).toBe(WALLET_PROVIDER_TYPE);
    });

    it('resolves the fail-closed skeleton, not some other provider', async () => {
      // Identity check on behaviour: the thing registered under 'wallet' is the
      // #232 skeleton, so enabling the flag cannot authenticate anyone.
      const fastify = await bootWithFlag(true);
      const provider = fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE);

      await expect(provider.verify({ vp_token: 'x' })).rejects.toThrow(/#232/);
    });
  });

  describe('AC1 — flag OFF (the default)', () => {
    it("does not register 'wallet'", async () => {
      const fastify = await bootWithFlag(false);
      expect(fastify.providerRegistry.has(WALLET_PROVIDER_TYPE)).toBe(false);
    });

    it("fails to resolve 'wallet'", async () => {
      const fastify = await bootWithFlag(false);
      expect(() => fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE)).toThrow(
        /No credential provider is registered/
      );
    });

    it('treats a non-boolean truthy flag value as OFF (fail-safe)', () => {
      // An unparsed `process.env.WALLET_FEDERATION_ENABLED='false'` is truthy in
      // JS; the strict `=== true` check is what stops that from enabling wallet
      // federation. Cast because the type system already forbids this call.
      const providers = createConfiguredProviders({
        walletFederationEnabled: 'false' as unknown as boolean,
        verifierProfileId: undefined,
        cryptoCapabilities: CRYPTO_TODAY,
      });

      expect(providers.map((p) => p.type)).toEqual([PASSWORD_PROVIDER_TYPE]);
    });
  });

  describe('AC2 — the password flow is unchanged in BOTH flag states', () => {
    it.each([
      ['off', false],
      ['on', true],
    ])(
      'resolves an identical, working password provider with the flag %s',
      async (_label, flag) => {
        const fastify = await bootWithFlag(flag);

        expect(fastify.providerRegistry.has(PASSWORD_PROVIDER_TYPE)).toBe(true);
        const provider = fastify.providerRegistry.resolve(PASSWORD_PROVIDER_TYPE);
        const identity = await provider.verify({
          email: 'user@example.com',
          passwordHash: '$argon2id$fake',
          emailVerified: true,
        });

        expect(identity).toEqual({
          externalSub: 'user@example.com',
          assuranceLevel: 'low',
          rawClaims: { email: 'user@example.com', email_verified: true },
        });
        expect(provider.extractAttributes(identity)).toEqual([
          {
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'user@example.com',
            verified: true,
          },
        ]);
      }
    );

    it('seeds ONLY the password provider when the flag is off', () => {
      // Pins the whole set, so a future provider cannot arrive unflagged.
      expect(
        createConfiguredProviders({
          walletFederationEnabled: false,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        }).map((p) => p.type)
      ).toEqual([PASSWORD_PROVIDER_TYPE]);
    });

    it('adds the wallet provider without disturbing the order when the flag is on', () => {
      expect(
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: 'oid4vp-1.0-base',
          cryptoCapabilities: CRYPTO_TODAY,
        }).map((p) => p.type)
      ).toEqual([PASSWORD_PROVIDER_TYPE, WALLET_PROVIDER_TYPE]);
    });
  });
});

/**
 * Fail-closed verifier configuration (issue #299), proved at the same layer and
 * for the same reason as #232 above: the whole decision is a pure function of
 * config, so "this deployment refuses to start" is provable in CI rather than
 * argued in review.
 */
describe('createConfiguredProviders (VerifierProfile gate, #299)', () => {
  describe('flag ON', () => {
    it('refuses to start when no profile is selected', () => {
      // The core #299 posture: an enabled verifier with no declared profile has
      // no defined posture, and there is deliberately no default to fall back to.
      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).toThrow(/no VerifierProfile is selected/);
    });

    it('advertises ONLY profiles that actually start, and says why the others do not', () => {
      // The F6 regression this prevents: the refusal used to advise "set it to
      // 'oid4vp-1.0-base' or 'haip-1.0'", sending an operator who picked the
      // second value straight into a different refusal on the next restart. Two
      // failed restarts to learn one advertised value cannot start anything.
      //
      // Asserted as advice, not as mere presence of both ids: `haip-1.0` must
      // appear ONLY inside a cannot-start explanation, and the reason it cannot
      // start must be carried verbatim so the operator does not have to spend a
      // restart discovering it.
      let message = '';
      try {
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        });
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }

      expect(message).toMatch(/Set OID4VP_VERIFIER_PROFILE to one of 'oid4vp-1\.0-base'/);
      expect(message).toMatch(/'haip-1\.0' is shipped but CANNOT start here yet/);
      expect(message).toMatch(/non-self-signed-chain/);
      // The startable list must not contain the profile that cannot start.
      expect(message).not.toMatch(/to one of [^.]*haip-1\.0/);
    });

    it('names BOTH remedies, so an upgrading operator is not forced into a posture decision', () => {
      // F2: an existing WALLET_FEDERATION_ENABLED=true deployment upgrades and
      // loses password login, /authorize and /token to a variable that did not
      // exist in the version it was running. The message has to say the
      // requirement is new AND offer the flag-off exit, because a deployment
      // that enabled the flag only to exercise the #232 wiring has no reason to
      // choose an OID4VP posture.
      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).toThrow(/NEW requirement/);

      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).toThrow(/Set OID4VP_VERIFIER_PROFILE/);

      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: undefined,
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).toThrow(/set WALLET_FEDERATION_ENABLED=false/);
    });

    it('refuses haip-1.0 — its x509_hash prefix needs a WRPAC nobody has provisioned', () => {
      // Not a missing feature: HAIP mandates a QTSP-issued chain, and certificate
      // provisioning arrives with #298/#233. Until then selecting it must refuse
      // rather than silently downgrade to the permissive profile.
      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: 'haip-1.0',
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).toThrow(/non-self-signed-chain/);
    });

    it('starts on oid4vp-1.0-base, whose preferred redirect_uri prefix needs no certificate', () => {
      expect(() =>
        createConfiguredProviders({
          walletFederationEnabled: true,
          verifierProfileId: 'oid4vp-1.0-base',
          cryptoCapabilities: CRYPTO_TODAY,
        })
      ).not.toThrow();
    });
  });

  describe('flag OFF — profile config is irrelevant and must not block the boot', () => {
    it.each([undefined, 'oid4vp-1.0-base', 'haip-1.0'] as const)(
      'starts with verifierProfileId %o and registers only the password provider',
      (verifierProfileId) => {
        // A deployment that never enables wallet federation must be unaffected by
        // profile configuration — including the otherwise-refusing `haip-1.0`.
        expect(
          createConfiguredProviders({
            walletFederationEnabled: false,
            verifierProfileId,
            cryptoCapabilities: CRYPTO_TODAY,
          }).map((p) => p.type)
        ).toEqual([PASSWORD_PROVIDER_TYPE]);
      }
    );
  });
});

/**
 * The crypto-capability gate (issue #299, finding F12).
 *
 * `verifier-profile.types.ts` says declaring `ES256` on `haip-1.0` "is precisely
 * how that gap becomes visible and fail-closed" — but a declaration nothing
 * reads is decorative. Before this gate, the ONLY thing keeping `haip-1.0` out
 * was its missing certificate chain, so #298/#233 provisioning a WRPAC would
 * have silently made `haip-1.0` bootable on an EdDSA-only crypto layer. Every
 * EUDI wallet would then have rejected every Authorization Request: a boot-time
 * misconfiguration surfacing as a 100% production presentation failure.
 *
 * Every case below therefore provisions the WRPAC — the certificate gate is
 * deliberately taken out of the picture so the crypto gate is what is measured.
 */
describe('createConfiguredProviders (crypto-capability gate, #299 F12)', () => {
  it("refuses haip-1.0 on today's crypto EVEN WITH the WRPAC provisioned", () => {
    // The exact #298/#233 future this gate exists for. Certificates present,
    // certificate check satisfied, and the boot must still fail — on ES256.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: CRYPTO_TODAY,
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/accepts 'ES256' for request signing/);
  });

  it('still refuses haip-1.0 when ES256 exists but the JWE stack does not', () => {
    // HAIP §5.1 mandates `direct_post.jwt`. Half of #298 is not enough: a
    // verifier that asks for an encrypted response it cannot decrypt is worse
    // than one that refuses to start.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: CRYPTO_ES256_WITHOUT_JWE,
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).toThrow(/requires encrypted Authorization Responses/);
  });

  it('accepts haip-1.0 once ES256, the JWE stack and the WRPAC all exist', () => {
    // Proves the gate is exactly these three requirements and not a hardcoded
    // ban on `haip-1.0` — profiles are data (#299 AC), so the profile that is
    // unusable today must become usable with no edit to the gate.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: CRYPTO_AFTER_298,
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      })
    ).not.toThrow();
  });

  it('accepts oid4vp-1.0-base on EdDSA alone — a profile needs ONE of its algs, not all', () => {
    // `oid4vp-1.0-base` declares ['EdDSA', 'ES256']. Reading `signingAlgs` as a
    // conjunction would refuse the one profile that is meant to run today.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'oid4vp-1.0-base',
        cryptoCapabilities: { signingAlgs: ['EdDSA'], responseEncryption: false },
      })
    ).not.toThrow();
  });

  it('refuses every profile when the crypto layer can sign with nothing', () => {
    // Fail-closed on the degenerate descriptor: an empty capability set must
    // refuse rather than vacuously satisfy the intersection.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: 'oid4vp-1.0-base',
        cryptoCapabilities: { signingAlgs: [], responseEncryption: false },
      })
    ).toThrow(/crypto layer produces none/);
  });

  it('tells an operator with no startable profile to turn the flag off instead', () => {
    // When the crypto layer can satisfy nothing, advertising a profile list
    // would send the operator into an unbounded sequence of failed restarts.
    // The refusal has to say so and fall back to the flag-off remedy.
    expect(() =>
      createConfiguredProviders({
        walletFederationEnabled: true,
        verifierProfileId: undefined,
        cryptoCapabilities: { signingAlgs: [], responseEncryption: false },
      })
    ).toThrow(/No shipped profile can start in this deployment/);
  });

  it('leaves the flag-OFF boot untouched by an unsatisfiable crypto descriptor', () => {
    // AC2 again, under the new gate: a deployment that never enables wallet
    // federation must not be able to fail on a verifier crypto requirement.
    expect(
      createConfiguredProviders({
        walletFederationEnabled: false,
        verifierProfileId: 'haip-1.0',
        cryptoCapabilities: { signingAlgs: [], responseEncryption: false },
        provisionedVerifierMaterial: WRPAC_PROVISIONED,
      }).map((p) => p.type)
    ).toEqual([PASSWORD_PROVIDER_TYPE]);
  });
});
