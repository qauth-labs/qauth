import { describe, expect, it } from 'vitest';

import { bootAuthServer, generateJwtPem, REQUIRED_TEST_ENVIRONMENT } from '../testing/e2e-harness';

/**
 * WALLET FEDERATION under `haip-1.0` — the second E2E suite issue #240 asks for,
 * PENDING on #298.
 *
 * The flows it will exercise: a SIGNED request JWT identified by an `x509_hash`
 * Client Identifier Prefix (with the trust anchor EXCLUDED from the `x5c`
 * header, HAIP §4.5.1), and an ENCRYPTED `direct_post.jwt` response (JWE:
 * ECDH-ES over P-256 with A128GCM/A256GCM) to the verifier's encryption key from
 * `client_metadata`.
 *
 * ## Why it is pending, and what is asserted meanwhile
 *
 * The profile cannot start. `createConfiguredProviders` refuses `haip-1.0` on
 * four independent counts today:
 *
 *  1. no WRPAC / X.509 verifier material is provisioned, so
 *     `assertVerifierIdentityProvisioned` refuses the `x509_hash` prefix;
 *  2. the crypto-capability gate finds `signingAlgs: ['ES256']` unmet — QAuth
 *     signs EdDSA — so a signed JAR cannot be produced (#298);
 *  3. `responseEncryption: 'required'` is unmet for the same reason: there is no
 *     JWE stack behind `direct_post.jwt` (#298);
 *  4. `keyStorageAssurance: 'required'` (#308) has neither an attesting-issuer
 *     registry nor key-attestation anchors provisioned.
 *
 * A suite written speculatively against an API #298 has not shipped would encode
 * guesses; one written and skipped would assert nothing at all. So the flows are
 * `it.todo`, and what DOES run is the property that must hold until they can be
 * written: selecting `haip-1.0` takes the deployment DOWN rather than quietly
 * serving wallet flows under a weaker posture. That refusal is the only thing
 * standing between a deployment that believes it runs HAIP and one that runs
 * unsigned requests over cleartext responses.
 *
 * ## What to write when #298 lands
 *
 * Reuse `src/testing/mock-wallet.ts`: it already parses a request off the wire
 * and dispatches presentation building through a per-format table, so the
 * additions are (a) verifying the signed request JWT and its `x5c` chain against
 * an anchor the header does not carry, and (b) encrypting the response to the
 * verifier's `client_metadata` encryption key. Neither changes the E2E's shape.
 *
 * No containers: the boot is refused during plugin registration, before anything
 * opens a connection.
 *
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 */

describe('wallet federation E2E — haip-1.0 profile (pending #298)', () => {
  it('refuses to boot rather than serving wallet flows under a weaker posture', async () => {
    const jwt = await generateJwtPem();

    const environment = {
      ...REQUIRED_TEST_ENVIRONMENT,
      // Syntactically valid and never dialled: registration throws first.
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_REQUESTED_VCT: 'https://credentials.example.com/pid',
    };

    // The control: the same deployment on the BASE profile boots. Without it the
    // assertion below would pass for any configuration mistake at all — which is
    // exactly how a "fails to boot" test stops testing what it claims to.
    const base = await bootAuthServer({
      ...environment,
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    });
    await base.close();

    await expect(
      bootAuthServer({ ...environment, OID4VP_VERIFIER_PROFILE: 'haip-1.0' })
    ).rejects.toThrow(/haip-1\.0/);
  }, 60_000);

  it.todo(
    'verifies a signed request JWT identified by x509_hash, with the anchor excluded from x5c (#298)'
  );

  it.todo('decrypts a direct_post.jwt response (ECDH-ES P-256 + A*GCM) (#298)');

  it.todo('completes a wallet login end to end under haip-1.0 (#298)');
});
