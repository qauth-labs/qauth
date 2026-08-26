import { describe, expect, it } from 'vitest';

import { bootAuthServer, generateJwtPem, REQUIRED_TEST_ENVIRONMENT } from '../testing/e2e-harness';
import { createMockVerifierPki, verifierIdentityEnvironment } from '../testing/mock-verifier-pki';

/**
 * WALLET FEDERATION under `haip-1.0` — the second E2E suite issue #240 asks for,
 * still PENDING on Phase C of #377 and on #379.
 *
 * ## Why it is still pending, and what is asserted meanwhile
 *
 * `createConfiguredProviders` refused `haip-1.0` on four independent counts.
 * #377 Phase A + B cleared the first two:
 *
 *  1. ~~no WRPAC / X.509 verifier material is provisioned~~ — **CLEARED**.
 *     `OID4VP_VERIFIER_SIGNING_KEY` and its chain/anchor siblings provision it,
 *     and this suite configures them below.
 *  2. ~~`signingAlgs: ['ES256']` unmet~~ — **CLEARED**. `deriveCryptoCapabilities`
 *     claims ES256 for a deployment that provisioned both halves.
 *  3. `responseEncryption: 'required'` is unmet: there is still no JWE path
 *     behind `direct_post.jwt` — Phase C of #377, which lands the response mode,
 *     the published `client_metadata` encryption key and the decrypting intake
 *     together.
 *  4. `keyStorageAssurance: 'required'` (#308) has neither an attesting-issuer
 *     registry nor key-attestation anchors provisioned — #379.
 *
 * So the profile still refuses, and the refusal below names count 3
 * SPECIFICALLY. That is the difference between this assertion and the one it
 * replaces: a test matching any `/haip-1\.0/` message would keep passing for
 * counts 1 and 2, which are exactly the ones #377 was supposed to clear — a
 * false green that would hide a regression in the work this suite is about.
 *
 * Count 4 is pinned separately, in `crypto-capabilities.test.ts`, by handing the
 * gate a descriptor whose `responseEncryption` is hypothetically true: that is
 * the one member Phase C changes, and asserting the NEXT refusal now means the
 * ordering is proven rather than assumed.
 *
 * ## What is covered elsewhere
 *
 * The signed-request half of #377 does not need this suite and is not duplicated
 * into it: `helpers/wallet-login-request.test.ts` drives the app's own builder
 * end to end and hands the resulting JAR to `testing/mock-wallet.ts`, which
 * validates the signature and the `x5c` chain against an anchor the header does
 * not carry — the independence that makes it an interoperability check.
 * `verifier-key-isolation.integration.test.ts` holds the other Phase A property:
 * that the verifier key reaches neither the JWKS nor any issued token.
 *
 * No containers: the boot is refused during plugin registration, before anything
 * opens a connection.
 *
 * @see https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
 */

describe('wallet federation E2E — haip-1.0 profile (pending Phase C of #377, and #379)', () => {
  it('refuses to boot on the response-encryption count, not the ones #377 cleared', async () => {
    const jwt = await generateJwtPem();
    const pki = createMockVerifierPki();

    const environment = {
      ...REQUIRED_TEST_ENVIRONMENT,
      // Syntactically valid and never dialled: registration throws first.
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_REQUESTED_VCT: 'https://credentials.example.com/pid',
      // Subject resolution, stated because #379 made it a BOOT gate: an enabled
      // deployment that names no binding claims now refuses to start (ADR-010
      // §6).
      OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
      OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
      // The verifier identity #377 made provisionable. Configured here on
      // purpose: without it the refusal below would fire on the CERTIFICATE
      // count, and the assertion would pass for the state that existed before
      // this work — the exact false green this test is written to avoid.
      ...verifierIdentityEnvironment(pki),
      // Both blocks sit in the SHARED environment on purpose — the control
      // below and the assertion after it must differ in the verifier profile
      // and in nothing else, or the control stops isolating the variable it
      // exists to isolate.
    };

    // The control: the same deployment on the BASE profile boots. Without it the
    // assertion below would pass for any configuration mistake at all — which is
    // exactly how a "fails to boot" test stops testing what it claims to. It is
    // also what proves the provisioned chain VALIDATED: an unusable one would
    // take this boot down too, since the material is checked whatever profile is
    // selected.
    const base = await bootAuthServer({
      ...environment,
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    });
    await base.close();

    const refusal = await bootAuthServer({
      ...environment,
      OID4VP_VERIFIER_PROFILE: 'haip-1.0',
    }).then(
      async (server) => {
        await server.close();
        return undefined;
      },
      (error: unknown) => (error instanceof Error ? error.message : String(error))
    );

    expect(refusal).toBeDefined();
    expect(refusal).toContain('haip-1.0');
    // Count 3, named.
    expect(refusal).toMatch(/requires encrypted Authorization Responses/);
    // NOT count 1: the certificate material is provisioned now.
    expect(refusal).not.toMatch(/X\.509 material that is not configured/);
    // NOT count 2: ES256 is producible now.
    expect(refusal).not.toMatch(/for request signing, but this deployment's crypto layer/);
  }, 60_000);

  it.todo('decrypts a direct_post.jwt response (ECDH-ES P-256 + A*GCM) (Phase C of #377)');

  it.todo('completes a wallet login end to end under haip-1.0 (Phase C of #377, #379)');
});
