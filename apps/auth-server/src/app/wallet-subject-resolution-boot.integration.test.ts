import { describe, expect, it } from 'vitest';

import { bootAuthServer, generateJwtPem, REQUIRED_TEST_ENVIRONMENT } from '../testing/e2e-harness';

/**
 * The subject-resolution BOOT gate, through a REAL auth-server (issue #379 D2,
 * ADR-010 §6).
 *
 * `assert-subject-resolution.test.ts` covers the predicate. This covers the
 * thing the predicate exists for: that `buildApp` actually refuses, that the
 * refusal names the variable, and — the part a naive gate gets wrong — that the
 * two deployment shapes which MUST keep booting still do.
 *
 * ## No containers
 *
 * The gate runs during plugin registration, beside `assertTrustedIssuersUsable`
 * and before `federationPlugin`, so nothing opens a connection first. The
 * database and Redis URLs below are syntactically valid and never dialled —
 * exactly the arrangement `wallet-federation-haip.integration.test.ts` uses.
 *
 * ## The breaking change this pins
 *
 * `WALLET_FEDERATION_ENABLED=true` + `oid4vp-1.0-base` + no `OID4VP_SUBJECT_*`
 * booted before #379, and `.env.example` shipped both variables commented out,
 * so it was the DOCUMENTED default shape. It also refused every presentation:
 * the profile default is `asserted-lookup`, and `asserted-lookup` with no
 * binding claims is ADR-009 §1's total authentication bypass. The deployment
 * learned about it from a 100% login-failure rate rather than from a failed
 * start, which is the defect — not the refusal.
 */

describe('subject-resolution boot gate (#379 D2)', () => {
  /** A deployment with wallet federation on, minus any subject configuration. */
  async function walletEnvironment(): Promise<Record<string, string>> {
    const jwt = await generateJwtPem();

    return {
      ...REQUIRED_TEST_ENVIRONMENT,
      // Syntactically valid and never dialled: registration throws first.
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      WALLET_FEDERATION_ENABLED: 'true',
      OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
      OID4VP_REQUESTED_VCT: 'https://credentials.example.com/pid',
    };
  }

  it('refuses the half-configured shape, naming the variable to set', async () => {
    const environment = await walletEnvironment();

    // The control: the SAME deployment with the binding claims stated boots. So
    // the refusal below is about subject resolution and not about the fake
    // database URL, the missing issuer keys, or anything else in this
    // environment — which is how a "fails to boot" test stops testing what it
    // claims to.
    const configured = await bootAuthServer({
      ...environment,
      OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
    });
    await configured.close();

    await expect(bootAuthServer(environment)).rejects.toThrow(/OID4VP_SUBJECT_BINDING_CLAIMS/);
  }, 60_000);

  it("surfaces the resolver's own message rather than a boolean of it", async () => {
    // D2 put the gate in `app.ts` instead of behind a boolean option threaded
    // into `createConfiguredProviders` precisely so this text reaches the
    // operator intact.
    await expect(bootAuthServer(await walletEnvironment())).rejects.toThrow(
      /at least one credential claim/
    );
  }, 60_000);

  it('refuses issuer-scoped-claim with no subject claim configured', async () => {
    const environment = await walletEnvironment();

    await expect(
      bootAuthServer({
        ...environment,
        OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
        OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name',
      })
    ).rejects.toThrow(/OID4VP_SUBJECT_CLAIM/);
  }, 60_000);

  it('boots clean with wallet federation OFF and no wallet configuration at all', async () => {
    const jwt = await generateJwtPem();

    // The other half of fail-closed, and the default. The flag must remain a
    // usable off switch: "you configured no subject-resolution strategy" is the
    // CORRECT state for a deployment that serves no wallet flows, and a gate
    // that refused it would have made WALLET_FEDERATION_ENABLED=false
    // unbootable — which is every deployment that predates epic #231.
    const server = await bootAuthServer({
      ...REQUIRED_TEST_ENVIRONMENT,
      DATABASE_URL: 'postgresql://unused:unused@127.0.0.1:1/unused',
      REDIS_URL: 'redis://127.0.0.1:1/0',
      JWT_PRIVATE_KEY: jwt.privateKey,
      JWT_PUBLIC_KEY: jwt.publicKey,
      WALLET_FEDERATION_ENABLED: 'false',
    });

    await server.close();
  }, 60_000);

  it('leaves the profile refusal to the profile gate', async () => {
    const environment = await walletEnvironment();

    // A deployment that is half-configured in BOTH ways must still report the
    // profile problem, because that is the one an operator has to fix first.
    // Asserting the message is `/no VerifierProfile is selected/` rather than
    // merely "it threw" is what stops the gate silently taking over a refusal it
    // does not own.
    await expect(bootAuthServer({ ...environment, OID4VP_VERIFIER_PROFILE: '' })).rejects.toThrow(
      /no VerifierProfile is selected/i
    );
  }, 60_000);
});
