import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

/**
 * The request path resolves the profile WITH the provisioned material (#377,
 * #379 review finding 3).
 *
 * `resolveVerifierProfile` folds in `assertVerifierIdentityProvisioned`, so its
 * answer depends on the third argument: omit it and the default is
 * `NO_VERIFIER_MATERIAL`, which THROWS for any profile whose Client Identifier
 * Prefixes need an X.509 identity. Two request-path call sites omitted it —
 * `wallet-login-request.ts` and `routes/oid4vp/response.ts` — and agreed with
 * the boot gate only for as long as the boot gate refused everything they would
 * have refused.
 *
 * Once a profile requiring a WRPAC can actually start, they disagree with it:
 * the deployment boots on a validated chain, and then the login page renders no
 * wallet link and every presentation is rejected — both because the request path
 * asked the question with the material missing. This file is the deployment that
 * would have hit it: `haip-1.0` selected, a full chain provisioned.
 *
 * ## Why the whole file is one deployment
 *
 * `verifierSigningMaterial()` memoises per process, so one module registry holds
 * exactly one material state. Vitest gives each test FILE its own registry,
 * which is what makes a fixed env mock here the right shape — and why the
 * unprovisioned control lives in `verifier-identity.test.ts` instead.
 *
 * ## Why it asserts on the LOG rather than on the return value
 *
 * `OID4VP_REQUESTED_VCT` is deliberately left unset, so the capability is
 * `undefined` either way. What differs is WHY. With the material threaded, the
 * profile resolves and the function walks on to the ordinary "this deployment
 * configured no VCT" branch, a `debug`. Without it, `resolveVerifierProfile`
 * throws and the function bails out at the top with an `error` naming an
 * unprovisioned profile — on a deployment that provisioned one and validated it
 * at boot. (Before #377 Phase C the encryption posture would have refused
 * `haip-1.0` too; it no longer does, which is why the VCT is the variable held
 * back here.)
 */

/** Split a concatenated PEM bundle the way the env schema does. */
function pemBlocks(bundle: string): readonly string[] {
  return (bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (pem) => pem.trim()
  );
}

vi.mock('../../config/env', async () => {
  const { createMockVerifierPki } = await import('../../testing/mock-verifier-pki');
  const pki = createMockVerifierPki();

  return {
    env: {
      JWT_ISSUER: 'https://auth.example.com/',
      WALLET_FEDERATION_ENABLED: true,
      // A profile whose Client Identifier Prefixes NEED an X.509 verifier
      // identity. That is the point: under `oid4vp-1.0-base` the `redirect_uri`
      // prefix is renderable with no material at all, so the regression this
      // file pins is invisible there.
      OID4VP_VERIFIER_PROFILE: 'haip-1.0',
      // Deliberately unset — see the assertions.
      OID4VP_REQUESTED_VCT: undefined,
      OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
      OID4VP_VERIFIER_SIGNING_KEY: pki.signingKeyPem,
      OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined,
      OID4VP_VERIFIER_CERTIFICATE_CHAIN: pemBlocks(pki.certificateChainPem),
      OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [],
      OID4VP_VERIFIER_TRUST_ANCHORS: pemBlocks(pki.trustAnchorPem),
      OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [],
    },
  };
});

import { provisionedVerifierMaterial } from './verifier-identity';
import { resolveWalletLoginCapability } from './wallet-login-request';

function fakeFastify() {
  return {
    log: { debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyInstance;
}

describe('a deployment that provisioned a verifier identity and selected haip-1.0', () => {
  it('exposes the boot-validated material through one shared helper', () => {
    // The helper `app.ts`'s boot gate and both request-path call sites read.
    // A call site that computed its own answer is the drift it removes.
    expect(provisionedVerifierMaterial().available).toContain('non-self-signed-chain');
  });

  it('does not report an unprovisioned profile', () => {
    const fastify = fakeFastify();

    expect(resolveWalletLoginCapability(fastify)).toBeUndefined();

    // The regression, stated directly: this log line is what an operator who
    // configured everything correctly used to get.
    expect(fastify.log.error).not.toHaveBeenCalled();
  });

  it('walks past the profile gate to the ordinary configuration branch', () => {
    // The positive half. Reaching this `debug` at all proves
    // `assertVerifierIdentityProvisioned` was satisfied — it runs first, and it
    // throws rather than returning when it is not.
    const fastify = fakeFastify();

    resolveWalletLoginCapability(fastify);

    expect(fastify.log.debug).toHaveBeenCalledWith(
      'wallet login unavailable: OID4VP_REQUESTED_VCT is not configured'
    );
  });
});
