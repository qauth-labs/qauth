import {
  assertCredentialStatusProvisioned,
  type CredentialStatusAuditEvent,
  VERIFIER_PROFILES,
} from '@qauth-labs/server-federation';
import { describe, expect, it } from 'vitest';

import {
  assertCredentialStatusConfigUsable,
  createConfiguredCredentialStatusChecker,
  credentialStatusProvisioningOf,
} from './credential-status';

/**
 * Turning `OID4VP_STATUS_LIST_*` into a wired checker — and refusing to boot
 * without one (#297, #378).
 *
 * `server-federation` owns the checker's behaviour and `credential-status-
 * provisioning.test.ts` owns the profile gate. What is only testable HERE is the
 * configuration seam: which environments produce a checker, which produce none,
 * and which are operator errors that must stop the process.
 *
 * The half-configured cases are the reason this file exists. Anchors without an
 * allowlist builds a checker that refuses every credential carrying a `status`
 * claim, because no URI is fetchable; an allowlist without anchors builds one
 * that refuses every credential too, because no Status List Token can chain to
 * anything. Both fail SILENTLY — the operator sees a 100% login-failure rate,
 * not a configuration error — and that is the exact defect class #378 exists to
 * close.
 */

/**
 * A parseable, long-lived, self-signed X.509 certificate.
 *
 * Checked in rather than generated, and that is a narrower decision than
 * `status/test/x509-fixtures.ts` argues against: nothing here depends on the
 * certificate's validity window, its extensions or its chain. The only question
 * this seam asks of an anchor is *"does `new X509Certificate(pem)` parse it?"* —
 * `createStatusListTrustAnchors` checks nothing else, and every chain, expiry
 * and SAN rule is exercised against generated certificates inside
 * `server-federation`. It expires in 2126.
 */
const ANCHOR_PEM = `-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUAu4ZNZqkENIGnEdizjFKScuNmdcwCgYIKoZIzj0EAwIw
KDEmMCQGA1UEAwwdUUF1dGggU3RhdHVzIExpc3QgVGVzdCBBbmNob3IwIBcNMjYw
NzI4MDIyMzUzWhgPMjEyNjA3MDQwMjIzNTNaMCgxJjAkBgNVBAMMHVFBdXRoIFN0
YXR1cyBMaXN0IFRlc3QgQW5jaG9yMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
FBiwe0ozVBmo01IxUTRcQnNMrafac2Pts/x5SfCApAJIkiLQtcg04//phPd18erG
jIR3UzhhyV5AARPldX7hyaNTMFEwHQYDVR0OBBYEFPbJbWlDJsJS1Ka4ycs748jM
1u3iMB8GA1UdIwQYMBaAFPbJbWlDJsJS1Ka4ycs748jM1u3iMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgWgbNgE+f4nk2uV9+vGS4pvLleQIutNZn
CZFVX6BZQwoCIQC7pQl45HOSyuJk14Fp9PHkIpig2vc+CcMKX267mL2CHA==
-----END CERTIFICATE-----`;

const ALLOWLIST = ['https://status.issuer.example/lists'];

describe('credentialStatusProvisioningOf (#297)', () => {
  it('reports each half independently', () => {
    expect(
      credentialStatusProvisioningOf({ trustAnchorPems: [ANCHOR_PEM], uriAllowlist: ALLOWLIST })
    ).toEqual({ trustAnchors: true, uriAllowlist: true });

    expect(credentialStatusProvisioningOf({ trustAnchorPems: [], uriAllowlist: [] })).toEqual({
      trustAnchors: false,
      uriAllowlist: false,
    });
  });

  it('does not count blank entries as provisioning anything', () => {
    // `OID4VP_STATUS_LIST_URI_ALLOWLIST=" "` is an unset variable with a typo in
    // it, and reading it as "the operator configured an allowlist" would make
    // the boot gate pass for a deployment that can fetch nothing.
    expect(
      credentialStatusProvisioningOf({ trustAnchorPems: ['   '], uriAllowlist: ['', '\t'] })
    ).toEqual({ trustAnchors: false, uriAllowlist: false });
  });
});

describe('assertCredentialStatusConfigUsable — half-configured is a BOOT failure (#297)', () => {
  it('accepts a deployment that configured neither half', () => {
    // The shipped `oid4vp-1.0-base` posture: no status checking, nothing
    // fetched, and `assurance.statusChecked` reports `'not-required'`.
    expect(() =>
      assertCredentialStatusConfigUsable({ trustAnchorPems: [], uriAllowlist: [] })
    ).not.toThrow();
  });

  it('accepts a deployment that configured both halves usably', () => {
    expect(() =>
      assertCredentialStatusConfigUsable({
        trustAnchorPems: [ANCHOR_PEM],
        uriAllowlist: ALLOWLIST,
      })
    ).not.toThrow();
  });

  it('REFUSES anchors with no URI allowlist, naming the variable that is missing', () => {
    expect(() =>
      assertCredentialStatusConfigUsable({ trustAnchorPems: [ANCHOR_PEM], uriAllowlist: [] })
    ).toThrow(/OID4VP_STATUS_LIST_URI_ALLOWLIST is not/);
  });

  it('REFUSES a URI allowlist with no anchors, naming the variables that are missing', () => {
    const error = (() => {
      try {
        assertCredentialStatusConfigUsable({ trustAnchorPems: [], uriAllowlist: ALLOWLIST });
      } catch (caught) {
        return caught as Error;
      }
      return undefined;
    })();

    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toContain('OID4VP_STATUS_LIST_TRUST_ANCHORS');
    expect(error?.message).toContain('OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH');
    // The operator has to be told what the silent failure WOULD have been,
    // otherwise "just set the other one" is indistinguishable from a nag.
    expect(error?.message).toMatch(/refuses every Status List Token, silently/);
  });

  it('REFUSES an anchor that will not parse, rather than dropping it', () => {
    // A dropped anchor is a trust decision the operator wrote and the server did
    // not apply — and it surfaces as "every presentation is rejected".
    expect(() =>
      assertCredentialStatusConfigUsable({
        trustAnchorPems: ['-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----'],
        uriAllowlist: ALLOWLIST,
      })
    ).toThrow(/not a parseable PEM-encoded X.509 certificate/);
  });

  it.each([
    ['a non-HTTPS prefix', 'http://status.issuer.example/lists'],
    ['a loopback host', 'https://localhost/lists'],
    ['an IP literal', 'https://127.0.0.1/lists'],
    ['userinfo smuggling the trusted host', 'https://status.issuer.example@evil.example/lists'],
    ['a query string', 'https://status.issuer.example/lists?tenant=1'],
  ])('REFUSES %s in the allowlist', (_label, prefix) => {
    expect(() =>
      assertCredentialStatusConfigUsable({
        trustAnchorPems: [ANCHOR_PEM],
        uriAllowlist: [prefix],
      })
    ).toThrow(/not a usable https:\/\/ prefix/);
  });

  it('keeps the offending allowlist value out of the message', () => {
    // The value is on `details`. A message that quotes it ends up in log lines
    // and error bodies that quote messages.
    const error = (() => {
      try {
        assertCredentialStatusConfigUsable({
          trustAnchorPems: [ANCHOR_PEM],
          uriAllowlist: ['http://internal.corp.example/secret-path'],
        });
      } catch (caught) {
        return caught as Error;
      }
      return undefined;
    })();

    expect(error?.message).not.toContain('internal.corp.example');
    expect(error?.message).not.toContain('secret-path');
  });
});

describe('createConfiguredCredentialStatusChecker (#297, #378)', () => {
  it('builds NO checker when this deployment configured no status checking', () => {
    // `undefined` is not permissive: validation reports `'not-required'` for it,
    // and a profile that mandates status never reaches here because
    // `assertCredentialStatusProvisioned` already refused the boot.
    expect(
      createConfiguredCredentialStatusChecker({ trustAnchorPems: [], uriAllowlist: [] })
    ).toBeUndefined();
  });

  it('refuses to build a checker from a half-configured deployment', () => {
    expect(() =>
      createConfiguredCredentialStatusChecker({
        trustAnchorPems: [ANCHOR_PEM],
        uriAllowlist: [],
      })
    ).toThrow(/OID4VP_STATUS_LIST_URI_ALLOWLIST/);
  });

  it('builds a checker that refuses a URI outside the allowlist without dialling it', async () => {
    // The SSRF boundary, end to end from configuration. Nothing is stubbed: if
    // the allowlist did not hold, this test would make a real outbound request.
    const audit: CredentialStatusAuditEvent[] = [];
    const checker = createConfiguredCredentialStatusChecker({
      trustAnchorPems: [ANCHOR_PEM],
      uriAllowlist: ALLOWLIST,
      onAudit: (event) => audit.push(event),
    });

    expect(checker).toBeDefined();

    await expect(
      checker?.assertCredentialNotRevoked({
        status_list: { idx: 0, uri: 'https://169.254.169.254.nip.example/latest/meta-data/' },
      })
    ).rejects.toThrow(/Verifiable Presentation rejected/);

    expect(audit).toEqual([
      expect.objectContaining({
        decision: 'rejected',
        reason: 'uri-not-permitted',
        fetched: false,
      }),
    ]);
  });

  it('reports every check to the audit sink, accepted ones included', async () => {
    // The denominator. The accepting branch reachable without a network is
    // "the profile requires no status and the credential carries none".
    const audit: CredentialStatusAuditEvent[] = [];
    const checker = createConfiguredCredentialStatusChecker({
      trustAnchorPems: [ANCHOR_PEM],
      uriAllowlist: ALLOWLIST,
      onAudit: (event) => audit.push(event),
    });

    await checker?.assertCredentialNotRevoked(undefined, { statusRequired: false });

    expect(audit).toEqual([expect.objectContaining({ decision: 'accepted' })]);
  });

  it('refuses a malformed status claim under BOTH postures (HAIP §6.1)', async () => {
    const checker = createConfiguredCredentialStatusChecker({
      trustAnchorPems: [ANCHOR_PEM],
      uriAllowlist: ALLOWLIST,
    });

    for (const statusRequired of [true, false]) {
      await expect(
        checker?.assertCredentialNotRevoked({ some_other_mechanism: {} }, { statusRequired })
      ).rejects.toThrow(/Verifiable Presentation rejected/);
    }
  });
});

describe('the config seam and the profile gate compose (#297, #378)', () => {
  it('lets a haip-1.0 deployment boot only once BOTH halves are configured', () => {
    // `haip-1.0` declares `requireCredentialStatus: true` (HAIP §6.1). The two
    // gates are separate on purpose — one asks "is this configuration coherent",
    // the other "does the selected profile need it" — so this pins that the
    // record one produces is the record the other consumes.
    const haip = VERIFIER_PROFILES['haip-1.0'];

    expect(() =>
      assertCredentialStatusProvisioned(
        haip,
        credentialStatusProvisioningOf({ trustAnchorPems: [], uriAllowlist: [] })
      )
    ).toThrow(/requires credential revocation checking/);

    expect(() =>
      assertCredentialStatusProvisioned(
        haip,
        credentialStatusProvisioningOf({ trustAnchorPems: [ANCHOR_PEM], uriAllowlist: [] })
      )
    ).toThrow(/OID4VP_STATUS_LIST_URI_ALLOWLIST/);

    expect(() =>
      assertCredentialStatusProvisioned(
        haip,
        credentialStatusProvisioningOf({ trustAnchorPems: [ANCHOR_PEM], uriAllowlist: ALLOWLIST })
      )
    ).not.toThrow();
  });

  it('leaves oid4vp-1.0-base bootable with nothing configured', () => {
    // Base OID4VP 1.0 mandates no revocation mechanism. A deployment that wants
    // none must still start — otherwise #378's fix is a breaking change for
    // every existing base-profile deployment.
    expect(() =>
      assertCredentialStatusProvisioned(
        VERIFIER_PROFILES['oid4vp-1.0-base'],
        credentialStatusProvisioningOf({ trustAnchorPems: [], uriAllowlist: [] })
      )
    ).not.toThrow();
  });
});
