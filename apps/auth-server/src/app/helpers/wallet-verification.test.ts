import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * The wallet VERIFICATION posture (#238) — four independent configuration
 * decisions resolved in one place.
 *
 * The tests below are about the two refusals and how they differ, because that
 * distinction is what an operator acts on: `undefined` means "this deployment
 * serves no wallet flows", a THROW means "a strategy is selected and its
 * settings are missing". Collapsing them would make a misconfiguration look like
 * an intentional opt-out.
 */

const { envMock } = vi.hoisted(() => ({
  envMock: {
    WALLET_FEDERATION_ENABLED: true,
    JWT_ISSUER: 'https://auth.example.com',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    // The verifier-identity variables at their parsed DEFAULTS (#377). Stated
    // rather than omitted because the request path now resolves the profile with
    // the deployment's provisioned material, and
    // `resolveVerifierCertificateChainPems` reads `.length` off the array forms —
    // which the real parsed env always supplies (Zod defaults them to `[]`) and
    // an env stub silently would not.
    OID4VP_VERIFIER_SIGNING_KEY: undefined as string | undefined,
    OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined as string | undefined,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
    OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
    OID4VP_SUBJECT_RESOLUTION: undefined as string | undefined,
    OID4VP_SUBJECT_BINDING_CLAIMS: ['given_name'] as readonly string[] | undefined,
    OID4VP_SUBJECT_CLAIM: undefined as string | undefined,
    OID4VP_SUBJECT_CLAIM_ISSUERS: undefined as readonly string[] | undefined,
    OID4VP_TRUSTED_ISSUERS: {} as Record<string, readonly string[]>,
    OID4VP_ISSUER_JWKS: {} as Record<string, readonly Record<string, unknown>[]>,
    // Credential revocation (#297/#378). Empty on both halves is the shipped
    // default: no checker is built, nothing is fetched, and
    // `assurance.statusChecked` reports `'not-required'`. Under
    // `oid4vp-1.0-base` — the profile every test here selects — that is the
    // documented posture; `haip-1.0` would not have booted.
    OID4VP_STATUS_LIST_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_STATUS_LIST_URI_ALLOWLIST: [] as readonly string[],
  },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

import { resolveRealmTrustRegistry, resolveWalletVerificationSetup } from './wallet-verification';

function makeFastify(realm?: { id: string; name: string } | null): FastifyInstance {
  return {
    repositories: {
      realms: { findById: vi.fn().mockResolvedValue(realm ?? undefined) },
    },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyInstance;
}

beforeEach(() => {
  vi.clearAllMocks();
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  envMock.OID4VP_SUBJECT_RESOLUTION = undefined;
  envMock.OID4VP_SUBJECT_BINDING_CLAIMS = ['given_name'];
  envMock.OID4VP_TRUSTED_ISSUERS = {};
});

describe('resolveWalletVerificationSetup — two distinguishable refusals (#238)', () => {
  it('resolves the profile, the strategy configuration and the key backend together', () => {
    const setup = resolveWalletVerificationSetup(makeFastify());

    expect(setup?.profile.id).toBe('oid4vp-1.0-base');
    expect(setup?.subjectResolution).toEqual({
      strategy: 'asserted-lookup',
      bindingClaims: ['given_name'],
    });
    expect(typeof setup?.resolveIssuerKey).toBe('function');
  });

  it('inherits asserted-lookup from the VerifierProfile when no strategy is named', () => {
    // ADR-009 §1's default, arriving through the profile rather than a literal.
    envMock.OID4VP_SUBJECT_RESOLUTION = undefined;
    expect(resolveWalletVerificationSetup(makeFastify())?.subjectResolution.strategy).toBe(
      'asserted-lookup'
    );
  });

  it.each<[string, () => void]>([
    [
      'wallet federation is off',
      () => {
        envMock.WALLET_FEDERATION_ENABLED = false;
      },
    ],
    [
      'no VerifierProfile is selected',
      () => {
        envMock.OID4VP_VERIFIER_PROFILE = undefined;
      },
    ],
    [
      'no credential type is requested',
      () => {
        envMock.OID4VP_REQUESTED_VCT = undefined;
      },
    ],
  ])('answers undefined when %s', (_label, mutate) => {
    mutate();
    expect(resolveWalletVerificationSetup(makeFastify())).toBeUndefined();
  });

  it('THROWS when a strategy is selected with no entitlement check configured', () => {
    // Not `undefined`: "the operator configured nothing" must not look like
    // "this deployment does not do wallet flows". `asserted-lookup` without a
    // binding check is ADR-009 §1's total authentication bypass.
    envMock.OID4VP_SUBJECT_BINDING_CLAIMS = undefined;
    expect(() => resolveWalletVerificationSetup(makeFastify())).toThrow();
  });

  it('THROWS when a strategy a deployment may not select is named', () => {
    // `session-binding` answers "link", not "log in" (ADR-009 §5).
    envMock.OID4VP_SUBJECT_RESOLUTION = 'session-binding';
    expect(() => resolveWalletVerificationSetup(makeFastify())).toThrow();
  });

  it('answers undefined for an unrecognised strategy rather than falling back', () => {
    envMock.OID4VP_SUBJECT_RESOLUTION = 'asserted-lookupp';
    expect(resolveWalletVerificationSetup(makeFastify())).toBeUndefined();
  });
});

describe('resolveRealmTrustRegistry — never permissive (#236)', () => {
  it('reads the allowlist by realm NAME, and still refuses an unbranded issuer', async () => {
    // Two properties in one: the map is keyed on `realms.name` (an operator
    // cannot know the database-minted uuid), and a hand-built issuer object is
    // refused even when its identifier is on the list — `createStaticIssuerAllowlist`
    // re-checks the `ValidatedIssuer` brand, which is what stops a raw `iss`
    // from being trusted.
    envMock.OID4VP_TRUSTED_ISSUERS = { master: ['https://issuer.example'] };
    const fastify = makeFastify({ id: 'realm-1', name: 'master' });
    const registry = await resolveRealmTrustRegistry(fastify, 'realm-1');

    expect(fastify.repositories.realms.findById).toHaveBeenCalledWith('realm-1');
    expect(registry.isTrusted({ identifier: 'https://issuer.example' } as never)).toBe(false);
  });

  it('trusts nobody for a realm that cannot be read', async () => {
    envMock.OID4VP_TRUSTED_ISSUERS = { master: ['https://issuer.example'] };
    const registry = await resolveRealmTrustRegistry(makeFastify(null), 'realm-1');

    expect(registry.isTrusted({ identifier: 'https://issuer.example' } as never)).toBe(false);
  });

  it('contains a repository failure and still returns a deny-all registry', async () => {
    // An unreadable realm must land on deny-all, not on a 500 an attacker can
    // tell apart from a refusal.
    const fastify = {
      repositories: { realms: { findById: vi.fn().mockRejectedValue(new Error('db down')) } },
      log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    } as unknown as FastifyInstance;

    const registry = await resolveRealmTrustRegistry(fastify, 'realm-1');

    expect(registry.isTrusted({ identifier: 'https://issuer.example' } as never)).toBe(false);
    expect(fastify.log.error).toHaveBeenCalled();
  });

  it('trusts nobody for a realm absent from the configured map', async () => {
    envMock.OID4VP_TRUSTED_ISSUERS = { other: ['https://issuer.example'] };
    const registry = await resolveRealmTrustRegistry(
      makeFastify({ id: 'realm-1', name: 'master' }),
      'realm-1'
    );

    expect(registry.isTrusted({ identifier: 'https://issuer.example' } as never)).toBe(false);
  });
});
