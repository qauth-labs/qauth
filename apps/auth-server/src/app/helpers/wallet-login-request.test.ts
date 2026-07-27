import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { envMock } = vi.hoisted(() => ({
  envMock: {
    JWT_ISSUER: 'https://auth.example.com/',
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
  },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

import {
  buildWalletLoginInvocation,
  OID4VP_RESPONSE_PATH,
  resolveWalletLoginCapability,
} from './wallet-login-request';

/**
 * The availability gate (#296 LOCKED: no permissive fallback) and the request it
 * builds. Every `undefined` below is a wallet-login entry point that must not be
 * rendered — the login page asks this question to decide whether the button
 * exists at all.
 */
function fakeFastify() {
  return { log: { debug: vi.fn(), warn: vi.fn(), error: vi.fn() } } as unknown as FastifyInstance;
}

beforeEach(() => {
  envMock.WALLET_FEDERATION_ENABLED = true;
  envMock.OID4VP_VERIFIER_PROFILE = 'oid4vp-1.0-base';
  envMock.OID4VP_REQUESTED_VCT = ['urn:example:pid'];
  envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = 'openid4vp://';
});

describe('resolveWalletLoginCapability', () => {
  it('resolves when the flag, the profile and a credential type are all present', () => {
    const capability = resolveWalletLoginCapability(fakeFastify());
    expect(capability?.profile.id).toBe('oid4vp-1.0-base');
    // The trailing slash on JWT_ISSUER is canonicalised away, so the
    // `response_uri` matches the endpoint the wallet actually posts to.
    expect(capability?.responseUri).toBe(`https://auth.example.com${OID4VP_RESPONSE_PATH}`);
    expect(capability?.credentials[0].typeValues).toEqual(['urn:example:pid']);
  });

  it('refuses when wallet federation is switched off', () => {
    envMock.WALLET_FEDERATION_ENABLED = false;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses when no VerifierProfile is selected', () => {
    envMock.OID4VP_VERIFIER_PROFILE = undefined;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses when the operator has not said which credential to ask for', () => {
    envMock.OID4VP_REQUESTED_VCT = undefined;
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('refuses haip-1.0, whose signed request and encrypted response need #298', () => {
    envMock.OID4VP_VERIFIER_PROFILE = 'haip-1.0';
    expect(resolveWalletLoginCapability(fakeFastify())).toBeUndefined();
  });

  it('does not throw when the selected profile is not provisioned', () => {
    envMock.OID4VP_VERIFIER_PROFILE = 'haip-1.0';
    const fastify = fakeFastify();
    expect(() => resolveWalletLoginCapability(fastify)).not.toThrow();
  });
});

describe('buildWalletLoginInvocation', () => {
  it('builds a direct_post request and encodes it as an opaque invocation URI', () => {
    const capability = resolveWalletLoginCapability(fakeFastify())!;
    const invocation = buildWalletLoginInvocation(capability);

    expect(invocation.request.response_type).toBe('vp_token');
    expect(invocation.request.response_mode).toBe('direct_post');
    expect(invocation.request.response_uri).toBe(capability.responseUri);
    // OID4VP 1.0 §8.2: `redirect_uri` MUST NOT be a parameter of a direct_post
    // request. It survives only as the Client Identifier Prefix.
    expect(Object.keys(invocation.request)).not.toContain('redirect_uri');
    expect(invocation.request.client_id).toBe(`redirect_uri:${capability.responseUri}`);

    expect(invocation.invocationUri.startsWith('openid4vp://?')).toBe(true);
    expect(invocation.invocationUri).toContain(`state=${invocation.request.state}`);
  });

  it('stores only the digest of the state, and the nonce verbatim', () => {
    const capability = resolveWalletLoginCapability(fakeFastify())!;
    const invocation = buildWalletLoginInvocation(capability);

    expect(invocation.stateHash).toMatch(/^[0-9a-f]{64}$/);
    expect(invocation.stateHash).not.toContain(invocation.request.state);
    expect(invocation.nonce).toBe(invocation.request.nonce);
  });

  it('mints a fresh state and nonce for every request', () => {
    const capability = resolveWalletLoginCapability(fakeFastify())!;
    const first = buildWalletLoginInvocation(capability);
    const second = buildWalletLoginInvocation(capability);

    expect(first.stateHash).not.toBe(second.stateHash);
    expect(first.nonce).not.toBe(second.nonce);
  });

  it('bounds the request lifetime', () => {
    const capability = resolveWalletLoginCapability(fakeFastify())!;
    const invocation = buildWalletLoginInvocation(capability);

    expect(invocation.expiresAt).toBeGreaterThan(Date.now());
    expect(invocation.expiresAt).toBeLessThanOrEqual(Date.now() + 15 * 60 * 1000);
  });

  it('honours a custom wallet invocation endpoint', () => {
    envMock.OID4VP_WALLET_INVOCATION_ENDPOINT = 'https://wallet.example/authorize?v=1';
    const capability = resolveWalletLoginCapability(fakeFastify())!;
    const invocation = buildWalletLoginInvocation(capability);

    expect(invocation.invocationUri.startsWith('https://wallet.example/authorize?v=1&')).toBe(true);
  });
});
