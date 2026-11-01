import { describe, expect, it, vi } from 'vitest';

import { createFakeProvider } from '../testing/fake-provider';
import { checkUpstreamOidcProvider, type UpstreamRegistrationEgress } from './registration-check';

/**
 * The registration check (#601, ADR-019 Decision 8): discovery as the method
 * runs it, then the egress client's address checks on every endpoint, with
 * the source that decides whether the allowlist applies.
 */

const ISSUER = 'https://idp.example.com';
const CONFIG = {
  issuer: ISSUER,
  clientId: 'qauth-client',
  clientAuthentication: { method: 'client_secret_basic', clientSecret: 'a-secret-value' },
};

async function hostEgress(refuse: (url: string, source: string) => boolean = () => false) {
  const provider = await createFakeProvider({ issuer: ISSUER });
  const egress = {
    request: vi.fn((request: Parameters<UpstreamRegistrationEgress['request']>[0]) =>
      provider.answer(request)
    ),
    validateDestination: vi.fn(async (url: string, options: { source: string }) => {
      if (refuse(url, options.source)) throw new Error('egress refused: a private address');
      return { url };
    }),
  };
  return { provider, egress };
}

describe('checkUpstreamOidcProvider', () => {
  it('passes a provider whose discovered endpoints all pass the egress checks', async () => {
    const { provider, egress } = await hostEgress();
    const check = await checkUpstreamOidcProvider(egress, 'acme', CONFIG);
    expect(check.ok).toBe(true);
    expect(egress.request).toHaveBeenCalledWith(
      expect.objectContaining({ source: 'admin', realm: 'acme', limits: { maxRedirects: 0 } })
    );
    expect(egress.validateDestination.mock.calls.map(([url, options]) => [url, options])).toEqual([
      [
        provider.authorizationEndpoint,
        { purpose: 'upstream-authorization', source: 'remote_document', realm: 'acme' },
      ],
      [
        provider.tokenEndpoint,
        { purpose: 'upstream-token', source: 'remote_document', realm: 'acme' },
      ],
      [provider.jwksUri, { purpose: 'upstream-jwks', source: 'remote_document', realm: 'acme' }],
      [
        provider.userinfoEndpoint,
        { purpose: 'upstream-userinfo', source: 'remote_document', realm: 'acme' },
      ],
    ]);
  });

  it('reports a discovered endpoint the egress client refuses', async () => {
    const { egress } = await hostEgress((url) => url.endsWith('/token'));
    expect(await checkUpstreamOidcProvider(egress, 'acme', CONFIG)).toEqual({
      ok: false,
      finding: 'destination_refused',
      detail: expect.stringContaining('the allowlist never opens'),
    });
  });

  it('checks endpoints set by hand as admin destinations', async () => {
    const { egress } = await hostEgress();
    const check = await checkUpstreamOidcProvider(egress, 'acme', {
      ...CONFIG,
      endpoints: {
        authorization: 'https://idp.internal.example/a',
        token: 'https://idp.internal.example/t',
        jwks: 'https://idp.internal.example/j',
      },
    });
    expect(check.ok).toBe(true);
    expect(egress.request).not.toHaveBeenCalled();
    for (const [, options] of egress.validateDestination.mock.calls) {
      expect(options.source).toBe('admin');
    }
  });

  it('tells a bad issuer, an unreachable provider and a bad config apart', async () => {
    const { provider, egress } = await hostEgress();
    provider.tamper.discovery = { issuer: 'https://evil.example.com' };
    expect(await checkUpstreamOidcProvider(egress, 'acme', CONFIG)).toMatchObject({
      ok: false,
      finding: 'invalid_document',
    });

    egress.request.mockRejectedValueOnce(new Error('egress failed: timeout'));
    expect(await checkUpstreamOidcProvider(egress, 'acme', CONFIG)).toMatchObject({
      ok: false,
      finding: 'discovery_unavailable',
    });

    expect(
      await checkUpstreamOidcProvider(egress, 'acme', {
        ...CONFIG,
        issuer: 'http://idp.example.com',
      })
    ).toMatchObject({ ok: false, finding: 'invalid_config', detail: 'issuer: custom' });
  });

  it('reports a client assertion algorithm the provider does not list as invalid_document', async () => {
    const { provider, egress } = await hostEgress();
    provider.tamper.discovery = { token_endpoint_auth_signing_alg_values_supported: ['RS256'] };
    expect(
      await checkUpstreamOidcProvider(egress, 'acme', {
        ...CONFIG,
        clientAuthentication: { method: 'private_key_jwt', signingAlgorithm: 'EdDSA' },
      })
    ).toEqual({
      ok: false,
      finding: 'invalid_document',
      detail: expect.stringContaining('EdDSA'),
    });
    expect(egress.validateDestination).not.toHaveBeenCalled();
  });
});
