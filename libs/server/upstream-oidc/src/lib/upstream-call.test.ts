import type { AuthMethodEgress, AuthMethodEgressResponse } from '@qauth-labs/server-federation';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createFakeProvider } from '../testing/fake-provider';
import { UPSTREAM_JWKS_REFRESH_INTERVAL_MS, UPSTREAM_JWKS_TTL_MS, UpstreamJwksCache } from './jwks';
import { jsonObjectBody, upstreamCall } from './upstream-call';

/**
 * The caps of every upstream call (#601): no redirect followed, a deadline
 * and a size cap of its own, an answer from the URL called.
 */

const URL_CALLED = 'https://idp.example.com/token';
const CAPS = { timeoutMs: 1000, maxBytes: 16 };

const answer = (overrides: Partial<AuthMethodEgressResponse> = {}): AuthMethodEgressResponse => ({
  status: 200,
  headers: { 'content-type': 'application/json' },
  body: Buffer.from('{}'),
  url: URL_CALLED,
  ...overrides,
});

const call = (egress: AuthMethodEgress) =>
  upstreamCall(egress, {
    method: 'POST',
    url: URL_CALLED,
    body: 'code=x',
    purpose: 'upstream-token',
    source: 'remote_document',
    caps: CAPS,
  });

afterEach(() => {
  vi.useRealTimers();
});

describe('upstreamCall', () => {
  it('asks the egress client to follow no redirect', async () => {
    const request = vi.fn(async () => answer());
    await call({ request });
    expect(request).toHaveBeenCalledWith(expect.objectContaining({ redirect: 'error' }));
  });

  it('refuses an answer larger than its cap', async () => {
    await expect(
      call({ request: async () => answer({ body: Buffer.alloc(17) }) })
    ).rejects.toMatchObject({
      reason: 'invalid_response',
      message: expect.stringContaining('larger'),
    });
  });

  it('refuses an answer from another URL', async () => {
    await expect(
      call({ request: async () => answer({ url: 'https://elsewhere.example.com/token' }) })
    ).rejects.toMatchObject({ reason: 'invalid_response' });
  });

  it('gives up at its deadline, whatever the egress client is still doing', async () => {
    vi.useFakeTimers();
    const pending = call({ request: () => new Promise(() => undefined) });
    const outcome = expect(pending).rejects.toMatchObject({ reason: 'upstream_unavailable' });
    await vi.advanceTimersByTimeAsync(CAPS.timeoutMs + 1);
    await outcome;
  });

  it('reports a refused or failed egress call as upstream_unavailable', async () => {
    await expect(
      call({
        request: async () => {
          throw new Error('egress refused: redirect limit of 0 reached');
        },
      })
    ).rejects.toMatchObject({ reason: 'upstream_unavailable' });
  });
});

describe('jsonObjectBody', () => {
  it.each([
    ['application/json', true],
    ['application/json; charset=utf-8', true],
    ['application/jwk-set+json', true],
    ['text/plain', false],
    ['application/jwt', false],
    ['application/jsonx', false],
  ])('reads %s: %s', (contentType, ok) => {
    const read = () => jsonObjectBody(answer({ headers: { 'content-type': contentType } }), 'x');
    if (ok) expect(read()).toEqual({});
    else expect(read).toThrow(/not JSON/);
  });

  it('refuses ill-formed UTF-8 and values that are not objects', () => {
    for (const body of [Buffer.from([0x7b, 0xff, 0x7d]), Buffer.from('null'), Buffer.from('"x"')]) {
      expect(() => jsonObjectBody(answer({ body }), 'x')).toThrow();
    }
  });
});

describe('the JWKS cache', () => {
  async function jwksSetup() {
    const provider = await createFakeProvider({ issuer: 'https://idp.example.com' });
    const request = vi.fn((call: Parameters<AuthMethodEgress['request']>[0]) =>
      provider.answer(call)
    );
    const cache = new UpstreamJwksCache();
    const location = {
      scope: 'realm-a',
      uri: provider.jwksUri,
      source: 'remote_document' as const,
    };
    return { provider, request, cache, location };
  }

  it('keeps a key set five minutes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { provider, request, cache, location } = await jwksSetup();
    const kid = provider.publicJwk.kid;
    await cache.candidates({ request }, location, 'ES256', kid);
    await cache.candidates({ request }, location, 'ES256', kid);
    expect(request).toHaveBeenCalledTimes(1);
    vi.setSystemTime(Date.now() + UPSTREAM_JWKS_TTL_MS + 1);
    await cache.candidates({ request }, location, 'ES256', kid);
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('fetches again for an unknown kid at most once a minute', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const { request, cache, location } = await jwksSetup();
    expect(await cache.candidates({ request }, location, 'ES256', 'unknown')).toEqual([]);
    expect(request).toHaveBeenCalledTimes(2);
    expect(await cache.candidates({ request }, location, 'ES256', 'unknown-2')).toEqual([]);
    expect(request).toHaveBeenCalledTimes(2);
    vi.setSystemTime(Date.now() + UPSTREAM_JWKS_REFRESH_INTERVAL_MS + 1);
    await cache.candidates({ request }, location, 'ES256', 'unknown-3');
    expect(request).toHaveBeenCalledTimes(3);
  });

  it('finds a rotated key for every callback that waited on the older set', async () => {
    const { provider, cache, location } = await jwksSetup();
    const older = { keys: [{ kty: 'EC', crv: 'P-256', x: 'old', y: 'old', kid: 'old' }] };
    const rotated = { keys: [provider.publicJwk] };
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    // The first fetch answers the older set, once the gate opens; later
    // fetches answer the rotated one.
    const request = vi.fn(async () => {
      const set = request.mock.calls.length === 1 ? older : rotated;
      await gate;
      return answer({ body: Buffer.from(JSON.stringify(set)), url: location.uri });
    });
    // Two callbacks for the new key wait on the first, older set.
    const first = cache.candidates({ request }, location, 'ES256', provider.publicJwk.kid);
    const second = cache.candidates({ request }, location, 'ES256', provider.publicJwk.kid);
    await vi.waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    release();
    expect(await first).toHaveLength(1);
    expect(await second).toHaveLength(1);
    // One refresh for both.
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('keeps one realm’s key set apart from another’s', async () => {
    const { request, cache, location, provider } = await jwksSetup();
    await cache.candidates({ request }, location, 'ES256', provider.publicJwk.kid);
    await cache.candidates(
      { request },
      { ...location, scope: 'realm-b' },
      'ES256',
      provider.publicJwk.kid
    );
    expect(request).toHaveBeenCalledTimes(2);
  });

  it.each([
    ['a private key', { keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y', d: 'd' }] }],
    ['a secret key', { keys: [{ kty: 'oct', k: 'c2VjcmV0' }] }],
    ['no keys', { keys: [] }],
    ['no list', {}],
    ['a key without kty', { keys: [{ kid: 'k' }] }],
  ])('refuses a key set with %s', async (_name, document) => {
    const { cache, location } = await jwksSetup();
    const request = async () =>
      answer({ body: Buffer.from(JSON.stringify(document)), url: location.uri });
    await expect(cache.candidates({ request }, location, 'ES256', undefined)).rejects.toMatchObject(
      {
        reason: 'invalid_response',
      }
    );
  });

  it('does not keep a failed fetch', async () => {
    const { cache, location, provider } = await jwksSetup();
    const failing = vi.fn(async () => {
      throw new Error('egress failed');
    });
    await expect(
      cache.candidates({ request: failing }, location, 'ES256', undefined)
    ).rejects.toThrow();
    const request = vi.fn((c: Parameters<AuthMethodEgress['request']>[0]) => provider.answer(c));
    await expect(cache.candidates({ request }, location, 'ES256', undefined)).resolves.toHaveLength(
      1
    );
  });
});
