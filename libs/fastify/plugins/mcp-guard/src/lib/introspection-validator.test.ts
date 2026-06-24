import { describe, expect, it, vi } from 'vitest';

import type { FetchLike } from '../types';
import { InvalidTokenError } from './errors';
import { IntrospectionValidator } from './introspection-validator';

const ENDPOINT = 'https://auth.example.com/oauth/introspect';
const RESOURCE = 'https://mcp.example.com';
const CLIENT = { clientId: 'rs-introspect', clientSecret: 's3cr3t' };

function fakeFetch(
  response: { ok?: boolean; status?: number; body: unknown },
  capture?: (input: string | URL, init?: Record<string, unknown>) => void
): FetchLike {
  return (async (input, init) => {
    capture?.(input, init as Record<string, unknown>);
    return {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: async () => response.body,
      text: async () => JSON.stringify(response.body),
    };
  }) as FetchLike;
}

function makeValidator(fetchImpl: FetchLike) {
  return new IntrospectionValidator({
    endpoint: ENDPOINT,
    audience: RESOURCE,
    client: CLIENT,
    fetch: fetchImpl,
  });
}

describe('IntrospectionValidator', () => {
  it('accepts an active, audience-bound token and normalises claims', async () => {
    const validator = makeValidator(
      fakeFetch({
        body: {
          active: true,
          sub: 'user-1',
          client_id: 'client-abc',
          scope: 'mcp:read',
          aud: RESOURCE,
          iss: 'https://auth.example.com',
          exp: 9999999999,
          iat: 1,
          token_type: 'Bearer',
        },
      })
    );
    const result = await validator.validate('opaque-token');
    expect(result.sub).toBe('user-1');
    expect(result.clientId).toBe('client-abc');
    expect(result.scopes).toEqual(['mcp:read']);
    expect(result.audience).toContain(RESOURCE);
  });

  it('authenticates with HTTP Basic and posts the token as form body (RFC 7662)', async () => {
    let seenInput: string | URL = '';
    let seenInit: Record<string, unknown> = {};
    const validator = makeValidator(
      fakeFetch({ body: { active: true, aud: RESOURCE } }, (input, init) => {
        seenInput = input;
        seenInit = init ?? {};
      })
    );
    await validator.validate('opaque-token');
    expect(seenInput).toBe(ENDPOINT);
    expect(seenInit['method']).toBe('POST');
    const headers = seenInit['headers'] as Record<string, string>;
    const expectedBasic = `Basic ${Buffer.from('rs-introspect:s3cr3t').toString('base64')}`;
    expect(headers['authorization']).toBe(expectedBasic);
    expect(headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(seenInit['body']).toContain('token=opaque-token');
  });

  it('rejects an inactive token', async () => {
    const validator = makeValidator(fakeFetch({ body: { active: false } }));
    await expect(validator.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(validator.validate('x')).rejects.toThrow(/not active/i);
  });

  it('rejects an active token bound to a DIFFERENT audience (defence-in-depth no-passthrough)', async () => {
    const validator = makeValidator(
      fakeFetch({ body: { active: true, aud: 'https://other.example.com' } })
    );
    await expect(validator.validate('x')).rejects.toThrow(/audience/i);
  });

  it('accepts an active token whose aud array includes the resource', async () => {
    const validator = makeValidator(
      fakeFetch({ body: { active: true, aud: ['https://other.example.com', RESOURCE] } })
    );
    const result = await validator.validate('x');
    expect(result.audience).toEqual(['https://other.example.com', RESOURCE]);
  });

  it('fails closed when the endpoint returns a non-2xx (e.g. our client misconfigured)', async () => {
    const validator = makeValidator(fakeFetch({ ok: false, status: 401, body: {} }));
    await expect(validator.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('fails closed on transport error', async () => {
    const throwing: FetchLike = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as FetchLike;
    const validator = makeValidator(throwing);
    await expect(validator.validate('x')).rejects.toThrow(/unreachable/i);
  });
});
