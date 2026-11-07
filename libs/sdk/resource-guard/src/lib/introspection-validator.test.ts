import { describe, expect, it, vi } from 'vitest';

import type { FetchLike } from '../types';
import { IntrospectionError, InvalidTokenError } from './errors';
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
    const expectedBasic = `Basic ${btoa('rs-introspect:s3cr3t')}`;
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

  it('surfaces a non-2xx as an operational IntrospectionError, NOT invalid_token (e.g. our client misconfigured → AS 401s us)', async () => {
    const validator = makeValidator(fakeFetch({ ok: false, status: 401, body: {} }));
    // A non-2xx is an RS/AS-side fault; it must not be reported as the
    // *bearer's* token being invalid (that would 401 the client and can drive
    // futile refresh loops). It is operational → propagates as a 5xx.
    await expect(validator.validate('x')).rejects.toBeInstanceOf(IntrospectionError);
    await expect(validator.validate('x')).rejects.not.toBeInstanceOf(InvalidTokenError);
    await expect(validator.validate('x')).rejects.toThrow(/failed with status 401/i);
  });

  it('surfaces a transport failure as an operational IntrospectionError, NOT invalid_token', async () => {
    const throwing: FetchLike = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as FetchLike;
    const validator = makeValidator(throwing);
    await expect(validator.validate('x')).rejects.toBeInstanceOf(IntrospectionError);
    await expect(validator.validate('x')).rejects.not.toBeInstanceOf(InvalidTokenError);
    await expect(validator.validate('x')).rejects.toThrow(/unreachable/i);
  });

  it('surfaces a malformed (2xx) introspection body as an operational IntrospectionError', async () => {
    // A 2xx whose body cannot be parsed is a broken/misbehaving AS — an
    // operational fault, not an invalid token.
    const bespoke: FetchLike = (async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new Error('not json');
      },
      text: async () => 'not json',
    })) as FetchLike;
    const validator = makeValidator(bespoke);
    await expect(validator.validate('x')).rejects.toBeInstanceOf(IntrospectionError);
    await expect(validator.validate('x')).rejects.toThrow(/malformed/i);
  });

  it('still rejects an inactive token as InvalidTokenError (token-state fault → 401)', async () => {
    const validator = makeValidator(fakeFetch({ body: { active: false } }));
    await expect(validator.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
  });
});

describe('IntrospectionValidator — sender-constrained tokens (RFC 9449 §6.2, §7.2)', () => {
  // What QAuth's introspection endpoint answers for an active token; a
  // DPoP-bound one adds `token_type: DPoP` and `cnf.jkt`. The SDK verifies no
  // proof of possession, so either signal refuses the token.
  const ACTIVE = {
    active: true,
    sub: 'user-1',
    client_id: 'client-abc',
    scope: 'mcp:read',
    aud: RESOURCE,
    iss: 'https://auth.example.com',
    exp: 9999999999,
    iat: 1,
  };
  const DPOP_CNF = { jkt: '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I' };

  it('accepts an ordinary Bearer token', async () => {
    const validator = makeValidator(fakeFetch({ body: { ...ACTIVE, token_type: 'Bearer' } }));
    await expect(validator.validate('x')).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('refuses a token reported as DPoP-bound, as QAuth reports one', async () => {
    const validator = makeValidator(
      fakeFetch({ body: { ...ACTIVE, token_type: 'DPoP', cnf: DPOP_CNF } })
    );
    const rejection = validator.validate('x');
    await expect(rejection).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(rejection).rejects.toMatchObject({
      reason: 'sender-constrained (DPoP-bound) token presented without a proof',
    });
  });

  it.each(['DPoP', 'dpop', 'DPOP'])(
    'refuses token_type %s even without cnf (case-insensitive, RFC 6749 §5.1)',
    async (tokenType) => {
      const validator = makeValidator(fakeFetch({ body: { ...ACTIVE, token_type: tokenType } }));
      await expect(validator.validate('x')).rejects.toThrow(/DPoP-bound/);
    }
  );

  it('refuses a token whose response carries cnf only', async () => {
    const validator = makeValidator(fakeFetch({ body: { ...ACTIVE, cnf: DPOP_CNF } }));
    await expect(validator.validate('x')).rejects.toThrow(/DPoP-bound/);
  });

  it('refuses a cnf beside token_type Bearer (the binding wins over the label)', async () => {
    const validator = makeValidator(
      fakeFetch({ body: { ...ACTIVE, token_type: 'Bearer', cnf: DPOP_CNF } })
    );
    await expect(validator.validate('x')).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it('refuses a certificate-bound (mTLS, cnf.x5t#S256) token', async () => {
    const validator = makeValidator(
      fakeFetch({
        body: {
          ...ACTIVE,
          token_type: 'Bearer',
          cnf: { 'x5t#S256': 'bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2' },
        },
      })
    );
    await expect(validator.validate('x')).rejects.toMatchObject({
      reason: 'sender-constrained token presented without a proof',
    });
  });

  // `token_type` is an allow-list: another AS may name a bound token type
  // this SDK has never heard of, and a deny-list would accept it as Bearer.
  it.each([
    ['absent', undefined],
    ['Bearer', 'Bearer'],
    ['bearer', 'bearer'],
    ['BEARER', 'BEARER'],
  ])('accepts token_type %s', async (_label, tokenType) => {
    const validator = makeValidator(
      fakeFetch({
        body: { ...ACTIVE, ...(tokenType === undefined ? {} : { token_type: tokenType }) },
      })
    );
    await expect(validator.validate('x')).resolves.toMatchObject({ sub: 'user-1' });
  });

  it.each([
    ['PoP', 'PoP'],
    ['DPoP with a trailing space', 'DPoP '],
    ['Bearer with a trailing space', 'Bearer '],
    ['N_A', 'N_A'],
    ['an empty string', ''],
    ['an array', ['DPoP']],
    ['an object', { type: 'Bearer' }],
    ['null', null],
    ['a number', 1],
  ])('refuses token_type %s without cnf as not Bearer', async (_label, tokenType) => {
    const validator = makeValidator(fakeFetch({ body: { ...ACTIVE, token_type: tokenType } }));
    const rejection = validator.validate('x');
    await expect(rejection).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(rejection).rejects.toMatchObject({ reason: 'token type is not Bearer' });
  });

  it.each([
    ['a null cnf', null],
    ['an empty cnf object', {}],
  ])('fails closed on %s', async (_label, cnf) => {
    const validator = makeValidator(fakeFetch({ body: { ...ACTIVE, token_type: 'Bearer', cnf } }));
    await expect(validator.validate('x')).rejects.toMatchObject({
      reason: 'sender-constrained token presented without a proof',
    });
  });

  it('still answers an inactive bound token with "not active"', async () => {
    const validator = makeValidator(
      fakeFetch({ body: { active: false, token_type: 'DPoP', cnf: DPOP_CNF } })
    );
    await expect(validator.validate('x')).rejects.toThrow(/not active/);
  });
});
