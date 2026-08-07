import { describe, expect, it } from 'vitest';

import {
  ASSERTION_MAX_LENGTH,
  ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
  idJagTokenResponseSchema,
  JWT_BEARER_GRANT_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPE_ID_JAG,
  TOKEN_TYPE_ID_TOKEN,
  tokenEndpointResponseSchema,
  tokenExchangeBodySchema,
} from './oauth';

/**
 * Contract tests for the shared ID-JAG / private_key_jwt foundations
 * (ADR-011, #383, #384).
 *
 * These pin the URNs and the request/response surface that the two feature
 * implementations build on. A URN typo here is not a test failure somewhere
 * else — it is a silently non-interoperable authorization server, so the exact
 * strings are asserted literally rather than via the constants themselves.
 */
describe('grant-type and token-type URNs', () => {
  it('spells every URN exactly as registered', () => {
    expect(JWT_BEARER_GRANT_TYPE).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    expect(TOKEN_EXCHANGE_GRANT_TYPE).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(TOKEN_TYPE_ID_JAG).toBe('urn:ietf:params:oauth:token-type:id-jag');
    expect(TOKEN_TYPE_ID_TOKEN).toBe('urn:ietf:params:oauth:token-type:id_token');
    expect(CLIENT_ASSERTION_TYPE_JWT_BEARER).toBe(
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    );
  });

  it('keeps the client-assertion-type URN distinct from the grant-type URN', () => {
    // They differ by one path segment and are routinely confused. A handler
    // that accepts either in either slot would let a caller select the wrong
    // authentication path.
    expect(CLIENT_ASSERTION_TYPE_JWT_BEARER).not.toBe(JWT_BEARER_GRANT_TYPE);
  });

  it('keeps the hyphenated id-jag and the underscored id_token URNs distinct', () => {
    expect(TOKEN_TYPE_ID_JAG).not.toBe(TOKEN_TYPE_ID_TOKEN);
    expect(TOKEN_TYPE_ID_JAG.endsWith('id-jag')).toBe(true);
    expect(TOKEN_TYPE_ID_TOKEN.endsWith('id_token')).toBe(true);
  });
});

describe('ASSERTION_SIGNING_ALG_VALUES_SUPPORTED', () => {
  it('contains asymmetric algorithms only', () => {
    // `HS*` is client_secret_jwt (a secret-based method QAuth does not
    // implement) and `none` is an unsigned assertion. Either in this list
    // would let a caller authenticate without the registered private key.
    for (const alg of ASSERTION_SIGNING_ALG_VALUES_SUPPORTED) {
      expect(alg.startsWith('HS')).toBe(false);
      expect(alg).not.toBe('none');
    }
    expect(ASSERTION_SIGNING_ALG_VALUES_SUPPORTED.length).toBeGreaterThan(0);
  });

  it('has no duplicates', () => {
    expect(new Set(ASSERTION_SIGNING_ALG_VALUES_SUPPORTED).size).toBe(
      ASSERTION_SIGNING_ALG_VALUES_SUPPORTED.length
    );
  });
});

describe('tokenExchangeBodySchema — jwt-bearer grant (ID-JAG consume)', () => {
  const validAssertion = 'a.b.c';

  it('accepts a minimal jwt-bearer request', () => {
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: JWT_BEARER_GRANT_TYPE,
      assertion: validAssertion,
    });

    expect(parsed.success).toBe(true);
    if (parsed.success && parsed.data.grant_type === JWT_BEARER_GRANT_TYPE) {
      expect(parsed.data.assertion).toBe(validAssertion);
    }
  });

  it('accepts scope and resource alongside the assertion', () => {
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: JWT_BEARER_GRANT_TYPE,
      assertion: validAssertion,
      scope: 'mcp:read',
      resource: 'https://mcp.example.com',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success && parsed.data.grant_type === JWT_BEARER_GRANT_TYPE) {
      // `resource` normalises to an array like every other grant.
      expect(parsed.data.resource).toEqual(['https://mcp.example.com']);
    }
  });

  it('rejects a jwt-bearer request with no assertion', () => {
    expect(tokenExchangeBodySchema.safeParse({ grant_type: JWT_BEARER_GRANT_TYPE }).success).toBe(
      false
    );
  });

  it('rejects an empty assertion', () => {
    expect(
      tokenExchangeBodySchema.safeParse({ grant_type: JWT_BEARER_GRANT_TYPE, assertion: '' })
        .success
    ).toBe(false);
  });

  it('rejects an oversized assertion before any signature work happens', () => {
    // The assertion is an UNAUTHENTICATED input — it is what establishes the
    // caller's identity — so the length bound must reject at the edge rather
    // than after a costly verification attempt.
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: JWT_BEARER_GRANT_TYPE,
      assertion: 'x'.repeat(ASSERTION_MAX_LENGTH + 1),
    });

    expect(parsed.success).toBe(false);
  });

  it('strips an unknown issuer/JWKS hint rather than surfacing it to the handler', () => {
    // Trust must come from the operator allowlist, never from the request.
    // Zod's default strip means such a parameter cannot reach a handler at all.
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: JWT_BEARER_GRANT_TYPE,
      assertion: validAssertion,
      jwks_uri: 'https://attacker.example/jwks.json',
      issuer: 'https://attacker.example',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect('jwks_uri' in parsed.data).toBe(false);
      expect('issuer' in parsed.data).toBe(false);
    }
  });

  it('still rejects an unknown grant_type at the union level', () => {
    expect(
      tokenExchangeBodySchema.safeParse({ grant_type: 'password', username: 'a', password: 'b' })
        .success
    ).toBe(false);
  });
});

describe('client_assertion parameters on every grant (RFC 7523 §2.2, #384)', () => {
  const bodies: Array<[string, Record<string, unknown>]> = [
    [
      'authorization_code',
      {
        grant_type: 'authorization_code',
        code: 'abc',
        redirect_uri: 'https://app.example.com/cb',
        code_verifier: 'a'.repeat(43),
      },
    ],
    ['client_credentials', { grant_type: 'client_credentials' }],
    ['refresh_token', { grant_type: 'refresh_token', refresh_token: 'a'.repeat(64) }],
    [
      'token-exchange',
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: 'tok',
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      },
    ],
    ['jwt-bearer', { grant_type: JWT_BEARER_GRANT_TYPE, assertion: 'a.b.c' }],
  ];

  it.each(bodies)('carries client_assertion through the %s grant body', (_name, base) => {
    const parsed = tokenExchangeBodySchema.safeParse({
      ...base,
      client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
      client_assertion: 'a.b.c',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const data = parsed.data as Record<string, unknown>;
      // If these were stripped, private_key_jwt would silently degrade to
      // "no credentials presented" on that grant.
      expect(data['client_assertion']).toBe('a.b.c');
      expect(data['client_assertion_type']).toBe(CLIENT_ASSERTION_TYPE_JWT_BEARER);
    }
  });

  it.each(bodies)('still parses the %s grant with no client credentials at all', (_name, base) => {
    // Requirement lives in the handler (so failures surface as
    // `invalid_client`, not a Zod 400), never in the schema.
    expect(tokenExchangeBodySchema.safeParse(base).success).toBe(true);
  });

  it('rejects an oversized client_assertion', () => {
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: 'client_credentials',
      client_assertion_type: CLIENT_ASSERTION_TYPE_JWT_BEARER,
      client_assertion: 'x'.repeat(ASSERTION_MAX_LENGTH + 1),
    });

    expect(parsed.success).toBe(false);
  });

  it('still accepts the pre-existing client_secret_post pair unchanged', () => {
    // Adding the assertion parameters must not alter any existing client.
    const parsed = tokenExchangeBodySchema.safeParse({
      grant_type: 'client_credentials',
      client_id: 'svc',
      client_secret: 'shh',
      scope: 'a b',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const data = parsed.data as Record<string, unknown>;
      expect(data['client_id']).toBe('svc');
      expect(data['client_secret']).toBe('shh');
    }
  });
});

describe('idJagTokenResponseSchema (ADR-011 mint side)', () => {
  const minted = {
    access_token: 'header.payload.signature',
    issued_token_type: TOKEN_TYPE_ID_JAG,
    token_type: 'N_A',
    expires_in: 300,
  };

  it('accepts a well-formed minted ID-JAG response', () => {
    expect(idJagTokenResponseSchema.safeParse(minted).success).toBe(true);
  });

  it('rejects token_type "Bearer" — an ID-JAG is not usable as an access token', () => {
    // RFC 8693 §2.2.1 mandates `N_A` when the issued token is not a bearer
    // token. Emitting `Bearer` would invite clients to send the assertion to a
    // protected resource instead of to the target AS.
    expect(idJagTokenResponseSchema.safeParse({ ...minted, token_type: 'Bearer' }).success).toBe(
      false
    );
  });

  it('rejects a mismatched issued_token_type', () => {
    expect(
      idJagTokenResponseSchema.safeParse({
        ...minted,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      }).success
    ).toBe(false);
  });

  it('rejects a response with a missing issued_token_type', () => {
    const { issued_token_type: _omitted, ...withoutType } = minted;
    expect(idJagTokenResponseSchema.safeParse(withoutType).success).toBe(false);
  });

  it('drops a refresh_token — an ID-JAG is single-use and short-lived', () => {
    const parsed = idJagTokenResponseSchema.safeParse({ ...minted, refresh_token: 'nope' });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect('refresh_token' in parsed.data).toBe(false);
    }
  });
});

describe('tokenEndpointResponseSchema', () => {
  it('serializes an ID-JAG response without collapsing it into the Bearer variant', () => {
    const parsed = tokenEndpointResponseSchema.safeParse({
      access_token: 'a.b.c',
      issued_token_type: TOKEN_TYPE_ID_JAG,
      token_type: 'N_A',
      expires_in: 300,
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.token_type).toBe('N_A');
    }
  });

  it('still serializes an ordinary Bearer access-token response', () => {
    const parsed = tokenEndpointResponseSchema.safeParse({
      access_token: 'a.b.c',
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: 'r'.repeat(64),
      scope: 'openid',
    });

    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.token_type).toBe('Bearer');
      expect((parsed.data as Record<string, unknown>)['refresh_token']).toBe('r'.repeat(64));
    }
  });

  it('rejects a response with an unrecognised token_type', () => {
    expect(
      tokenEndpointResponseSchema.safeParse({
        access_token: 'a.b.c',
        token_type: 'mac',
        expires_in: 60,
      }).success
    ).toBe(false);
  });
});
