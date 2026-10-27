import { describe, expect, it, vi } from 'vitest';

import { OAUTH_SCOPE_PARAM_MAX_LENGTH } from '../constants';
import { redirectUriMatchesRegistered } from '../helpers/oauth-redirect';
import {
  ASSERTION_MAX_LENGTH,
  ASSERTION_SIGNING_ALG_VALUES_SUPPORTED,
  authorizeQuerySchema,
  CLIENT_ASSERTION_TYPE_JWT_BEARER,
  dynamicClientRegistrationRequestSchema,
  idJagTokenResponseSchema,
  introspectRequestSchema,
  JWT_BEARER_GRANT_TYPE,
  resourceParamSchema,
  revokeRequestSchema,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPE_ID_JAG,
  TOKEN_TYPE_ID_TOKEN,
  tokenEndpointResponseSchema,
  tokenExchangeAuthCodeBodySchema,
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

/**
 * Since Zod 4.5, `z.url()` returns its input with every tab, LF and CR
 * deleted. Passed to the redirect_uri matcher, `https://app.exa\nmple.com/cb`
 * would then equal a registered `https://app.example.com/cb`. These schemas use
 * `exactUrl()` instead, so the value reaches the exact-string comparison as
 * sent, or the request is refused.
 */
describe('redirect_uri and resource reach the handler as sent (exactUrl)', () => {
  const authorize = {
    response_type: 'code',
    client_id: 'c1',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  } as const;
  const registered = ['https://app.example.com/cb'];
  const withControl = [
    'https://app.example.com/c\tb',
    'https://app.exa\nmple.com/cb',
    'https://app.example.com/c\rb',
  ];

  it('/authorize refuses a tab or line break inside redirect_uri instead of stripping it into a match', () => {
    for (const redirect_uri of withControl) {
      expect(authorizeQuerySchema.safeParse({ ...authorize, redirect_uri }).success).toBe(false);
      expect(redirectUriMatchesRegistered(redirect_uri, registered)).toBe(false);
    }
  });

  it('/authorize passes a valid redirect_uri on unchanged, ends trimmed', () => {
    const parse = (redirect_uri: string) =>
      authorizeQuerySchema.parse({ ...authorize, redirect_uri }).redirect_uri;
    expect(parse('https://app.example.com/cb')).toBe('https://app.example.com/cb');
    expect(parse('https://app.example.com/cb\r\n')).toBe('https://app.example.com/cb');
  });

  it('refuses a tab or line break inside an RFC 8707 resource on /authorize and /token', () => {
    const resource = 'https://api.example.com/mc\tp';
    expect(resourceParamSchema.safeParse(resource).success).toBe(false);
    expect(resourceParamSchema.safeParse([resource]).success).toBe(false);
    expect(
      authorizeQuerySchema.safeParse({
        ...authorize,
        redirect_uri: 'https://app.example.com/cb',
        resource,
      }).success
    ).toBe(false);
    expect(
      tokenExchangeAuthCodeBodySchema.safeParse({
        grant_type: 'authorization_code',
        code: 'c',
        redirect_uri: 'https://app.example.com/cb',
        code_verifier: 'A'.repeat(43),
        resource,
      }).success
    ).toBe(false);
    expect(resourceParamSchema.parse('https://api.example.com/mcp')).toEqual([
      'https://api.example.com/mcp',
    ]);
  });
});

/**
 * ADR-017 Decision 10: whether a token request needs `redirect_uri` depends on
 * the code, which the schema cannot see. So the schema lets a request without
 * one, or with an empty one, through to the handler, which answers
 * `invalid_grant` for a browser code instead of a validation error.
 */
describe('tokenExchangeAuthCodeBodySchema — redirect_uri', () => {
  const body = { grant_type: 'authorization_code', code: 'c', code_verifier: 'A'.repeat(43) };

  it.each([
    ['absent', {}],
    ['empty', { redirect_uri: '' }],
    ['present', { redirect_uri: 'https://app.example.com/cb' }],
  ])('accepts a request with the parameter %s', (_label, extra) => {
    expect(tokenExchangeAuthCodeBodySchema.safeParse({ ...body, ...extra }).success).toBe(true);
  });

  it('still refuses a value that is not a string', () => {
    expect(
      tokenExchangeAuthCodeBodySchema.safeParse({ ...body, redirect_uri: ['a'] }).success
    ).toBe(false);
  });
});

/**
 * OIDC Core §3.1.2.1 `max_age` on `GET`/`POST /oauth/authorize`.
 *
 * `POST /oauth/authorize` also accepts a JSON body, so `max_age` can be any
 * JSON value. `z.coerce.number()` ran `Number()` on it before looking at its
 * type, and `Number()` of an array joins it recursively: one nested a few
 * thousand levels deep held the event loop for seconds on an unauthenticated
 * route. A value that is neither a digit string nor a number must be refused
 * by type, before anything converts it.
 */
describe('authorizeQuerySchema — max_age', () => {
  const authorize = {
    response_type: 'code',
    client_id: 'c1',
    redirect_uri: 'https://app.example.com/cb',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  } as const;
  const maxAgeOf = (max_age: unknown) => authorizeQuerySchema.safeParse({ ...authorize, max_age });

  it('accepts a digit string (query string, form body) and a JSON number', () => {
    expect(maxAgeOf('300').data?.max_age).toBe(300);
    expect(maxAgeOf('0').data?.max_age).toBe(0);
    expect(maxAgeOf(300).data?.max_age).toBe(300);
    expect(maxAgeOf('315360000').data?.max_age).toBe(315360000);
    expect(maxAgeOf(undefined).data?.max_age).toBeUndefined();
  });

  it('refuses anything else', () => {
    for (const value of ['-1', '1.5', '1e3', ' 300', '315360001', true, null, {}, ['300']]) {
      expect(maxAgeOf(value).success, JSON.stringify(value)).toBe(false);
    }
  });

  it('refuses an array or object WITHOUT converting it', () => {
    const toString = vi.fn(() => '300');
    const valueOf = vi.fn(() => 300);
    // Shaped like the attack: the element sits deep inside nested arrays.
    let nested: unknown = [{ toString, valueOf }];
    for (let i = 0; i < 100; i += 1) nested = [nested, 0];

    expect(maxAgeOf(nested).success).toBe(false);
    expect(maxAgeOf({ toString, valueOf }).success).toBe(false);
    expect(toString).not.toHaveBeenCalled();
    expect(valueOf).not.toHaveBeenCalled();
  });
});

/**
 * `new URL()` is quadratic in the number of distinct non-ASCII characters in a
 * host, and every caller-supplied URI used to reach it before its length cap:
 * 63 CJK-host `resource` entries in a 1 MiB body held the event loop for ~4 s
 * on an unauthenticated POST /oauth/token. `client_id` had no cap at all and
 * is parsed several times on the CIMD path.
 */
describe('URIs and client_id are bounded before anything parses them', () => {
  const cjkHost = Array.from({ length: 1000 }, (_, i) => String.fromCodePoint(0x4e00 + i)).join('');
  const cjkUrl = `https://${cjkHost}/`;
  const longUrl = `https://api.example.com/${'a'.repeat(2048)}`;
  const authorize = {
    response_type: 'code',
    redirect_uri: 'https://app.example.com/cb',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  } as const;

  function urlParses(run: () => void): number {
    const canParse = vi.spyOn(URL, 'canParse');
    try {
      run();
      return canParse.mock.calls.length;
    } finally {
      canParse.mockRestore();
    }
  }

  it('refuses a non-ASCII or over-long resource without parsing it', () => {
    const parses = urlParses(() => {
      for (const resource of [cjkUrl, longUrl, Array(10).fill(cjkUrl), Array(10).fill(longUrl)]) {
        expect(resourceParamSchema.safeParse(resource).success).toBe(false);
      }
    });
    expect(parses).toBe(0);
  });

  it('refuses a non-ASCII or over-long redirect_uri on /authorize without parsing it', () => {
    const parses = urlParses(() => {
      for (const redirect_uri of [cjkUrl, longUrl]) {
        expect(
          authorizeQuerySchema.safeParse({ ...authorize, client_id: 'c1', redirect_uri }).success
        ).toBe(false);
      }
    });
    expect(parses).toBe(0);
  });

  it('refuses a non-ASCII or over-long registration URI field without parsing it', () => {
    const parses = urlParses(() => {
      for (const field of ['client_uri', 'logo_uri', 'tos_uri', 'policy_uri']) {
        for (const value of [cjkUrl, longUrl]) {
          expect(
            dynamicClientRegistrationRequestSchema.safeParse({ [field]: value }).success,
            field
          ).toBe(false);
        }
      }
    });
    expect(parses).toBe(0);
  });

  it('caps client_id at 2048 printable ASCII characters on every request schema', () => {
    // 2048 leaves room for a Client ID Metadata Document URL, whose own schema
    // caps `client_id` at 2048 (helpers/cimd.ts). RFC 6749 Appendix A.1:
    // client-id = *VSCHAR, i.e. %x20-7E.
    const cimd = `https://app.example.com/${'a'.repeat(2048 - 'https://app.example.com/'.length)}`;
    const token = { grant_type: 'client_credentials' } as const;
    const parsers: Array<(clientId: string) => boolean> = [
      (client_id) => authorizeQuerySchema.safeParse({ ...authorize, client_id }).success,
      (client_id) => tokenExchangeBodySchema.safeParse({ ...token, client_id }).success,
      (client_id) => introspectRequestSchema.safeParse({ token: 't', client_id }).success,
      (client_id) => revokeRequestSchema.safeParse({ token: 't', client_id }).success,
    ];

    for (const parse of parsers) {
      expect(parse(cimd)).toBe(true);
      expect(parse('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
      expect(parse(`${cimd}a`)).toBe(false);
      expect(parse(`https://${cjkHost}/client.json`)).toBe(false);
    }
  });
});

/**
 * `scope` is capped on every grant that takes it. The refresh_token and
 * client_credentials bodies were the two left out, so the only bound was the
 * 1 MiB body limit: a refresh `scope` of 522,000 names, checked against a
 * stored list of 174,000, held the event loop for ~78 s.
 */
describe('scope is bounded on every token grant', () => {
  const grants: Array<[string, Record<string, unknown>]> = [
    ['client_credentials', { grant_type: 'client_credentials' }],
    ['refresh_token', { grant_type: 'refresh_token', refresh_token: 'a'.repeat(64) }],
    [
      'token exchange',
      { grant_type: TOKEN_EXCHANGE_GRANT_TYPE, subject_token: 't', subject_token_type: 't' },
    ],
    ['jwt-bearer', { grant_type: JWT_BEARER_GRANT_TYPE, assertion: 'a.b.c' }],
  ];

  it.each(grants)('%s accepts a scope at the bound and refuses one past it', (_grant, body) => {
    const atBound = 'a'.repeat(OAUTH_SCOPE_PARAM_MAX_LENGTH);
    expect(tokenExchangeBodySchema.safeParse({ ...body, scope: atBound }).success).toBe(true);
    expect(tokenExchangeBodySchema.safeParse({ ...body, scope: `${atBound}a` }).success).toBe(
      false
    );
  });
});
