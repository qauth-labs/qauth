import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://auth-server:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

// Outside a request the real helpers throw; the tests drive them explicitly.
const { mockGetRequestIP, mockGetRequestHeader } = vi.hoisted(() => ({
  mockGetRequestIP: vi.fn(),
  mockGetRequestHeader: vi.fn(),
}));
vi.mock('@tanstack/react-start/server', () => ({
  getRequestIP: mockGetRequestIP,
  getRequestHeader: mockGetRequestHeader,
}));

import { authServerClient } from './auth-server-client';

function mockFetch(status: number, body: unknown, contentType = 'application/json') {
  global.fetch = vi.fn().mockResolvedValue(
    new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: { 'content-type': contentType },
    })
  );
}

/**
 * An RFC 9457 problem document, as every auth-server route but the OAuth
 * protocol endpoints answers an error (#513). Fastify appends the charset.
 */
function mockProblem(status: number, code: string, extra: Record<string, unknown> = {}) {
  mockFetch(
    status,
    {
      type: `https://docs.qauth.dev/reference/problem-types/#${code.replaceAll('_', '-')}`,
      title: 'Problem title',
      status,
      detail: 'Problem detail',
      instance: '/some/path',
      code,
      trace_id: 'req-1',
      ...extra,
    },
    'application/problem+json; charset=utf-8'
  );
}

/** An OAuth error body (RFC 6749 §5.2), as userinfo answers an error. */
function mockOAuthError(status: number, error: string, description?: string) {
  mockFetch(status, { error, ...(description ? { error_description: description } : {}) });
}

/** An answer whose body is not JSON, as a proxy in front of the auth-server may send. */
function mockText(status: number, text: string) {
  global.fetch = vi
    .fn()
    .mockResolvedValue(new Response(text, { status, headers: { 'content-type': 'text/html' } }));
}

afterEach(() => {
  vi.restoreAllMocks();
});

// The portal calls the auth-server server-to-server: without forwarding the
// caller's address, every developer shares the portal's IP, and one caller can
// fill the per-IP limits and the ip: lockout for all of them. It forwards
// exactly one address, the client address srvx resolved for the request (the
// TCP peer unless PORTAL_TRUST_PROXY lists it; see trust-proxy.test.ts).
describe('client address forwarding (X-Forwarded-For)', () => {
  function sentHeaders(): Record<string, string> {
    const [, init] = (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    return (init.headers ?? {}) as Record<string, string>;
  }

  function receivedForwardedFor(value: string | undefined) {
    mockGetRequestHeader.mockImplementation((name: string) =>
      name.toLowerCase() === 'x-forwarded-for' ? value : undefined
    );
  }

  it('sends the TCP peer of the request being served', async () => {
    mockGetRequestIP.mockReturnValue('203.0.113.9');
    receivedForwardedFor(undefined);
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBe('203.0.113.9');
    // No option that would make h3 read the X-Forwarded-For header itself.
    expect(mockGetRequestIP).toHaveBeenCalledWith();
  });

  it('sends only the peer when the request carried its own X-Forwarded-For', async () => {
    mockGetRequestIP.mockReturnValue('198.51.100.20');
    receivedForwardedFor('203.0.113.9, 192.0.2.1');
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBe('198.51.100.20');
  });

  it('sends an IPv4-mapped peer in plain IPv4 form', async () => {
    mockGetRequestIP.mockReturnValue('::ffff:203.0.113.9');
    receivedForwardedFor(undefined);
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBe('203.0.113.9');
  });

  it('sends an IPv6 peer unchanged', async () => {
    mockGetRequestIP.mockReturnValue('2001:db8::7');
    receivedForwardedFor(undefined);
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBe('2001:db8::7');
  });

  it('sends no header when the request has no peer address', async () => {
    mockGetRequestIP.mockReturnValue(undefined);
    receivedForwardedFor('203.0.113.9');
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBeUndefined();
  });

  it.each(['not-an-ip', '203.0.113.9:5678', '::ffff:not-an-ip'])(
    'sends no header when the client address is not an IP address (%s)',
    async (client) => {
      mockGetRequestIP.mockReturnValue(client);
      receivedForwardedFor(undefined);
      mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

      await authServerClient.login('dev@example.com', 'pw');

      expect(sentHeaders()['X-Forwarded-For']).toBeUndefined();
    }
  );

  it('sends the peer on DELETE calls too', async () => {
    mockGetRequestIP.mockReturnValue('203.0.113.9');
    receivedForwardedFor('198.51.100.1');
    mockFetch(204, null);

    const result = await authServerClient.deleteClient('t', 'id');

    expect(result.ok).toBe(true);
    expect(sentHeaders()['X-Forwarded-For']).toBe('203.0.113.9');
    expect(sentHeaders()['Authorization']).toBe('Bearer t');
  });

  it('sends no header outside a request context', async () => {
    mockGetRequestIP.mockImplementation(() => {
      throw new Error('no request context');
    });
    mockFetch(200, { accessToken: 't', refreshToken: 'r', expiresIn: 900 });

    await authServerClient.login('dev@example.com', 'pw');

    expect(sentHeaders()['X-Forwarded-For']).toBeUndefined();
  });
});

describe('authServerClient.register', () => {
  it('returns ok result on 202 with the generic message', async () => {
    const data = {
      message: 'Registration received. Check your inbox for an email with the next step.',
    };
    mockFetch(202, data);
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toEqual(data);
  });

  it('returns WEAK_PASSWORD error', async () => {
    // The feedback arrives as `errors` under `/password`; the portal shows it
    // as the details of the field.
    mockProblem(422, 'weak_password', {
      errors: [
        { pointer: '/password', message: 'Too short' },
        { pointer: '/password', message: 'Add a symbol' },
      ],
    });
    const result = await authServerClient.register('test@example.com', 'pw');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('WEAK_PASSWORD');
      expect(result.error.status).toBe(422);
      expect(result.error.details).toEqual(['Too short', 'Add a symbol']);
    }
  });

  it('returns VALIDATION_ERROR with the message of each field error as details', async () => {
    mockProblem(400, 'validation_error', {
      errors: [{ pointer: '/email', message: 'Invalid email address' }],
    });
    const result = await authServerClient.register('not-an-address', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('VALIDATION_ERROR');
      expect(result.error.status).toBe(400);
      expect(result.error.details).toEqual(['Invalid email address']);
    }
  });

  it('maps a unique-constraint conflict to a generic CONFLICT, never EMAIL_TAKEN', async () => {
    // Registration no longer answers 409 (ANT-2026-SPEMY9GU); a conflict from
    // another route must not be read as "this address is registered".
    mockProblem(409, 'unique_constraint_violation');
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('CONFLICT');
      expect(result.error.status).toBe(409);
    }
  });

  it('returns RATE_LIMITED on 429', async () => {
    mockProblem(429, 'too_many_requests');
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('RATE_LIMITED');
  });

  it('returns NETWORK_ERROR when fetch throws', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('NETWORK_ERROR');
      expect(result.error.status).toBe(0);
    }
  });
});

describe('authServerClient.login', () => {
  it('returns ok result with tokens on 200', async () => {
    const data = {
      access_token: 'at',
      refresh_token: 'rt',
      expires_in: 900,
      token_type: 'Bearer',
    };
    mockFetch(200, data);
    const result = await authServerClient.login('test@example.com', 'Password1!');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.access_token).toBe('at');
      expect(result.data.token_type).toBe('Bearer');
    }
  });

  it('returns INVALID_CREDENTIALS on 401', async () => {
    mockProblem(401, 'invalid_credentials');
    const result = await authServerClient.login('bad@example.com', 'wrong');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('INVALID_CREDENTIALS');
      expect(result.error.status).toBe(401);
    }
  });

  it('classifies a code it does not know by the status', async () => {
    // The auth-server may add codes in a minor release (ADR-018 §5).
    mockProblem(401, 'some_future_code');
    const result = await authServerClient.login('bad@example.com', 'wrong');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNAUTHENTICATED');
      expect(result.error.status).toBe(401);
    }
  });

  it('returns NETWORK_ERROR when fetch throws', async () => {
    global.fetch = vi.fn().mockRejectedValue(new TypeError('fetch failed'));
    const result = await authServerClient.login('test@example.com', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('NETWORK_ERROR');
  });
});

describe('authServerClient.logout', () => {
  it('returns ok result on success', async () => {
    mockFetch(200, { success: true, message: 'Successfully logged out' });
    const result = await authServerClient.logout('valid-access-token');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.success).toBe(true);
  });

  it('returns UNKNOWN error on unexpected status', async () => {
    mockProblem(500, 'internal_error', { detail: undefined });
    const result = await authServerClient.logout('some-token');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNKNOWN');
      expect(result.error.status).toBe(500);
    }
  });

  it('maps a refused access token to UNAUTHENTICATED', async () => {
    mockProblem(401, 'jwt_invalid');
    const result = await authServerClient.logout('some-token');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
  });
});

describe('authServerClient.verifyEmail', () => {
  const validToken = 'a'.repeat(64);

  it('POSTs the token and password in a JSON body — never a GET with the token in the URL', async () => {
    mockFetch(200, { message: 'Email verified successfully', email: 'test@example.com' });
    await authServerClient.verifyEmail(validToken, 'registrant-pw');

    const [url, init] = (global.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url.endsWith('/auth/verify')).toBe(true);
    expect(url).not.toContain(validToken);
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({ token: validToken, password: 'registrant-pw' });
  });

  it('returns ok result on 200', async () => {
    mockFetch(200, { message: 'Email verified successfully', email: 'test@example.com' });
    const result = await authServerClient.verifyEmail(validToken, 'registrant-pw');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.email).toBe('test@example.com');
  });

  it('returns INVALID_TOKEN on 400 with code', async () => {
    mockProblem(400, 'invalid_token');
    const result = await authServerClient.verifyEmail(validToken, 'registrant-pw');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('INVALID_TOKEN');
      expect(result.error.status).toBe(400);
    }
  });

  it('returns INVALID_CREDENTIALS for a wrong password', async () => {
    mockProblem(401, 'invalid_credentials');
    const result = await authServerClient.verifyEmail(validToken, 'wrong-pw');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('returns EMAIL_ALREADY_VERIFIED on 409', async () => {
    mockProblem(409, 'email_already_verified');
    const result = await authServerClient.verifyEmail(validToken, 'registrant-pw');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('EMAIL_ALREADY_VERIFIED');
      expect(result.error.status).toBe(409);
    }
  });
});

describe('authServerClient.resendVerification', () => {
  it('returns ok result on 200', async () => {
    mockFetch(200, { message: 'If the email exists, a verification link has been sent.' });
    const result = await authServerClient.resendVerification('test@example.com');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.message).toBeTruthy();
  });

  it('returns RATE_LIMITED on 429', async () => {
    mockProblem(429, 'too_many_requests');
    const result = await authServerClient.resendVerification('test@example.com');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('RATE_LIMITED');
  });
});

describe('authServerClient.userinfo', () => {
  it('returns ok result with user claims', async () => {
    mockFetch(200, { sub: 'user-id', email: 'test@example.com', email_verified: true });
    const result = await authServerClient.userinfo('valid-access-token');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.sub).toBe('user-id');
      expect(result.data.email).toBe('test@example.com');
    }
  });

  // Userinfo is an OAuth protocol endpoint: it answers the RFC 6750 §3.1 body,
  // not a problem document. Its `invalid_token` is the ACCESS token.
  it('maps an OAuth invalid_token to UNAUTHENTICATED', async () => {
    mockOAuthError(401, 'invalid_token', 'The access token has expired');
    const result = await authServerClient.userinfo('expired-token');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNAUTHENTICATED');
      expect(result.error.status).toBe(401);
    }
  });

  it('maps an OAuth invalid_token without a description to UNAUTHENTICATED', async () => {
    mockOAuthError(401, 'invalid_token');
    const result = await authServerClient.userinfo('expired-token');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNAUTHENTICATED');
      expect(result.error.message).not.toBe('');
    }
  });

  it('classifies an OAuth error it does not map by the status', async () => {
    mockOAuthError(503, 'temporarily_unavailable');
    const result = await authServerClient.userinfo('valid-access-token');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNKNOWN');
      expect(result.error.status).toBe(503);
    }
  });
});

const sampleClient = {
  id: 'row-1',
  clientId: 'client-uuid',
  name: 'My App',
  description: null,
  redirectUris: ['https://app.example.com/cb'],
  scopes: ['openid'],
  grantTypes: ['authorization_code', 'refresh_token'],
  responseTypes: ['code'],
  tokenEndpointAuthMethod: 'client_secret_post',
  enabled: true,
  requirePkce: true,
  createdAt: 1_750_000_000_000,
  updatedAt: 1_750_000_000_000,
  lastUsedAt: null,
};

describe('authServerClient.listClients', () => {
  it('returns the clients array on 200', async () => {
    mockFetch(200, { clients: [sampleClient] });
    const result = await authServerClient.listClients('at');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.clients).toHaveLength(1);
  });

  it('maps 401 to UNAUTHENTICATED', async () => {
    mockProblem(401, 'jwt_invalid');
    const result = await authServerClient.listClients('bad');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNAUTHENTICATED');
      expect(result.error.status).toBe(401);
    }
  });

  it('maps an expired access token to UNAUTHENTICATED', async () => {
    mockProblem(401, 'jwt_expired');
    const result = await authServerClient.listClients('expired');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
  });

  it('classifies a body that is not JSON by the status', async () => {
    mockText(401, '<html>401 Authorization Required</html>');
    const result = await authServerClient.listClients('bad');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNAUTHENTICATED');
      expect(result.error.status).toBe(401);
    }
  });

  it('classifies a body that is not JSON and has no mapped status as UNKNOWN', async () => {
    mockText(502, '<html>502 Bad Gateway</html>');
    const result = await authServerClient.listClients('at');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('UNKNOWN');
      expect(result.error.status).toBe(502);
    }
  });
});

describe('authServerClient.getClient', () => {
  it('returns the client on 200', async () => {
    mockFetch(200, sampleClient);
    const result = await authServerClient.getClient('at', 'row-1');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.clientId).toBe('client-uuid');
  });

  it('maps 404 to NOT_FOUND (not owned / missing)', async () => {
    mockProblem(404, 'not_found');
    const result = await authServerClient.getClient('at', 'missing');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('NOT_FOUND');
  });
});

describe('authServerClient.createClient', () => {
  it('returns the client with a one-time secret on 201', async () => {
    mockFetch(201, { ...sampleClient, clientSecret: 'a'.repeat(64) });
    const result = await authServerClient.createClient('at', { name: 'My App' });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.clientSecret).toHaveLength(64);
  });

  it('maps a bad_request to VALIDATION_ERROR', async () => {
    mockProblem(400, 'bad_request');
    const result = await authServerClient.createClient('at', { name: 'x' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('VALIDATION_ERROR');
      expect(result.error.status).toBe(400);
    }
  });

  it.each(['validation_error', 'invalid_redirect_uri', 'invalid_client_metadata', 'invalid_scope'])(
    'maps %s to VALIDATION_ERROR',
    async (code) => {
      mockProblem(400, code);
      const result = await authServerClient.createClient('at', { name: 'x' });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.code).toBe('VALIDATION_ERROR');
    }
  );

  it('maps 429 to RATE_LIMITED', async () => {
    mockProblem(429, 'too_many_requests');
    const result = await authServerClient.createClient('at', { name: 'x' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('RATE_LIMITED');
  });
});

describe('authServerClient.updateClient', () => {
  it('returns the updated client on 200 (no secret)', async () => {
    mockFetch(200, { ...sampleClient, name: 'Renamed' });
    const result = await authServerClient.updateClient('at', 'row-1', { name: 'Renamed' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.name).toBe('Renamed');
      expect((result.data as { clientSecret?: string }).clientSecret).toBeUndefined();
    }
  });
});

describe('authServerClient.deleteClient', () => {
  it('returns ok with null data on 204 without parsing a body', async () => {
    const jsonSpy = vi.fn(() => Promise.reject(new Error('no body')));
    global.fetch = vi
      .fn()
      .mockResolvedValue({ ok: true, status: 204, json: jsonSpy } as unknown as Response);
    const result = await authServerClient.deleteClient('at', 'row-1');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data).toBeNull();
    expect(jsonSpy).not.toHaveBeenCalled();
  });

  it('maps 404 to NOT_FOUND', async () => {
    mockProblem(404, 'not_found');
    const result = await authServerClient.deleteClient('at', 'missing');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('NOT_FOUND');
      expect(result.error.status).toBe(404);
    }
  });

  it('maps a refused access token to UNAUTHENTICATED', async () => {
    mockProblem(401, 'jwt_invalid');
    const result = await authServerClient.deleteClient('expired', 'row-1');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
  });

  it('classifies a body that is not JSON by the status', async () => {
    mockText(429, 'Too Many Requests');
    const result = await authServerClient.deleteClient('at', 'row-1');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('RATE_LIMITED');
      expect(result.error.status).toBe(429);
    }
  });
});

describe('authServerClient.regenerateClientSecret', () => {
  it('returns the new one-time secret on 200', async () => {
    mockFetch(200, { ...sampleClient, clientSecret: 'b'.repeat(64) });
    const result = await authServerClient.regenerateClientSecret('at', 'row-1');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.clientSecret).toBe('b'.repeat(64));
  });

  it('maps a public-client 400 to VALIDATION_ERROR', async () => {
    mockProblem(400, 'bad_request');
    const result = await authServerClient.regenerateClientSecret('at', 'row-1');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('VALIDATION_ERROR');
  });
});

describe('authServerClient.createApiKey', () => {
  it('maps the environment gate (403 forbidden) to FORBIDDEN', async () => {
    // ADR-008 §6: static API keys are minted for development clients only.
    mockProblem(403, 'forbidden');
    const result = await authServerClient.createApiKey('at', 'client-uuid', { name: 'ci' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('FORBIDDEN');
      expect(result.error.status).toBe(403);
    }
  });
});
