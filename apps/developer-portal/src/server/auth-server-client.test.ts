import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://auth-server:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

import { authServerClient } from './auth-server-client';

function mockFetch(status: number, body: unknown, ok = status >= 200 && status < 300) {
  global.fetch = vi.fn().mockResolvedValue({
    ok,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('authServerClient.register', () => {
  it('returns ok result on 201', async () => {
    const data = {
      id: 'user-id',
      email: 'test@example.com',
      emailVerified: false,
      realmId: 'realm-id',
      createdAt: Date.now(),
      updatedAt: null,
    };
    mockFetch(201, data);
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.email).toBe('test@example.com');
  });

  it('returns WEAK_PASSWORD error', async () => {
    mockFetch(
      422,
      { error: 'Weak password', statusCode: 422, code: 'WEAK_PASSWORD', feedback: ['Too short'] },
      false
    );
    const result = await authServerClient.register('test@example.com', 'pw');
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe('WEAK_PASSWORD');
      expect(result.error.details).toEqual(['Too short']);
    }
  });

  it('returns EMAIL_TAKEN error when unique constraint is violated', async () => {
    mockFetch(
      409,
      {
        error: 'Duplicate',
        statusCode: 409,
        code: 'UNIQUE_CONSTRAINT_VIOLATION',
        constraint: 'users_email_unique',
      },
      false
    );
    const result = await authServerClient.register('test@example.com', 'Password1!');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('EMAIL_TAKEN');
  });

  it('returns RATE_LIMITED on 429', async () => {
    mockFetch(429, { error: 'Too many requests', statusCode: 429 }, false);
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
    mockFetch(
      401,
      { error: 'Invalid email or password', statusCode: 401, code: 'INVALID_CREDENTIALS' },
      false
    );
    const result = await authServerClient.login('bad@example.com', 'wrong');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('INVALID_CREDENTIALS');
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
    mockFetch(500, { error: 'Internal server error', statusCode: 500 }, false);
    const result = await authServerClient.logout('some-token');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNKNOWN');
  });
});

describe('authServerClient.verifyEmail', () => {
  const validToken = 'a'.repeat(64);

  it('returns ok result on 200', async () => {
    mockFetch(200, { message: 'Email verified successfully', email: 'test@example.com' });
    const result = await authServerClient.verifyEmail(validToken);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.email).toBe('test@example.com');
  });

  it('returns INVALID_TOKEN on 400 with code', async () => {
    mockFetch(
      400,
      { error: 'Invalid or expired token', statusCode: 400, code: 'INVALID_TOKEN' },
      false
    );
    const result = await authServerClient.verifyEmail(validToken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('returns EMAIL_ALREADY_VERIFIED on 409', async () => {
    mockFetch(
      409,
      { error: 'Email already verified', statusCode: 409, code: 'EMAIL_ALREADY_VERIFIED' },
      false
    );
    const result = await authServerClient.verifyEmail(validToken);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('EMAIL_ALREADY_VERIFIED');
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
    mockFetch(429, { error: 'Rate limit exceeded', statusCode: 429 }, false);
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

  it('returns UNKNOWN error on 401', async () => {
    mockFetch(401, { error: 'Unauthorized', statusCode: 401 }, false);
    const result = await authServerClient.userinfo('expired-token');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.status).toBe(401);
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
    mockFetch(401, { error: 'Unauthorized', statusCode: 401 }, false);
    const result = await authServerClient.listClients('bad');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
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
    mockFetch(404, { error: 'Not found', statusCode: 404 }, false);
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

  it('maps a 400 without a code to VALIDATION_ERROR', async () => {
    mockFetch(400, { error: 'Invalid redirect URI', statusCode: 400 }, false);
    const result = await authServerClient.createClient('at', { name: 'x' });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('VALIDATION_ERROR');
  });

  it('maps 429 to RATE_LIMITED', async () => {
    mockFetch(429, { error: 'Too many requests', statusCode: 429 }, false);
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
    mockFetch(404, { error: 'Not found', statusCode: 404 }, false);
    const result = await authServerClient.deleteClient('at', 'missing');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('NOT_FOUND');
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
    mockFetch(400, { error: 'Public client has no secret', statusCode: 400 }, false);
    const result = await authServerClient.regenerateClientSecret('at', 'row-1');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('VALIDATION_ERROR');
  });
});
