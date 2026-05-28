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
