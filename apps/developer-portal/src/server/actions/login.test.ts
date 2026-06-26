import { describe, expect, it, vi } from 'vitest';

vi.mock('../config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://localhost:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

vi.mock('../auth-server-client', () => ({
  authServerClient: {
    login: vi.fn(),
  },
}));

vi.mock('../session-cookie', () => ({
  SESSION_COOKIE_NAME: '__Host-qauth_portal_session',
  signSession: vi.fn((payload: unknown) => `signed:${JSON.stringify(payload)}`),
  setSessionCookieHeader: vi.fn(() => '__Host-qauth_portal_session=signed-value; Path=/; HttpOnly'),
  readSessionCookie: vi.fn(),
  clearSessionCookieHeader: vi.fn(),
  verifySession: vi.fn(),
}));

const { mockSetResponseHeader } = vi.hoisted(() => ({
  mockSetResponseHeader: vi.fn(),
}));

vi.mock('@tanstack/react-start/server', () => ({
  setResponseHeader: mockSetResponseHeader,
  getRequestHeader: vi.fn(),
}));

import { authServerClient } from '../auth-server-client';
import { setSessionCookieHeader } from '../session-cookie';
import { loginHandler } from './login.server';

describe('loginHandler', () => {
  it('sets session cookie and returns expiresAt on success', async () => {
    vi.mocked(authServerClient.login).mockResolvedValue({
      ok: true,
      data: {
        access_token: 'at-value',
        refresh_token: 'rt-value',
        expires_in: 900,
        token_type: 'Bearer',
      },
    });

    const before = Date.now();
    const result = await loginHandler({
      data: { email: 'test@example.com', password: 'Password1!' },
    });
    const after = Date.now();

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.expiresAt).toBeGreaterThanOrEqual(before + 900_000);
      expect(result.data.expiresAt).toBeLessThanOrEqual(after + 900_000);
    }

    expect(setSessionCookieHeader).toHaveBeenCalledWith(
      expect.objectContaining({ accessToken: 'at-value', refreshToken: 'rt-value' })
    );
    expect(mockSetResponseHeader).toHaveBeenCalledWith('set-cookie', expect.any(String));
  });

  it('does not set cookie and returns error on login failure', async () => {
    vi.mocked(authServerClient.login).mockResolvedValue({
      ok: false,
      error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password', status: 401 },
    });
    mockSetResponseHeader.mockClear();

    const result = await loginHandler({ data: { email: 'bad@example.com', password: 'wrong' } });

    expect(result.ok).toBe(false);
    expect(mockSetResponseHeader).not.toHaveBeenCalled();
  });

  it('preserves the error code from the client', async () => {
    vi.mocked(authServerClient.login).mockResolvedValue({
      ok: false,
      error: { code: 'RATE_LIMITED', message: 'Too many requests', status: 429 },
    });

    const result = await loginHandler({
      data: { email: 'test@example.com', password: 'Password1!' },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('RATE_LIMITED');
  });
});
