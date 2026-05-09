import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://localhost:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

vi.mock('../auth-server-client', () => ({
  authServerClient: {
    logout: vi.fn(),
  },
}));

vi.mock('../session-cookie', () => ({
  SESSION_COOKIE_NAME: '__Host-qauth_portal_session',
  readSessionCookie: vi.fn(),
  clearSessionCookieHeader: vi.fn(
    () => '__Host-qauth_portal_session=; Path=/; HttpOnly; Max-Age=0'
  ),
  signSession: vi.fn(),
  setSessionCookieHeader: vi.fn(),
  verifySession: vi.fn(),
}));

const { mockSetResponseHeader, mockGetRequestHeader } = vi.hoisted(() => ({
  mockSetResponseHeader: vi.fn(),
  mockGetRequestHeader: vi.fn(),
}));

vi.mock('@tanstack/react-start/server', () => ({
  setResponseHeader: mockSetResponseHeader,
  getRequestHeader: mockGetRequestHeader,
}));

import { authServerClient } from '../auth-server-client';
import { clearSessionCookieHeader, readSessionCookie } from '../session-cookie';
import { logoutHandler } from './logout';

describe('logoutHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  it('calls auth-server logout and clears the cookie when session exists', async () => {
    const session = { accessToken: 'at', refreshToken: 'rt', expiresAt: Date.now() + 1000 };
    vi.mocked(readSessionCookie).mockReturnValue(session);
    vi.mocked(authServerClient.logout).mockResolvedValue({
      ok: true,
      data: { success: true, message: 'Successfully logged out' },
    });
    mockGetRequestHeader.mockReturnValue('__Host-qauth_portal_session=signed-value');

    const result = await logoutHandler();

    expect(authServerClient.logout).toHaveBeenCalledWith('at');
    expect(clearSessionCookieHeader).toHaveBeenCalled();
    expect(mockSetResponseHeader).toHaveBeenCalledWith('set-cookie', expect.any(String));
    expect(result.ok).toBe(true);
  });

  it('still clears the cookie when no session cookie is present', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(null);
    mockGetRequestHeader.mockReturnValue(undefined);
    mockSetResponseHeader.mockClear();

    const result = await logoutHandler();

    expect(authServerClient.logout).not.toHaveBeenCalled();
    expect(mockSetResponseHeader).toHaveBeenCalledWith('set-cookie', expect.any(String));
    expect(result.ok).toBe(true);
  });
});
