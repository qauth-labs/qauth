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
    userinfo: vi.fn(),
  },
}));

vi.mock('../session-cookie', () => ({
  SESSION_COOKIE_NAME: '__Host-qauth_portal_session',
  readSessionCookie: vi.fn(),
  signSession: vi.fn(),
  verifySession: vi.fn(),
  setSessionCookieHeader: vi.fn(),
  clearSessionCookieHeader: vi.fn(),
}));

const { mockGetRequestHeader } = vi.hoisted(() => ({
  mockGetRequestHeader: vi.fn(),
}));

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mockGetRequestHeader,
  setResponseHeader: vi.fn(),
}));

import { authServerClient } from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';
import { currentUserHandler } from './current-user.server';

describe('currentUserHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  it('returns user data when session is valid and userinfo succeeds', async () => {
    const session = { accessToken: 'at', refreshToken: 'rt', expiresAt: Date.now() + 1000 };
    vi.mocked(readSessionCookie).mockReturnValue(session);
    vi.mocked(authServerClient.userinfo).mockResolvedValue({
      ok: true,
      data: { sub: 'user-id', email: 'test@example.com', email_verified: true },
    });
    mockGetRequestHeader.mockReturnValue('cookie-header-value');

    const result = await currentUserHandler();
    expect(result).not.toBeNull();
    expect(result?.user.sub).toBe('user-id');
    expect(result?.user.email).toBe('test@example.com');
  });

  it('returns null when no session cookie is present', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(null);
    mockGetRequestHeader.mockReturnValue(undefined);

    const result = await currentUserHandler();
    expect(result).toBeNull();
    expect(authServerClient.userinfo).not.toHaveBeenCalled();
  });

  it('returns null without hitting userinfo when expiresAt is in the past', async () => {
    const session = { accessToken: 'expired-at', refreshToken: 'rt', expiresAt: Date.now() - 1000 };
    vi.mocked(readSessionCookie).mockReturnValue(session);
    mockGetRequestHeader.mockReturnValue('some-cookie-header');

    const result = await currentUserHandler();
    expect(result).toBeNull();
    expect(authServerClient.userinfo).not.toHaveBeenCalled();
  });

  it('returns null when userinfo call fails for a non-expired session', async () => {
    const session = { accessToken: 'at', refreshToken: 'rt', expiresAt: Date.now() + 60_000 };
    vi.mocked(readSessionCookie).mockReturnValue(session);
    vi.mocked(authServerClient.userinfo).mockResolvedValue({
      ok: false,
      error: { code: 'UNKNOWN', message: 'Unauthorized', status: 401 },
    });
    mockGetRequestHeader.mockReturnValue('some-cookie-header');

    const result = await currentUserHandler();
    expect(result).toBeNull();
    expect(authServerClient.userinfo).toHaveBeenCalledOnce();
  });
});
