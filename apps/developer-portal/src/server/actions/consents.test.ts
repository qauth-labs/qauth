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
    listConsents: vi.fn(),
    revokeConsent: vi.fn(),
  },
}));

vi.mock('../session-cookie', () => ({
  SESSION_COOKIE_NAME: '__Host-qauth_portal_session',
  readSessionCookie: vi.fn(),
}));

const { mockGetRequestHeader, mockSetResponseHeader } = vi.hoisted(() => ({
  mockGetRequestHeader: vi.fn(),
  mockSetResponseHeader: vi.fn(),
}));

vi.mock('@tanstack/react-start/server', () => ({
  getRequestHeader: mockGetRequestHeader,
  setResponseHeader: mockSetResponseHeader,
}));

import { authServerClient } from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';
import { listConsentsHandler, revokeConsentHandler } from './consents.server';

const validSession = {
  accessToken: 'dev-token',
  refreshToken: 'rt',
  expiresAt: Date.now() + 60_000,
};
const expiredSession = { accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1000 };

const CONSENT = {
  id: '11111111-1111-4111-8111-111111111111',
  clientId: 'app-client-id',
  clientName: 'Some App',
  scopes: ['openid'],
  grantedAt: 1_700_000_000_000,
};

/**
 * The consent server functions (issue #366).
 *
 * The point of these handlers is that the developer's access token is read on
 * the SERVER, from the signed HttpOnly portal session, and attached to the
 * auth-server call there. The page they replaced tried to authenticate from the
 * browser with an auth-server session cookie a portal user never holds — so the
 * assertions below are mostly about which credential goes where.
 */
describe('consent server functions', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetRequestHeader.mockReturnValue('__Host-qauth_portal_session=signed-value');
  });

  it('lists consents with the PORTAL session token as a Bearer credential', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.listConsents).mockResolvedValue({
      ok: true,
      data: { consents: [CONSENT] },
    });

    const result = await listConsentsHandler();

    // The token came from the portal's own cookie, read server-side.
    expect(readSessionCookie).toHaveBeenCalledWith('__Host-qauth_portal_session=signed-value');
    expect(authServerClient.listConsents).toHaveBeenCalledWith('dev-token');
    expect(result).toEqual({ ok: true, data: { consents: [CONSENT] } });
  });

  it('marks the consent list uncacheable', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.listConsents).mockResolvedValue({
      ok: true,
      data: { consents: [] },
    });

    await listConsentsHandler();

    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });

  it('revokes through the auth-server with the same credential', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.revokeConsent).mockResolvedValue({ ok: true, data: null });

    const result = await revokeConsentHandler({ data: { id: CONSENT.id } });

    expect(authServerClient.revokeConsent).toHaveBeenCalledWith('dev-token', CONSENT.id);
    expect(result).toEqual({ ok: true, data: null });
  });

  it('answers UNAUTHENTICATED with no session, without calling the auth-server', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(null);

    const list = await listConsentsHandler();
    const revoke = await revokeConsentHandler({ data: { id: CONSENT.id } });

    expect(list.ok).toBe(false);
    expect(revoke.ok).toBe(false);
    expect(!list.ok && list.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.listConsents).not.toHaveBeenCalled();
    expect(authServerClient.revokeConsent).not.toHaveBeenCalled();
  });

  it('treats an expired session as unauthenticated rather than sending a stale token', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(expiredSession);

    const result = await listConsentsHandler();

    expect(result.ok).toBe(false);
    expect(authServerClient.listConsents).not.toHaveBeenCalled();
  });

  it('propagates an auth-server error instead of masking it as an empty list', async () => {
    // The old page rendered a failure as "no applications", which reads as
    // "you have revoked everything" — the most dangerous possible wrong answer
    // on a consent screen.
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.listConsents).mockResolvedValue({
      ok: false,
      error: { code: 'INTERNAL', message: 'boom', status: 500 },
    });

    const result = await listConsentsHandler();

    expect(result.ok).toBe(false);
    expect(!result.ok && result.error.status).toBe(500);
  });
});
