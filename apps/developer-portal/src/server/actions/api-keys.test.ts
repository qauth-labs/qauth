import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../config', () => ({
  env: {
    AUTH_SERVER_URL: 'http://localhost:3001',
    PORTAL_SESSION_SECRET: 'test-secret-minimum-32-chars-long!!',
    PORTAL_SESSION_TTL: 900,
  },
}));

vi.mock('../auth-server-client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth-server-client')>();
  return {
    ...actual,
    authServerClient: {
      listApiKeys: vi.fn(),
      createApiKey: vi.fn(),
      revokeApiKey: vi.fn(),
    },
  };
});

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
import { normalizeCreateApiKeyInput, normalizeRevokeInput } from './api-keys';
import { createApiKeyHandler, listApiKeysHandler, revokeApiKeyHandler } from './api-keys.server';

const validSession = {
  accessToken: 'dev-token',
  refreshToken: 'rt',
  expiresAt: Date.now() + 60_000,
};
const expiredSession = { accessToken: 'old', refreshToken: 'rt', expiresAt: Date.now() - 1000 };

beforeEach(() => {
  vi.clearAllMocks();
  mockGetRequestHeader.mockReturnValue('cookie-header');
});

describe('listApiKeysHandler', () => {
  it('returns UNAUTHENTICATED when the session is missing', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(null);
    const result = await listApiKeysHandler({ data: { clientId: 'c1' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.listApiKeys).not.toHaveBeenCalled();
  });

  it('returns UNAUTHENTICATED when the session has expired', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(expiredSession);
    const result = await listApiKeysHandler({ data: { clientId: 'c1' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
  });

  it('proxies the call with the access token and sets no-store', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(validSession);
    (authServerClient.listApiKeys as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: { apiKeys: [] },
    });
    const result = await listApiKeysHandler({ data: { clientId: 'c1' } });
    expect(authServerClient.listApiKeys).toHaveBeenCalledWith('dev-token', 'c1');
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(result.ok).toBe(true);
  });
});

describe('createApiKeyHandler', () => {
  it('returns UNAUTHENTICATED when the session is missing', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(null);
    const result = await createApiKeyHandler({
      data: { clientId: 'c1', input: { name: 'k' } },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.createApiKey).not.toHaveBeenCalled();
  });

  it('proxies create and sets no-store on the one-time key response', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(validSession);
    (authServerClient.createApiKey as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: { id: 'k1', key: 'qauth_x_y' },
    });
    const result = await createApiKeyHandler({
      data: { clientId: 'c1', input: { name: 'My key' } },
    });
    expect(authServerClient.createApiKey).toHaveBeenCalledWith('dev-token', 'c1', {
      name: 'My key',
    });
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(result.ok).toBe(true);
  });

  it('does NOT set no-store when create fails (e.g. FORBIDDEN)', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(validSession);
    (authServerClient.createApiKey as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: false,
      error: { code: 'FORBIDDEN', message: 'forbidden', status: 403 },
    });
    await createApiKeyHandler({ data: { clientId: 'c1', input: { name: 'My key' } } });
    expect(mockSetResponseHeader).not.toHaveBeenCalled();
  });
});

describe('revokeApiKeyHandler', () => {
  it('returns UNAUTHENTICATED when the session is missing', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(null);
    const result = await revokeApiKeyHandler({ data: { clientId: 'c1', keyId: 'k1' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.revokeApiKey).not.toHaveBeenCalled();
  });

  it('proxies revoke with the access token', async () => {
    (readSessionCookie as ReturnType<typeof vi.fn>).mockReturnValue(validSession);
    (authServerClient.revokeApiKey as ReturnType<typeof vi.fn>).mockResolvedValue({
      ok: true,
      data: { id: 'k1', revokedAt: 1800 },
    });
    const result = await revokeApiKeyHandler({ data: { clientId: 'c1', keyId: 'k1' } });
    expect(authServerClient.revokeApiKey).toHaveBeenCalledWith('dev-token', 'c1', 'k1');
    expect(result.ok).toBe(true);
  });
});

describe('input normalization', () => {
  it('trims the key name and rejects an empty one', () => {
    expect(normalizeCreateApiKeyInput({ clientId: 'c1', name: '  My key  ' })).toEqual({
      clientId: 'c1',
      input: { name: 'My key' },
    });
    expect(() => normalizeCreateApiKeyInput({ clientId: 'c1', name: '   ' })).toThrow();
    expect(() => normalizeCreateApiKeyInput({ clientId: 'c1' })).toThrow();
  });

  it('caps the key name length', () => {
    expect(() => normalizeCreateApiKeyInput({ clientId: 'c1', name: 'a'.repeat(256) })).toThrow();
  });

  it('validates revoke input', () => {
    expect(normalizeRevokeInput({ clientId: 'c1', keyId: 'k1' })).toEqual({
      clientId: 'c1',
      keyId: 'k1',
    });
    expect(() => normalizeRevokeInput({ clientId: 'c1' })).toThrow();
    expect(() => normalizeRevokeInput({ keyId: 'k1' })).toThrow();
  });
});
