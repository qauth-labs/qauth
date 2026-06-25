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
    listClients: vi.fn(),
    getClient: vi.fn(),
    createClient: vi.fn(),
    updateClient: vi.fn(),
    deleteClient: vi.fn(),
    regenerateClientSecret: vi.fn(),
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
import {
  createClientHandler,
  deleteClientHandler,
  getClientHandler,
  listClientsHandler,
  normalizeCreateInput,
  normalizeUpdateInput,
  regenerateSecretHandler,
  updateClientHandler,
} from './clients';

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

describe('listClientsHandler', () => {
  it('forwards the bearer token from the session cookie', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.listClients).mockResolvedValue({ ok: true, data: { clients: [] } });

    const result = await listClientsHandler();
    expect(result.ok).toBe(true);
    expect(authServerClient.listClients).toHaveBeenCalledWith('dev-token');
  });

  it('returns UNAUTHENTICATED without a network call when no session exists', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(null);

    const result = await listClientsHandler();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.listClients).not.toHaveBeenCalled();
  });

  it('returns UNAUTHENTICATED when the session is past its expiry', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(expiredSession);

    const result = await listClientsHandler();
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.listClients).not.toHaveBeenCalled();
  });
});

describe('getClientHandler', () => {
  it('passes the id through to the client', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.getClient).mockResolvedValue({
      ok: false,
      error: { code: 'NOT_FOUND', message: 'x', status: 404 },
    });

    const result = await getClientHandler({ data: { id: 'row-1' } });
    expect(authServerClient.getClient).toHaveBeenCalledWith('dev-token', 'row-1');
    expect(result.ok).toBe(false);
  });
});

describe('createClientHandler', () => {
  it('sets Cache-Control: no-store on a successful (secret-bearing) response', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.createClient).mockResolvedValue({
      ok: true,
      data: { clientId: 'c', clientSecret: 's' } as never,
    });

    const result = await createClientHandler({ data: { name: 'My App' } });
    expect(result.ok).toBe(true);
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });

  it('does not set no-store on a failed create', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.createClient).mockResolvedValue({
      ok: false,
      error: { code: 'VALIDATION_ERROR', message: 'bad', status: 400 },
    });

    await createClientHandler({ data: { name: 'x' } });
    expect(mockSetResponseHeader).not.toHaveBeenCalled();
  });
});

describe('updateClientHandler', () => {
  it('forwards id and patch', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.updateClient).mockResolvedValue({
      ok: true,
      data: { name: 'New' } as never,
    });

    await updateClientHandler({ data: { id: 'row-1', patch: { name: 'New' } } });
    expect(authServerClient.updateClient).toHaveBeenCalledWith('dev-token', 'row-1', {
      name: 'New',
    });
  });
});

describe('deleteClientHandler', () => {
  it('returns ok on a successful delete', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.deleteClient).mockResolvedValue({ ok: true, data: null });

    const result = await deleteClientHandler({ data: { id: 'row-1' } });
    expect(result.ok).toBe(true);
    expect(authServerClient.deleteClient).toHaveBeenCalledWith('dev-token', 'row-1');
  });

  it('returns UNAUTHENTICATED when not logged in', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(null);
    const result = await deleteClientHandler({ data: { id: 'row-1' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.deleteClient).not.toHaveBeenCalled();
  });
});

describe('regenerateSecretHandler', () => {
  it('sets no-store on the new-secret response', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.regenerateClientSecret).mockResolvedValue({
      ok: true,
      data: { clientId: 'c', clientSecret: 'new' } as never,
    });

    const result = await regenerateSecretHandler({ data: { id: 'row-1' } });
    expect(result.ok).toBe(true);
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });
});

describe('GET handlers set no-store', () => {
  it('listClientsHandler marks the list non-cacheable', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.listClients).mockResolvedValue({ ok: true, data: { clients: [] } });
    await listClientsHandler();
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });

  it('getClientHandler marks the response non-cacheable', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(validSession);
    vi.mocked(authServerClient.getClient).mockResolvedValue({ ok: true, data: {} as never });
    await getClientHandler({ data: { id: 'row-1' } });
    expect(mockSetResponseHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
  });
});

describe('expired-session short-circuit applies to mutations too', () => {
  it('updateClientHandler returns UNAUTHENTICATED without a network call', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(expiredSession);
    const result = await updateClientHandler({ data: { id: 'row-1', patch: { name: 'x' } } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.updateClient).not.toHaveBeenCalled();
  });

  it('regenerateSecretHandler returns UNAUTHENTICATED without a network call', async () => {
    vi.mocked(readSessionCookie).mockReturnValue(expiredSession);
    const result = await regenerateSecretHandler({ data: { id: 'row-1' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('UNAUTHENTICATED');
    expect(authServerClient.regenerateClientSecret).not.toHaveBeenCalled();
  });
});

describe('normalizeCreateInput — input caps & enum validation', () => {
  it('accepts a minimal valid payload', () => {
    expect(normalizeCreateInput({ name: '  My App  ' })).toEqual({ name: 'My App' });
  });

  it('rejects a missing/blank name', () => {
    expect(() => normalizeCreateInput({ name: '   ' })).toThrow(/name is required/i);
  });

  it('rejects an over-length name', () => {
    expect(() => normalizeCreateInput({ name: 'a'.repeat(256) })).toThrow(/at most 255/i);
  });

  it('rejects an over-length description', () => {
    expect(() => normalizeCreateInput({ name: 'ok', description: 'd'.repeat(2001) })).toThrow(
      /at most 2000/i
    );
  });

  it('rejects too many redirect URIs', () => {
    const redirectUris = Array.from({ length: 51 }, (_, i) => `https://app.example.com/cb${i}`);
    expect(() => normalizeCreateInput({ name: 'ok', redirectUris })).toThrow(/at most 50 entries/i);
  });

  it('rejects an over-length redirect URI', () => {
    expect(() =>
      normalizeCreateInput({ name: 'ok', redirectUris: [`https://x/${'a'.repeat(2001)}`] })
    ).toThrow(/at most 2000 characters/i);
  });

  it('rejects too many scopes', () => {
    const scopes = Array.from({ length: 101 }, (_, i) => `scope${i}`);
    expect(() => normalizeCreateInput({ name: 'ok', scopes })).toThrow(/at most 100 entries/i);
  });

  it('surfaces an unknown grant type instead of silently dropping it', () => {
    expect(() =>
      normalizeCreateInput({ name: 'ok', grantTypes: ['authorization_code', 'password'] })
    ).toThrow(/unknown grant type/i);
  });

  it('surfaces an unknown token endpoint auth method', () => {
    expect(() => normalizeCreateInput({ name: 'ok', tokenEndpointAuthMethod: 'magic' })).toThrow(
      /unknown token endpoint auth method/i
    );
  });
});

describe('normalizeUpdateInput — input caps & enum validation', () => {
  it('rejects an over-length name', () => {
    expect(() => normalizeUpdateInput({ id: 'row-1', name: 'a'.repeat(256) })).toThrow(
      /at most 255/i
    );
  });

  it('clears the description when an empty string is given', () => {
    expect(normalizeUpdateInput({ id: 'row-1', description: '' })).toEqual({
      id: 'row-1',
      patch: { description: null },
    });
  });

  it('surfaces an unknown grant type', () => {
    expect(() => normalizeUpdateInput({ id: 'row-1', grantTypes: ['nope'] })).toThrow(
      /unknown grant type/i
    );
  });
});
