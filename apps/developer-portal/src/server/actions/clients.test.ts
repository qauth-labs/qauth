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
