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
    register: vi.fn(),
  },
}));

import { authServerClient } from '../auth-server-client';
import { registerHandler } from './register';

describe('registerHandler', () => {
  it('returns the result from authServerClient.register on success', async () => {
    const data = {
      id: 'user-id',
      email: 'test@example.com',
      emailVerified: false,
      realmId: 'realm-id',
      createdAt: Date.now(),
      updatedAt: null,
    };
    vi.mocked(authServerClient.register).mockResolvedValue({ ok: true, data });

    const result = await registerHandler({
      data: { email: 'test@example.com', password: 'Password1!' },
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.email).toBe('test@example.com');
    expect(authServerClient.register).toHaveBeenCalledWith('test@example.com', 'Password1!');
  });

  it('propagates error result from authServerClient.register', async () => {
    vi.mocked(authServerClient.register).mockResolvedValue({
      ok: false,
      error: { code: 'WEAK_PASSWORD', message: 'Password too weak', status: 422 },
    });

    const result = await registerHandler({ data: { email: 'test@example.com', password: 'pw' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('WEAK_PASSWORD');
  });

  it('propagates EMAIL_TAKEN error', async () => {
    vi.mocked(authServerClient.register).mockResolvedValue({
      ok: false,
      error: { code: 'EMAIL_TAKEN', message: 'Email already in use', status: 409 },
    });

    const result = await registerHandler({
      data: { email: 'existing@example.com', password: 'Password1!' },
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('EMAIL_TAKEN');
  });
});
