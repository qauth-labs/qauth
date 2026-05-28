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
    verifyEmail: vi.fn(),
  },
}));

import { authServerClient } from '../auth-server-client';
import { verifyHandler } from './verify';

const validToken = 'a'.repeat(64);

describe('verifyHandler', () => {
  it('returns ok result on successful verification', async () => {
    vi.mocked(authServerClient.verifyEmail).mockResolvedValue({
      ok: true,
      data: { message: 'Email verified successfully', email: 'test@example.com' },
    });

    const result = await verifyHandler({ data: { token: validToken } });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.data.email).toBe('test@example.com');
    expect(authServerClient.verifyEmail).toHaveBeenCalledWith(validToken);
  });

  it('propagates INVALID_TOKEN error', async () => {
    vi.mocked(authServerClient.verifyEmail).mockResolvedValue({
      ok: false,
      error: { code: 'INVALID_TOKEN', message: 'Invalid or expired token', status: 400 },
    });

    const result = await verifyHandler({ data: { token: validToken } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('INVALID_TOKEN');
  });

  it('propagates EMAIL_ALREADY_VERIFIED error', async () => {
    vi.mocked(authServerClient.verifyEmail).mockResolvedValue({
      ok: false,
      error: { code: 'EMAIL_ALREADY_VERIFIED', message: 'Email already verified', status: 409 },
    });

    const result = await verifyHandler({ data: { token: validToken } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('EMAIL_ALREADY_VERIFIED');
  });
});
