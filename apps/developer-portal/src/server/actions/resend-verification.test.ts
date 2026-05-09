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
    resendVerification: vi.fn(),
  },
}));

import { authServerClient } from '../auth-server-client';
import { resendVerificationHandler } from './resend-verification';

describe('resendVerificationHandler', () => {
  it('returns ok result on success', async () => {
    vi.mocked(authServerClient.resendVerification).mockResolvedValue({
      ok: true,
      data: { message: 'If the email exists, a verification link has been sent.' },
    });

    const result = await resendVerificationHandler({ data: { email: 'test@example.com' } });
    expect(result.ok).toBe(true);
    expect(authServerClient.resendVerification).toHaveBeenCalledWith('test@example.com');
  });

  it('propagates RATE_LIMITED error', async () => {
    vi.mocked(authServerClient.resendVerification).mockResolvedValue({
      ok: false,
      error: { code: 'RATE_LIMITED', message: 'Too many requests', status: 429 },
    });

    const result = await resendVerificationHandler({ data: { email: 'test@example.com' } });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe('RATE_LIMITED');
  });
});
