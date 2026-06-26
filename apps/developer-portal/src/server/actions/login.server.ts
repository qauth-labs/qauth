import { setResponseHeader } from '@tanstack/react-start/server';

import { authServerClient, type Result } from '../auth-server-client';
import { setSessionCookieHeader } from '../session-cookie';

export type LoginResult = Result<{ expiresAt: number }>;

export async function loginHandler({
  data,
}: {
  data: { email: string; password: string };
}): Promise<LoginResult> {
  const result = await authServerClient.login(data.email, data.password);
  if (!result.ok) return result;

  const expiresAt = Date.now() + result.data.expires_in * 1000;

  setResponseHeader(
    'set-cookie',
    setSessionCookieHeader({
      accessToken: result.data.access_token,
      refreshToken: result.data.refresh_token,
      expiresAt,
    })
  );

  return { ok: true, data: { expiresAt } };
}
