import { createServerFn } from '@tanstack/react-start';
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

export const loginFn = createServerFn({ method: 'POST' })
  .inputValidator((data: unknown): { email: string; password: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as Record<string, unknown>).email !== 'string' ||
      typeof (data as Record<string, unknown>).password !== 'string'
    ) {
      throw new Error('Invalid input: expected { email: string; password: string }');
    }
    const { email, password } = data as { email: string; password: string };
    return { email, password };
  })
  .handler(loginHandler);
