import { createServerFn } from '@tanstack/react-start';
import { getRequestHeader, setResponseHeader } from '@tanstack/react-start/server';

import { authServerClient } from '../auth-server-client';
import { clearSessionCookieHeader, readSessionCookie } from '../session-cookie';

export async function logoutHandler(): Promise<{ ok: true }> {
  const cookieHeader = getRequestHeader('cookie');
  const session = readSessionCookie(cookieHeader);

  if (session) {
    await authServerClient.logout(session.accessToken);
  }

  setResponseHeader('set-cookie', clearSessionCookieHeader());

  return { ok: true };
}

export const logoutFn = createServerFn({ method: 'POST' }).handler(logoutHandler);
