import { createServerFn } from '@tanstack/react-start';
import { getRequestHeader } from '@tanstack/react-start/server';

import { authServerClient, type UserInfoData } from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';

export type CurrentUserResult = { user: UserInfoData } | null;

export async function currentUserHandler(): Promise<CurrentUserResult> {
  const cookieHeader = getRequestHeader('cookie');
  const session = readSessionCookie(cookieHeader);
  // Skip the network round-trip when we already know the access token is past
  // its issued lifetime. (Refresh-token rotation lives in Phase 2.x; for now
  // an expired session bounces the user to /login.)
  if (!session || Date.now() >= session.expiresAt) return null;

  const result = await authServerClient.userinfo(session.accessToken);
  if (!result.ok) return null;

  return { user: result.data };
}

export const currentUserFn = createServerFn({ method: 'GET' }).handler(currentUserHandler);
