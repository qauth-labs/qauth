import { getRequestHeader, setResponseHeader } from '@tanstack/react-start/server';

import { authServerClient, type ConsentListData, type Result } from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';
import { UNAUTHENTICATED } from './consents';

/**
 * Server-only half of the consent screen (issue #366).
 *
 * The page this backs used to `fetch()` the auth-server straight from the
 * browser with `credentials: 'include'`, betting on a `__Host-qauth_session`
 * cookie a portal user never has — and which `SameSite=Lax` would not have sent
 * cross-origin anyway, behind a production CORS policy that refuses the request
 * outright. Routing it through a server function puts consents on the same
 * footing as every other portal feature: the developer's access token is read
 * from the signed, HttpOnly portal session here and never reaches the browser.
 */
function readAccessToken(): string | null {
  const session = readSessionCookie(getRequestHeader('cookie'));
  if (!session || Date.now() >= session.expiresAt) return null;
  return session.accessToken;
}

export async function listConsentsHandler(): Promise<Result<ConsentListData>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  // Which applications a developer has authorized is per-user data; keep it out
  // of any shared or proxy cache, matching the client-management handlers.
  setResponseHeader('Cache-Control', 'no-store');
  return authServerClient.listConsents(token);
}

export async function revokeConsentHandler({
  data,
}: {
  data: { id: string };
}): Promise<Result<null>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  setResponseHeader('Cache-Control', 'no-store');
  return authServerClient.revokeConsent(token, data.id);
}
