import { getRequestHeader, setResponseHeader } from '@tanstack/react-start/server';

import {
  type ApiKey,
  type ApiKeyListData,
  type ApiKeyWithSecret,
  authServerClient,
  type CreateApiKeyInput,
  type Result,
} from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';
import { UNAUTHENTICATED } from './clients';

/**
 * Read the developer's access token from the signed, HttpOnly session cookie.
 * Identical to the helper in `actions/clients.server.ts`; kept local so this
 * module is self-contained.
 */
function readAccessToken(): string | null {
  const session = readSessionCookie(getRequestHeader('cookie'));
  if (!session || Date.now() >= session.expiresAt) return null;
  return session.accessToken;
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export async function listApiKeysHandler({
  data,
}: {
  data: { clientId: string };
}): Promise<Result<ApiKeyListData>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  // Masked, per-developer data — keep it out of any shared/proxy cache for
  // consistency with the rest of the client-management surface.
  setResponseHeader('Cache-Control', 'no-store');
  return authServerClient.listApiKeys(token, data.clientId);
}

// ---------------------------------------------------------------------------
// Create (one-time plaintext key)
// ---------------------------------------------------------------------------

export async function createApiKeyHandler({
  data,
}: {
  data: { clientId: string; input: CreateApiKeyInput };
}): Promise<Result<ApiKeyWithSecret>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  const result = await authServerClient.createApiKey(token, data.clientId, data.input);
  // The plaintext key is carried once — the browser must never cache it.
  if (result.ok) setResponseHeader('Cache-Control', 'no-store');
  return result;
}

// ---------------------------------------------------------------------------
// Revoke (idempotent soft-delete)
// ---------------------------------------------------------------------------

export async function revokeApiKeyHandler({
  data,
}: {
  data: { clientId: string; keyId: string };
}): Promise<Result<ApiKey>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.revokeApiKey(token, data.clientId, data.keyId);
}
