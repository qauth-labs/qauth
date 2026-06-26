import { getRequestHeader, setResponseHeader } from '@tanstack/react-start/server';

import {
  authServerClient,
  type ClientWithSecret,
  type CreateClientInput,
  type OAuthClient,
  type Result,
  type UpdateClientInput,
} from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';
import { UNAUTHENTICATED } from './clients';

/**
 * Read the developer's access token from the signed, HttpOnly session cookie.
 * The token never leaves the server — every `/api/clients` call is proxied
 * through these server functions with `Authorization: Bearer <token>`.
 */
function readAccessToken(): string | null {
  const session = readSessionCookie(getRequestHeader('cookie'));
  if (!session || Date.now() >= session.expiresAt) return null;
  return session.accessToken;
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export async function listClientsHandler(): Promise<Result<{ clients: OAuthClient[] }>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  // Client config is not secret, but it is per-developer; keep it out of any
  // shared/proxy cache for consistency with the secret-bearing responses.
  setResponseHeader('Cache-Control', 'no-store');
  return authServerClient.listClients(token);
}

// ---------------------------------------------------------------------------
// Get one
// ---------------------------------------------------------------------------

export async function getClientHandler({
  data,
}: {
  data: { id: string };
}): Promise<Result<OAuthClient>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  setResponseHeader('Cache-Control', 'no-store');
  return authServerClient.getClient(token, data.id);
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

export async function createClientHandler({
  data,
}: {
  data: CreateClientInput;
}): Promise<Result<ClientWithSecret>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  const result = await authServerClient.createClient(token, data);
  // Secret-bearing responses are no-store; the browser must never cache them.
  if (result.ok) setResponseHeader('Cache-Control', 'no-store');
  return result;
}

// ---------------------------------------------------------------------------
// Update (PATCH)
// ---------------------------------------------------------------------------

export async function updateClientHandler({
  data,
}: {
  data: { id: string; patch: UpdateClientInput };
}): Promise<Result<OAuthClient>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.updateClient(token, data.id, data.patch);
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

export async function deleteClientHandler({
  data,
}: {
  data: { id: string };
}): Promise<Result<null>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.deleteClient(token, data.id);
}

// ---------------------------------------------------------------------------
// Regenerate secret
// ---------------------------------------------------------------------------

export async function regenerateSecretHandler({
  data,
}: {
  data: { id: string };
}): Promise<Result<ClientWithSecret>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  const result = await authServerClient.regenerateClientSecret(token, data.id);
  if (result.ok) setResponseHeader('Cache-Control', 'no-store');
  return result;
}
