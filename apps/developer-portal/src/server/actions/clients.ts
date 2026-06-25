import { createServerFn } from '@tanstack/react-start';
import { getRequestHeader, setResponseHeader } from '@tanstack/react-start/server';

import {
  authServerClient,
  type ClientWithSecret,
  type CreateClientInput,
  type GrantType,
  type OAuthClient,
  type Result,
  type TokenEndpointAuthMethod,
  type UpdateClientInput,
} from '../auth-server-client';
import { readSessionCookie } from '../session-cookie';

/**
 * Result returned to the browser when the portal session is missing or
 * expired. The route components map this onto a re-authentication prompt.
 * Mirrors the auth-server's `401` semantics without making a network call.
 */
export const UNAUTHENTICATED: Result<never> = {
  ok: false,
  error: {
    code: 'UNAUTHENTICATED',
    message: 'Your session has expired. Please log in again.',
    status: 401,
  },
};

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

const VALID_GRANT_TYPES: GrantType[] = [
  'authorization_code',
  'refresh_token',
  'client_credentials',
];
const VALID_AUTH_METHODS: TokenEndpointAuthMethod[] = [
  'none',
  'client_secret_post',
  'client_secret_basic',
  'private_key_jwt',
];

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === 'string');
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export async function listClientsHandler(): Promise<Result<{ clients: OAuthClient[] }>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.listClients(token);
}

export const listClientsFn = createServerFn({ method: 'GET' }).handler(listClientsHandler);

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
  return authServerClient.getClient(token, data.id);
}

export const getClientFn = createServerFn({ method: 'GET' })
  .inputValidator((data: unknown): { id: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as { id?: unknown }).id !== 'string'
    ) {
      throw new Error('Invalid input: expected { id: string }');
    }
    return { id: (data as { id: string }).id };
  })
  .handler(getClientHandler);

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

function normalizeCreateInput(data: unknown): CreateClientInput {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid input: expected an object');
  }
  const d = data as Record<string, unknown>;
  if (typeof d['name'] !== 'string' || d['name'].trim().length === 0) {
    throw new Error('Invalid input: name is required');
  }
  const input: CreateClientInput = { name: d['name'].trim() };
  if (typeof d['description'] === 'string' && d['description'].trim().length > 0) {
    input.description = d['description'].trim();
  }
  if (d['redirectUris'] !== undefined) input.redirectUris = asStringArray(d['redirectUris']);
  if (d['scopes'] !== undefined) input.scopes = asStringArray(d['scopes']);
  if (d['grantTypes'] !== undefined) {
    input.grantTypes = asStringArray(d['grantTypes']).filter((g): g is GrantType =>
      VALID_GRANT_TYPES.includes(g as GrantType)
    );
  }
  if (typeof d['tokenEndpointAuthMethod'] === 'string') {
    const m = d['tokenEndpointAuthMethod'] as TokenEndpointAuthMethod;
    if (VALID_AUTH_METHODS.includes(m)) input.tokenEndpointAuthMethod = m;
  }
  return input;
}

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

export const createClientFn = createServerFn({ method: 'POST' })
  .inputValidator(normalizeCreateInput)
  .handler(createClientHandler);

// ---------------------------------------------------------------------------
// Update (PATCH)
// ---------------------------------------------------------------------------

function normalizeUpdateInput(data: unknown): { id: string; patch: UpdateClientInput } {
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof (data as { id?: unknown }).id !== 'string'
  ) {
    throw new Error('Invalid input: expected { id: string, ... }');
  }
  const d = data as Record<string, unknown>;
  const patch: UpdateClientInput = {};
  if (typeof d['name'] === 'string') patch.name = d['name'].trim();
  if (d['description'] !== undefined) {
    patch.description =
      typeof d['description'] === 'string' && d['description'].trim().length > 0
        ? d['description'].trim()
        : null;
  }
  if (d['redirectUris'] !== undefined) patch.redirectUris = asStringArray(d['redirectUris']);
  if (d['scopes'] !== undefined) patch.scopes = asStringArray(d['scopes']);
  if (d['grantTypes'] !== undefined) {
    patch.grantTypes = asStringArray(d['grantTypes']).filter((g): g is GrantType =>
      VALID_GRANT_TYPES.includes(g as GrantType)
    );
  }
  if (typeof d['tokenEndpointAuthMethod'] === 'string') {
    const m = d['tokenEndpointAuthMethod'] as TokenEndpointAuthMethod;
    if (VALID_AUTH_METHODS.includes(m)) patch.tokenEndpointAuthMethod = m;
  }
  if (typeof d['enabled'] === 'boolean') patch.enabled = d['enabled'];
  return { id: d['id'] as string, patch };
}

export async function updateClientHandler({
  data,
}: {
  data: { id: string; patch: UpdateClientInput };
}): Promise<Result<OAuthClient>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.updateClient(token, data.id, data.patch);
}

export const updateClientFn = createServerFn({ method: 'POST' })
  .inputValidator(normalizeUpdateInput)
  .handler(updateClientHandler);

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

export const deleteClientFn = createServerFn({ method: 'POST' })
  .inputValidator((data: unknown): { id: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as { id?: unknown }).id !== 'string'
    ) {
      throw new Error('Invalid input: expected { id: string }');
    }
    return { id: (data as { id: string }).id };
  })
  .handler(deleteClientHandler);

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

export const regenerateSecretFn = createServerFn({ method: 'POST' })
  .inputValidator((data: unknown): { id: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as { id?: unknown }).id !== 'string'
    ) {
      throw new Error('Invalid input: expected { id: string }');
    }
    return { id: (data as { id: string }).id };
  })
  .handler(regenerateSecretHandler);
