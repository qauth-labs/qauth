import { createServerFn } from '@tanstack/react-start';
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
 * Server functions for the static developer API-key surface (ADR-008 §6,
 * issue #98 consuming the #97 backend). They mirror `actions/clients.ts`
 * exactly: the developer access token is read from the signed HttpOnly session
 * cookie server-side and never leaves the server — every `/api/clients/.../api-keys`
 * call is proxied with `Authorization: Bearer <token>`. The one-time plaintext
 * key (create) is returned to the browser once and is never persisted here.
 */

/**
 * Read the developer's access token from the signed, HttpOnly session cookie.
 * Identical to the helper in `actions/clients.ts`; kept local so this module is
 * self-contained.
 */
function readAccessToken(): string | null {
  const session = readSessionCookie(getRequestHeader('cookie'));
  if (!session || Date.now() >= session.expiresAt) return null;
  return session.accessToken;
}

/** Defense-in-depth cap mirroring the auth-server's `name` limit (1..255). */
const NAME_MAX = 255;

class InputError extends Error {}

function normalizeClientId(data: unknown): { clientId: string } {
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof (data as { clientId?: unknown }).clientId !== 'string'
  ) {
    throw new Error('Invalid input: expected { clientId: string }');
  }
  return { clientId: (data as { clientId: string }).clientId };
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

export const listApiKeysFn = createServerFn({ method: 'GET' })
  .inputValidator(normalizeClientId)
  .handler(listApiKeysHandler);

// ---------------------------------------------------------------------------
// Create (one-time plaintext key)
// ---------------------------------------------------------------------------

export function normalizeCreateApiKeyInput(data: unknown): {
  clientId: string;
  input: CreateApiKeyInput;
} {
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof (data as { clientId?: unknown }).clientId !== 'string'
  ) {
    throw new Error('Invalid input: expected { clientId: string, name: string }');
  }
  const d = data as Record<string, unknown>;
  if (typeof d['name'] !== 'string' || d['name'].trim().length === 0) {
    throw new InputError('Name is required.');
  }
  const name = d['name'].trim();
  if (name.length > NAME_MAX) {
    throw new InputError(`Name must be at most ${NAME_MAX} characters.`);
  }
  return { clientId: d['clientId'] as string, input: { name } };
}

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

export const createApiKeyFn = createServerFn({ method: 'POST' })
  .inputValidator(normalizeCreateApiKeyInput)
  .handler(createApiKeyHandler);

// ---------------------------------------------------------------------------
// Revoke (idempotent soft-delete)
// ---------------------------------------------------------------------------

export function normalizeRevokeInput(data: unknown): { clientId: string; keyId: string } {
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof (data as { clientId?: unknown }).clientId !== 'string' ||
    typeof (data as { keyId?: unknown }).keyId !== 'string'
  ) {
    throw new Error('Invalid input: expected { clientId: string, keyId: string }');
  }
  const d = data as { clientId: string; keyId: string };
  return { clientId: d.clientId, keyId: d.keyId };
}

export async function revokeApiKeyHandler({
  data,
}: {
  data: { clientId: string; keyId: string };
}): Promise<Result<ApiKey>> {
  const token = readAccessToken();
  if (!token) return UNAUTHENTICATED;
  return authServerClient.revokeApiKey(token, data.clientId, data.keyId);
}

export const revokeApiKeyFn = createServerFn({ method: 'POST' })
  .inputValidator(normalizeRevokeInput)
  .handler(revokeApiKeyHandler);
