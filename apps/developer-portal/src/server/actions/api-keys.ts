import { createServerFn } from '@tanstack/react-start';

import { type CreateApiKeyInput } from '../auth-server-client';
import { createApiKeyHandler, listApiKeysHandler, revokeApiKeyHandler } from './api-keys.server';

/**
 * Server functions for the static developer API-key surface (ADR-008 §6,
 * issue #98 consuming the #97 backend). They mirror `actions/clients.ts`
 * exactly: the developer access token is read from the signed HttpOnly session
 * cookie server-side and never leaves the server — every `/api/clients/.../api-keys`
 * call is proxied with `Authorization: Bearer <token>`. The one-time plaintext
 * key (create) is returned to the browser once and is never persisted here.
 */

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

export const listApiKeysFn = createServerFn({ method: 'GET' })
  .validator(normalizeClientId)
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

export const createApiKeyFn = createServerFn({ method: 'POST' })
  .validator(normalizeCreateApiKeyInput)
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

export const revokeApiKeyFn = createServerFn({ method: 'POST' })
  .validator(normalizeRevokeInput)
  .handler(revokeApiKeyHandler);
