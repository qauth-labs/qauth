import { createServerFn } from '@tanstack/react-start';

import {
  type CreateClientInput,
  type GrantType,
  type Result,
  type TokenEndpointAuthMethod,
  type UpdateClientInput,
} from '../auth-server-client';
import {
  createClientHandler,
  deleteClientHandler,
  getClientHandler,
  listClientsHandler,
  regenerateSecretHandler,
  updateClientHandler,
} from './clients.server';

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

/**
 * Defense-in-depth input caps. The auth-server is authoritative, but these
 * keep the portal from proxying an unbounded payload (e.g. a megabyte of
 * redirect URIs) before the upstream rejects it. Values are generous — they
 * only fence off abuse, not legitimate use.
 */
const LIMITS = {
  NAME_MAX: 255,
  DESCRIPTION_MAX: 2000,
  REDIRECT_URIS_MAX: 50,
  REDIRECT_URI_MAX: 2000,
  SCOPES_MAX: 100,
  SCOPE_MAX: 255,
} as const;

class InputError extends Error {}

function checkLength(field: string, value: string, max: number): void {
  if (value.length > max) {
    throw new InputError(`${field} must be at most ${max} characters.`);
  }
}

function checkArray(field: string, arr: string[], maxItems: number, itemMax: number): void {
  if (arr.length > maxItems) {
    throw new InputError(`${field} must have at most ${maxItems} entries.`);
  }
  for (const item of arr) {
    if (item.length > itemMax) {
      throw new InputError(`Each ${field} entry must be at most ${itemMax} characters.`);
    }
  }
}

/**
 * Validate `grantTypes` strictly: unknown values are reported rather than
 * silently dropped, so a malformed selection surfaces as an error instead of
 * vanishing.
 */
function validateGrantTypes(value: unknown): GrantType[] {
  const arr = asStringArray(value);
  const invalid = arr.filter((g) => !VALID_GRANT_TYPES.includes(g as GrantType));
  if (invalid.length > 0) {
    throw new InputError(`Unknown grant type(s): ${invalid.join(', ')}.`);
  }
  return arr as GrantType[];
}

function validateAuthMethod(value: unknown): TokenEndpointAuthMethod {
  if (typeof value !== 'string' || !VALID_AUTH_METHODS.includes(value as TokenEndpointAuthMethod)) {
    throw new InputError(`Unknown token endpoint auth method: ${String(value)}.`);
  }
  return value as TokenEndpointAuthMethod;
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export const listClientsFn = createServerFn({ method: 'GET' }).handler(listClientsHandler);

// ---------------------------------------------------------------------------
// Get one
// ---------------------------------------------------------------------------

export const getClientFn = createServerFn({ method: 'GET' })
  .validator((data: unknown): { id: string } => {
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

export function normalizeCreateInput(data: unknown): CreateClientInput {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid input: expected an object');
  }
  const d = data as Record<string, unknown>;
  if (typeof d['name'] !== 'string' || d['name'].trim().length === 0) {
    throw new InputError('Name is required.');
  }
  const name = d['name'].trim();
  checkLength('Name', name, LIMITS.NAME_MAX);
  const input: CreateClientInput = { name };
  if (typeof d['description'] === 'string' && d['description'].trim().length > 0) {
    const description = d['description'].trim();
    checkLength('Description', description, LIMITS.DESCRIPTION_MAX);
    input.description = description;
  }
  if (d['redirectUris'] !== undefined) {
    const uris = asStringArray(d['redirectUris']);
    checkArray('Redirect URI', uris, LIMITS.REDIRECT_URIS_MAX, LIMITS.REDIRECT_URI_MAX);
    input.redirectUris = uris;
  }
  if (d['scopes'] !== undefined) {
    const scopes = asStringArray(d['scopes']);
    checkArray('Scope', scopes, LIMITS.SCOPES_MAX, LIMITS.SCOPE_MAX);
    input.scopes = scopes;
  }
  if (d['grantTypes'] !== undefined) input.grantTypes = validateGrantTypes(d['grantTypes']);
  if (d['tokenEndpointAuthMethod'] !== undefined) {
    input.tokenEndpointAuthMethod = validateAuthMethod(d['tokenEndpointAuthMethod']);
  }
  return input;
}

export const createClientFn = createServerFn({ method: 'POST' })
  .validator(normalizeCreateInput)
  .handler(createClientHandler);

// ---------------------------------------------------------------------------
// Update (PATCH)
// ---------------------------------------------------------------------------

export function normalizeUpdateInput(data: unknown): { id: string; patch: UpdateClientInput } {
  if (
    typeof data !== 'object' ||
    data === null ||
    typeof (data as { id?: unknown }).id !== 'string'
  ) {
    throw new Error('Invalid input: expected { id: string, ... }');
  }
  const d = data as Record<string, unknown>;
  const patch: UpdateClientInput = {};
  if (typeof d['name'] === 'string') {
    const name = d['name'].trim();
    checkLength('Name', name, LIMITS.NAME_MAX);
    patch.name = name;
  }
  if (d['description'] !== undefined) {
    if (typeof d['description'] === 'string' && d['description'].trim().length > 0) {
      const description = d['description'].trim();
      checkLength('Description', description, LIMITS.DESCRIPTION_MAX);
      patch.description = description;
    } else {
      patch.description = null;
    }
  }
  if (d['redirectUris'] !== undefined) {
    const uris = asStringArray(d['redirectUris']);
    checkArray('Redirect URI', uris, LIMITS.REDIRECT_URIS_MAX, LIMITS.REDIRECT_URI_MAX);
    patch.redirectUris = uris;
  }
  if (d['scopes'] !== undefined) {
    const scopes = asStringArray(d['scopes']);
    checkArray('Scope', scopes, LIMITS.SCOPES_MAX, LIMITS.SCOPE_MAX);
    patch.scopes = scopes;
  }
  if (d['grantTypes'] !== undefined) patch.grantTypes = validateGrantTypes(d['grantTypes']);
  if (d['tokenEndpointAuthMethod'] !== undefined) {
    patch.tokenEndpointAuthMethod = validateAuthMethod(d['tokenEndpointAuthMethod']);
  }
  if (typeof d['enabled'] === 'boolean') patch.enabled = d['enabled'];
  return { id: d['id'] as string, patch };
}

export const updateClientFn = createServerFn({ method: 'POST' })
  .validator(normalizeUpdateInput)
  .handler(updateClientHandler);

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

export const deleteClientFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { id: string } => {
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

export const regenerateSecretFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { id: string } => {
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
