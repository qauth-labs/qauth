import { isIP } from 'node:net';

import { getRequestIP } from '@tanstack/react-start/server';

import { env } from './config';

export type Result<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: { code: string; message: string; details?: string | string[]; status: number };
    };

/**
 * The body of `POST /auth/register`'s `202 Accepted`.
 *
 * The auth-server answers every address with this same message, whether it
 * created an account or the address already had one, so it carries no user id
 * and nothing else that could tell the two apart. The next step (a
 * verification link, or a notice for an existing account) arrives by email.
 */
export interface RegisterData {
  message: string;
}

export interface LoginData {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
}

export interface LogoutData {
  success: true;
  message: string;
}

export interface VerifyEmailData {
  message: string;
  email: string;
}

export interface ResendVerificationData {
  message: string;
}

export interface UserInfoData {
  sub: string;
  email?: string;
  email_verified?: boolean;
}

export type TokenEndpointAuthMethod =
  | 'none'
  | 'client_secret_post'
  | 'client_secret_basic'
  | 'private_key_jwt';

export type GrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  // RFC 8693 on-behalf-of delegation (ADR-007 §2). Settable by a developer on
  // their own client since #381; see `grantTypeSchema` in the auth-server's
  // `schemas/clients.ts` for why this subset excludes `jwt-bearer`.
  | 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * Safe representation of an OAuth client as returned by every `/api/clients`
 * route except the secret-bearing responses. The plaintext `clientSecret` is
 * deliberately absent here — it only exists on {@link ClientWithSecret}.
 */
/**
 * A client's effective deployment environment (ADR-008). Resolved server-side
 * as the stricter of the client's declared environment and its realm ceiling —
 * the portal only reads it, never sets it.
 */
export type ClientEnvironment = 'development' | 'staging' | 'production';

export interface OAuthClient {
  id: string;
  clientId: string;
  name: string;
  description: string | null;
  redirectUris: string[];
  scopes: string[];
  grantTypes: GrantType[];
  responseTypes: string[];
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
  /** The owner's switch. */
  enabled: boolean;
  /**
   * Set by the operator, never by the owner: a suspended client is refused
   * whatever `enabled` says. Optional for an auth-server that predates it.
   */
  suspended?: boolean;
  requirePkce: boolean;
  /** Effective environment (ADR-008); read-only, resolved by the auth-server. */
  environment: ClientEnvironment;
  /**
   * Whether static developer API keys may be minted for this client (#97/#98).
   * Resolved from the effective environment (`development` only). The portal
   * gates the create form on this; the mint endpoint's `403` is the
   * authoritative defense-in-depth check.
   */
  staticApiKeysAllowed: boolean;
  createdAt: number;
  updatedAt: number | null;
  lastUsedAt: number | null;
}

/**
 * A static developer API key as returned by the management API — masked,
 * non-secret fields only (issue #98 consumes #97). The full `key` is present
 * ONLY on the create response (see {@link ApiKeyWithSecret}); the hash is never
 * returned.
 */
export interface ApiKey {
  id: string;
  clientId: string;
  name: string;
  /** Public lookup handle (`qauth_<id>`); non-secret, safe to display. */
  prefix: string;
  /** Trailing 4 chars of the secret, for masked display. */
  last4: string;
  createdAt: number;
  lastUsedAt: number | null;
  /** Set once revoked; a revoked key never authenticates again. */
  revokedAt: number | null;
}

/**
 * Returned only by `POST /api/clients/:clientId/api-keys` (create). The
 * plaintext `key` is shown once and is unrecoverable afterwards — never persist
 * it beyond the one-time display modal.
 */
export interface ApiKeyWithSecret extends ApiKey {
  /** Full plaintext key (`qauth_...`). Shown once; never recoverable. */
  key: string;
}

export interface ApiKeyListData {
  apiKeys: ApiKey[];
}

export interface CreateApiKeyInput {
  name: string;
}

/**
 * Returned only by `POST /api/clients` (create) and
 * `POST /api/clients/:id/regenerate-secret`. The `clientSecret` is shown once
 * and is unrecoverable afterwards — never persist it beyond the one-time
 * display modal.
 */
export interface ClientWithSecret extends OAuthClient {
  clientSecret?: string;
}

/**
 * One row of `GET /api/consents` (issue #366). The auth-server owns the shape;
 * this mirrors `consentRowSchema` in `routes/consents-api`.
 */
export interface Consent {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  /** Epoch milliseconds. */
  grantedAt: number;
}

export interface ConsentListData {
  consents: Consent[];
}

export interface ClientListData {
  clients: OAuthClient[];
}

export interface CreateClientInput {
  name: string;
  description?: string | null;
  redirectUris?: string[];
  scopes?: string[];
  grantTypes?: GrantType[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
}

export interface UpdateClientInput {
  name?: string;
  description?: string | null;
  redirectUris?: string[];
  scopes?: string[];
  grantTypes?: GrantType[];
  responseTypes?: string[];
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  enabled?: boolean;
}

/** The error of a failed {@link Result}. */
type ResultError = Extract<Result<unknown>, { ok: false }>['error'];

/** RFC 9457 §3: the media type of a problem details document in JSON. */
const PROBLEM_MEDIA_TYPE = 'application/problem+json';

/**
 * The portal's code for each problem `code` the auth-server answers on the
 * routes the portal calls (#513). Every auth-server route but the OAuth
 * protocol endpoints answers an error as an RFC 9457 problem document, whose
 * `code` is lower-case snake_case. A code missing here is classified by the
 * HTTP status ({@link codeForStatus}): the auth-server may add codes in a
 * minor release, and a client treats one it does not know by its status.
 */
const PROBLEM_CODE_MAP: Readonly<Record<string, string>> = {
  invalid_credentials: 'INVALID_CREDENTIALS',
  weak_password: 'WEAK_PASSWORD',
  // A generic conflict. Registration never answers with it: an address that
  // already has an account gets the same 202 as a free one.
  already_exists: 'CONFLICT',
  conflict: 'CONFLICT',
  // An email verification token, not an access token.
  invalid_verification_token: 'INVALID_TOKEN',
  email_already_verified: 'EMAIL_ALREADY_VERIFIED',
  // Login refuses an unverified account with `invalid_credentials`; a 403
  // elsewhere is the generic refusal it always was here.
  email_not_verified: 'FORBIDDEN',
  validation_error: 'VALIDATION_ERROR',
  bad_request: 'VALIDATION_ERROR',
  invalid_request: 'VALIDATION_ERROR',
  invalid_redirect_uri: 'VALIDATION_ERROR',
  invalid_client_metadata: 'VALIDATION_ERROR',
  invalid_scope: 'VALIDATION_ERROR',
  // The environment gate on API-key minting (ADR-008 §6) — a staging /
  // production client is refused here and steered to client_credentials.
  forbidden: 'FORBIDDEN',
  // An access token that is missing, expired, not valid or names no active
  // user: the session is over.
  unauthorized: 'UNAUTHENTICATED',
  invalid_access_token: 'UNAUTHENTICATED',
  access_token_expired: 'UNAUTHENTICATED',
  not_found: 'NOT_FOUND',
  too_many_requests: 'RATE_LIMITED',
};

/**
 * The portal's code for each `error` an OAuth protocol endpoint answers
 * (RFC 6749 §5.2, RFC 6750 §3.1). The portal calls one: userinfo. A value
 * missing here (`temporarily_unavailable` for a 429 and a 503 alike,
 * `server_error`) is classified by the HTTP status.
 */
const OAUTH_ERROR_MAP: Readonly<Record<string, string>> = {
  // The access token, not a one-time token: the session is over.
  invalid_token: 'UNAUTHENTICATED',
  insufficient_scope: 'FORBIDDEN',
  access_denied: 'FORBIDDEN',
  invalid_request: 'VALIDATION_ERROR',
};

/** The portal's code for an answer it can read nothing but the status of. */
function codeForStatus(httpStatus: number): string {
  switch (httpStatus) {
    case 400:
      return 'VALIDATION_ERROR';
    case 401:
      return 'UNAUTHENTICATED';
    case 403:
      return 'FORBIDDEN';
    case 404:
      return 'NOT_FOUND';
    case 429:
      return 'RATE_LIMITED';
    default:
      return 'UNKNOWN';
  }
}

/** A non-empty string, or `undefined`. */
function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/** The portal code `map` holds for `key`, else the code of `httpStatus`. */
function mapCode(
  map: Readonly<Record<string, string>>,
  key: string | undefined,
  httpStatus: number
): string {
  return key !== undefined && Object.hasOwn(map, key) ? map[key] : codeForStatus(httpStatus);
}

/**
 * The error of a problem document: its `code` mapped to the portal's, its
 * `detail` (else its `title`) as the message, and the message of each entry
 * of `errors` as the details. A weak password's feedback arrives as entries
 * under `/password`. Neither the `title` nor the `detail` is branched on.
 */
function problemError(body: Record<string, unknown>, httpStatus: number): ResultError {
  const entries = Array.isArray(body['errors']) ? (body['errors'] as unknown[]) : [];
  const details = entries
    .map((entry) =>
      typeof entry === 'object' && entry !== null
        ? nonEmptyString((entry as Record<string, unknown>)['message'])
        : undefined
    )
    .filter((message): message is string => message !== undefined);
  return {
    code: mapCode(PROBLEM_CODE_MAP, nonEmptyString(body['code']), httpStatus),
    message:
      nonEmptyString(body['detail']) ?? nonEmptyString(body['title']) ?? `HTTP ${httpStatus}`,
    ...(details.length > 0 ? { details } : {}),
    status: httpStatus,
  };
}

/** The error of an OAuth error body: `error` mapped, `error_description` (else `error`) as the message. */
function oauthError(error: string, body: Record<string, unknown>, httpStatus: number): ResultError {
  return {
    code: mapCode(OAUTH_ERROR_MAP, error, httpStatus),
    message: nonEmptyString(body['error_description']) ?? error,
    status: httpStatus,
  };
}

/**
 * Read a failed answer of the auth-server into the portal's error (#513).
 *
 * - `application/problem+json`: an RFC 9457 problem document, what every
 *   route the portal calls answers but userinfo.
 * - Any other JSON object with an `error` string: the OAuth error body of an
 *   OAuth protocol endpoint (RFC 6749 §5.2).
 * - Anything else (no body, not JSON, not an object): classified by status.
 */
async function readError(res: Response): Promise<ResultError> {
  let parsed: unknown;
  try {
    parsed = await res.json();
  } catch {
    parsed = undefined;
  }
  if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
    const body = parsed as Record<string, unknown>;
    const mediaType = (res.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
    if (mediaType === PROBLEM_MEDIA_TYPE) return problemError(body, res.status);
    const error = nonEmptyString(body['error']);
    if (error !== undefined) return oauthError(error, body, res.status);
  }
  return { code: codeForStatus(res.status), message: `HTTP ${res.status}`, status: res.status };
}

/**
 * Variant of {@link apiRequest} for endpoints that return `204 No Content`
 * (notably `DELETE /api/clients/:id`). Calling `res.json()` on an empty body
 * would throw, so success is reported without parsing.
 */
async function apiRequestNoContent(
  path: string,
  init: RequestInit & { skipContentType?: boolean }
): Promise<Result<null>> {
  // `skipContentType` is irrelevant here (no request body); drop it so it is
  // not forwarded to `fetch`.
  const { skipContentType, ...fetchInit } = init;
  void skipContentType;
  const headers: Record<string, string> = {
    ...(fetchInit.headers as Record<string, string> | undefined),
  };
  const xff = forwardedFor();
  if (xff) {
    headers['X-Forwarded-For'] = xff;
  }
  try {
    const res = await fetch(`${env.AUTH_SERVER_URL}${path}`, {
      ...fetchInit,
      headers,
    });

    if (res.ok) return { ok: true, data: null };

    return { ok: false, error: await readError(res) };
  } catch (err) {
    return {
      ok: false,
      error: {
        code: 'NETWORK_ERROR',
        message: err instanceof Error ? err.message : 'Network error',
        status: 0,
      },
    };
  }
}

/** An IPv4 address in IPv6 form (`::ffff:a.b.c.d`), as a dual-stack socket reports it. */
const IPV4_MAPPED = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i;

/**
 * The `X-Forwarded-For` value to send upstream, or `undefined` when there is
 * no request being served (tests, build) or its client address is not a
 * single IP address.
 *
 * The portal calls the auth-server server-to-server, so without this every
 * developer reaches it from the portal's address: one shared bucket for the
 * per-IP login, registration and resend limits and the `ip:` failed-login
 * lockout, which one caller could fill to lock everyone out. The auth-server
 * reads the header only when its `TRUST_PROXY` lists the portal's address;
 * otherwise it keys every request on the portal's own address.
 *
 * The portal sends exactly one address: the TCP peer of this connection, or,
 * when that peer is a proxy listed in `PORTAL_TRUST_PROXY`, the client address
 * that proxy reports. `getRequestIP()` with no options is the srvx request's
 * `ip`, which srvx resolves from the peer and the listed proxies only (see
 * `node-entry.ts` and `trust-proxy.ts`); the request's own `X-Forwarded-For`
 * is never sent on. An IPv4-mapped address is sent in plain IPv4 form, so a
 * client has the same address whichever way it reaches the auth-server.
 * Anything that is not an IP address (for example `host:port`) is not sent:
 * the auth-server then keys the request on the portal's own address.
 */
function forwardedFor(): string | undefined {
  try {
    const client = getRequestIP();
    if (!client) return undefined;
    const address = IPV4_MAPPED.exec(client)?.[1] ?? client;
    return isIP(address) === 0 ? undefined : address;
  } catch {
    return undefined;
  }
}

async function apiRequest<T>(
  path: string,
  init: RequestInit & { skipContentType?: boolean }
): Promise<Result<T>> {
  const { skipContentType, ...fetchInit } = init;
  const headers: Record<string, string> = {
    ...(fetchInit.headers as Record<string, string> | undefined),
  };
  if (!skipContentType && fetchInit.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
  }
  const xff = forwardedFor();
  if (xff) {
    headers['X-Forwarded-For'] = xff;
  }

  try {
    const res = await fetch(`${env.AUTH_SERVER_URL}${path}`, {
      ...fetchInit,
      headers,
    });

    if (res.ok) {
      const data = (await res.json()) as T;
      return { ok: true, data };
    }

    return { ok: false, error: await readError(res) };
  } catch (err) {
    return {
      ok: false,
      error: {
        code: 'NETWORK_ERROR',
        message: err instanceof Error ? err.message : 'Network error',
        status: 0,
      },
    };
  }
}

export const authServerClient = {
  /**
   * Register a password account. Success means only that the request was
   * accepted: the same `202` comes back for an address that already has an
   * account, so the caller must show a "check your inbox" state, never
   * "account created" or "address taken".
   */
  register(email: string, password: string, realmId?: string): Promise<Result<RegisterData>> {
    return apiRequest<RegisterData>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, ...(realmId ? { realmId } : {}) }),
    });
  },

  login(email: string, password: string): Promise<Result<LoginData>> {
    return apiRequest<LoginData>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  },

  logout(accessToken: string): Promise<Result<LogoutData>> {
    return apiRequest<LogoutData>('/auth/logout', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  /**
   * POST, token and password in the body: verification is a state change (a
   * link fetch must not verify), and it needs both the mailbox (token) and the
   * registrant (password).
   */
  verifyEmail(token: string, password: string): Promise<Result<VerifyEmailData>> {
    return apiRequest<VerifyEmailData>('/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ token, password }),
    });
  },

  resendVerification(email: string): Promise<Result<ResendVerificationData>> {
    return apiRequest<ResendVerificationData>('/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  userinfo(accessToken: string): Promise<Result<UserInfoData>> {
    // The OIDC userinfo endpoint is served under `/oauth` (its discovery
    // `userinfo_endpoint`); a bare `/userinfo` is a 404, which signed every
    // portal user out on their first page.
    return apiRequest<UserInfoData>('/oauth/userinfo', {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  listClients(accessToken: string): Promise<Result<ClientListData>> {
    return apiRequest<ClientListData>('/api/clients', {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  listConsents(accessToken: string): Promise<Result<ConsentListData>> {
    return apiRequest<ConsentListData>('/api/consents', {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  /**
   * Revoke one consent. `/api/consents` is Bearer-authenticated, so unlike the
   * cookie-authed `/consents` it needs no `X-CSRF-Token` header — see that
   * route's module comment for why.
   */
  revokeConsent(accessToken: string, id: string): Promise<Result<null>> {
    return apiRequestNoContent(`/api/consents/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  getClient(accessToken: string, id: string): Promise<Result<OAuthClient>> {
    return apiRequest<OAuthClient>(`/api/clients/${encodeURIComponent(id)}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  createClient(accessToken: string, input: CreateClientInput): Promise<Result<ClientWithSecret>> {
    return apiRequest<ClientWithSecret>('/api/clients', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(input),
    });
  },

  updateClient(
    accessToken: string,
    id: string,
    input: UpdateClientInput
  ): Promise<Result<OAuthClient>> {
    return apiRequest<OAuthClient>(`/api/clients/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(input),
    });
  },

  deleteClient(accessToken: string, id: string): Promise<Result<null>> {
    return apiRequestNoContent(`/api/clients/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  regenerateClientSecret(accessToken: string, id: string): Promise<Result<ClientWithSecret>> {
    return apiRequest<ClientWithSecret>(
      `/api/clients/${encodeURIComponent(id)}/regenerate-secret`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
        skipContentType: true,
      }
    );
  },

  // ── Static developer API keys (#97 backend, consumed by #98) ──────────────

  listApiKeys(accessToken: string, clientId: string): Promise<Result<ApiKeyListData>> {
    return apiRequest<ApiKeyListData>(`/api/clients/${encodeURIComponent(clientId)}/api-keys`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  createApiKey(
    accessToken: string,
    clientId: string,
    input: CreateApiKeyInput
  ): Promise<Result<ApiKeyWithSecret>> {
    return apiRequest<ApiKeyWithSecret>(`/api/clients/${encodeURIComponent(clientId)}/api-keys`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(input),
    });
  },

  // Revoke returns the masked key as a 200 JSON body (idempotent soft-delete),
  // so this parses the response rather than using the no-content variant.
  revokeApiKey(accessToken: string, clientId: string, keyId: string): Promise<Result<ApiKey>> {
    return apiRequest<ApiKey>(
      `/api/clients/${encodeURIComponent(clientId)}/api-keys/${encodeURIComponent(keyId)}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${accessToken}` },
        skipContentType: true,
      }
    );
  },
};
