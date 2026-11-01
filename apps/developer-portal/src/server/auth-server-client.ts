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
 * A client's effective deployment environment (ADR-008). Resolved server-side
 * as the stricter of the client's declared environment and its realm ceiling —
 * the portal only reads it, never sets it.
 */
export type ClientEnvironment = 'development' | 'staging' | 'production';

/**
 * An OAuth client as the portal's pages use it: the developer API's
 * representation (`/developer/v1-rc.0/clients`, #524) mapped onto the
 * portal's own camelCase names, times as epoch milliseconds. The plaintext
 * `clientSecret` is deliberately absent here — it only exists on
 * {@link ClientWithSecret}.
 */
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
  /**
   * The client's `ETag` when the answer carried one: the version an update
   * names in `If-Match`, so a change made since this read is refused (412)
   * instead of overwritten.
   */
  etag?: string;
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
 * Returned only by the mint of a key (`POST .../api-keys`). The
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
 * Returned only by a create and by `.../regenerate-secret`. The
 * `clientSecret` is shown once
 * and is unrecoverable afterwards — never persist it beyond the one-time
 * display modal.
 */
export interface ClientWithSecret extends OAuthClient {
  clientSecret?: string;
}

/**
 * One active consent of the developer as a user (issue #366), from
 * `GET /developer/v1-rc.0/consents`, mapped onto the portal's names.
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
  // The developer API's conventions (#524): a page cursor the list did not
  // issue, an update whose `If-Match` is missing or names another version, a
  // merge patch the client cannot become.
  invalid_cursor: 'VALIDATION_ERROR',
  precondition_required: 'VALIDATION_ERROR',
  precondition_failed: 'CONFLICT',
  unprocessable_content: 'VALIDATION_ERROR',
  unsupported_media_type: 'VALIDATION_ERROR',
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
 * (notably a client delete). Calling `res.json()` on an empty body
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

/**
 * One call to the auth-server: the parsed JSON body of a success with the
 * answer's `ETag`, or the error. A caller that names its own `Content-Type`
 * keeps it (a merge patch); any other body is sent as JSON.
 */
async function apiExchange<T>(
  path: string,
  init: RequestInit & { skipContentType?: boolean }
): Promise<Result<{ body: T; etag: string | undefined }>> {
  const { skipContentType, ...fetchInit } = init;
  const headers: Record<string, string> = {
    ...(fetchInit.headers as Record<string, string> | undefined),
  };
  if (!skipContentType && fetchInit.method !== 'GET' && headers['Content-Type'] === undefined) {
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
      const body = (await res.json()) as T;
      return { ok: true, data: { body, etag: res.headers?.get('etag') ?? undefined } };
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

async function apiRequest<T>(
  path: string,
  init: RequestInit & { skipContentType?: boolean }
): Promise<Result<T>> {
  const result = await apiExchange<T>(path, init);
  return result.ok ? { ok: true, data: result.data.body } : result;
}

// ---------------------------------------------------------------------------
// The developer API (`/developer/v1-rc.0`, #524)
// ---------------------------------------------------------------------------

/** Where the developer API is served. */
export const DEVELOPER_API = '/developer/v1-rc.0';

/** A client as the developer API represents it: RFC 7591 names, RFC 3339 times. */
interface WireClient {
  id: string;
  client_id: string;
  client_name: string;
  description: string | null;
  redirect_uris: string[];
  scopes: string[];
  grant_types: GrantType[];
  response_types: string[];
  token_endpoint_auth_method: TokenEndpointAuthMethod;
  enabled: boolean;
  suspended: boolean;
  requirePkce: boolean;
  environment: ClientEnvironment;
  staticApiKeysAllowed: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsedAt: string | null;
  client_secret?: string;
}

/** A static API key as the developer API represents it. */
interface WireApiKey {
  id: string;
  clientId: string;
  name: string;
  prefix: string;
  last4: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  key?: string;
}

/** A consent as the developer API represents it. */
interface WireConsent {
  id: string;
  client_id: string;
  client_name: string;
  scopes: string[];
  grantedAt: string;
}

/** One page of a developer API list. */
interface WirePage<Item> {
  items: Item[];
  nextCursor: string | null;
}

/** The largest page the developer API serves (API conventions). */
const PAGE_LIMIT = 200;

/**
 * Most pages one list read follows. A developer owns at most
 * `MAX_CLIENTS_PER_DEVELOPER` clients, so a list longer than this is a server
 * that keeps answering a cursor, never a real list.
 */
const MAX_PAGES = 50;

/** An RFC 3339 time as epoch milliseconds, as the portal's pages show times. */
function epochMs(value: string): number {
  return Date.parse(value);
}

function epochMsOrNull(value: string | null): number | null {
  return value === null ? null : Date.parse(value);
}

function fromWireClient(wire: WireClient, etag?: string): ClientWithSecret {
  return {
    id: wire.id,
    clientId: wire.client_id,
    name: wire.client_name,
    description: wire.description,
    redirectUris: wire.redirect_uris,
    scopes: wire.scopes,
    grantTypes: wire.grant_types,
    responseTypes: wire.response_types,
    tokenEndpointAuthMethod: wire.token_endpoint_auth_method,
    enabled: wire.enabled,
    suspended: wire.suspended,
    requirePkce: wire.requirePkce,
    environment: wire.environment,
    staticApiKeysAllowed: wire.staticApiKeysAllowed,
    createdAt: epochMs(wire.createdAt),
    updatedAt: epochMs(wire.updatedAt),
    lastUsedAt: epochMsOrNull(wire.lastUsedAt),
    ...(etag === undefined ? {} : { etag }),
    ...(wire.client_secret === undefined ? {} : { clientSecret: wire.client_secret }),
  };
}

function fromWireApiKey(wire: WireApiKey): ApiKeyWithSecret | ApiKey {
  return {
    id: wire.id,
    clientId: wire.clientId,
    name: wire.name,
    prefix: wire.prefix,
    last4: wire.last4,
    createdAt: epochMs(wire.createdAt),
    lastUsedAt: epochMsOrNull(wire.lastUsedAt),
    revokedAt: epochMsOrNull(wire.revokedAt),
    ...(wire.key === undefined ? {} : { key: wire.key }),
  };
}

function fromWireConsent(wire: WireConsent): Consent {
  return {
    id: wire.id,
    clientId: wire.client_id,
    clientName: wire.client_name,
    scopes: wire.scopes,
    grantedAt: epochMs(wire.grantedAt),
  };
}

/** A create's body in the developer API's names; members left out keep their defaults. */
function toWireNewClient(input: CreateClientInput): Record<string, unknown> {
  return {
    client_name: input.name,
    ...(input.description === undefined ? {} : { description: input.description }),
    ...(input.redirectUris === undefined ? {} : { redirect_uris: input.redirectUris }),
    ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
    ...(input.grantTypes === undefined ? {} : { grant_types: input.grantTypes }),
    ...(input.responseTypes === undefined ? {} : { response_types: input.responseTypes }),
    ...(input.tokenEndpointAuthMethod === undefined
      ? {}
      : { token_endpoint_auth_method: input.tokenEndpointAuthMethod }),
  };
}

/**
 * An update as a JSON Merge Patch (RFC 7396): only the members the portal
 * changes. `description: null` removes the description, as before.
 */
function toWireClientPatch(input: UpdateClientInput): Record<string, unknown> {
  return {
    ...(input.name === undefined ? {} : { client_name: input.name }),
    ...(input.description === undefined ? {} : { description: input.description }),
    ...(input.redirectUris === undefined ? {} : { redirect_uris: input.redirectUris }),
    ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
    ...(input.grantTypes === undefined ? {} : { grant_types: input.grantTypes }),
    ...(input.responseTypes === undefined ? {} : { response_types: input.responseTypes }),
    ...(input.tokenEndpointAuthMethod === undefined
      ? {}
      : { token_endpoint_auth_method: input.tokenEndpointAuthMethod }),
    ...(input.enabled === undefined ? {} : { enabled: input.enabled }),
  };
}

/**
 * Every item of a developer API list, following `nextCursor` page by page.
 * The pages the portal shows are short (a developer's clients, a client's
 * keys, a user's consents), so it reads them whole, as it did before lists
 * were paged.
 */
async function listAll<Item>(path: string, accessToken: string): Promise<Result<Item[]>> {
  const items: Item[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_PAGES; page++) {
    const query = new URLSearchParams({ limit: String(PAGE_LIMIT) });
    if (cursor !== null) query.set('cursor', cursor);
    const result: Result<WirePage<Item>> = await apiRequest<WirePage<Item>>(
      `${path}?${query.toString()}`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${accessToken}` },
        skipContentType: true,
      }
    );
    if (!result.ok) return result;
    items.push(...result.data.items);
    cursor = result.data.nextCursor;
    if (cursor === null) return { ok: true, data: items };
  }
  return {
    ok: false,
    error: { code: 'UNKNOWN', message: 'The list did not end', status: 0 },
  };
}

/** The developer API path of one client. */
function clientPath(id: string): string {
  return `${DEVELOPER_API}/clients/${encodeURIComponent(id)}`;
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

  async listClients(accessToken: string): Promise<Result<ClientListData>> {
    const result = await listAll<WireClient>(`${DEVELOPER_API}/clients`, accessToken);
    return result.ok
      ? { ok: true, data: { clients: result.data.map((wire) => fromWireClient(wire)) } }
      : result;
  },

  async listConsents(accessToken: string): Promise<Result<ConsentListData>> {
    const result = await listAll<WireConsent>(`${DEVELOPER_API}/consents`, accessToken);
    return result.ok ? { ok: true, data: { consents: result.data.map(fromWireConsent) } } : result;
  },

  /**
   * Revoke one consent. The developer API is Bearer-authenticated, so unlike
   * the cookie-authed `/consents` it needs no `X-CSRF-Token` header.
   */
  revokeConsent(accessToken: string, id: string): Promise<Result<null>> {
    return apiRequestNoContent(`${DEVELOPER_API}/consents/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  /** One client, with its `ETag` for a later update. */
  async getClient(accessToken: string, id: string): Promise<Result<OAuthClient>> {
    const result = await apiExchange<WireClient>(clientPath(id), {
      method: 'GET',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
    return result.ok
      ? { ok: true, data: fromWireClient(result.data.body, result.data.etag) }
      : result;
  },

  async createClient(
    accessToken: string,
    input: CreateClientInput
  ): Promise<Result<ClientWithSecret>> {
    const result = await apiExchange<WireClient>(`${DEVELOPER_API}/clients`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(toWireNewClient(input)),
    });
    return result.ok
      ? { ok: true, data: fromWireClient(result.data.body, result.data.etag) }
      : result;
  },

  /**
   * Change a client with a JSON Merge Patch. `ifMatch` is the `ETag` of the
   * representation the developer edited: a client changed since is refused
   * (412, `CONFLICT`) rather than overwritten. Without one, the client is read
   * first and its current version is named.
   */
  async updateClient(
    accessToken: string,
    id: string,
    input: UpdateClientInput,
    ifMatch?: string
  ): Promise<Result<OAuthClient>> {
    let version = ifMatch;
    if (version === undefined) {
      const current = await authServerClient.getClient(accessToken, id);
      if (!current.ok) return current;
      version = current.data.etag;
    }
    const result = await apiExchange<WireClient>(clientPath(id), {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/merge-patch+json',
        ...(version === undefined ? {} : { 'If-Match': version }),
      },
      body: JSON.stringify(toWireClientPatch(input)),
    });
    return result.ok
      ? { ok: true, data: fromWireClient(result.data.body, result.data.etag) }
      : result;
  },

  deleteClient(accessToken: string, id: string): Promise<Result<null>> {
    return apiRequestNoContent(clientPath(id), {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
  },

  async regenerateClientSecret(accessToken: string, id: string): Promise<Result<ClientWithSecret>> {
    const result = await apiExchange<WireClient>(`${clientPath(id)}/regenerate-secret`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      skipContentType: true,
    });
    return result.ok
      ? { ok: true, data: fromWireClient(result.data.body, result.data.etag) }
      : result;
  },

  // ── Static developer API keys (#97 backend, consumed by #98) ──────────────

  async listApiKeys(accessToken: string, clientId: string): Promise<Result<ApiKeyListData>> {
    const result = await listAll<WireApiKey>(`${clientPath(clientId)}/api-keys`, accessToken);
    return result.ok ? { ok: true, data: { apiKeys: result.data.map(fromWireApiKey) } } : result;
  },

  async createApiKey(
    accessToken: string,
    clientId: string,
    input: CreateApiKeyInput
  ): Promise<Result<ApiKeyWithSecret>> {
    const result = await apiRequest<WireApiKey>(`${clientPath(clientId)}/api-keys`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(input),
    });
    return result.ok ? { ok: true, data: fromWireApiKey(result.data) as ApiKeyWithSecret } : result;
  },

  // Revoke returns the masked key as a 200 JSON body (idempotent soft-delete),
  // so this parses the response rather than using the no-content variant.
  async revokeApiKey(
    accessToken: string,
    clientId: string,
    keyId: string
  ): Promise<Result<ApiKey>> {
    const result = await apiRequest<WireApiKey>(
      `${clientPath(clientId)}/api-keys/${encodeURIComponent(keyId)}`,
      {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${accessToken}` },
        skipContentType: true,
      }
    );
    return result.ok ? { ok: true, data: fromWireApiKey(result.data) } : result;
  },
};
