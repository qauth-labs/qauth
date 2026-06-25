import { env } from './config';

export type Result<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: { code: string; message: string; details?: string | string[]; status: number };
    };

interface AuthServerErrorBody {
  error: string;
  statusCode: number;
  code?: string;
  feedback?: string[];
  constraint?: string;
}

export interface RegisterData {
  id: string;
  email: string;
  emailVerified: boolean;
  realmId: string;
  createdAt: number;
  updatedAt: number | null;
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

export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials';

/**
 * Safe representation of an OAuth client as returned by every `/api/clients`
 * route except the secret-bearing responses. The plaintext `clientSecret` is
 * deliberately absent here — it only exists on {@link ClientWithSecret}.
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
  enabled: boolean;
  requirePkce: boolean;
  createdAt: number;
  updatedAt: number | null;
  lastUsedAt: number | null;
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

function mapErrorCode(body: AuthServerErrorBody, httpStatus: number): string {
  if (httpStatus === 429) return 'RATE_LIMITED';
  if (httpStatus === 404) return 'NOT_FOUND';
  switch (body.code) {
    case 'INVALID_CREDENTIALS':
      return 'INVALID_CREDENTIALS';
    case 'WEAK_PASSWORD':
      return 'WEAK_PASSWORD';
    case 'UNIQUE_CONSTRAINT_VIOLATION':
      return 'EMAIL_TAKEN';
    case 'INVALID_TOKEN':
      return 'INVALID_TOKEN';
    case 'EMAIL_ALREADY_VERIFIED':
      return 'EMAIL_ALREADY_VERIFIED';
    case 'VALIDATION_ERROR':
      return 'VALIDATION_ERROR';
    default:
      // No domain code: classify by status. The `/api/clients` routes return
      // bare `401`/`400`s; login etc. carry a `code` handled above.
      if (httpStatus === 401) return 'UNAUTHENTICATED';
      if (httpStatus === 400) return 'VALIDATION_ERROR';
      return 'UNKNOWN';
  }
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
  try {
    const res = await fetch(`${env.AUTH_SERVER_URL}${path}`, {
      ...fetchInit,
      headers: { ...(fetchInit.headers as Record<string, string> | undefined) },
    });

    if (res.ok) return { ok: true, data: null };

    let parsed: unknown;
    try {
      parsed = await res.json();
    } catch {
      return {
        ok: false,
        error: {
          code: mapErrorCode({ error: '', statusCode: res.status }, res.status),
          message: `HTTP ${res.status}`,
          status: res.status,
        },
      };
    }
    const body = (
      typeof parsed === 'object' && parsed !== null ? parsed : {}
    ) as AuthServerErrorBody;
    return {
      ok: false,
      error: {
        code: mapErrorCode(body, res.status),
        message: body.error || `HTTP ${res.status}`,
        status: res.status,
      },
    };
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
  const { skipContentType, ...fetchInit } = init;
  const headers: Record<string, string> = {
    ...(fetchInit.headers as Record<string, string> | undefined),
  };
  if (!skipContentType && fetchInit.method !== 'GET') {
    headers['Content-Type'] = 'application/json';
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

    let parsed: unknown;
    try {
      parsed = await res.json();
    } catch {
      return {
        ok: false,
        error: { code: 'UNKNOWN', message: `HTTP ${res.status}`, status: res.status },
      };
    }

    if (typeof parsed !== 'object' || parsed === null) {
      return {
        ok: false,
        error: { code: 'UNKNOWN', message: `HTTP ${res.status}`, status: res.status },
      };
    }

    const body = parsed as AuthServerErrorBody;
    const details = body.feedback ?? body.constraint ?? undefined;
    return {
      ok: false,
      error: {
        code: mapErrorCode(body, res.status),
        message: body.error,
        ...(details !== undefined ? { details } : {}),
        status: res.status,
      },
    };
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

  verifyEmail(token: string): Promise<Result<VerifyEmailData>> {
    return apiRequest<VerifyEmailData>(`/auth/verify?token=${encodeURIComponent(token)}`, {
      method: 'GET',
      skipContentType: true,
    });
  },

  resendVerification(email: string): Promise<Result<ResendVerificationData>> {
    return apiRequest<ResendVerificationData>('/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  userinfo(accessToken: string): Promise<Result<UserInfoData>> {
    return apiRequest<UserInfoData>('/userinfo', {
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
};
