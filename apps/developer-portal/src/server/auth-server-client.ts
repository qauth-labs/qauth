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

function mapErrorCode(body: AuthServerErrorBody, httpStatus: number): string {
  if (httpStatus === 429) return 'RATE_LIMITED';
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
    default:
      return 'UNKNOWN';
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
};
