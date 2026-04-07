const AUTH_SERVER_URL = import.meta.env.VITE_AUTH_SERVER_URL ?? 'http://localhost:3000';

export interface RegisterResponse {
  id: string;
  email: string;
  emailVerified: boolean;
  realmId: string;
  createdAt: number;
  updatedAt: number | null;
}

interface ApiErrorBody {
  error: string;
  code?: string;
  statusCode: number;
  feedback?: string[];
}

export class ApiRequestError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly body: ApiErrorBody
  ) {
    super(body.error);
  }
}

export async function register(email: string, password: string): Promise<RegisterResponse> {
  const res = await fetch(`${AUTH_SERVER_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const body = (await res.json()) as ApiErrorBody;
    throw new ApiRequestError(res.status, body);
  }

  return res.json() as Promise<RegisterResponse>;
}
