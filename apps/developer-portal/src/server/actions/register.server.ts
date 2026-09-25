// Server-only: the auth-server client reads the incoming request, so it must
// never reach the client bundle (same split as login/logout).

import { authServerClient, type RegisterData, type Result } from '../auth-server-client';

export async function registerHandler({
  data,
}: {
  data: { email: string; password: string };
}): Promise<Result<RegisterData>> {
  return authServerClient.register(data.email, data.password);
}
