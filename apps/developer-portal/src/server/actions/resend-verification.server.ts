// Server-only: the auth-server client reads the incoming request, so it must
// never reach the client bundle (same split as login/logout).

import { authServerClient, type ResendVerificationData, type Result } from '../auth-server-client';

export async function resendVerificationHandler({
  data,
}: {
  data: { email: string };
}): Promise<Result<ResendVerificationData>> {
  return authServerClient.resendVerification(data.email);
}
