// Server-only: the auth-server client reads the incoming request, so it must
// never reach the client bundle (same split as login/logout).

import { authServerClient, type Result, type VerifyEmailData } from '../auth-server-client';

/**
 * Verify an email address. Needs the emailed token (proves the mailbox) and the
 * account's password (proves the registrant), so someone who only has the
 * mailbox cannot verify an account someone else registered with it.
 */
export async function verifyHandler({
  data,
}: {
  data: { token: string; password: string };
}): Promise<Result<VerifyEmailData>> {
  return authServerClient.verifyEmail(data.token, data.password);
}
