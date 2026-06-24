import { createServerFn } from '@tanstack/react-start';

import { authServerClient, type ResendVerificationData, type Result } from '../auth-server-client';

export async function resendVerificationHandler({
  data,
}: {
  data: { email: string };
}): Promise<Result<ResendVerificationData>> {
  return authServerClient.resendVerification(data.email);
}

export const resendVerificationFn = createServerFn({ method: 'POST' })
  .inputValidator((data: { email: string }) => data)
  .handler(resendVerificationHandler);
