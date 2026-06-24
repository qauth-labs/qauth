import { createServerFn } from '@tanstack/react-start';

import { authServerClient, type Result, type VerifyEmailData } from '../auth-server-client';

export async function verifyHandler({
  data,
}: {
  data: { token: string };
}): Promise<Result<VerifyEmailData>> {
  return authServerClient.verifyEmail(data.token);
}

export const verifyFn = createServerFn({ method: 'POST' })
  .inputValidator((data: { token: string }) => data)
  .handler(verifyHandler);
