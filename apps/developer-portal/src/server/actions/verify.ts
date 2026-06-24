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
  .inputValidator((data: unknown): { token: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as Record<string, unknown>).token !== 'string'
    ) {
      throw new Error('Invalid input: expected { token: string }');
    }
    return { token: (data as { token: string }).token };
  })
  .handler(verifyHandler);
