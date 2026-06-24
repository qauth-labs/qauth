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
  .inputValidator((data: unknown): { email: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as Record<string, unknown>).email !== 'string'
    ) {
      throw new Error('Invalid input: expected { email: string }');
    }
    return { email: (data as { email: string }).email };
  })
  .handler(resendVerificationHandler);
