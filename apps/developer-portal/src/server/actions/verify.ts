import { createServerFn } from '@tanstack/react-start';

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

export const verifyFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { token: string; password: string } => {
    const input = data as Record<string, unknown> | null;
    if (
      typeof data !== 'object' ||
      input === null ||
      typeof input.token !== 'string' ||
      typeof input.password !== 'string'
    ) {
      throw new Error('Invalid input: expected { token: string, password: string }');
    }
    return { token: input.token, password: input.password };
  })
  .handler(verifyHandler);
