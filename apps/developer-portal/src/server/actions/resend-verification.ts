import { createServerFn } from '@tanstack/react-start';

import { resendVerificationHandler } from './resend-verification.server';

export const resendVerificationFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { email: string } => {
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
