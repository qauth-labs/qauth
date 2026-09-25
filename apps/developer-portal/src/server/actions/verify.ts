import { createServerFn } from '@tanstack/react-start';

import { verifyHandler } from './verify.server';

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
