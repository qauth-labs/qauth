import { createServerFn } from '@tanstack/react-start';

import { loginHandler, type LoginResult } from './login.server';

export type { LoginResult };

export const loginFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { email: string; password: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as Record<string, unknown>).email !== 'string' ||
      typeof (data as Record<string, unknown>).password !== 'string'
    ) {
      throw new Error('Invalid input: expected { email: string; password: string }');
    }
    const { email, password } = data as { email: string; password: string };
    return { email, password };
  })
  .handler(loginHandler);
