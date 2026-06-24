import { createServerFn } from '@tanstack/react-start';

import { authServerClient, type RegisterData, type Result } from '../auth-server-client';

export async function registerHandler({
  data,
}: {
  data: { email: string; password: string };
}): Promise<Result<RegisterData>> {
  return authServerClient.register(data.email, data.password);
}

export const registerFn = createServerFn({ method: 'POST' })
  .inputValidator((data: unknown): { email: string; password: string } => {
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
  .handler(registerHandler);
