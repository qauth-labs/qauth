import { createServerFn } from '@tanstack/react-start';

import { authServerClient, type RegisterData, type Result } from '../auth-server-client';

export async function registerHandler({
  data,
}: {
  data: { email: string; password: string };
}): Promise<Result<RegisterData>> {
  return authServerClient.register(data.email, data.password);
}

export const registerFn = createServerFn({ method: 'POST' }).handler(registerHandler);
