import { createServerFn } from '@tanstack/react-start';

import type { Result } from '../auth-server-client';
import { listConsentsHandler, revokeConsentHandler } from './consents.server';

/**
 * Result returned to the browser when the portal session is missing or
 * expired, mirroring `clients.ts`. Answered without a network call so an
 * expired session renders a re-authentication prompt rather than a raw 401.
 */
export const UNAUTHENTICATED: Result<never> = {
  ok: false,
  error: {
    code: 'UNAUTHENTICATED',
    message: 'Your session has expired. Please log in again.',
    status: 401,
  },
};

export const listConsentsFn = createServerFn({ method: 'GET' }).handler(listConsentsHandler);

export const revokeConsentFn = createServerFn({ method: 'POST' })
  .validator((data: unknown): { id: string } => {
    if (
      typeof data !== 'object' ||
      data === null ||
      typeof (data as { id?: unknown }).id !== 'string'
    ) {
      throw new Error('Invalid input: expected { id: string }');
    }
    return { id: (data as { id: string }).id };
  })
  .handler(revokeConsentHandler);
