import { EgressError } from '@qauth-labs/fastify-plugin-egress';

/**
 * TEST SUPPORT — the error the egress client rejects with when a check
 * refuses a destination (#481), for a unit test that mocks `egressGet`.
 */
export function blockedEgress(message: string): EgressError {
  return new EgressError({
    reason: 'address',
    outcome: 'blocked',
    purpose: 'test',
    host: 'blocked.example',
    message,
  });
}

/** The error the egress client rejects with when a fetch fails (a timeout here). */
export function failedEgress(message: string): EgressError {
  return new EgressError({
    reason: 'timeout',
    outcome: 'failed',
    purpose: 'test',
    host: 'slow.example',
    message,
  });
}
