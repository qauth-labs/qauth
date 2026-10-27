import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

/**
 * The signer of a process that does not hold the `signer` role (ADR-019
 * Decision 9, #495).
 *
 * Such a process holds no KEK and no key, so it cannot sign, encrypt or read a
 * key itself; it is meant to call the signer service at `SIGNER_URL` over
 * mutual TLS, and that client (#497) is not built yet. Until it is, every
 * operation fails closed with a 503 `TemporarilyUnavailableError`, so a route
 * that needs a signature answers `temporarily_unavailable`, never a token or a
 * document signed with something else.
 *
 * @param signerUrl - the configured signer service, for the operator's log
 */
export function createUnavailableSigner(signerUrl: string | undefined): FastifyInstance['signer'] {
  const refuse = (operation: string) => (): Promise<never> =>
    Promise.reject(
      new TemporarilyUnavailableError(60, {
        reason: 'signer_service_not_reachable',
        operation,
        ...(signerUrl === undefined ? {} : { signerUrl }),
      })
    );
  return Object.freeze({
    signJws: refuse('signJws'),
    signHybrid: refuse('signHybrid'),
    signWebhook: refuse('signWebhook'),
    signClientAssertion: refuse('signClientAssertion'),
    getCookieSecrets: refuse('getCookieSecrets'),
    encrypt: refuse('encrypt'),
    decrypt: refuse('decrypt'),
    getVerificationKeys: refuse('getVerificationKeys'),
    getJwks: refuse('getJwks'),
    getUpstreamJwks: refuse('getUpstreamJwks'),
  });
}
