import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';

/**
 * The signer of a process that does not hold the `signer` role (ADR-019
 * Decision 9, #495).
 *
 * Such a process holds no KEK and no key, so it cannot sign, encrypt or read a
 * secret itself; it is meant to call the signer service at `SIGNER_URL` over
 * mutual TLS, and that client (#497) is not built yet. Until it is, every
 * operation that needs a key fails closed with a 503
 * `TemporarilyUnavailableError`, so a route that needs a signature answers
 * `temporarily_unavailable`, never a token or a document signed with something
 * else.
 *
 * The two public reads are the exception (#491): `getVerificationKeys` and
 * `getJwks` answer from the realm's published keys through `publishedKeys`,
 * which reads public material only, so the process verifies a realm's tokens
 * with that realm's keys and serves its JWKS. Without a reader they refuse too.
 *
 * @param signerUrl - the configured signer service, for the operator's log
 * @param publishedKeys - the realm's published keys, read without a KEK
 */
export function createUnavailableSigner(
  signerUrl: string | undefined,
  publishedKeys?: Pick<FastifyInstance['signer'], 'getVerificationKeys' | 'getJwks'>
): FastifyInstance['signer'] {
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
    getVerificationKeys:
      publishedKeys === undefined
        ? refuse('getVerificationKeys')
        : publishedKeys.getVerificationKeys.bind(publishedKeys),
    getJwks:
      publishedKeys === undefined ? refuse('getJwks') : publishedKeys.getJwks.bind(publishedKeys),
    // The upstream assertion keys are named by the provider's key list in
    // `realm_keys`, which only the signer reads.
    getUpstreamJwks: refuse('getUpstreamJwks'),
  });
}
