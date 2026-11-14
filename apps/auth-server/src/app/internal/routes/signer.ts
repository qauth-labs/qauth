import {
  createSignerService,
  SIGNER_OPERATIONS,
  SIGNER_REQUEST_BODY_LIMITS,
  SIGNER_SERVICE_ROUTES,
  type SignerOperation,
} from '@qauth-labs/fastify-plugin-signer';
import { BadRequestError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { UnsupportedMediaTypeError } from '../../helpers/api-request-errors';
import { requestPeerIdentity, requestPeerRole } from '../listener';
import { createPeerRateLimit } from '../peer-rate-limit';

/**
 * THE SIGNER SERVICE (ADR-019 Decision 9, issue #497):
 * `POST /internal/signer/v1-rc.0/<operation>`, one route per operation of the
 * signer (`SIGNER_SERVICE_ROUTES`), on the internal listener of a process that
 * holds the signer while the roles are split. The other roles call it
 * through their remote signer, over mutual TLS.
 *
 * - **The certificate decides who calls.** The caller is the role
 *   INTERNAL_PEER_ROLES maps the peer's certificate to
 *   (`requestPeerRole`), never a name the request carries; the module
 *   admits the `web`, `api`, `delivery` and `admin` peers only. The signer
 *   service holds each call to that role's grant in `SIGNER_POLICY`, and
 *   every refusal is logged and counted
 *   (`qauth_signer_refusals_total{role,operation,reason}`).
 * - **Bounded.** Each operation takes at most its body of
 *   `SIGNER_REQUEST_BODY_LIMITS` (`413` past it), JSON only (`415`
 *   otherwise), and each peer at most {@link SIGNER_PEER_RATE_PER_SECOND}
 *   calls a second after a burst of {@link SIGNER_PEER_BURST} (`429`, with
 *   `Retry-After`), checked before its body is read.
 * - **Nothing secret in an error or a log.** A body that is not JSON is
 *   refused without quoting it; the service answers an error with its
 *   public fields only (`encodeSignerError`), and the logs name the role,
 *   the operation and the error's class, never a claim value, a plaintext
 *   or key material.
 * - **Never cached.** Every answer is `Cache-Control: no-store`: some carry
 *   secrets (cookie secrets, a decryption).
 */

/** The calls a second each peer may make once its burst is spent. */
export const SIGNER_PEER_RATE_PER_SECOND = 2_000;

/**
 * The calls each peer may make at once: a busy `api` process's token
 * requests of a second or two, which the signer serves in milliseconds each.
 */
export const SIGNER_PEER_BURST = 4_000;

/** The media type of every call. */
const JSON_MEDIA_TYPE = 'application/json';

export default async function signerServiceRoutes(fastify: FastifyInstance) {
  const service = createSignerService(fastify.signer);
  const rates = createPeerRateLimit({
    ratePerSecond: SIGNER_PEER_RATE_PER_SECOND,
    burst: SIGNER_PEER_BURST,
  });

  // The module's own body parser: JSON, read with the default parser's
  // refusal of `__proto__` and `constructor` keys, and refused without the
  // parser's message, which quotes the body. Any other media type is 415.
  fastify.removeAllContentTypeParsers();
  const parseJson = fastify.getDefaultJsonParser('error', 'error');
  fastify.addContentTypeParser(JSON_MEDIA_TYPE, { parseAs: 'string' }, (request, body, done) => {
    parseJson(request, typeof body === 'string' ? body : body.toString('utf8'), (error, value) => {
      if (error) {
        done(new BadRequestError('The request body is not a JSON object'), undefined);
        return;
      }
      done(null, value);
    });
  });
  fastify.addContentTypeParser('*', (_request, _payload, done) => {
    done(new UnsupportedMediaTypeError('A signer call is sent as application/json.'), undefined);
  });

  fastify.addHook('onSend', async (_request, reply, payload) => {
    reply.header('Cache-Control', 'no-store');
    return payload;
  });

  /** Spend one call of the peer's rate, or refuse the call with 429 before its body is read. */
  const limitPeer =
    (operation: SignerOperation) =>
    async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const verdict = rates.take(requestPeerIdentity(request));
      if (verdict.allowed) return;
      const role = requestPeerRole(request);
      fastify.metrics.signerRefusals.inc({ role, operation, reason: 'rate_limited' });
      if (verdict.logSuppressed !== undefined) {
        request.log.warn(
          { peerRole: role, operation, suppressed: verdict.logSuppressed },
          "Refused a signer call: the peer called faster than the signer service's rate"
        );
      }
      reply.header('Retry-After', String(Math.max(1, Math.ceil(verdict.retryAfterMs / 1000))));
      throw new TooManyRequestsError('The peer called the signer service too often');
    };

  for (const operation of SIGNER_OPERATIONS) {
    fastify.post(
      SIGNER_SERVICE_ROUTES[operation],
      {
        bodyLimit: SIGNER_REQUEST_BODY_LIMITS[operation],
        onRequest: limitPeer(operation),
      },
      async (request, reply) => {
        const role = requestPeerRole(request);
        const answer = await service.call(role, operation, request.body);
        if (answer.refused !== undefined) {
          fastify.metrics.signerRefusals.inc({
            role: answer.refused.caller,
            operation,
            reason: 'not_allowed',
          });
          request.log.warn(
            { peerRole: role, operation },
            "Refused a signer call the peer's role may not make"
          );
        }
        if (answer.fault !== undefined) {
          const unavailable =
            'error' in answer.body && answer.body.error.code === 'SIGNER_UNAVAILABLE';
          request.log.error(
            { peerRole: role, operation, fault: answer.fault },
            unavailable
              ? 'The signer cannot reach its keys: the call answers 503'
              : 'The signer failed a call'
          );
        }
        return reply.code(answer.status).send(answer.body);
      }
    );
  }
}
