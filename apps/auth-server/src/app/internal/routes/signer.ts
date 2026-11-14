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
import {
  createLogSampler,
  createPeerConcurrencyLimit,
  createPeerRateLimit,
} from '../peer-rate-limit';

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
 *   service holds each call to that role's grant in `SIGNER_POLICY`: a role
 *   with no grant for the operation is refused before its body is read.
 *   Every refusal is counted
 *   (`qauth_signer_refusals_total{role,operation,reason}`) and logged, one
 *   line a minute per peer and operation with how many it stands for.
 * - **Bounded per peer.** Each operation takes at most its body of
 *   `SIGNER_REQUEST_BODY_LIMITS` (`413` past it), JSON only (`415`
 *   otherwise). Each peer certificate gets {@link SIGNER_PEER_RATE_PER_SECOND}
 *   tokens a second after a burst of {@link SIGNER_PEER_BURST}, and a call
 *   costs one token per {@link SIGNER_RATE_UNIT_BYTES} its `Content-Length`
 *   declares, so a peer's bytes are bounded as well as its calls; and at most
 *   {@link SIGNER_PEER_MAX_IN_FLIGHT} of its calls run at once, so a peer
 *   that trickles its bodies holds that many at most (`429` with
 *   `Retry-After` for both). Both are checked before the body is read.
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

/**
 * The bytes of a call's body one token of a peer's rate stands for: a call
 * of up to this size costs one token, and a 1 MiB one 65, so the rate bounds
 * a peer to about 31 MiB a second.
 */
export const SIGNER_RATE_UNIT_BYTES = 16 * 1024;

/**
 * The calls each peer certificate may have in flight at once: four times
 * the sockets of one process's internal client, room for the processes that
 * share a certificate.
 */
export const SIGNER_PEER_MAX_IN_FLIGHT = 128;

/** What a call costs of its peer's rate: one token, and one more per {@link SIGNER_RATE_UNIT_BYTES} of its declared body. */
function costOf(request: FastifyRequest, operation: SignerOperation): number {
  const limit = SIGNER_REQUEST_BODY_LIMITS[operation];
  const declared = Number(request.headers['content-length']);
  // No declared length, as a chunked body has: charged as the largest it may be.
  const bytes = Number.isSafeInteger(declared) && declared >= 0 ? Math.min(declared, limit) : limit;
  return 1 + Math.floor(bytes / SIGNER_RATE_UNIT_BYTES);
}

/** The media type of every call. */
const JSON_MEDIA_TYPE = 'application/json';

export default async function signerServiceRoutes(fastify: FastifyInstance) {
  const service = createSignerService(fastify.signer);
  const rates = createPeerRateLimit({
    ratePerSecond: SIGNER_PEER_RATE_PER_SECOND,
    burst: SIGNER_PEER_BURST,
  });
  const inFlight = createPeerConcurrencyLimit(SIGNER_PEER_MAX_IN_FLIGHT);
  const refusalLogs = createLogSampler();

  /** Count a refusal of the peer's role, and log it once a minute per peer and operation. */
  const refusedRole = (request: FastifyRequest, caller: string, operation: SignerOperation) => {
    fastify.metrics.signerRefusals.inc({ role: caller, operation, reason: 'not_allowed' });
    const suppressed = refusalLogs.take(`${requestPeerIdentity(request)}\u0000${operation}`);
    if (suppressed !== undefined) {
      request.log.warn(
        { peerRole: requestPeerRole(request), operation, suppressed },
        "Refused a signer call the peer's role may not make"
      );
    }
  };

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

  /**
   * Before the call's body is read: spend its cost of the peer's rate, refuse
   * a role with no grant for the operation, and hold the peer to its calls in
   * flight. A refusal answers here, so the body is never parsed, and closes
   * the connection: kept alive, it would still take in the body the call
   * declared, so a refused peer could keep sending bodies it is refused for.
   */
  const admitPeer =
    (operation: SignerOperation) =>
    async (request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
      const identity = requestPeerIdentity(request);
      const role = requestPeerRole(request);
      const verdict = rates.take(identity, costOf(request, operation));
      if (!verdict.allowed) {
        fastify.metrics.signerRefusals.inc({ role, operation, reason: 'rate_limited' });
        if (verdict.logSuppressed !== undefined) {
          request.log.warn(
            { peerRole: role, operation, suppressed: verdict.logSuppressed },
            "Refused a signer call: the peer called faster than the signer service's rate"
          );
        }
        reply.header('Retry-After', String(Math.max(1, Math.ceil(verdict.retryAfterMs / 1000))));
        reply.header('Connection', 'close');
        throw new TooManyRequestsError('The peer called the signer service too often');
      }
      const refused = service.precheck(role, operation);
      if (refused !== undefined) {
        refusedRole(request, refused.refused?.caller ?? role, operation);
        return reply.code(refused.status).header('Connection', 'close').send(refused.body);
      }
      if (!inFlight.enter(identity)) {
        fastify.metrics.signerRefusals.inc({ role, operation, reason: 'in_flight' });
        const suppressed = refusalLogs.take(`${identity}\u0000in-flight`);
        if (suppressed !== undefined) {
          request.log.warn(
            { peerRole: role, operation, suppressed, inFlight: SIGNER_PEER_MAX_IN_FLIGHT },
            'Refused a signer call: the peer has the most calls in flight one peer may'
          );
        }
        reply.header('Retry-After', '1');
        reply.header('Connection', 'close');
        throw new TooManyRequestsError('The peer has too many signer calls in flight');
      }
      // Once the answer is sent, or the connection closed under it.
      reply.raw.once('close', () => inFlight.leave(identity));
      return undefined;
    };

  for (const operation of SIGNER_OPERATIONS) {
    fastify.post(
      SIGNER_SERVICE_ROUTES[operation],
      {
        bodyLimit: SIGNER_REQUEST_BODY_LIMITS[operation],
        onRequest: admitPeer(operation),
      },
      async (request, reply) => {
        const role = requestPeerRole(request);
        const answer = await service.call(role, operation, request.body);
        if (answer.refused !== undefined) refusedRole(request, answer.refused.caller, operation);
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
