import { OID4VP_REQUEST_OBJECT_MEDIA_TYPE } from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../../config/env';
import { readWalletRequestObject } from '../../helpers/wallet-login-flow';

/**
 * `GET /oid4vp/request/:handle` — the JAR Request Object Endpoint
 * (RFC 9101 §5.2.2, HAIP 1.0 §5.1, issue #377).
 *
 * HAIP §5.1: *"Signed Authorization Requests MUST be used by utilizing
 * JWT-Secured Authorization Request (JAR) [RFC9101] with the `request_uri`
 * parameter."* This is the endpoint that `request_uri` points at. The wallet
 * fetches the signed request object from here, reads its `x5c` header, checks
 * the chain against a trust anchor IT holds, checks `client_id` against the
 * digest of the leaf, and only then verifies the signature.
 *
 * ## THIS ENDPOINT AUTHENTICATES NOBODY, AND IT CONSUMES NOTHING
 *
 * It reads a parked JWT by an unguessable handle and serves it. It does not
 * redeem the request `state`, does not touch Postgres, writes nothing anywhere,
 * and produces no audit record — which is deliberate and load-bearing on an
 * unauthenticated GET:
 *
 * - **Not consuming** because a wallet may fetch the request object and only
 *   later post a presentation, and some wallets retry the fetch (a dropped
 *   connection, a backgrounded app). Redeeming here would turn a retry into a
 *   failed login. Single use is enforced where it belongs — at `state`
 *   redemption in `POST /oid4vp/response`.
 * - **Writing nothing** because any write reachable before a caller has proven
 *   anything is an unbounded write primitive for an anonymous GET, which is the
 *   constraint the `direct_post` endpoint states for itself.
 *
 * ## Non-enumerating, for the reason there is nothing else to be
 *
 * An unknown handle, an expired one, a malformed one and an unreachable store
 * all produce the SAME 404 with no body of consequence. That is not a choice
 * between shapes so much as the only honest one: the handle is 32 CSPRNG bytes
 * and the store cannot tell "never existed" from "expired" anyway, so any
 * attempt to distinguish them would be inventing an oracle rather than
 * suppressing one. The reason is logged server-side; the wire says nothing.
 *
 * ## No `response` schema, deliberately
 *
 * The Zod serializer compiler is installed globally (`main.ts`), so a declared
 * `response` schema would JSON-serialize the body and emit a QUOTED string
 * instead of the compact JWS a wallet parses. The two other non-JSON endpoints
 * in this app — `GET /.well-known/jwks.json` and `GET /metrics` — declare none
 * for the same reason, and set their media type on the reply instead.
 */

/** How many characters of a fetch handle may reach the store (43 + slack). */
const MAX_REQUEST_OBJECT_HANDLE_LENGTH = 64;

export default async function (fastify: FastifyInstance) {
  // Flag gate (#232 / #299), repeated per route file because @fastify/autoload
  // registers each one as its own encapsulated plugin — this does not inherit
  // `response.ts`'s. Checked at REGISTRATION, not per request: an endpoint that
  // does not exist cannot be probed, and a deployment that never opted into
  // wallet federation should not grow an unauthenticated GET surface.
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug(
      'OID4VP request-object endpoint not registered (WALLET_FEDERATION_ENABLED is off)'
    );
    return;
  }

  fastify.get(
    '/request/:handle',
    {
      schema: {
        description:
          'OID4VP 1.0 / RFC 9101 Request Object Endpoint. Serves the signed Authorization Request a `request_uri` refers to, as application/oauth-authz-req+jwt. TRANSPORT ONLY: the request state is neither read nor consumed here, nothing is written, and an unknown or expired reference is indistinguishable from a malformed one.',
        tags: ['OID4VP'],
      },
      config: {
        // IP-scoped, in the shape every other unauthenticated surface in this
        // app uses. Its own budget rather than the response endpoint's: see
        // OID4VP_REQUEST_OBJECT_RATE_LIMIT for why the two halves of the
        // exchange are tuned separately.
        rateLimit: {
          max: env.OID4VP_REQUEST_OBJECT_RATE_LIMIT,
          timeWindow: env.OID4VP_REQUEST_OBJECT_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle?: unknown };

      // An edge bound before the store is touched, for the same reason every
      // other unauthenticated surface has one: a caller must not be able to
      // choose how much work a lookup costs. `readWalletRequestObject` re-checks
      // the shape itself, so this is a cheap outer bound rather than the
      // validation.
      const candidate =
        typeof handle === 'string' && handle.length <= MAX_REQUEST_OBJECT_HANDLE_LENGTH
          ? handle
          : undefined;

      const requestObject =
        candidate === undefined ? null : await readWalletRequestObject(fastify, candidate);

      if (requestObject === null) {
        fastify.log.warn(
          { ip: request.ip },
          'OID4VP request object not found (unknown, expired, malformed, or store unavailable)'
        );

        return reply.code(404).send();
      }

      // `no-store`, not the discovery endpoints' `public, max-age`. This body is
      // a single-flow artifact carrying that flow's `state` and `nonce`; a cache
      // that kept it would hand the next holder of the handle a request the
      // first one was still using.
      reply
        .header('Content-Type', OID4VP_REQUEST_OBJECT_MEDIA_TYPE)
        .header('Cache-Control', 'no-store');

      return reply.send(requestObject);
    }
  );
}
