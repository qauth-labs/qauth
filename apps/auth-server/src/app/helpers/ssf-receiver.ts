import { SSF_STREAM_SCOPE } from '@qauth-labs/fastify-plugin-ssf';
import { ForbiddenError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { type RealmRow, requestRealm } from './request-realm';

/**
 * A 404 of the SSF surface: a realm that does not run the transmitter, or a
 * stream the receiver does not have. It names nothing the caller did not
 * send, so it tells no receiver whether another receiver's stream exists.
 */
export class SsfNotFoundError extends Error {
  readonly statusCode = 404;

  constructor(message = 'Not found') {
    super(message);
    this.name = 'SsfNotFoundError';
  }
}

/** A receiver's OAuth client row, as the repository returns it. */
type ReceiverClientRow = NonNullable<
  Awaited<ReturnType<FastifyInstance['repositories']['oauthClients']['findByClientId']>>
>;

/** The receiver a stream management request comes from (issue #410). */
export interface SsfReceiver {
  readonly realm: RealmRow;
  readonly client: ReceiverClientRow;
}

declare module 'fastify' {
  interface FastifyRequest {
    /** Set by {@link createRequireSsfReceiver} on the SSF stream management routes. */
    ssfReceiver?: SsfReceiver;
  }
}

/**
 * Whether the request's realm runs the SSF transmitter: the deployment's
 * SSF_TRANSMITTER_ENABLED (the routes exist only when it is on) and the
 * realm's own switch. The realm row is the resolver's, up to its cache time
 * old, so a realm switched on or off takes that long to follow.
 */
export function realmRunsTransmitter(request: FastifyRequest): boolean {
  // A server built without the plugin, as unit tests build one, has none.
  return Boolean(request.server.ssf) && requestRealm(request).ssfTransmitterEnabled;
}

/**
 * The preHandler of the stream management routes (SSF 1.0 §8.1): the
 * request's receiver, or a refusal.
 *
 * - The realm must run the transmitter; otherwise the routes answer 404, as
 *   if they did not exist.
 * - `requireJwt` checks the access token: signature, `typ`, issuer,
 *   revocation and, with DPoP on, its proof.
 * - The token is a client's own (`client_credentials`): `sub` is its
 *   `client_id`, and it carries no `act`, so no user's or agent's delegated
 *   token manages a stream.
 * - It carries the `ssf:stream` scope, which the operator gives receivers;
 *   a token without it is a 403 (RFC 6750 §3.1, `insufficient_scope`).
 * - Its `aud` names the realm's issuer, the transmitter: a token minted for
 *   another resource, which that resource holds, cannot manage streams.
 * - The client exists in this realm and is enabled and not suspended.
 *
 * Every other refusal after the first is a 401 with an `invalid_token`
 * challenge, as RFC 6750 §3.1 prescribes for a token not valid for the
 * resource.
 */
export function createRequireSsfReceiver(
  fastify: FastifyInstance
): (request: FastifyRequest, reply: FastifyReply) => Promise<void> {
  return async function requireSsfReceiver(request, reply) {
    if (!realmRunsTransmitter(request)) throw new SsfNotFoundError();
    await fastify.requireJwt(request, reply);
    const claims = request.jwtPayload;
    if (!claims) throw new JWTInvalidError('Missing JWT payload');
    if (!claims.clientId || claims.sub !== claims.clientId || claims.act !== undefined) {
      throw new JWTInvalidError('Access token is not a receiver client token');
    }
    const scopes = (claims.scope ?? '').split(' ');
    if (!scopes.includes(SSF_STREAM_SCOPE)) {
      // RFC 6750 §3.1: a valid token without the scope is a 403.
      throw new ForbiddenError(`Access token lacks the ${SSF_STREAM_SCOPE} scope`);
    }
    const realm = requestRealm(request);
    const audiences = claims.aud === undefined ? [] : [claims.aud].flat();
    if (realm.issuer === null || !audiences.includes(realm.issuer)) {
      throw new JWTInvalidError('Access token audience is not this transmitter');
    }
    const client = await fastify.repositories.oauthClients.findByClientId(
      realm.id,
      claims.clientId
    );
    if (!client || !client.enabled || client.suspended) {
      throw new JWTInvalidError('Access token client is not an active receiver of this realm');
    }
    request.ssfReceiver = { realm, client };
  };
}

/** The receiver {@link createRequireSsfReceiver} found; a route without that preHandler has none. */
export function ssfReceiverOf(request: FastifyRequest): SsfReceiver {
  if (!request.ssfReceiver) throw new JWTInvalidError('Missing receiver');
  return request.ssfReceiver;
}
