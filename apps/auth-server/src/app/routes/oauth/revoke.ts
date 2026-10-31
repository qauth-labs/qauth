import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { authenticateClient, extractClientCredentials } from '../../helpers/client-auth';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { tokenRealm } from '../../helpers/realm-url';
import { type RealmRow, requestRealm } from '../../helpers/request-realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { revokeJti } from '../../helpers/token-revocation';
import { emitUserEvent, type EventTransaction, failureData } from '../../helpers/user-events';
import { type RevokeRequest, revokeRequestSchema } from '../../schemas/oauth';

/**
 * POST /oauth/revoke
 * RFC 7009 OAuth 2.0 Token Revocation.
 *
 * - Accepts a `token` (access or refresh) in an
 *   `application/x-www-form-urlencoded` body, with an advisory
 *   `token_type_hint`.
 * - Requires confidential client authentication (client_secret_basic or
 *   client_secret_post), reusing the same path as introspection.
 * - Only the client that owns a token may revoke it. A token belonging to a
 *   different client (or an unknown/invalid token) is a NO-OP — never an error,
 *   per RFC 7009 §2.2, so the endpoint cannot be used to probe token existence
 *   or ownership.
 * - ALWAYS returns HTTP 200 with an empty body on success (RFC 7009 §2.2),
 *   regardless of whether anything was actually revoked. The only non-200
 *   outcome is a client-authentication failure (`invalid_client`, §2.2.1),
 *   matching the introspection endpoint.
 *
 * Revocation mechanics:
 * - Refresh token: looked up by hash; if owned by the authenticated client, the
 *   whole token family is revoked (consistent with the rotation/replay model in
 *   the token endpoint) so no descendant can be exchanged. The revocation and
 *   its `token.revoked` event commit in one transaction (ADR-019 Decision 8).
 * - Access token (stateless JWT): verified, and if it was issued to the
 *   authenticated client its `jti` is added to the Redis denylist with a TTL of
 *   its remaining lifetime. The `requireJwt` preHandler and the introspection
 *   endpoint both consult that denylist. The denylist is Redis, so the event
 *   is recorded after it.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/revoke',
    {
      schema: {
        description:
          'RFC 7009 token revocation. Send the token and confidential client credentials in an application/x-www-form-urlencoded body. Always returns 200 with an empty body on success.',
        tags: ['OAuth', 'Revocation'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 503],
        body: revokeRequestSchema,
      },
      config: {
        surface: 'api',
        // An OAuth protocol endpoint: errors answer the RFC 6749 §5.2 body
        // (ADR-019 Decision 7, #513).
        errorFormat: 'oauth',
        rateLimit: {
          // Consistent with introspection — both are confidential-client,
          // token-bearing endpoints (#211 follow-up; reuses the introspect cap).
          max: env.INTROSPECT_RATE_LIMIT,
          timeWindow: env.INTROSPECT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as RevokeRequest;
      const { token, token_type_hint } = body;

      const realm = requestRealm(request);

      // Confidential client authentication (RFC 7009 §2.1). A failure here is
      // the ONLY non-200 outcome (`invalid_client`, §2.2.1).
      let client;
      try {
        const creds = extractClientCredentials(request, body.client_id, body.client_secret);
        client = await authenticateClient(fastify, realm.id, creds);
      } catch (err) {
        // The caller did not authenticate: its claimed `client_id` is not
        // recorded as the event's client.
        await emitUserEvent(
          request,
          'urn:qauth:event:token.revocation_failed:v1-rc.0',
          failureData(err, 'client_authentication_failed'),
          { realmId: realm.id, actor: 'client' }
        );
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);
        throw err;
      }

      // No token material is recorded; only the (advisory) hint. The user
      // whose token it was is the subject, so the SSF stream of this client
      // that added the user learns of it (#540); a revocation that matched no
      // token of the client, a family revoked already, or a client's own token
      // names no one.
      const record: RecordRevocation = async (userId, tx) => {
        await emitUserEvent(
          request,
          'urn:qauth:event:token.revoked:v1-rc.0',
          token_type_hint === undefined ? {} : { typeHint: token_type_hint },
          {
            ...(tx === undefined ? {} : { tx }),
            realmId: realm.id,
            userId,
            clientId: client.clientId,
            actor: 'client',
          }
        );
      };

      // RFC 7009 §2.1: the hint is advisory. It only picks which type is tried
      // first (refresh token by default); if the token is not found as that type
      // we still attempt the other. Either way the response is an empty 200.
      let revoked: Revoked | null;
      if (token_type_hint === 'access_token') {
        revoked =
          (await tryRevokeAccessToken(fastify, realm, client.clientId, token)) ??
          (await tryRevokeRefreshToken(fastify, realm, client.id, token, record));
      } else {
        revoked =
          (await tryRevokeRefreshToken(fastify, realm, client.id, token, record)) ??
          (await tryRevokeAccessToken(fastify, realm, client.clientId, token));
      }
      // The refresh path recorded its event with the family's revocation.
      if (revoked?.recorded !== true) await record(revoked?.userId ?? null);

      await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

      // RFC 7009 §2.2: empty body, HTTP 200.
      return reply.code(200).send();
    }
  );
}

/**
 * What a revocation found: the user whose token it was, or `null` for none;
 * `recorded` when the revocation recorded its `token.revoked` event itself.
 */
interface Revoked {
  readonly userId: string | null;
  readonly recorded: boolean;
}

/** Record the request's `token.revoked` event about `userId`, in `tx` when given. */
type RecordRevocation = (userId: string | null, tx?: EventTransaction) => Promise<void>;

/**
 * Revoke a refresh token (and its whole family) IFF it hashes to a stored row
 * owned by the authenticated client, and record the revocation in the same
 * transaction (ADR-019 Decision 8): the family is never revoked without its
 * event, so an SSF receiver is never left unaware of it. Returns `null` when
 * no owned token was found. A token owned by a DIFFERENT client is a no-op
 * (returns `null`) so cross-client revocation is impossible; so is a token of
 * another realm, which the realm-scoped lookup does not find (#489).
 *
 * Re-revocation is idempotent (RFC 7009 §2.2): a family revoked already
 * revokes nothing, and its event names no user, so a receiver gets no second
 * SET for it.
 */
async function tryRevokeRefreshToken(
  fastify: FastifyInstance,
  realm: RealmRow,
  clientRowId: string,
  token: string,
  record: RecordRevocation
): Promise<Revoked | null> {
  const hash = fastify.jwtUtils.hashRefreshToken(token);
  const stored = await fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked(
    realm.id,
    hash
  );
  if (!stored) return null;
  // Ownership: only the owning client may revoke. A mismatch is a silent no-op.
  if (stored.oauthClientId !== clientRowId) return null;
  // Revoke the entire family so no rotated descendant remains exchangeable
  // (consistent with the replay-revocation model in the token endpoint).
  const userId = await fastify.db.transaction(async (tx) => {
    const revokedCount = await fastify.repositories.refreshTokens.revokeFamily(
      stored.familyId,
      'client_revocation',
      tx
    );
    const revokedFor = revokedCount > 0 ? stored.userId : null;
    await record(revokedFor, tx);
    return revokedFor;
  });
  return { userId, recorded: true };
}

/**
 * Revoke an access token by denylisting its `jti` IFF it is a valid JWT issued
 * to the authenticated client. Returns the token's user when such a token was
 * denylisted, `null` otherwise. A token belonging to another client, an
 * invalid token, or one already expired is a silent no-op (RFC 7009 §2.2).
 */
async function tryRevokeAccessToken(
  fastify: FastifyInstance,
  realm: RealmRow,
  clientId: string,
  token: string
): Promise<Revoked | null> {
  let payload;
  try {
    // RFC 9700 mix-up defence: only a token this realm issued, under its
    // keys and its issuer (#490, #491).
    payload = await fastify.jwtUtils.verifyAccessToken(tokenRealm(realm), token);
  } catch (error) {
    // Invalid/expired/foreign-issuer token — nothing to revoke. Any other
    // failure (the key store unreachable) is the server's: it propagates, so
    // a token is never reported revoked when it was not checked (#491).
    if (error instanceof JWTInvalidError || error instanceof JWTExpiredError) return null;
    throw error;
  }
  // Ownership: only the client the token was issued for may revoke it.
  if (payload.clientId !== clientId) return null;
  if (!payload.jti || payload.exp === undefined) return null;
  // A client's own token (client_credentials) has the client as `sub`; any
  // other `sub` names a user, recorded only when it is one of the realm's.
  // Looked up before the denylist: a lookup that fails then leaves the token
  // as it was, rather than revoked with no event recorded.
  const user =
    !payload.sub || payload.sub === payload.clientId
      ? undefined
      : await fastify.repositories.users.findById(realm.id, payload.sub);
  const remainingSeconds = payload.exp - Math.floor(Date.now() / 1000);
  await revokeJti(fastify, payload.jti, remainingSeconds);
  return { userId: user?.id ?? null, recorded: false };
}
