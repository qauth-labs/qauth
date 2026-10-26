import {
  InvalidClientError,
  JWTExpiredError,
  JWTInvalidError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { authenticateClient, extractClientCredentials } from '../../helpers/client-auth';
import { getPqcSignature } from '../../helpers/hybrid-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { realmTokenIssuer } from '../../helpers/realm-url';
import { requestRealm } from '../../helpers/request-realm';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { isJtiRevoked } from '../../helpers/token-revocation';
import { emitUserEvent, failureData } from '../../helpers/user-events';
import {
  type IntrospectRequest,
  introspectRequestSchema,
  introspectResponseSchema,
} from '../../schemas/oauth';

/**
 * POST /oauth/introspect
 * RFC 7662 token introspection endpoint.
 *
 * - Accepts access token in application/x-www-form-urlencoded body.
 * - Requires confidential client authentication (client_id + client_secret).
 * - Returns token activity and selected claims for valid tokens.
 * - Returns active: false for invalid, expired, or cross-client tokens.
 *
 * Authorization model (who may introspect what):
 *   1. Same-client: a client may always introspect tokens it itself issued
 *      (`payload.client_id === client.client_id`).
 *   2. Audience-bound: a resource server holds a confidential introspection
 *      client whose `audience` column lists the audiences it is authoritative
 *      for. If the token's `aud` is a member of the client's `audience`, the
 *      introspection is allowed. This is what lets a single resource server
 *      validate tokens minted by many distinct callers, without giving the
 *      resource server the ability to mint tokens for those audiences itself.
 *   Any other cross-client introspection returns `active: false`.
 */

/**
 * Canonical hex UUID shape (8-4-4-4-12). Used to gate the user lookup:
 * `users.id` is strictly a uuid column, so non-UUID subjects
 * (client_credentials client slugs, future service-account identifiers)
 * are never looked up as users.
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Returns true if the introspecting client is authoritative for the token's
 * audience: every token-aud value appears in the client's configured audience
 * list. Undefined/null/empty on either side returns false. Accepts both string
 * and string[] shapes for `payload.aud` per RFC 7519.
 */
function isClientAuthoritativeForAudience(
  payloadAud: string | string[] | undefined,
  clientAudience: string[] | null
): boolean {
  if (
    !payloadAud ||
    (Array.isArray(payloadAud) && payloadAud.length === 0) ||
    !clientAudience ||
    clientAudience.length === 0
  ) {
    return false;
  }
  const tokenAuds = Array.isArray(payloadAud) ? payloadAud : [payloadAud];
  return tokenAuds.every((a) => clientAudience.includes(a));
}
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/introspect',
    {
      schema: {
        description:
          'RFC 7662 token introspection. Send access token and client credentials in application/x-www-form-urlencoded body. Returns active and claims when token is valid for the client.',
        tags: ['OAuth', 'Introspection'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 503],
        body: introspectRequestSchema,
        response: {
          200: introspectResponseSchema,
        },
      },
      config: {
        surface: 'api',
        // An OAuth protocol endpoint: errors answer the RFC 6749 §5.2 body
        // (ADR-019 Decision 7, #513).
        errorFormat: 'oauth',
        rateLimit: {
          max: env.INTROSPECT_RATE_LIMIT,
          timeWindow: env.INTROSPECT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as IntrospectRequest;
      const { token } = body;
      // The realm and the authenticated caller, once known, for the
      // catch-all failure event below.
      let realmId: string | undefined;
      let callerClientId: string | undefined;

      try {
        const realm = requestRealm(request);
        realmId = realm.id;

        // Accept both `client_secret_post` (body) and `client_secret_basic`
        // (Authorization header) per RFC 6749 §2.3.
        let client;
        try {
          const creds = extractClientCredentials(request, body.client_id, body.client_secret);
          client = await authenticateClient(fastify, realm.id, creds);
        } catch (err) {
          // The caller did not authenticate: its claimed `client_id` is not
          // recorded as the event's client.
          await emitUserEvent(
            request,
            'urn:qauth:event:token.introspection_failed:v1-rc.0',
            failureData(err, 'client_authentication_failed'),
            { realmId: realm.id, actor: 'client' }
          );
          throw err;
        }
        callerClientId = client.clientId;
        // The caller is the authenticated resource server or client.
        const caller = { realmId: realm.id, clientId: client.clientId, actor: 'client' } as const;

        let payload;
        try {
          // RFC 9700 mix-up defence: pin the issuer so a token minted by a
          // different AS (even one sharing our signing key), or for another
          // realm's issuer (#489), is reported inactive rather than
          // introspected as ours.
          payload = await fastify.jwtUtils.verifyAccessToken(token, {
            issuer: realmTokenIssuer(fastify, realm),
          });
        } catch (error) {
          if (error instanceof JWTExpiredError || error instanceof JWTInvalidError) {
            await emitUserEvent(
              request,
              'urn:qauth:event:token.introspection_failed:v1-rc.0',
              failureData(
                error,
                error instanceof JWTExpiredError ? 'token_expired' : 'token_invalid'
              ),
              caller
            );

            await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

            return reply.send({
              active: false as const,
            });
          }

          throw error;
        }

        // RFC 7009 revocation: a signature-valid, unexpired token that has been
        // explicitly revoked MUST be reported inactive. Checked before the
        // authorization branch so a revoked token is never surfaced as active.
        if (await isJtiRevoked(fastify, payload.jti)) {
          await emitUserEvent(
            request,
            'urn:qauth:event:token.introspection_failed:v1-rc.0',
            { error: 'invalid_token', reason: 'token_revoked' },
            caller
          );

          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

          return reply.send({
            active: false as const,
          });
        }

        // Authorize the introspection: same-client OR audience-authoritative.
        const sameClient = payload.clientId === client.clientId;
        const audAuthoritative = isClientAuthoritativeForAudience(payload.aud, client.audience);
        if (!sameClient && !audAuthoritative) {
          await emitUserEvent(
            request,
            'urn:qauth:event:token.introspection_failed:v1-rc.0',
            { error: 'invalid_token', reason: 'client_not_authorized' },
            caller
          );

          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

          return reply.send({
            active: false as const,
          });
        }

        // A token's `sub` is a user UUID for authorization_code flows but a
        // client slug for client_credentials flows — and future grant types
        // could introduce service-account or prefixed subjects. Rather than
        // couple this to qauth's current emission convention, gate on the
        // `users.id` schema invariant itself: only a UUID-shaped `sub` is
        // looked up as a user.
        const subIsUuid = payload.sub !== undefined && UUID_REGEX.test(payload.sub);

        // A user's token is active only while the user exists and is enabled:
        // disabling an account must end the access it already holds at every
        // resource server that asks, as `/oauth/userinfo` and every grant
        // refuse it. A `client_credentials` token carries `sub = client_id`,
        // and a dynamically registered client's id is a random UUID, so the
        // UUID shape alone does not mark a user subject.
        const hasUserSubject = subIsUuid && payload.sub !== payload.clientId;
        if (hasUserSubject) {
          // Looked up in the request's realm (#489): another realm's user is
          // `subject_unknown` here, as a random id is.
          const user = await fastify.repositories.users.findById(realm.id, payload.sub as string);
          if (!user || !user.enabled) {
            // Only a subject the lookup confirmed is the event's subject: an
            // unknown one names no user.
            await emitUserEvent(
              request,
              'urn:qauth:event:token.introspection_failed:v1-rc.0',
              { error: 'invalid_token', reason: user ? 'user_disabled' : 'subject_unknown' },
              { ...caller, userId: user ? user.id : null }
            );

            await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

            return reply.send({
              active: false as const,
            });
          }
        }

        // The token's user, confirmed above, is the subject. A token with no
        // user subject (a client_credentials token, whose subject is its own
        // client) has none.
        await emitUserEvent(
          request,
          'urn:qauth:event:token.introspected:v1-rc.0',
          payload.clientId ? { tokenClientId: payload.clientId } : {},
          { ...caller, userId: hasUserSubject ? payload.sub : null }
        );

        // ADR-005 / #275 reference delivery: hand the resource server the
        // detached ML-DSA-65 signature it cannot receive in the bearer token
        // itself. Only reached AFTER the token verified AND the client was
        // authorized for it, so the PQC material is never disclosed to a caller
        // that is not already entitled to the token's claims. A store miss
        // simply omits the fields — it never affects the `active` decision.
        const pqc = await getPqcSignature(fastify, payload.jti, token);

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

        return reply.send({
          active: true as const,
          ...(pqc ? { pqc_signature: pqc.pqcSignature, pqc_alg: pqc.pqcAlg } : {}),
          sub: payload.sub,
          client_id: payload.clientId,
          exp: payload.exp,
          iat: payload.iat,
          iss: payload.iss,
          aud: payload.aud,
          scope: payload.scope,
          // RFC 9449 §6.2 (#480): a DPoP-bound token is reported as such, with
          // the key's thumbprint for the resource server to check the request's
          // proof against. A Bearer token's response is unchanged.
          ...(payload.cnf === undefined
            ? { token_type: 'Bearer' as const }
            : { token_type: 'DPoP' as const, cnf: { jkt: payload.cnf.jkt } }),
        });
      } catch (error) {
        // Both come only from client authentication, whose catch above already
        // recorded the event; the second is a secret check shed under load (#751).
        if (error instanceof InvalidClientError || error instanceof TemporarilyUnavailableError) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);
          throw error;
        }

        await emitUserEvent(
          request,
          'urn:qauth:event:token.introspection_failed:v1-rc.0',
          failureData(error),
          { realmId, clientId: callerClientId, actor: 'client' }
        );

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.INTROSPECT);

        throw error;
      }
    }
  );
}
