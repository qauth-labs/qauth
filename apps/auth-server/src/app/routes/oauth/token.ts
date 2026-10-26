import { randomUUID } from 'node:crypto';

import { DpopProofError } from '@qauth-labs/fastify-plugin-dpop';
import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';
import {
  InvalidClientError,
  InvalidDpopProofError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  NotFoundError,
  TemporarilyUnavailableError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { resolveAcrClaims } from '../../helpers/acr-claims';
import { actDepth, MAX_DELEGATION_DEPTH } from '../../helpers/agent-audit';
import {
  authenticateClientRequest,
  enforceAgentScopeCap,
  type OAuthClientLike,
  resolveAudience,
  toAgentScopeContext,
  validateScopes,
} from '../../helpers/client-auth';
import { isAgentClient } from '../../helpers/client-resolution';
import { isScopeSubset } from '../../helpers/consent';
import { resolveIssuerIdentifier } from '../../helpers/discovery';
import { dpopEventReason, verifyTokenRequestProof } from '../../helpers/dpop';
import { resolveEmailClaimsForScopes } from '../../helpers/email-claims';
import {
  type EnvironmentPolicy,
  resolveAccessTokenLifespanSeconds,
  resolveEnvironmentPolicy,
} from '../../helpers/environment-policy';
import { issueAccessToken } from '../../helpers/hybrid-token';
import {
  idJagCredentialProviderType,
  IdJagValidationError,
  mintIdJag,
  type ValidatedIdJag,
  validateIdJagAssertion,
} from '../../helpers/id-jag';
import { resolveProfileClaimsForScopes } from '../../helpers/profile-claims';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import {
  refreshFamilyEnd,
  refreshFamilyEnded,
  refreshTokenExpiresAt,
} from '../../helpers/refresh-family';
import { requestRealm } from '../../helpers/request-realm';
import { highestAgentModeInScopes } from '../../helpers/scope-modes';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import { isJtiRevoked } from '../../helpers/token-revocation';
import { inactiveSubjectTokenError } from '../../helpers/token-subject';
import { emitUserEvent, failureData, oauthErrorCode } from '../../helpers/user-events';
import {
  type IdJagTokenResponse,
  JWT_BEARER_GRANT_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_GRANT_TYPES,
  TOKEN_TYPE_ACCESS_TOKEN,
  TOKEN_TYPE_ID_JAG,
  type TokenEndpointResponse,
  tokenEndpointResponseSchema,
  type TokenExchangeAuthCodeBody,
  tokenExchangeBodySchema,
  type TokenExchangeClientCredsBody,
  type TokenExchangeJwtBearerBody,
  type TokenExchangeRefreshBody,
  type TokenExchangeResponse,
  type TokenExchangeTokenExchangeBody,
} from '../../schemas/oauth';

/** The event of a token request that issued tokens. */
const TOKEN_ISSUED = 'urn:qauth:event:token.issued:v1-rc.0';
/** The event of a refused token request. */
const TOKEN_REQUEST_FAILED = 'urn:qauth:event:token.request_failed:v1-rc.0';

/**
 * RFC 6749 §5.2: a `grant_type` the endpoint does not serve is answered
 * `unsupported_grant_type`, not as a malformed request (#513). The body
 * schema is a union keyed on `grant_type`, so without this hook an unknown
 * value failed validation and answered `invalid_request`. A missing or
 * repeated `grant_type` is still the schema's to refuse: that request is
 * malformed. Runs before validation, so it reads the parsed body as sent.
 *
 * The jwt-bearer grant while `ID_JAG_ENABLED` is off is refused here too, as
 * the handler's master gate refuses it (ADR-011): exactly as an unknown grant
 * type, whatever else the body holds or lacks, with the gate's event.
 */
async function rejectUnsupportedGrantType(request: FastifyRequest): Promise<void> {
  const body = request.body;
  const grantType =
    typeof body === 'object' && body !== null
      ? (body as { grant_type?: unknown }).grant_type
      : undefined;
  if (typeof grantType !== 'string') return;
  if (grantType === JWT_BEARER_GRANT_TYPE && !env.ID_JAG_ENABLED) {
    await emitUserEvent(
      request,
      TOKEN_REQUEST_FAILED,
      { grantType, error: 'unsupported_grant_type', reason: 'id_jag_disabled' },
      { actor: 'client' }
    );
    throw new UnsupportedGrantTypeError();
  }
  if (!TOKEN_GRANT_TYPES.includes(grantType)) {
    throw new UnsupportedGrantTypeError();
  }
}

/**
 * POST /oauth/token
 *
 * OAuth 2.1 token endpoint. Supports:
 *  - `authorization_code` grant with PKCE (RFC 6749 4.1.3 + RFC 7636).
 *  - `client_credentials` grant for service-to-service auth (RFC 6749 4.4).
 *  - `refresh_token` grant with rotation + replay detection (RFC 6749 §6,
 *    OAuth 2.1 §4.3.1, RFC 9700 §2.2.2). Confidential and public clients
 *    both dispatch here; public clients authenticate by refresh-token
 *    ownership instead of a client secret.
 *
 *  - `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) for agent
 *    on-behalf-of delegation, and — when `ID_JAG_ENABLED` — for MINTING an
 *    Identity Assertion Authorization Grant (ID-JAG) targeted at a third-party
 *    resource authorization server (ADR-011).
 *  - `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523 §2.1) for
 *    CONSUMING an ID-JAG minted by a trusted enterprise IdP, issuing an access
 *    token audience-restricted to the MCP server the assertion names. Available
 *    only when `ID_JAG_ENABLED`; rejected as `unsupported_grant_type` otherwise.
 *
 * Client auth supports both `client_secret_post` (form body) and
 * `client_secret_basic` (Authorization header, RFC 6749 2.3.1).
 *
 * Issued JWTs include `iss`, `aud` (per-client, RFC 8707 light), `exp`, `iat`,
 * and `scope` (when granted). `client_credentials` tokens set `sub = client_id`
 * and do NOT include a refresh token (RFC 6749 4.4.3).
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/token',
    {
      schema: {
        description:
          'OAuth 2.1 token endpoint. Supports authorization_code (with PKCE) and client_credentials grants. Client auth via client_secret_post or client_secret_basic.',
        tags: ['OAuth', 'Token'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 503],
        body: tokenExchangeBodySchema,
        response: {
          // A UNION, not the Bearer-only schema: an ID-JAG mint (ADR-011) must
          // report `token_type: "N_A"` (RFC 8693 §2.2.1), which the Bearer
          // literal would reject at serialization time. The ID-JAG variant is
          // listed first inside the union so an `N_A` response matches it
          // instead of failing the Bearer branch.
          200: tokenEndpointResponseSchema,
        },
      },
      preValidation: rejectUnsupportedGrantType,
      config: {
        surface: 'api',
        // An OAuth protocol endpoint: errors answer the RFC 6749 §5.2 body
        // (ADR-019 Decision 7, #513).
        errorFormat: 'oauth',
        rateLimit: {
          // Environment-aware cap (ADR-008 §5, #209): a production realm ceiling
          // forces the strict cap; a development/staging ceiling permits the
          // lenient cap. Resolved from the request's realm (#487) because rate
          // limiting runs before the client is authenticated. Fail-safe to strict.
          max: (request: FastifyRequest) =>
            resolveRealmRateLimitMax(request.realm, {
              lenientMax: env.TOKEN_RATE_LIMIT_LENIENT,
              strictMax: env.TOKEN_RATE_LIMIT,
            }),
          timeWindow: env.TOKEN_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as
        | TokenExchangeAuthCodeBody
        | TokenExchangeClientCredsBody
        | TokenExchangeRefreshBody
        | TokenExchangeTokenExchangeBody
        | TokenExchangeJwtBearerBody;
      // The realm and the authenticated client once known, for the event of
      // the catch-all below.
      let realmId: string | undefined;
      let clientId: string | undefined;

      try {
        // ADR-011 MASTER GATE. With `ID_JAG_ENABLED` off the jwt-bearer grant
        // does not exist on this deployment, so it is refused HERE (and in
        // `rejectUnsupportedGrantType`, before validation, for a body the
        // schema would refuse) — before
        // client authentication, before any DB work — exactly as an unknown
        // grant type is. This keeps the flag-off behaviour equivalent to the
        // pre-ADR-011 build (which fell through to `unsupported_grant_type`)
        // and means a disabled feature costs an attacker one string compare.
        // Discovery does not advertise the grant when the flag is off, so this
        // answer leaks nothing a client could not already read there.
        if (body.grant_type === JWT_BEARER_GRANT_TYPE && !env.ID_JAG_ENABLED) {
          await emitUserEvent(
            request as FastifyRequest,
            TOKEN_REQUEST_FAILED,
            {
              grantType: body.grant_type,
              error: 'unsupported_grant_type',
              reason: 'id_jag_disabled',
            },
            { actor: 'client' }
          );
          throw new UnsupportedGrantTypeError();
        }

        const realm = requestRealm(request);
        realmId = realm.id;

        // Authenticate the client. authorization_code (PKCE) and
        // refresh_token both support public clients
        // (OAuth 2.1 §4.1.3 / §4.3.1 / RFC 6749 §6). The PKCE verifier /
        // refresh-token ownership binds the grant to the client; no
        // `client_secret` is required when `token_endpoint_auth_method:
        // 'none'`. client_credentials is confidential-only by definition.
        // `authenticateClientRequest` dispatches on the mechanism the request
        // PRESENTS (secret / `private_key_jwt` assertion / none), rejecting any
        // request that presents more than one (RFC 6749 §2.3), and then checks
        // that mechanism against what the client is REGISTERED for. Both
        // pre-existing branches are preserved exactly: with `allowPublic` it is
        // `authenticateClientPublicOrConfidential`, without it it is
        // `extractClientCredentials` + `authenticateClient`.
        //
        // client_credentials, token-exchange AND jwt-bearer are
        // CONFIDENTIAL-ONLY (`allowPublic: false`). For token-exchange this is a
        // deliberate security floor (RFC 9700, epic #181): on-behalf-of
        // delegation must not be mintable by a public client that proves nothing
        // but knowledge of a `client_id`. A public agent
        // (token_endpoint_auth_method=none) presents no credential at all, so it
        // is refused before any lookup.
        //
        // jwt-bearer is confidential-only DELIBERATELY (ADR-011). RFC 7523 §2.1
        // permits an assertion grant from an unauthenticated client, and this is
        // NOT widened to allow that: MCP EMA §5 has the client authenticate
        // "with its credentials as registered with the Resource Authorization
        // Server", and an ID-JAG's `client_id` claim can only be BOUND to a real
        // caller if that caller proved who it is. Without client authentication,
        // anyone who observed an assertion in transit could redeem it.
        // `private_key_jwt` (#384) satisfies this requirement too — that is the
        // CIMD-client route the EMA spec points at, and it needs no widening.
        let client: OAuthClientLike;
        try {
          client = await authenticateClientRequest(
            fastify,
            realm.id,
            request as FastifyRequest,
            body,
            {
              allowPublic:
                body.grant_type === 'authorization_code' || body.grant_type === 'refresh_token',
            }
          );
        } catch (err) {
          // The event records the refusal as a code. The prose
          // `authenticateClientAssertion` attaches to `errorDescription` (the
          // secret path throws bare on purpose) is not an event member: it can
          // name a `jwks_uri` target and the address it resolved to. It goes
          // to the operator's log, the one place it may be read.
          if (err instanceof InvalidClientError && err.errorDescription) {
            fastify.log.warn(
              { reqId: request.id, grantType: body.grant_type, reason: err.errorDescription },
              'token endpoint: client authentication refused'
            );
          }
          await emitUserEvent(
            request as FastifyRequest,
            TOKEN_REQUEST_FAILED,
            {
              grantType: body.grant_type,
              error: oauthErrorCode(err),
              reason: 'client_authentication_failed',
            },
            { realmId: realm.id, actor: 'client' }
          );
          // The reason stops here (ANT-2026-MW7I4DS4). The error handler renders
          // `errorDescription` as `error_description`, and an authentication
          // failure that describes itself is an oracle: it tells an
          // unauthenticated caller which client_ids are registered and enabled,
          // how they authenticate, and what a `jwks_uri` fetch found — including
          // the address an internal name resolves to when the SSRF guard blocks
          // it. Every mechanism answers with the bare `invalid_client`.
          throw err instanceof InvalidClientError ? new InvalidClientError() : err;
        }
        clientId = client.clientId;

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // RFC 9449 §5 (#480): the request's DPoP proof, while DPoP is on. A
        // valid proof binds every access token this request is issued to its
        // key (`cnf.jkt`, `token_type: DPoP`), whatever the grant ("regardless
        // of grant type"), and a client registered with
        // `dpop_bound_access_tokens` must send one (§5.2). Checked after client
        // authentication, so the event names the client and a confidential
        // client with a wrong secret never reaches the replay store (a public
        // client proves nothing but its `client_id`). While DPoP is off no
        // header is read and every access token is a Bearer token, as before.
        let dpopThumbprint: string | undefined;
        try {
          dpopThumbprint = await verifyTokenRequestProof(
            fastify,
            request as FastifyRequest,
            client
          );
        } catch (err) {
          if (!(err instanceof DpopProofError)) throw err;
          // Which check failed goes to the operator's log and the event, never
          // to the wire: it would help tune a forged proof. A replay store
          // outage refuses every proof, so it is logged as the server's error.
          fastify.log[err.reason === 'replay-store-unavailable' ? 'error' : 'warn'](
            { reqId: request.id, grantType: body.grant_type, reason: err.reason },
            'token endpoint: DPoP proof refused'
          );
          await emitUserEvent(
            request as FastifyRequest,
            TOKEN_REQUEST_FAILED,
            {
              grantType: body.grant_type,
              error: 'invalid_dpop_proof',
              reason: dpopEventReason(err.reason),
            },
            { realmId: realm.id, clientId: client.clientId, actor: 'client' }
          );
          throw new InvalidDpopProofError();
        }

        // ADR-008 §5/§7 (#197): resolve the effective environment policy ONCE,
        // here, where both the authenticated client and its realm are in scope.
        // The grant handlers consult this `policy` (token TTL tier, PKCE
        // requirement, refresh rotation) instead of re-deriving rules — the
        // single-resolver pattern from ADR-008 §7. Fail-safe: an unset client
        // or realm resolves to the `production` profile (hardened default).
        const policy = resolveEnvironmentPolicy(client, realm);

        // Route by grant type.
        if (body.grant_type === 'authorization_code') {
          const responseBody = await handleAuthorizationCode({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
            policy,
            realmId: realm.id,
            ssoMaxLifespan: realm.ssoMaxLifespan,
            dpopThumbprint,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'client_credentials') {
          const responseBody = await handleClientCredentials({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
            policy,
            realmId: realm.id,
            ssoMaxLifespan: realm.ssoMaxLifespan,
            dpopThumbprint,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'refresh_token') {
          const responseBody = await handleRefreshToken({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
            policy,
            realmId: realm.id,
            ssoMaxLifespan: realm.ssoMaxLifespan,
            dpopThumbprint,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === TOKEN_EXCHANGE_GRANT_TYPE) {
          const responseBody = await handleTokenExchange({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
            policy,
            realmId: realm.id,
            ssoMaxLifespan: realm.ssoMaxLifespan,
            dpopThumbprint,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === JWT_BEARER_GRANT_TYPE) {
          const responseBody = await handleJwtBearer({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
            policy,
            realmId: realm.id,
            ssoMaxLifespan: realm.ssoMaxLifespan,
            dpopThumbprint,
          });
          return reply.send(responseBody);
        }

        // `rejectUnsupportedGrantType` should have refused this already, but
        // guard anyway.
        throw new UnsupportedGrantTypeError();
      } catch (error) {
        // A client-secret check shed under load (#751) is thrown only by
        // client authentication, whose catch above already recorded it.
        if (
          error instanceof InvalidGrantError ||
          error instanceof InvalidTargetError ||
          error instanceof InvalidClientError ||
          error instanceof InvalidScopeError ||
          error instanceof InvalidRequestError ||
          error instanceof NotFoundError ||
          error instanceof UnsupportedGrantTypeError ||
          error instanceof UnauthorizedClientError ||
          error instanceof InvalidDpopProofError ||
          error instanceof TemporarilyUnavailableError
        ) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
          throw error;
        }

        await emitUserEvent(
          request as FastifyRequest,
          TOKEN_REQUEST_FAILED,
          { grantType: body.grant_type, ...failureData(error) },
          { realmId, clientId, actor: 'client' }
        );

        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
        throw error;
      }
    }
  );
}

type HandlerContext<TBody> = {
  fastify: FastifyInstance;
  request: FastifyRequest;
  client: OAuthClientLike;
  body: TBody;
  /**
   * The resolved environment policy for this (client, realm) (ADR-008 §7,
   * #197). Carries the access-token lifespan tier, PKCE requirement, and
   * refresh-rotation requirement the handler enforces. Always present — the
   * dispatch resolves it fail-safe to `production` before calling any handler.
   */
  policy: EnvironmentPolicy;
  /**
   * The realm the client authenticated in. Resolved once at dispatch alongside
   * the client itself, so a handler that needs a realm-scoped lookup (the
   * ID-JAG consume path resolves the assertion's subject through
   * `user_credentials`, which is keyed by realm) never re-resolves it and can
   * never disagree with the realm the client was authenticated against.
   */
  realmId: string;
  /**
   * The realm's `sso_max_lifespan` in seconds, or null when it sets none: the
   * longest a refresh-token family of the realm may live, counted from its
   * start (ADR-019 Decision 3, #552). Read from the same row as
   * {@link realmId}, the realm resolver's.
   */
  ssoMaxLifespan: number | null;
  /**
   * The RFC 7638 thumbprint of the request's DPoP proof key (RFC 9449 §5,
   * #480), checked at dispatch; undefined when the request carried no proof or
   * DPoP is off. Every access token the handler issues is bound to it
   * ({@link dpopConfirmation}, {@link tokenTypeFor}), and a code or refresh
   * token bound to a key is compared with it ({@link dpopBindingRefusal}).
   */
  dpopThumbprint: string | undefined;
};

/**
 * The RFC 9449 §6.1 `cnf` claim of the access token a request is issued:
 * `{ cnf: { jkt } }` to spread into the claims when the request proved a DPoP
 * key, nothing otherwise.
 */
function dpopConfirmation(ctx: { dpopThumbprint: string | undefined }): {
  cnf?: { jkt: string };
} {
  return ctx.dpopThumbprint === undefined ? {} : { cnf: { jkt: ctx.dpopThumbprint } };
}

/**
 * The `token_type` of the response (RFC 9449 §5): `DPoP` for an access token
 * bound to the request's key, `Bearer` otherwise.
 */
function tokenTypeFor(ctx: { dpopThumbprint: string | undefined }): 'DPoP' | 'Bearer' {
  return ctx.dpopThumbprint === undefined ? 'Bearer' : 'DPoP';
}

/** A public client: it authenticates with nothing but its `client_id` (RFC 6749 §2.1). */
function isPublicClient(client: OAuthClientLike): boolean {
  return client.tokenEndpointAuthMethod === 'none';
}

/**
 * The key a newly issued refresh token is bound to (RFC 9449 §5): the
 * request's proof key for a PUBLIC client, which nothing else binds; none for
 * a confidential client, whose refresh tokens client authentication already
 * binds, so it may rotate its DPoP key without losing them.
 */
function refreshTokenBinding(ctx: HandlerContext<unknown>): string | null {
  return isPublicClient(ctx.client) ? (ctx.dpopThumbprint ?? null) : null;
}

/**
 * Hold a code or refresh token bound to a DPoP key to that key (RFC 9449 §5,
 * §10): the request must carry a proof, already checked at dispatch, under the
 * key with the bound thumbprint. Returns the refusal, or undefined when the
 * artifact is unbound or the binding holds.
 *
 * A bound artifact is refused while DPoP is off (`invalid_grant`): its binding
 * can no longer be checked, and accepting it would turn it into a bearer
 * credential. The artifact is left as it is either way, so a party without the
 * key can neither redeem nor spend it.
 */
function dpopBindingRefusal(
  ctx: HandlerContext<unknown>,
  boundThumbprint: string | null | undefined
): { error: 'invalid_grant' | 'invalid_dpop_proof'; reason: string } | undefined {
  if (boundThumbprint === null || boundThumbprint === undefined) return undefined;
  if (!ctx.fastify.dpop) return { error: 'invalid_grant', reason: 'dpop_disabled' };
  if (ctx.dpopThumbprint === undefined) {
    return { error: 'invalid_dpop_proof', reason: 'dpop_missing_proof' };
  }
  // Thumbprints of public keys: nothing secret to compare in constant time.
  if (ctx.dpopThumbprint !== boundThumbprint) {
    return { error: 'invalid_dpop_proof', reason: 'dpop_key_mismatch' };
  }
  return undefined;
}

/**
 * Map the policy's access-token lifespan TIER to a concrete number of seconds,
 * in ONE place (ADR-008 §5, #197). The concrete numbers stay in config: the
 * `short` tier (staging/production) is `ACCESS_TOKEN_LIFESPAN`, the `long` tier
 * (development) is `DEV_ACCESS_TOKEN_LIFESPAN`. `getAccessTokenLifespan()`
 * remains the source of truth for the strict baseline; the dev relaxation only
 * lengthens it for a `development`-profile token. Callers pass the returned
 * value as `signAccessToken({ expiresInOverride })` AND as the response
 * `expires_in` so the advertised lifetime matches the signed `exp`.
 */
function accessTokenLifespanForPolicy(fastify: FastifyInstance, policy: EnvironmentPolicy): number {
  return resolveAccessTokenLifespanSeconds(policy.accessTokenLifespanTier, {
    shortSeconds: fastify.jwtUtils.getAccessTokenLifespan(),
    longSeconds: env.DEV_ACCESS_TOKEN_LIFESPAN,
  });
}

/**
 * Record a refused token request (`token.request_failed`) for a grant
 * handler: the dispatch's realm, the authenticated client as the actor, the
 * request's `grant_type`, and the end user when the grant names one.
 *
 * @param error - the OAuth `error` code the response carries
 * @param reason - why, as a `snake_case` code
 * @param userId - the end user the grant is for, when known
 */
async function emitRequestFailed(
  ctx: HandlerContext<{ grant_type: string }>,
  error: string,
  reason: string,
  userId: string | null = null
): Promise<void> {
  await emitUserEvent(
    ctx.request,
    TOKEN_REQUEST_FAILED,
    { grantType: ctx.body.grant_type, error, reason },
    { realmId: ctx.realmId, userId, clientId: ctx.client.clientId, actor: 'client' }
  );
}

/** What a caller is told about an authorization code it cannot redeem. */
const UNUSABLE_CODE = 'Invalid or expired authorization code';

/** What a caller is told about a refresh token it cannot use. */
const UNUSABLE_REFRESH_TOKEN = 'Invalid or expired refresh token';

/**
 * Spend a grant through its compare-and-set (`authorizationCodes.markUsed`,
 * `refreshTokens.revoke`). The repository answers a row that is no longer
 * unspent with `NotFoundError`: a concurrent request spent or revoked it
 * first. That is a grant the client may not use, RFC 6749 §5.2
 * `invalid_grant` with the usual wording, never a 404 `invalid_request`
 * naming the row's internal id.
 */
async function spendGrant<T>(spend: () => Promise<T>, description: string): Promise<T> {
  try {
    return await spend();
  } catch (error) {
    if (error instanceof NotFoundError) throw new InvalidGrantError(description);
    throw error;
  }
}

/**
 * Handle the authorization_code grant (legacy flow from Phase 1).
 * Now also issues `aud` + `scope` claims on the access token.
 */
async function handleAuthorizationCode(
  ctx: HandlerContext<TokenExchangeAuthCodeBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body, policy } = ctx;

  if (!client.grantTypes.includes('authorization_code')) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'grant_type_not_allowed');
    // RFC 6749 5.2: client authenticated, but not authorized for this grant.
    throw new UnauthorizedClientError();
  }

  // Authorization code lookup
  const authCode = await fastify.repositories.authorizationCodes.findByCode(body.code);
  if (!authCode) {
    await emitRequestFailed(ctx, 'invalid_grant', 'code_invalid');
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  if (authCode.oauthClientId !== client.id) {
    await emitRequestFailed(ctx, 'invalid_grant', 'client_mismatch', authCode.userId);
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  // Exact string match, port included (RFC 6749 §4.1.3). The loopback-port
  // relaxation of `redirectUriMatchesRegistered` (#414) applies only at the
  // authorization request: the code stores the URI as requested, with the
  // port the client actually listened on, so there is nothing to relax here.
  if (body.redirect_uri !== authCode.redirectUri) {
    await emitRequestFailed(ctx, 'invalid_grant', 'redirect_uri_mismatch', authCode.userId);
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  // PKCE enforcement (RFC 7636, OAuth 2.1 §4.1.3) under the environment policy
  // (ADR-008 §5, #197). The strict baseline — `production`/`staging`, and the
  // OAuth 2.1 default — REQUIRES a bound S256 challenge; `development` only
  // RECOMMENDS it. Two distinct cases:
  //
  //   1. No challenge bound to the code. Today the authorize endpoint always
  //      binds one (the schema mandates `code_challenge`), so this is a defence-
  //      in-depth guard for any future dev-only flow that mints a code without
  //      PKCE: when `policy.pkceRequired` it is rejected; in `development` it is
  //      allowed (with a warning) since PKCE is merely recommended there.
  //   2. PKCE DOWNGRADE (RFC 9700 §2.1.1 / §4.5): a `code_verifier` presented
  //      against a code that carries NO challenge must NEVER be silently
  //      accepted — that is the downgrade attack. This is a HARD FLOOR enforced
  //      in EVERY environment (including `development`): a verifier with no
  //      bound challenge is always `invalid_grant`.
  const hasBoundChallenge = authCode.codeChallenge.length > 0;
  if (!hasBoundChallenge) {
    // Downgrade defence first — a verifier with no bound challenge is rejected
    // regardless of environment (the resolver can never relax this floor).
    if (body.code_verifier.length > 0) {
      await emitRequestFailed(ctx, 'invalid_grant', 'pkce_downgrade', authCode.userId);
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    if (policy.pkceRequired) {
      await emitRequestFailed(ctx, 'invalid_grant', 'pkce_required', authCode.userId);
      throw new InvalidGrantError('Invalid or expired authorization code');
    }
    fastify.log.warn(
      { clientId: client.clientId, environment: policy.environment },
      'authorization_code exchanged without PKCE (recommended in development, required otherwise)'
    );
  }

  const pkceValid =
    !hasBoundChallenge ||
    fastify.pkceUtils.verifyCodeChallenge(body.code_verifier, authCode.codeChallenge);
  if (!pkceValid) {
    await emitRequestFailed(ctx, 'invalid_grant', 'pkce_mismatch', authCode.userId);
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  // RFC 9449 §10 (#480): a code the authorization request bound to a DPoP key
  // (`dpop_jkt`) is redeemed only with a proof under that key. It is not
  // burned on a refusal: whoever lacks the key cannot spend the code the
  // client is about to redeem.
  const codeBinding = dpopBindingRefusal(ctx, authCode.dpopJkt);
  if (codeBinding) {
    await emitRequestFailed(ctx, codeBinding.error, codeBinding.reason, authCode.userId);
    throw codeBinding.error === 'invalid_grant'
      ? new InvalidGrantError('Invalid or expired authorization code')
      : new InvalidDpopProofError();
  }

  // RFC 8707 §2.2: if the token request also includes `resource`, it MUST
  // be a subset of the one bound to the auth code. Empty request resource
  // carries forward the code's resource unchanged.
  const codeResource = authCode.resource ?? [];
  const requestedResource = body.resource ?? [];
  if (requestedResource.length > 0) {
    const extra = requestedResource.filter((r) => !codeResource.includes(r));
    if (extra.length > 0) {
      await emitRequestFailed(ctx, 'invalid_target', 'resource_outside_binding', authCode.userId);
      throw new InvalidTargetError('requested resource is outside the authorization-code binding');
    }
  }
  const effectiveResource = requestedResource.length > 0 ? requestedResource : codeResource;

  const user = await fastify.repositories.users.findById(authCode.userId);
  if (!user) {
    // The code names no user any more, so the event has none. Answered as the
    // disabled user below is (RFC 6749 §5.2 `invalid_grant`), so the answer
    // does not tell a deleted account from a disabled one (#513).
    await emitRequestFailed(ctx, 'invalid_grant', 'user_not_found');
    throw new InvalidGrantError('Invalid or expired authorization code');
  }
  // A code outlives the session that produced it by up to its TTL, and a user
  // disabled in between must not receive tokens for it — the same gate the
  // refresh, token-exchange and jwt-bearer grants apply (RFC 9700 §4.14). The
  // code is burned all the same, so it cannot be retried.
  if (!user.enabled) {
    await spendGrant(
      () => fastify.repositories.authorizationCodes.markUsed(authCode.id),
      UNUSABLE_CODE
    );
    await emitRequestFailed(ctx, 'invalid_grant', 'user_disabled', user.id);
    throw new InvalidGrantError(UNUSABLE_CODE);
  }

  // Clamp to the agent's CURRENT server-side `max_agent_mode` (ADR-007 §2,
  // #184), exactly as the refresh, client_credentials, jwt-bearer and token-
  // exchange grants do. The code carries the scopes approved under the cap as
  // it stood at consent time; if the operator has since lowered it (or the
  // client is no longer an agent), redeeming the code must not mint the old
  // mode. Fail-closed via `toAgentScopeContext`. The code is burned all the
  // same: a client cannot narrow a code, so it goes back through
  // /oauth/authorize.
  try {
    enforceAgentScopeCap(authCode.scopes, toAgentScopeContext(client));
  } catch (err) {
    await spendGrant(
      () => fastify.repositories.authorizationCodes.markUsed(authCode.id),
      UNUSABLE_CODE
    );
    await emitRequestFailed(ctx, oauthErrorCode(err), 'scope_exceeds_agent_mode', user.id);
    throw err;
  }

  // A refresh token is standing access, and the active consent row is the
  // user's only handle on it: `/consents` lists those rows, and consent
  // revocation reaches the refresh tokens through one. So a refresh token is
  // minted only under a stored consent that covers the code's scopes. An
  // approval given with "Remember this decision" unticked, a consent revoked
  // since the code was issued, and the legacy Bearer authorize path (which
  // stores no consent) yield the access token (and ID token) alone; the client
  // returns through /oauth/authorize when it expires.
  const consent = await fastify.repositories.oauthConsents.findActive(user.id, client.id);
  const familyCreatedAt = Date.now();
  const refresh =
    consent && isScopeSubset(authCode.scopes, consent.scopes)
      ? {
          ...fastify.jwtUtils.generateRefreshToken(),
          // The realm's `sso_max_lifespan` caps the family from its start,
          // and never past the browser session that backed the code
          // (ADR-019 Decision 3, #552).
          expiresAt: refreshTokenExpiresAt(
            familyCreatedAt,
            fastify.jwtUtils.getRefreshTokenLifespan(),
            refreshFamilyEnd(familyCreatedAt, ctx.ssoMaxLifespan, authCode.sessionExpiresAt ?? null)
          ),
          // Start a fresh refresh-token family. Every rotation (see
          // `handleRefreshToken`) inherits this `familyId` so replay of a
          // revoked token can be traced to — and revoke — the entire family,
          // and this start time, so the family's age counts from here.
          familyId: randomUUID(),
          familyCreatedAt,
          // The session's end as of the code's mint; every rotation copies it.
          familySessionExpiresAt: authCode.sessionExpiresAt ?? null,
        }
      : undefined;

  // Access-token lifespan under the environment policy (ADR-008 §5, #197):
  // `short` (staging/production baseline) vs `long` (development convenience),
  // mapped to concrete seconds in one place. Passed both as the signed `exp`
  // override and the response `expires_in` so they always agree.
  const accessTokenExpiresIn = accessTokenLifespanForPolicy(fastify, policy);
  const aud = resolveAudience(client, effectiveResource);

  const scopeString = authCode.scopes.length > 0 ? authCode.scopes.join(' ') : undefined;

  // BREAKING (#229, ADR-002): ONE trust-ordered resolution shared by the
  // access token AND the ID token, so the two can never disagree about the
  // email within a single issuance. Both claims are omitted entirely when no
  // verified email attribute exists.
  //
  // BREAKING (#259, then ANT-2026-2O0T72HY): released only under the `email`
  // scope, in BOTH tokens. The access token is a JWT the client reads in the
  // same response as the ID token, so gating only the ID token gated nothing.
  const emailClaims = await resolveEmailClaimsForScopes(fastify, user.id, authCode.scopes);

  // Spend the code and store the refresh token it buys in ONE transaction, so
  // the grant is never observable in between: code already used, refresh
  // token not yet there. Logout and consent revocation invalidate the user's
  // unredeemed codes before they sweep the refresh tokens; their UPDATE on
  // this code row either lands first, and the compare-and-set in `markUsed`
  // matches nothing, or waits on the row lock taken here until the refresh
  // token is committed, where the sweep that follows sees it. The
  // `token.issued` event commits with the redemption, or neither does.
  const { accessToken, idToken } = await fastify.db.transaction(async (tx) => {
    await spendGrant(
      () => fastify.repositories.authorizationCodes.markUsed(authCode.id, tx),
      UNUSABLE_CODE
    );
    if (refresh) {
      await fastify.repositories.refreshTokens.create(
        {
          userId: user.id,
          oauthClientId: client.id,
          tokenHash: refresh.tokenHash,
          familyId: refresh.familyId,
          familyCreatedAt: refresh.familyCreatedAt,
          familySessionExpiresAt: refresh.familySessionExpiresAt,
          expiresAt: refresh.expiresAt,
          scopes: authCode.scopes,
          // RFC 8707: carry the resource set onto the refresh token so subsequent
          // refreshes produce access tokens with the same `aud`.
          resource: effectiveResource,
          // RFC 9449 §5 (#480): a public client's refresh token is bound to
          // the proof key; a confidential client's is not.
          cnfJkt: refreshTokenBinding(ctx),
        },
        tx
      );
    }
    // Signed here, after the compare-and-set and before the event: a lost
    // race mints nothing, and a signing failure rolls the redemption back, so
    // the code is not spent and `token.issued` records only tokens that exist.
    const accessToken = await issueAccessToken(fastify, {
      sub: user.id,
      ...emailClaims,
      clientId: client.clientId,
      scope: scopeString,
      aud,
      ...dpopConfirmation(ctx),
      expiresInOverride: accessTokenExpiresIn,
    });

    // OIDC Core §3.1.3.3: when the granted scope includes `openid`, the token
    // response also carries an ID token asserting the end-user's authentication
    // to this client. `aud` is the client_id (NOT the resource audience used for
    // the access token), and the authorization request's `nonce` is echoed when
    // present (OIDC Core §3.1.3.6). Signed with the same EdDSA key as the access
    // token so a single JWKS verifies both.
    const idToken = authCode.scopes.includes('openid')
      ? await fastify.jwtUtils.signIdToken({
          sub: user.id,
          audience: client.clientId,
          // BREAKING (#259, data minimization): email claims are released only
          // under the `email` scope, matching userinfo's gating (OIDC Core
          // §5.4). `emailClaims` is already empty without it, and the shared
          // resolution keeps the access token and ID token consistent.
          ...emailClaims,
          // BREAKING (#755): `name` is released only under the `profile` scope,
          // through the same helper userinfo uses, so the two cannot drift.
          ...resolveProfileClaimsForScopes(user, authCode.scopes),
          nonce: authCode.nonce ?? undefined,
          // OIDC Core §2 `auth_time`: the real end-user authentication time
          // (session establishment), captured on the auth code at mint time. In
          // epoch MS here; signIdToken floors to seconds. Nullable on in-flight
          // codes minted before the column existed → omit the claim.
          authTime: authCode.authTime ?? undefined,
          // OIDC Core §2 `acr` (#237, ADR-004/ADR-010): the eIDAS Level of
          // Assurance of the authentication this code represents, rendered into
          // the deployment's `acr` vocabulary here rather than at mint time. A
          // NULL column — every password login, and every wallet login whose
          // issuer the realm assures nothing about — spreads to NOTHING, so the
          // claim is absent rather than present-and-low.
          ...resolveAcrClaims(authCode.assuranceLevel),
        })
      : undefined;

    await emitUserEvent(
      request,
      TOKEN_ISSUED,
      {
        grantType: body.grant_type,
        scopes: authCode.scopes,
        audience: audToArray(aud),
        ...(effectiveResource.length > 0 ? { resources: effectiveResource } : {}),
        expiresIn: accessTokenExpiresIn,
        ...(refresh ? { refreshFamilyId: refresh.familyId } : {}),
      },
      { tx, realmId: ctx.realmId, userId: user.id, clientId: client.clientId, actor: 'client' }
    );
    return { accessToken, idToken };
  });

  // Token issuance metrics (#126).
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'authorization_code' });
  if (refresh) {
    fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'authorization_code' });
  }

  return {
    access_token: accessToken,
    ...(refresh ? { refresh_token: refresh.token } : {}),
    expires_in: accessTokenExpiresIn,
    token_type: tokenTypeFor(ctx),
    ...(scopeString ? { scope: scopeString } : {}),
    ...(idToken ? { id_token: idToken } : {}),
  };
}

/**
 * Handle the client_credentials grant (RFC 6749 4.4).
 *
 * - `sub` = clientId (no end-user).
 * - No refresh token issued (RFC 6749 4.4.3).
 * - Scopes must be a subset of client's configured `scopes` column.
 * - `aud` resolves from client.audience (default: clientId).
 */
async function handleClientCredentials(
  ctx: HandlerContext<TokenExchangeClientCredsBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body, policy } = ctx;

  if (!client.grantTypes.includes('client_credentials')) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'grant_type_not_allowed');
    // RFC 6749 5.2: client authenticated, but not authorized for this grant.
    throw new UnauthorizedClientError();
  }

  // Validate requested scopes against client.scopes allowlist, additionally
  // clamping any reserved agent-mode scope (`agent:readonly|admin|exec`) to the
  // agent client's server-side `max_agent_mode` (ADR-007 §2, #184 — wired now
  // that #182/#183/#184 are merged). Deny-by-default + fail-closed via
  // `toAgentScopeContext`: a non-agent client (incl. one that omitted
  // `is_agent`) or one over its cap can never mint a machine token carrying an
  // agent-mode scope, even if that scope also sits in its raw allowlist.
  let grantedScopes: string[];
  try {
    grantedScopes = validateScopes(body.scope, client.scopes, toAgentScopeContext(client));
  } catch (err) {
    await emitRequestFailed(ctx, oauthErrorCode(err), 'scope_not_allowed_for_client');
    throw err;
  }

  // A scopeless machine token has no authorisation surface — almost always a
  // misconfiguration. Require at least one granted scope per RFC 9700 best
  // practice for client_credentials tokens.
  if (grantedScopes.length === 0) {
    await emitRequestFailed(ctx, 'invalid_scope', 'scope_required');
    throw new InvalidScopeError('client_credentials grant requires at least one scope');
  }

  const scopeString = grantedScopes.join(' ');

  // RFC 8707 §2.2: machine clients MAY include `resource` to scope the
  // minted token to a specific resource server, but only WITHIN the
  // client's pre-configured audience allowlist. Without this check, a
  // compromised machine-client credential could mint tokens for arbitrary
  // resource URIs — including resource servers it was never configured
  // to reach. Falls back to `[client.clientId]` when the client has no
  // explicit audience, matching resolveAudience's light-mode default.
  const requestedResource = body.resource ?? [];
  if (requestedResource.length > 0) {
    const allowedAudience =
      client.audience && client.audience.length > 0 ? client.audience : [client.clientId];
    const extra = requestedResource.filter((r) => !allowedAudience.includes(r));
    if (extra.length > 0) {
      await emitRequestFailed(ctx, 'invalid_target', 'resource_outside_client_audience');
      throw new InvalidTargetError('requested resource is outside the client audience allowlist');
    }
  }

  // Access-token lifespan under the environment policy (ADR-008 §5, #197).
  const accessTokenExpiresIn = accessTokenLifespanForPolicy(fastify, policy);

  const aud = resolveAudience(client, requestedResource);
  const accessToken = await issueAccessToken(fastify, {
    sub: client.clientId,
    clientId: client.clientId,
    scope: scopeString,
    aud,
    ...dpopConfirmation(ctx),
    expiresInOverride: accessTokenExpiresIn,
  });

  // Per-agent action audit (ADR-007 §2, #186). client_credentials has no
  // subject user and no on-behalf-of `act` chain — the client acts as itself,
  // so the event has no subject and its actor is the client. Only an agent
  // client (fail-closed `isAgentClient`) has its effective scope mode
  // recorded; an ordinary machine client records none.
  const scopeMode = isAgentClient(client) ? highestAgentModeInScopes(grantedScopes) : null;
  await emitUserEvent(
    request,
    TOKEN_ISSUED,
    {
      grantType: body.grant_type,
      scopes: grantedScopes,
      audience: audToArray(aud),
      ...(requestedResource.length > 0 ? { resources: requestedResource } : {}),
      expiresIn: accessTokenExpiresIn,
      ...(scopeMode === null ? {} : { scopeMode }),
    },
    { realmId: ctx.realmId, clientId: client.clientId, actor: 'client' }
  );

  // Token issuance metrics (#126). No refresh token on client_credentials.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'client_credentials' });

  return {
    access_token: accessToken,
    expires_in: accessTokenExpiresIn,
    token_type: tokenTypeFor(ctx),
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * Revoke a refresh-token family on replay and answer `invalid_grant`.
 *
 * RFC 9700 §2.2.2 / OAuth 2.1 §4.3.1: presenting a refresh token that is no
 * longer live means either the client or an attacker holds a copy, so every
 * token descended from the same grant is revoked. Reached two ways — the token
 * was already revoked when read, or a concurrent request rotated it between
 * the read and this request's compare-and-set — and both are the same event.
 */
async function rejectRefreshTokenReplay(
  ctx: HandlerContext<TokenExchangeRefreshBody>,
  storedToken: { userId: string; familyId: string }
): Promise<never> {
  await ctx.fastify.repositories.refreshTokens.revokeFamily(
    storedToken.familyId,
    'replay_detected'
  );
  await emitRequestFailed(ctx, 'invalid_grant', 'refresh_replay', storedToken.userId);
  throw new InvalidGrantError('Invalid or expired refresh token');
}

/**
 * Handle the refresh_token grant (RFC 6749 §6, OAuth 2.1 §4.3.1).
 *
 * Security invariants enforced here:
 * - The client (confidential or public) must be enabled and allowed the
 *   `refresh_token` grant type (RFC 6749 §5.2 `unauthorized_client`).
 * - Presented refresh token must hash to a row that is either active OR
 *   revoked-but-known. Unknown/expired → `invalid_grant`.
 * - Ownership: `refreshToken.oauthClientId === client.id` (OAuth 2.1
 *   §4.3.1). Cross-client presentation → `invalid_grant`.
 * - Replay detection (RFC 9700 §2.2.2): if a revoked token is presented,
 *   revoke the entire family (every rotation sharing `family_id`) so any
 *   still-active descendant cannot be exchanged.
 * - Family lifetime (ADR-019 Decision 3, #552): when the realm sets
 *   `sso_max_lifespan`, a family ends that long after its start. Past it the
 *   family is revoked and the answer is `invalid_grant`; before it, the
 *   rotated token expires no later than the family's end.
 * - Rotation: the presented token is marked `revoked='rotated'` BEFORE
 *   the new refresh token is persisted, by a compare-and-set that only one
 *   concurrent request can win — never issue two concurrently live tokens
 *   for the same link in the family chain. The loser is a replay.
 * - Down-scoping: a `scope` param may request a subset of the original
 *   scopes; any scope not present in the original set → `invalid_scope`.
 *   Omitting the parameter reuses the original scopes verbatim.
 */
async function handleRefreshToken(
  ctx: HandlerContext<TokenExchangeRefreshBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body, policy } = ctx;

  // ADR-008 §5 (#197) refresh-token rotation. The profile knob
  // `policy.refreshRotationRequired` is true for staging/production and false
  // for development. QAuth ALWAYS rotates on every refresh — revoke-then-issue
  // in a single transaction, with family-wide replay detection (see the
  // rotation block below) — so the requirement is trivially SATISFIED in every
  // environment, and `development` does NOT relax it below the implemented
  // behaviour (rotation stays on; the dev knob would only permit a non-rotating
  // implementation, which QAuth deliberately does not offer). The access-token
  // LIFESPAN is the only refresh-path knob the environment actually moves
  // (`policy.accessTokenLifespanTier`, applied below).
  void policy.refreshRotationRequired;

  if (!client.grantTypes.includes('refresh_token')) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'grant_type_not_allowed');
    throw new UnauthorizedClientError();
  }

  const presentedHash = fastify.jwtUtils.hashRefreshToken(body.refresh_token);

  // Fetch the row without any active-state filter so replay of a
  // revoked token is detectable; downstream checks enforce liveness.
  const storedToken =
    await fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked(presentedHash);

  if (!storedToken) {
    await emitRequestFailed(ctx, 'invalid_grant', 'refresh_token_unknown');
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Ownership check — before any replay logic, before any revocation.
  // Cross-client replay must never be able to fan out family revocation
  // on another client's tokens.
  if (storedToken.oauthClientId !== client.id) {
    await emitRequestFailed(ctx, 'invalid_grant', 'client_mismatch', storedToken.userId);
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // RFC 9449 §5 (#480): a refresh token bound to a DPoP key is used only with
  // a proof under that key. Checked before replay detection, so a party that
  // holds a rotated copy but not the key cannot revoke the client's family.
  const refreshBinding = dpopBindingRefusal(ctx, storedToken.cnfJkt);
  if (refreshBinding) {
    await emitRequestFailed(ctx, refreshBinding.error, refreshBinding.reason, storedToken.userId);
    throw refreshBinding.error === 'invalid_grant'
      ? new InvalidGrantError('Invalid or expired refresh token')
      : new InvalidDpopProofError();
  }

  // Replay detection — a revoked token in the correct family MUST trigger
  // family-wide revocation per RFC 9700 §2.2.2 / OAuth 2.1 §4.3.1.
  if (storedToken.revoked) {
    return rejectRefreshTokenReplay(ctx, storedToken);
  }

  // The family's end under the realm's CURRENT `sso_max_lifespan` (ADR-019
  // Decision 3, #552), counted from the family's start and never past the
  // browser session that started it. Checked before the token's own expiry,
  // which the end also caps: past it the whole family is revoked, not only
  // this token. A realm that lowered the limit since the token was issued ends
  // the family here, at its next use.
  const now = Date.now();
  const familyEnd = refreshFamilyEnd(
    storedToken.familyCreatedAt,
    ctx.ssoMaxLifespan,
    storedToken.familySessionExpiresAt ?? null
  );
  if (refreshFamilyEnded(familyEnd, now)) {
    await fastify.repositories.refreshTokens.revokeFamily(storedToken.familyId, 'family_expired');
    await emitRequestFailed(ctx, 'invalid_grant', 'refresh_family_expired', storedToken.userId);
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  if (storedToken.expiresAt <= now) {
    await emitRequestFailed(ctx, 'invalid_grant', 'refresh_token_expired', storedToken.userId);
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Load the subject user; reject if missing or disabled (RFC 9700 §4.14).
  const user = await fastify.repositories.users.findById(storedToken.userId);
  if (!user) {
    await emitRequestFailed(ctx, 'invalid_grant', 'user_not_found');
    throw new InvalidGrantError('Invalid or expired refresh token');
  }
  if (!user.enabled) {
    await spendGrant(
      () => fastify.repositories.refreshTokens.revoke(storedToken.id, 'user_disabled'),
      UNUSABLE_REFRESH_TOKEN
    );
    await emitRequestFailed(ctx, 'invalid_grant', 'user_disabled', user.id);
    throw new InvalidGrantError(UNUSABLE_REFRESH_TOKEN);
  }

  // Down-scoping: request narrower scope or keep original set.
  // Upscoping (any scope not in the original set) → invalid_scope.
  let grantedScopes: string[];
  if (body.scope !== undefined) {
    // De-duplicated, as token exchange does: the result is stored on the
    // rotated token, so a repeated name would grow the stored list on every
    // refresh. Membership goes through a Set, so the check is linear however
    // long the stored list already is.
    const requested = [...new Set(body.scope.split(/\s+/).filter((s) => s.length > 0))];
    const original = new Set(storedToken.scopes);
    const extraneous = requested.filter((s) => !original.has(s));
    if (extraneous.length > 0) {
      await emitRequestFailed(ctx, 'invalid_scope', 'scope_exceeds_refresh_token', user.id);
      throw new InvalidScopeError(`${extraneous.join(' ')} not in original refresh token scope`);
    }
    grantedScopes = requested;
  } else {
    // De-duplicated too, so a list stored with repeats before the refresh
    // `scope` was de-duplicated shrinks on its next rotation.
    grantedScopes = [...new Set(storedToken.scopes)];
  }

  // Clamp to the agent's CURRENT server-side `max_agent_mode` (ADR-007 §2,
  // #184), exactly as client_credentials, jwt-bearer and token exchange do. A
  // refresh token carries the scopes of the grant it came from; if the
  // operator has since lowered the cap (or the client is no longer an agent),
  // refreshing must not keep minting the old mode. The client may narrow with
  // `scope` to continue within the new cap. Fail-closed via
  // `toAgentScopeContext`.
  //
  // The same holds for the client's CURRENT `scopes` allowlist, the ceiling
  // `/oauth/authorize`, client_credentials and jwt-bearer apply: a scope taken
  // off the client after the grant must not keep being minted from the refresh
  // token. `validateScopes` runs both checks.
  try {
    validateScopes(grantedScopes.join(' '), client.scopes, toAgentScopeContext(client));
  } catch (err) {
    await emitRequestFailed(ctx, oauthErrorCode(err), 'scope_not_allowed_for_client', user.id);
    throw err;
  }

  // RFC 8707 §2.2: refresh requests MAY include `resource` to narrow the
  // audience of the minted access token, but MUST NOT request a resource
  // outside the set bound to the refresh token (which itself descends
  // from the auth code). Empty request resource carries the stored set
  // forward unchanged.
  const storedResource = storedToken.resource ?? [];
  const requestedResource = body.resource ?? [];
  if (requestedResource.length > 0) {
    const extra = requestedResource.filter((r) => !storedResource.includes(r));
    if (extra.length > 0) {
      await emitRequestFailed(ctx, 'invalid_target', 'resource_outside_binding', user.id);
      throw new InvalidTargetError('requested resource is outside the refresh-token binding');
    }
  }
  const effectiveResource = requestedResource.length > 0 ? requestedResource : storedResource;

  // Rotate atomically: revoke the presented token and insert the new one
  // inside a single transaction so a crash/failure between the two steps
  // can never leave the user with a revoked token and no replacement.
  //
  // The revoke is a compare-and-set on `revoked = false`
  // (`revokeIfActive`). The liveness check above read a snapshot, and two
  // concurrent presentations of the same token can both pass it; the second
  // UPDATE then waits on the first's row lock, re-evaluates the predicate,
  // and matches nothing. That request writes nothing, and the lost race is
  // handled as the replay it is (family revoke + invalid_grant) — never as a
  // second child in the same family. The unique index on `token_hash`
  // protects against the degenerate collision case.
  //
  // The `token.issued` event records the rotation, so it commits with it, or
  // neither does. A lost race writes no event here; the replay records its own.
  const { token: newRefreshToken, tokenHash: newRefreshTokenHash } =
    fastify.jwtUtils.generateRefreshToken();
  // Never past the family's end (#552); the refresh lifespan from now otherwise.
  const newRefreshTokenExpiresAt = refreshTokenExpiresAt(
    now,
    fastify.jwtUtils.getRefreshTokenLifespan(),
    familyEnd
  );

  // Access-token lifespan under the environment policy (ADR-008 §5, #197).
  const accessTokenExpiresIn = accessTokenLifespanForPolicy(fastify, policy);
  const aud = resolveAudience(client, effectiveResource);

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;

  // BREAKING (#229): trust-ordered resolution; omitted when unverified. Only
  // under the refreshed grant's `email` scope (ANT-2026-2O0T72HY).
  const emailClaims = await resolveEmailClaimsForScopes(fastify, user.id, grantedScopes);

  const accessToken = await fastify.db.transaction(async (tx) => {
    const revoked = await fastify.repositories.refreshTokens.revokeIfActive(
      storedToken.id,
      'rotated',
      tx
    );
    if (!revoked) return undefined;
    await fastify.repositories.refreshTokens.create(
      {
        userId: user.id,
        oauthClientId: client.id,
        tokenHash: newRefreshTokenHash,
        familyId: storedToken.familyId,
        // The family's start and its session's end, unchanged: a rotation
        // never restarts its clock or lifts the session's cap.
        familyCreatedAt: storedToken.familyCreatedAt,
        familySessionExpiresAt: storedToken.familySessionExpiresAt ?? null,
        previousTokenHash: presentedHash,
        expiresAt: newRefreshTokenExpiresAt,
        scopes: grantedScopes,
        // RFC 8707: the rotated refresh token carries the (possibly
        // narrowed) resource binding — NOT the request's — so we never
        // widen the binding across a rotation.
        resource: effectiveResource,
        // RFC 9449 §5 (#480): every rotation keeps the family's DPoP key; a
        // public client's unbound token is bound to the key it proves now.
        cnfJkt: storedToken.cnfJkt ?? refreshTokenBinding(ctx),
      },
      tx
    );
    // Signed here, after the compare-and-set and before the event: a lost
    // race mints nothing, and a signing failure rolls the rotation back, so
    // the presented token stays live and `token.issued` records only a token
    // that exists.
    const signed = await issueAccessToken(fastify, {
      sub: user.id,
      ...emailClaims,
      clientId: client.clientId,
      scope: scopeString,
      aud,
      ...dpopConfirmation(ctx),
      expiresInOverride: accessTokenExpiresIn,
    });
    await emitUserEvent(
      request,
      TOKEN_ISSUED,
      {
        grantType: body.grant_type,
        scopes: grantedScopes,
        audience: audToArray(aud),
        ...(effectiveResource.length > 0 ? { resources: effectiveResource } : {}),
        expiresIn: accessTokenExpiresIn,
        refreshFamilyId: storedToken.familyId,
      },
      { tx, realmId: ctx.realmId, userId: user.id, clientId: client.clientId, actor: 'client' }
    );
    return signed;
  });

  if (accessToken === undefined) {
    return rejectRefreshTokenReplay(ctx, storedToken);
  }

  // Token issuance metrics (#126). Refresh-token rotation mints both.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'refresh_token' });
  fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'refresh_token' });

  return {
    access_token: accessToken,
    refresh_token: newRefreshToken,
    expires_in: accessTokenExpiresIn,
    token_type: tokenTypeFor(ctx),
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * Normalise a JWT `aud` claim (string | string[] | undefined) to a string[].
 */
function audToArray(aud: string | string[] | undefined): string[] {
  if (aud === undefined) return [];
  return Array.isArray(aud) ? aud : [aud];
}

/**
 * Collapse a string[] back to the JWT `aud` shape (single → string).
 */
function arrayToAud(values: string[]): string | string[] {
  return values.length === 1 ? values[0] : values;
}

/**
 * Handle the OAuth 2.0 Token Exchange grant (RFC 8693) — QAuth's agent
 * on-behalf-of delegation (ADR-007 §2). An **agent** client presents a user's
 * `subject_token` and receives a delegated access token whose `sub` is the
 * user and whose `act` (actor) claim identifies the agent (nested for chained
 * delegation). This is an MCP auth *extension* (ext-auth), not core MCP.
 *
 * Security invariants (epic #181 default-deny: `is_agent` is self-asserted and
 * NEVER sufficient on its own):
 *  - GATE 1 — agent classification: `isAgentClient(client)` must hold AND the
 *    client must be allowed the token-exchange grant. Non-agent clients are
 *    rejected with `unauthorized_client` (RFC 6749 §5.2). The client is
 *    already authenticated + enabled at this point (client-auth path).
 *  - GATE 2 — token-type support: only `urn:...:token-type:access_token` is
 *    accepted for `subject_token_type` / `actor_token_type` /
 *    `requested_token_type`. Anything else → `invalid_request` (RFC 8693
 *    §2.2.2).
 *  - GATE 3 — subject-token validity: the subject token is cryptographically
 *    verified (EdDSA signature + `exp`) via `jwtUtils.verifyAccessToken`. Since
 *    QAuth's own signing key is the only key that verifies, a valid signature
 *    establishes provenance (the `iss` claim itself is not separately asserted
 *    by `verifyAccessToken`). An unverifiable / expired token →
 *    `invalid_request` (the presented token is unacceptable, RFC 8693 §2.2.2).
 *    The subject user must still exist and be enabled (RFC 9700 §4.14).
 *  - GATE 4 — no privilege escalation: scope and audience are PRESERVED or
 *    NARROWED relative to the subject token, never widened (RFC 8707 §2.2 /
 *    RFC 8693). Up-scoping → `invalid_scope`; out-of-set audience →
 *    `invalid_target`. Delegation depth is bounded by `MAX_DELEGATION_DEPTH`.
 *
 * No refresh token is issued — a delegated token is intentionally short-lived
 * and the agent re-exchanges as needed.
 *
 * GATE 4c — agent scope-mode cap (ADR-007 §2, #184, wired now that #182/#183/
 * #184 are merged): on top of the generic preserve/narrow logic, any reserved
 * agent-mode scope (`agent:readonly|admin|exec`) that survives narrowing is
 * additionally clamped to the requesting agent's server-side `max_agent_mode`.
 * Fail-closed via `toAgentScopeContext`: a capped agent cannot launder a
 * higher-mode scope through delegation even when the subject token carried it.
 *
 * GATE 4d — the agent's registered `scopes` (ADR-011 §3, amended 2026-10-19):
 * applied on the ID-JAG mint branch only, in {@link mintIdJagForExchange}. An
 * assertion leaves QAuth's trust domain and cannot be revoked, so its scope
 * must also be one the operator registered for this agent, as on every other
 * grant the agent can use. The delegation branch does not apply it yet; ADR-014
 * adds it there behind `AUTHORITY_TREE_ENABLED`.
 */
async function handleTokenExchange(
  ctx: HandlerContext<TokenExchangeTokenExchangeBody>
): Promise<TokenEndpointResponse> {
  const { fastify, request, client, body, policy } = ctx;

  // GATE 1 — agent classification + grant authorisation (default-deny).
  // `isAgentClient` is fail-closed; a client that omitted `is_agent` reads as
  // a non-agent and is rejected here.
  if (!isAgentClient(client)) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'client_not_agent');
    throw new UnauthorizedClientError();
  }
  if (!client.grantTypes.includes(TOKEN_EXCHANGE_GRANT_TYPE)) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'grant_type_not_allowed');
    throw new UnauthorizedClientError();
  }

  // GATE 2 — token-type support.
  //
  // ADR-011 relaxes this by EXACTLY ONE URN and no more: a
  // `requested_token_type` of `...:token-type:id-jag` asks QAuth to MINT an
  // Identity Assertion Authorization Grant instead of a delegated access token,
  // and is honoured only while `ID_JAG_ENABLED`. Every other value stays
  // rejected, and with the flag off `mintingIdJag` is always false, so this
  // gate's behaviour is byte-identical to the pre-ADR-011 build.
  //
  // `subject_token_type` is NOT relaxed. MCP EMA §4 describes an OIDC ID token
  // (or a refresh token) as the subject token, but QAuth's JWT plugin exposes no
  // ID-token verifier — `verifyAccessToken` pins `typ: at+jwt` and
  // `token_use: 'access'` on purpose — and inventing an ad-hoc one in the route
  // layer is exactly the kind of parallel verification path that produces
  // token-confusion bugs. QAuth's OWN access token is a strictly stronger
  // subject proof here: it is cryptographically verified, carries the same
  // authenticated end-user, and GATE 3c already asserts it was minted FOR this
  // client, which is the binding draft §4.3.3 step 1 requires. Accepting
  // `...:token-type:id_token` is a follow-up that belongs in the JWT plugin.
  //
  // OAuth error codes are the BARE token (RFC 6749 §5.2 / RFC 8693 §2.2.2);
  // human detail goes in `error_description` via InvalidRequestError.
  const mintingIdJag = env.ID_JAG_ENABLED && body.requested_token_type === TOKEN_TYPE_ID_JAG;

  if (body.subject_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
    await emitRequestFailed(ctx, 'invalid_request', 'unsupported_subject_token_type');
    throw new InvalidRequestError('unsupported subject_token_type');
  }
  if (
    body.requested_token_type !== undefined &&
    body.requested_token_type !== TOKEN_TYPE_ACCESS_TOKEN &&
    !mintingIdJag
  ) {
    await emitRequestFailed(ctx, 'invalid_request', 'unsupported_requested_token_type');
    throw new InvalidRequestError('unsupported requested_token_type');
  }
  // RFC 8693 §2.1: actor_token_type is REQUIRED when actor_token is present.
  if (body.actor_token !== undefined && body.actor_token_type === undefined) {
    await emitRequestFailed(ctx, 'invalid_request', 'actor_token_type_missing');
    throw new InvalidRequestError('actor_token_type is required when actor_token is present');
  }
  if (body.actor_token !== undefined && body.actor_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
    await emitRequestFailed(ctx, 'invalid_request', 'unsupported_actor_token_type');
    throw new InvalidRequestError('unsupported actor_token_type');
  }

  // GATE 3 — verify the subject token (EdDSA signature + exp + issuer). The
  // issuer is pinned in `verifyAccessToken` (RFC 9700 mix-up defence), so a
  // token minted by a different AS — even one sharing our signing key — fails
  // verification here. Only QAuth's signing key + issuer verifies, so success
  // establishes provenance; an unverifiable / expired / foreign-issuer token is
  // "unacceptable" → invalid_request.
  const expectedIssuer = fastify.jwtUtils.getIssuer();
  let subjectPayload: Awaited<ReturnType<typeof fastify.jwtUtils.verifyAccessToken>>;
  try {
    subjectPayload = await fastify.jwtUtils.verifyAccessToken(body.subject_token, {
      issuer: expectedIssuer,
    });
  } catch {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_invalid');
    throw new InvalidRequestError('subject_token is not a valid access token');
  }
  if (!subjectPayload.sub) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_missing_sub');
    throw inactiveSubjectTokenError();
  }

  // GATE 3b — token-confusion defence. Issuer is now asserted by
  // `verifyAccessToken` above; the remaining check is token PURPOSE. Without
  // it, ANY JWT QAuth signs with the same key (e.g. an ID token) would verify
  // and, if its `sub` resolved to a user, be accepted as a subject token.
  // Require the access-token `token_use` marker. The marker is absent on legacy
  // access tokens minted before it existed, so we accept its absence only when
  // the structural access-token markers (`client_id` + `aud`) are present —
  // never accept a token that positively declares a non-access `token_use`.
  const tokenUse = subjectPayload.token_use;
  const isAccessToken =
    tokenUse === 'access' ||
    (tokenUse === undefined &&
      subjectPayload.clientId !== undefined &&
      subjectPayload.aud !== undefined);
  if (!isAccessToken) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_not_access_token');
    throw new InvalidRequestError('subject_token is not a QAuth-issued access token');
  }

  // If an actor_token is supplied, verify it too (issuer pinned). We do not
  // trust the agent's self-declared identity from an unverified token — the
  // actor identity used in the `act` claim is the authenticated agent's own
  // client_id (below).
  let actorPayload: Awaited<ReturnType<typeof fastify.jwtUtils.verifyAccessToken>> | undefined;
  if (body.actor_token !== undefined) {
    try {
      actorPayload = await fastify.jwtUtils.verifyAccessToken(body.actor_token, {
        issuer: expectedIssuer,
      });
    } catch {
      await emitRequestFailed(ctx, 'invalid_request', 'actor_token_invalid');
      throw new InvalidRequestError('actor_token is not a valid access token');
    }
  }

  // GATE 3a — RFC 7009 revocation. `verifyAccessToken` checks signature,
  // expiry and issuer only; the jti denylist `/oauth/revoke` writes is applied
  // by `requireJwt` and introspection, not by the bare verifier. Without this
  // check a revoked subject or actor token would still be exchanged for a
  // fresh delegated token with a new, non-revoked jti. A revoked token is
  // "unacceptable" under RFC 8693 §2.2.2 → invalid_request. A denylist store
  // outage throws out of `isJtiRevoked` and fails the exchange closed.
  if (await isJtiRevoked(fastify, subjectPayload.jti)) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_revoked');
    throw new InvalidRequestError('subject_token has been revoked');
  }
  if (actorPayload && (await isJtiRevoked(fastify, actorPayload.jti))) {
    await emitRequestFailed(ctx, 'invalid_request', 'actor_token_revoked');
    throw new InvalidRequestError('actor_token has been revoked');
  }

  // GATE 3c — bind the subject token to the requesting agent (RFC 8693 leaves
  // authorisation to AS policy; epic #181 default-deny). The subject token MUST
  // have been minted for THIS agent: its `aud` must contain the agent's
  // `client_id`. Without this, possession of ANY user's access token plus a
  // known agent client_id would suffice to mint a delegated token. Combined
  // with the confidential-client requirement (the agent proved its secret at
  // the dispatch layer), this closes the unauthorized-delegation gap.
  const subjectAudience = audToArray(subjectPayload.aud);
  if (!subjectAudience.includes(client.clientId)) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_audience_mismatch');
    throw new InvalidRequestError('subject_token was not issued for this client');
  }

  // A DPoP-bound subject token (RFC 9449, #480) is exchanged only by the
  // holder of its key: the request must carry a proof under the key its
  // `cnf.jkt` names, whether the exchange mints a delegated token or an
  // ID-JAG. Otherwise the agent's secret and a copied subject token would buy
  // a bearer credential, the downgrade the binding exists to prevent. A proof
  // under another key is refused too: moving a token to a new key takes the
  // spawn assertion of ADR-014 P1b, which this server does not accept yet.
  // While DPoP is off the binding cannot be checked, so the token is refused.
  if (subjectPayload.cnf !== undefined) {
    if (!fastify.dpop) {
      await emitRequestFailed(ctx, 'invalid_request', 'subject_token_dpop_disabled');
      throw new InvalidRequestError('subject_token is bound to a DPoP key');
    }
    if (ctx.dpopThumbprint === undefined) {
      await emitRequestFailed(ctx, 'invalid_dpop_proof', 'dpop_missing_proof');
      throw new InvalidDpopProofError();
    }
    if (ctx.dpopThumbprint !== subjectPayload.cnf.jkt) {
      await emitRequestFailed(ctx, 'invalid_request', 'subject_token_key_mismatch');
      throw new InvalidRequestError('subject_token is bound to another DPoP key');
    }
  }

  // A `client_credentials` token names no user: its `sub` is its own
  // `client_id` (handleClientCredentials). An agent's own machine token
  // passes GATE 3c, since its `aud` falls back to that `client_id`, but there
  // is no one to act on behalf of. Refused before the user lookup, so a
  // `client_id` is never read as a `users.id` (#754).
  if (subjectPayload.sub === subjectPayload.clientId) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_not_a_user');
    throw inactiveSubjectTokenError();
  }

  // The subject user must still exist and be enabled (RFC 9700 §4.14). We bind
  // the delegated token's `sub` to the *current* user record, not blindly to
  // the token's `sub` string.
  const user = await fastify.repositories.users.findById(subjectPayload.sub);
  if (!user) {
    await emitRequestFailed(ctx, 'invalid_request', 'user_not_found');
    throw inactiveSubjectTokenError();
  }
  if (!user.enabled) {
    await emitRequestFailed(ctx, 'invalid_request', 'user_disabled', user.id);
    throw inactiveSubjectTokenError();
  }

  // GATE 4a — scope narrowing. The delegated token's scope is the subject
  // token's scope, optionally narrowed by the request. Up-scoping is rejected.
  const subjectScopes = subjectPayload.scope
    ? subjectPayload.scope.split(/\s+/).filter((s) => s.length > 0)
    : [];
  let grantedScopes: string[];
  if (body.scope !== undefined && body.scope.trim().length > 0) {
    const requested = body.scope.split(/\s+/).filter((s) => s.length > 0);
    const extraneous = requested.filter((s) => !subjectScopes.includes(s));
    if (extraneous.length > 0) {
      await emitRequestFailed(ctx, 'invalid_scope', 'scope_exceeds_subject_token', user.id);
      throw new InvalidScopeError(`${extraneous.join(' ')} not in subject_token scope`);
    }
    // Dedupe so a repeated scope cannot bloat the minted claim.
    grantedScopes = [...new Set(requested)];
  } else {
    grantedScopes = subjectScopes;
  }

  // GATE 4c — clamp the (narrowed) scope set to the agent's server-side
  // `max_agent_mode` (ADR-007 §2, #184). A reserved agent-mode scope is
  // permitted ONLY when this client is a verified agent within its cap; a
  // capped agent must not be able to mint a higher-mode delegated token even
  // when the subject token (issued under a broader prior grant) still carries
  // it. Fail-closed via `toAgentScopeContext`. `enforceAgentScopeCap` throws
  // the same `InvalidScopeError` shape as the up-scoping check above.
  try {
    enforceAgentScopeCap(grantedScopes, toAgentScopeContext(client));
  } catch (err) {
    await emitRequestFailed(ctx, oauthErrorCode(err), 'scope_exceeds_agent_mode', user.id);
    throw err;
  }

  // ADR-011 MINT BRANCH. Everything above this line — agent classification,
  // grant authorisation, subject-token verification and provenance, the
  // client-binding check, the enabled-user check, scope narrowing and the agent
  // scope-mode cap — applies IDENTICALLY to both outcomes and has already run.
  //
  // What diverges below is the TARGET model, and it diverges because it
  // must: GATE 4b narrows the issued token's `aud` against the SUBJECT TOKEN's
  // audience, which is correct for a delegated access token minted inside
  // QAuth's own trust domain and meaningless for an assertion whose `aud` is a
  // FOREIGN authorization server that could never appear in a QAuth-issued
  // token. Substituting the operator's per-client ID-JAG target list there (see
  // `mintIdJagForExchange`) is a narrowing, not a widening: it is operator-set
  // server state that no self-service path can write, and an empty one denies.
  //
  // Because the target now comes from the agent's registration and not from
  // the subject token, the scope must be bounded by the agent's registration
  // too, or the assertion would pair a target the operator granted with a
  // scope it did not. The mint branch therefore adds GATE 4d, the client's
  // registered `scopes`, exactly as `client_credentials` applies both columns
  // together (ADR-011 §3, amended 2026-10-19).
  if (mintingIdJag) {
    return mintIdJagForExchange({
      fastify,
      request,
      client,
      body,
      user,
      grantedScopes,
      subjectAct: subjectPayload.act,
      subjectExp: subjectPayload.exp,
      realmId: ctx.realmId,
      emitFailure: (error, reason) => emitRequestFailed(ctx, error, reason, user.id),
    });
  }

  // GATE 4b — audience narrowing (RFC 8707 §2.2 + RFC 8693 `audience`). The
  // delegated token's `aud` is the subject token's `aud`, optionally narrowed
  // by `resource` and/or `audience`. Any value outside the subject token's
  // audience set is rejected (`invalid_target`) — never widen. Deduped to keep
  // the minted claim bounded.
  const requestedTargets = [...new Set([...(body.resource ?? []), ...(body.audience ?? [])])];
  let effectiveAudience: string[];
  if (requestedTargets.length > 0) {
    const extra = requestedTargets.filter((t) => !subjectAudience.includes(t));
    if (extra.length > 0) {
      await emitRequestFailed(ctx, 'invalid_target', 'audience_outside_subject_token', user.id);
      throw new InvalidTargetError('requested resource/audience is outside the subject token');
    }
    effectiveAudience = requestedTargets;
  } else {
    // Preserve the subject token's audience verbatim. The subject `aud` is
    // always present (signing falls back to client_id) and was asserted to
    // contain this agent above — so there is no agent-default fallback here.
    effectiveAudience = subjectAudience;
  }

  // Build the RFC 8693 §4.1 `act` claim. The current actor (the authenticated
  // agent) is the outermost `act`; any pre-existing delegation chain on the
  // subject token is nested beneath it. This reflects the *real* actor — the
  // agent's own client_id — not an unverified self-declaration.
  const act: ActClaim = {
    sub: client.clientId,
    ...(subjectPayload.act ? { act: subjectPayload.act } : {}),
  };

  // Bound delegation depth: each re-exchange nests another `act`, growing the
  // JWT unboundedly. Reject once the chain would exceed MAX_DELEGATION_DEPTH.
  const depth = actDepth(act);
  if (depth > MAX_DELEGATION_DEPTH) {
    await emitRequestFailed(ctx, 'invalid_request', 'delegation_too_deep', user.id);
    throw new InvalidRequestError('delegation chain exceeds the maximum depth');
  }

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;
  const aud = arrayToAud(effectiveAudience);

  // Clamp lifespan so the delegated token NEVER outlives the subject token's
  // authority (and so it cannot be re-exchanged to extend it indefinitely).
  // `exp` is in seconds; verifyAccessToken already rejected an expired token,
  // so remaining is > 0 here, but we guard against the boundary defensively.
  // The configured ceiling is the environment-policy lifespan (ADR-008 §5,
  // #197): a `development` delegated token may match the longer dev TTL, but is
  // still clamped to the subject token's remaining lifetime (a HARD floor — the
  // delegated token can never outlive the authority it was derived from).
  const configuredLifespan = accessTokenLifespanForPolicy(fastify, policy);
  const subjectRemaining =
    subjectPayload.exp !== undefined
      ? subjectPayload.exp - Math.floor(Date.now() / 1000)
      : configuredLifespan;
  const accessTokenExpiresIn = Math.max(0, Math.min(configuredLifespan, subjectRemaining));
  if (accessTokenExpiresIn <= 0) {
    await emitRequestFailed(ctx, 'invalid_request', 'subject_token_expired', user.id);
    throw new InvalidRequestError('subject_token has expired');
  }

  // BREAKING (#229): trust-ordered resolution; omitted when unverified. Only
  // under the delegated (narrowed) scope's `email` (ANT-2026-2O0T72HY): an
  // agent learns the address only when the user's grant included it.
  const emailClaims = await resolveEmailClaimsForScopes(fastify, user.id, grantedScopes);

  const accessToken = await issueAccessToken(fastify, {
    sub: user.id,
    ...emailClaims,
    clientId: client.clientId,
    scope: scopeString,
    aud,
    act,
    // RFC 9449 §5 (#480): the delegated token is bound to the agent's proof
    // key, which for a bound subject token is the subject's own key (checked
    // above).
    ...dpopConfirmation(ctx),
    expiresInOverride: accessTokenExpiresIn,
  });

  // Per-agent action audit (ADR-007 §2, #186). The delegated token was minted
  // on behalf of `user` BY this agent: the event's subject is the user, and
  // its actor the agent, with the minted token's `act` chain as its
  // delegation chain (this agent first). Only public identifiers are
  // recorded; no subject/actor token, secret, or minted token.
  const scopeMode = highestAgentModeInScopes(grantedScopes);
  await emitUserEvent(
    request,
    TOKEN_ISSUED,
    {
      grantType: body.grant_type,
      scopes: grantedScopes,
      audience: effectiveAudience,
      expiresIn: accessTokenExpiresIn,
      issuedTokenType: TOKEN_TYPE_ACCESS_TOKEN,
      delegationDepth: depth,
      ...(scopeMode === null ? {} : { scopeMode }),
    },
    { realmId: ctx.realmId, userId: user.id, clientId: client.clientId, actor: 'client', act }
  );

  // Token issuance metrics (#126). Token-exchange mints an access token only.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'token-exchange' });

  // RFC 8693 §2.2.1: token-exchange responses MUST include `issued_token_type`.
  return {
    access_token: accessToken,
    issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
    expires_in: accessTokenExpiresIn,
    token_type: tokenTypeFor(ctx),
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * The operator-configured set of targets a client may name in an ID-JAG request.
 *
 * This is `oauth_clients.id_jag_targets` (#434), and deliberately NOT
 * `oauth_clients.audience`. `audience` bounds the tokens QAuth itself issues
 * (`handleClientCredentials`); sharing it meant that listing a foreign
 * authorization server for ID-JAG also let the client obtain QAuth access tokens
 * naming it. With a column of its own, each list grants exactly one thing: a
 * value only in `audience` reaches no ID-JAG target, and a value only here
 * reaches no `client_credentials` audience. Only the seed manifest writes it.
 *
 * `client_credentials` falls back to `[client.clientId]` when its column is
 * empty, because a token audience-restricted to the client itself is a
 * meaningful (if narrow) default. THAT FALLBACK IS DELIBERATELY ABSENT HERE:
 * both ID-JAG paths name a FOREIGN party — a third-party authorization server,
 * or an MCP server this deployment protects — and "the client's own id" is never
 * a correct answer for either. An unconfigured client therefore reaches no
 * target at all, which is the ADR-011 default-off posture expressed per client.
 *
 * The stored shape is re-checked here, beside the DB CHECK: anything but an
 * array of non-empty strings denies, so a malformed value can never turn the
 * membership test into a substring match.
 */
function idJagTargetAllowlist(client: OAuthClientLike): string[] {
  const targets = client.idJagTargets;
  return Array.isArray(targets) &&
    targets.every((target) => typeof target === 'string' && target.length > 0)
    ? targets
    : [];
}

/**
 * MINT an Identity Assertion Authorization Grant through RFC 8693 token
 * exchange (ADR-011, MCP EMA §4). QAuth acts as the enterprise IdP; the
 * assertion is redeemed at a THIRD-PARTY resource authorization server.
 *
 * Reached only from {@link handleTokenExchange}, after every control that
 * governs a delegated access token has already passed. What remains is the
 * scope ceiling and the target model:
 *
 *  - GATE 4d — every scope the assertion would carry (the subject token's
 *    scope, or the narrower `scope` the request named) must be in the client's
 *    registered `scopes` (`validateScopes`, the check `client_credentials` and
 *    the jwt-bearer consume side run). An empty list denies any scoped
 *    assertion. The request is refused (`invalid_scope`), never trimmed: the
 *    agent narrows with `scope` when it wants less. ADR-011 §3, amended
 *    2026-10-19: the assertion leaves QAuth's trust domain and cannot be
 *    revoked, so this cannot wait for ADR-014.
 *
 *  - `audience` (EMA §4, MUST) — the issuer identifier of the resource
 *    authorization server, and becomes the assertion's `aud`. Exactly one value:
 *    an assertion naming two authorization servers is redeemable at either of
 *    them, so a multi-valued `audience` is refused rather than silently
 *    truncated to the first entry.
 *  - `resource` (EMA §4, OPTIONAL in the draft) — the MCP server's resource
 *    identifier, and becomes the assertion's `resource`. REQUIRED here: EMA §5.1
 *    obliges the redeeming AS to audience-restrict its access token to this
 *    value, so an assertion without one authorizes an unbounded token. Being
 *    stricter than the draft can only refuse requests, never widen a grant.
 *  - both MUST appear in {@link idJagTargetAllowlist}. This is the
 *    "administrator-defined policy" EMA §4.1 requires the IdP to evaluate, in
 *    the form QAuth already has: operator-set server state, never client input.
 */
async function mintIdJagForExchange(args: {
  fastify: FastifyInstance;
  request: FastifyRequest;
  client: OAuthClientLike;
  body: TokenExchangeTokenExchangeBody;
  user: { id: string };
  grantedScopes: string[];
  subjectAct: ActClaim | undefined;
  /** The subject token's `exp` (epoch seconds); the assertion never outlives it. */
  subjectExp: number | undefined;
  /** The realm the client authenticated in, for the `token.issued` event. */
  realmId: string;
  /** Record a refusal (`token.request_failed`), with its OAuth `error` and its reason. */
  emitFailure: (error: string, reason: string) => Promise<void>;
}): Promise<IdJagTokenResponse> {
  const {
    fastify,
    request,
    client,
    body,
    user,
    grantedScopes,
    subjectAct,
    subjectExp,
    realmId,
    emitFailure,
  } = args;

  // GATE 4d — the client's registered `scopes` are a ceiling on the assertion,
  // beside the subject token's scope (GATE 4a). The subject token says what the
  // USER granted to the app that holds it; the registration says what the
  // OPERATOR lets THIS agent hold. The assertion is QAuth's word to a foreign
  // authorization server that its policy was evaluated, so it must satisfy both.
  try {
    validateScopes(grantedScopes.join(' '), client.scopes, toAgentScopeContext(client));
  } catch (err) {
    await emitFailure(oauthErrorCode(err), 'scope_not_allowed_for_client');
    throw err;
  }

  const allowedTargets = idJagTargetAllowlist(client);

  const requestedAudience = body.audience ?? [];
  if (requestedAudience.length !== 1) {
    await emitFailure('invalid_request', 'id_jag_requires_one_audience');
    throw new InvalidRequestError(
      'audience is required and must name exactly one authorization server when requesting an ID-JAG'
    );
  }
  const targetAuthorizationServer = requestedAudience[0];

  const requestedResource = body.resource ?? [];
  if (requestedResource.length !== 1) {
    await emitFailure('invalid_request', 'id_jag_requires_one_resource');
    throw new InvalidRequestError(
      'resource is required and must name exactly one MCP server when requesting an ID-JAG'
    );
  }
  const targetResource = requestedResource[0];

  // ADR-011 gate 5, mirrored on the mint side: never mint an assertion for THIS
  // server, even if an operator listed its issuer among the client's targets.
  // The consume side refuses a self-issued assertion too; refusing here keeps the
  // pair from ever forming a loop, and keeps a misconfigured allowlist from
  // handing a client a way around the delegation path's audience narrowing.
  if (
    resolveIssuerIdentifier(targetAuthorizationServer) ===
    resolveIssuerIdentifier(fastify.jwtUtils.getIssuer())
  ) {
    await emitFailure('invalid_target', 'id_jag_audience_is_self');
    throw new InvalidTargetError('an ID-JAG cannot be minted for this authorization server');
  }

  const outsidePolicy = [targetAuthorizationServer, targetResource].filter(
    (target) => !allowedTargets.includes(target)
  );
  if (outsidePolicy.length > 0) {
    await emitFailure('invalid_target', 'id_jag_target_not_allowed');
    throw new InvalidTargetError('requested audience/resource is outside the client policy');
  }

  // Delegation depth stays bounded on this path too. The assertion carries no
  // `act` claim (it is not part of the ID-JAG claim set, and a foreign AS would
  // either ignore or reject it), but the CHAIN still exists — the subject token
  // may already be a delegated token — and an unbounded re-exchange loop must
  // not become reachable just because the issued artefact happens to be smaller.
  const act: ActClaim = { sub: client.clientId, ...(subjectAct ? { act: subjectAct } : {}) };
  const depth = actDepth(act);
  if (depth > MAX_DELEGATION_DEPTH) {
    await emitFailure('invalid_request', 'delegation_too_deep');
    throw new InvalidRequestError('delegation chain exceeds the maximum depth');
  }

  // The assertion must not outlive the subject token it was derived from, as
  // the delegation branch clamps its token: it cannot be withdrawn once it has
  // crossed into the target's trust domain, so revoking the grant behind the
  // subject token ends it no later than that token would have ended.
  const subjectRemaining =
    subjectExp !== undefined ? subjectExp - Math.floor(Date.now() / 1000) : undefined;
  if (subjectRemaining !== undefined && subjectRemaining <= 0) {
    await emitFailure('invalid_request', 'subject_token_expired');
    throw new InvalidRequestError('subject_token has expired');
  }

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;

  const minted = await mintIdJag(fastify, {
    subject: user.id,
    audience: targetAuthorizationServer,
    resource: targetResource,
    clientId: client.clientId,
    ...(scopeString !== undefined ? { scope: scopeString } : {}),
    ...(subjectRemaining !== undefined ? { maxLifetimeSeconds: subjectRemaining } : {}),
  });

  // The actor is this agent with the delegation chain the assertion was
  // derived through, though the assertion itself carries no `act` claim.
  const scopeMode = highestAgentModeInScopes(grantedScopes);
  await emitUserEvent(
    request,
    TOKEN_ISSUED,
    {
      grantType: body.grant_type,
      scopes: grantedScopes,
      audience: [targetAuthorizationServer],
      resources: [targetResource],
      expiresIn: minted.expiresIn,
      issuedTokenType: TOKEN_TYPE_ID_JAG,
      delegationDepth: depth,
      // Public identifiers only — the assertion itself is never recorded, only
      // the `jti` that identifies it.
      idJagId: minted.jti,
      ...(scopeMode === null ? {} : { scopeMode }),
    },
    { realmId, userId: user.id, clientId: client.clientId, actor: 'client', act }
  );

  fastify.metrics.tokensIssued.inc({ type: 'id_jag', grant_type: 'token-exchange' });

  // RFC 8693 §2.2.1 / EMA §4.2: `token_type` MUST be `N_A` because the issued
  // artefact is not usable as a bearer access token, and `issued_token_type`
  // names what it actually is. No refresh token — an ID-JAG is a single-use
  // hand-off credential, and a refreshable one would let a client keep
  // redeeming access at the target long after the enterprise policy that
  // authorised this exchange stopped applying.
  return {
    access_token: minted.assertion,
    issued_token_type: TOKEN_TYPE_ID_JAG,
    token_type: 'N_A' as const,
    expires_in: minted.expiresIn,
    ...(scopeString ? { scope: scopeString } : {}),
  };
}

/**
 * Handle the RFC 7523 §2.1 JWT authorization grant — QAuth's CONSUME side of
 * ID-JAG (ADR-011, MCP EMA §5). Here QAuth is the MCP server's Resource
 * Authorization Server: a client presents an assertion minted by a trusted
 * ENTERPRISE IdP and receives an access token for the MCP server that assertion
 * names.
 *
 * Security invariants, all default-deny:
 *
 *  - GATE 0 — `ID_JAG_ENABLED`. Already enforced at dispatch (before client
 *    authentication); re-asserted here so the handler is safe in isolation.
 *  - GATE 1 — the client must be REGISTERED for the jwt-bearer grant
 *    (`unauthorized_client`, RFC 6749 §5.2). The client is already
 *    authenticated as a confidential client by the dispatch layer.
 *  - GATE 2 — the assertion must verify end to end: `typ`, an allowlisted
 *    issuer, a key resolved only from that issuer's own OIDC metadata, an
 *    asymmetric algorithm, `aud` equal to THIS server's issuer identifier, a
 *    bounded lifetime, and a single-use `jti`. See `helpers/id-jag.ts`; every
 *    refusal there lands on one uniform `invalid_grant` here.
 *  - GATE 3 — the assertion's `client_id` claim MUST equal the AUTHENTICATED
 *    client (draft §4.4.1). This is what stops a valid assertion intended for
 *    client A being redeemed by client B.
 *  - GATE 4 — the assertion's `resource` MUST be inside the operator's
 *    per-client ID-JAG target list (`id_jag_targets`). A trusted IdP is trusted
 *    to say WHICH USER authorized WHICH CLIENT; it is not thereby trusted to
 *    enrol this deployment's clients into resources an operator never granted
 *    them.
 *  - GATE 5 — the granted scope is the assertion's scope, optionally narrowed by
 *    the request, and then still subject to the client's own allowlist and the
 *    agent scope-mode cap. Both ceilings apply; neither can raise the other.
 *  - GATE 6 — the subject must already be LINKED to a QAuth user. There is no
 *    just-in-time provisioning (see below).
 *
 * The issued token is audience-restricted to the assertion's `resource` — the
 * central MUST of EMA §5.1 — and NO refresh token is issued: the enterprise
 * re-evaluates policy every time it mints an assertion, and a refresh token
 * would let the client keep renewing access without that evaluation ever
 * happening again.
 */
async function handleJwtBearer(
  ctx: HandlerContext<TokenExchangeJwtBearerBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body, policy, realmId } = ctx;

  // GATE 0 — defence in depth. The dispatch rejected this before client
  // authentication; a future caller reaching the handler directly must not be
  // able to skip the flag.
  if (!env.ID_JAG_ENABLED) {
    await emitRequestFailed(ctx, 'unsupported_grant_type', 'id_jag_disabled');
    throw new UnsupportedGrantTypeError();
  }

  // GATE 1 — grant authorisation (RFC 6749 §5.2). The grant is not registrable
  // through DCR, so this reflects an operator's provisioning decision.
  if (!client.grantTypes.includes(JWT_BEARER_GRANT_TYPE)) {
    await emitRequestFailed(ctx, 'unauthorized_client', 'grant_type_not_allowed');
    throw new UnauthorizedClientError();
  }

  // GATE 2 — the assertion itself, INCLUDING the `client_id` binding to this
  // authenticated client. The binding is passed in rather than checked after the
  // fact so it is evaluated BEFORE the single-use `jti` is burned: otherwise any
  // client holding another client's assertion could destroy it by presenting it
  // once and being refused a step later.
  let assertion: ValidatedIdJag;
  try {
    assertion = await validateIdJagAssertion(fastify, {
      assertion: body.assertion,
      expectedClientId: client.clientId,
      realm: requestRealm(request).name,
    });
  } catch (err) {
    // Every distinct refusal reason is recorded for the operator and collapsed
    // to ONE opaque `invalid_grant` on the wire. Telling a caller whether an
    // issuer is allowlisted, whether a `kid` exists, or whether a `jti` was
    // already burned turns this endpoint into an oracle for each of those.
    // The event carries the reason as a code; the validator's message, which
    // may name the unverified issuer, goes to the operator's log.
    const reason = err instanceof IdJagValidationError ? err.reason : 'unexpected';
    fastify.log.warn(
      { reqId: request.id, reason, detail: err instanceof Error ? err.message : 'unknown error' },
      'token endpoint: identity assertion refused'
    );
    await emitRequestFailed(ctx, 'invalid_grant', reason);
    throw new InvalidGrantError('the presented assertion is not acceptable');
  }

  // GATE 3 — belt-and-braces re-assertion of the `client_id` binding GATE 2
  // already enforced. Kept because it is the invariant that stops an assertion
  // captured in transit (or one legitimately issued to a different client) being
  // redeemed by any client that happens to hold credentials at this AS, and a
  // future refactor of the helper must not be able to drop it silently.
  if (assertion.clientId !== client.clientId) {
    await emitRequestFailed(ctx, 'invalid_grant', 'client_mismatch');
    throw new InvalidGrantError('the presented assertion is not acceptable');
  }

  // GATE 4 — the resource must be one an operator granted this client.
  const allowedTargets = idJagTargetAllowlist(client);
  if (!allowedTargets.includes(assertion.resource)) {
    await emitRequestFailed(ctx, 'invalid_target', 'id_jag_target_not_allowed');
    throw new InvalidTargetError('the assertion resource is outside the client policy');
  }

  // RFC 8707 §2.2: an explicit `resource` parameter may only AGREE with the
  // claim. The claim is authoritative — it is what the enterprise signed — so a
  // parameter naming anything else is a mismatch to reject, never a set to merge
  // with or a value that can broaden the audience.
  const requestedResource = body.resource ?? [];
  const mismatched = requestedResource.filter((value) => value !== assertion.resource);
  if (mismatched.length > 0) {
    await emitRequestFailed(ctx, 'invalid_target', 'resource_mismatch');
    throw new InvalidTargetError('requested resource is outside the assertion');
  }

  // GATE 5 — scope. TWO independent ceilings, both of which must hold:
  //   1. the assertion's own `scope` claim — what the enterprise authorized;
  //   2. the client's registered `scopes` (plus the agent scope-mode cap) —
  //      what THIS deployment permits this client to hold at all.
  // The result is the intersection. A trusted IdP cannot grant a client a scope
  // the operator never configured, and the operator's allowlist cannot grant a
  // scope the enterprise did not authorize.
  const assertionScopes = [...assertion.scopes];
  let requestedScopes: string[];
  if (body.scope !== undefined && body.scope.trim().length > 0) {
    const requested = [...new Set(body.scope.split(/\s+/).filter((s) => s.length > 0))];
    const extraneous = requested.filter((s) => !assertionScopes.includes(s));
    if (extraneous.length > 0) {
      await emitRequestFailed(ctx, 'invalid_scope', 'scope_exceeds_assertion');
      throw new InvalidScopeError(`${extraneous.join(' ')} not in assertion scope`);
    }
    requestedScopes = requested;
  } else {
    requestedScopes = assertionScopes;
  }

  let grantedScopes: string[];
  try {
    grantedScopes = validateScopes(
      requestedScopes.join(' '),
      client.scopes,
      toAgentScopeContext(client)
    );
  } catch (err) {
    await emitRequestFailed(ctx, oauthErrorCode(err), 'scope_not_allowed_for_client');
    throw err;
  }

  // GATE 6 — subject resolution. The assertion's `sub` is unique only WITHIN its
  // issuer (draft §6), so the lookup is keyed by BOTH: a `user_credentials` row
  // under provider type `oidc_<issuer>` with that `external_sub`.
  //
  // AN UNKNOWN SUBJECT IS REJECTED. Just-in-time provisioning is deliberately
  // NOT implemented: it would let any allowlisted IdP create QAuth identities by
  // asserting subjects that do not exist, turning a trust decision about
  // AUTHENTICATION into an account-creation primitive, and email-based linking
  // would additionally let a compromised IdP bind itself to an existing local
  // account. Linking an enterprise subject to a QAuth user stays an explicit,
  // out-of-band operator action.
  const credential = await fastify.repositories.userCredentials.findByRealmProviderSub(
    realmId,
    idJagCredentialProviderType(assertion.issuer),
    assertion.subject
  );
  if (!credential) {
    await emitRequestFailed(ctx, 'invalid_grant', 'subject_not_linked');
    throw new InvalidGrantError('the presented assertion is not acceptable');
  }

  const user = await fastify.repositories.users.findById(credential.userId);
  if (!user || !user.enabled) {
    await emitRequestFailed(
      ctx,
      'invalid_grant',
      user ? 'user_disabled' : 'user_not_found',
      user?.id ?? null
    );
    throw new InvalidGrantError('the presented assertion is not acceptable');
  }

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;

  // Access-token lifespan under the environment policy (ADR-008 §5, #197). The
  // token is NOT clamped to the assertion's remaining lifetime: an assertion is
  // a GRANT, like an authorization code, and a grant's short single-use window
  // exists to bound REDEMPTION, not to bound what redemption produces. EMA §5.2
  // shows exactly this (a 300s assertion yielding an 86400s access token).
  const accessTokenExpiresIn = accessTokenLifespanForPolicy(fastify, policy);

  // Only under the granted `email` scope (ANT-2026-2O0T72HY), like every other
  // grant: the assertion's scope, narrowed and capped by GATE 5, decides.
  const emailClaims = await resolveEmailClaimsForScopes(fastify, user.id, grantedScopes);

  // EMA §5.1, the profile's central MUST: the issued access token is
  // audience-restricted to the MCP server the assertion's `resource` claim
  // identifies — never the client's configured default audience, and never the
  // whole allowlist. `resolveAudience` collapses the single value to a string
  // `aud`, so the token names exactly one resource server.
  const aud = resolveAudience(client, [assertion.resource]);
  const accessToken = await issueAccessToken(fastify, {
    sub: user.id,
    ...emailClaims,
    clientId: client.clientId,
    scope: scopeString,
    aud,
    ...dpopConfirmation(ctx),
    expiresInOverride: accessTokenExpiresIn,
  });

  const scopeMode = isAgentClient(client) ? highestAgentModeInScopes(grantedScopes) : null;
  await emitUserEvent(
    request,
    TOKEN_ISSUED,
    {
      grantType: body.grant_type,
      scopes: grantedScopes,
      audience: audToArray(aud),
      resources: [assertion.resource],
      expiresIn: accessTokenExpiresIn,
      // Public identifiers only. The assertion is never recorded; its `jti` is
      // what ties this issuance to the single-use record that consumed it.
      idJagId: assertion.jti,
      idJagIssuer: assertion.issuer,
      ...(scopeMode === null ? {} : { scopeMode }),
    },
    { realmId, userId: user.id, clientId: client.clientId, actor: 'client' }
  );

  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'jwt-bearer' });

  // No refresh token, and no `issued_token_type`: EMA §5.2 is an ordinary
  // RFC 6749 §5.1 access-token response, not an RFC 8693 exchange response.
  return {
    access_token: accessToken,
    expires_in: accessTokenExpiresIn,
    token_type: tokenTypeFor(ctx),
    ...(scopeString ? { scope: scopeString } : {}),
  };
}
