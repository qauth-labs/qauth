import { randomUUID } from 'node:crypto';

import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';
import {
  BadRequestError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  NotFoundError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { flattenActChain, MAX_DELEGATION_DEPTH } from '../../helpers/agent-audit';
import {
  authenticateClient,
  authenticateClientPublicOrConfidential,
  enforceAgentScopeCap,
  extractClientCredentials,
  type OAuthClientLike,
  resolveAudience,
  toAgentScopeContext,
  validateScopes,
} from '../../helpers/client-auth';
import { isAgentClient } from '../../helpers/client-resolution';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { highestAgentModeInScopes } from '../../helpers/scope-modes';
import { ensureMinimumResponseTime } from '../../helpers/timing';
import {
  TOKEN_EXCHANGE_GRANT_TYPE,
  TOKEN_TYPE_ACCESS_TOKEN,
  type TokenExchangeAuthCodeBody,
  tokenExchangeBodySchema,
  type TokenExchangeClientCredsBody,
  type TokenExchangeRefreshBody,
  type TokenExchangeResponse,
  tokenExchangeResponseSchema,
  type TokenExchangeTokenExchangeBody,
} from '../../schemas/oauth';

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
        body: tokenExchangeBodySchema,
        response: {
          200: tokenExchangeResponseSchema,
        },
      },
      config: {
        rateLimit: {
          max: env.TOKEN_RATE_LIMIT,
          timeWindow: env.TOKEN_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as
        | TokenExchangeAuthCodeBody
        | TokenExchangeClientCredsBody
        | TokenExchangeRefreshBody
        | TokenExchangeTokenExchangeBody;

      try {
        const realm = await getOrCreateDefaultRealm(fastify);

        // Authenticate the client. authorization_code (PKCE) and
        // refresh_token both support public clients
        // (OAuth 2.1 §4.1.3 / §4.3.1 / RFC 6749 §6). The PKCE verifier /
        // refresh-token ownership binds the grant to the client; no
        // `client_secret` is required when `token_endpoint_auth_method:
        // 'none'`. client_credentials is confidential-only by definition.
        let client: OAuthClientLike;
        try {
          if (body.grant_type === 'authorization_code' || body.grant_type === 'refresh_token') {
            client = await authenticateClientPublicOrConfidential(
              fastify,
              realm.id,
              request as FastifyRequest,
              body.client_id,
              body.client_secret
            );
          } else {
            // client_credentials AND token-exchange are CONFIDENTIAL-ONLY. For
            // token-exchange this is a deliberate security floor (RFC 9700,
            // epic #181): on-behalf-of delegation must not be mintable by a
            // public client that proves nothing but knowledge of a `client_id`.
            // A public agent (token_endpoint_auth_method=none) presents no
            // secret, so `extractClientCredentials` → `invalid_client`.
            const creds = extractClientCredentials(
              request as FastifyRequest,
              body.client_id,
              body.client_secret
            );
            client = await authenticateClient(fastify, realm.id, creds);
          }
        } catch (err) {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: null,
            event: 'oauth.token.exchange.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'Client authentication failed', grantType: body.grant_type },
          });
          throw err;
        }

        // RFC 6749 §5.1: token responses MUST NOT be cached by intermediaries.
        reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');

        // Route by grant type.
        if (body.grant_type === 'authorization_code') {
          const responseBody = await handleAuthorizationCode({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'client_credentials') {
          const responseBody = await handleClientCredentials({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === 'refresh_token') {
          const responseBody = await handleRefreshToken({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        if (body.grant_type === TOKEN_EXCHANGE_GRANT_TYPE) {
          const responseBody = await handleTokenExchange({
            fastify,
            request: request as FastifyRequest,
            client,
            body,
          });
          return reply.send(responseBody);
        }

        // Schema validation should have rejected this already, but guard anyway.
        throw new BadRequestError('unsupported_grant_type');
      } catch (error) {
        if (
          error instanceof InvalidGrantError ||
          error instanceof InvalidTargetError ||
          error instanceof InvalidClientError ||
          error instanceof InvalidScopeError ||
          error instanceof InvalidRequestError ||
          error instanceof NotFoundError ||
          error instanceof BadRequestError ||
          error instanceof UnauthorizedClientError
        ) {
          await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.TOKEN);
          throw error;
        }

        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oauth.token.exchange.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: error instanceof Error ? error.message : 'Unknown error',
          },
        });

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
};

/**
 * Handle the authorization_code grant (legacy flow from Phase 1).
 * Now also issues `aud` + `scope` claims on the access token.
 */
async function handleAuthorizationCode(
  ctx: HandlerContext<TokenExchangeAuthCodeBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('authorization_code')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'authorization_code' },
    });
    // RFC 6749 5.2: client authenticated, but not authorized for this grant.
    throw new UnauthorizedClientError();
  }

  // Authorization code lookup
  const authCode = await fastify.repositories.authorizationCodes.findByCode(body.code);
  if (!authCode) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  if (authCode.oauthClientId !== client.id) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  if (body.redirect_uri !== authCode.redirectUri) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  const pkceValid = fastify.pkceUtils.verifyCodeChallenge(
    body.code_verifier,
    authCode.codeChallenge
  );
  if (!pkceValid) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'Invalid or expired authorization code' },
    });
    throw new InvalidGrantError('Invalid or expired authorization code');
  }

  // RFC 8707 §2.2: if the token request also includes `resource`, it MUST
  // be a subset of the one bound to the auth code. Empty request resource
  // carries forward the code's resource unchanged.
  const codeResource = authCode.resource ?? [];
  const requestedResource = body.resource ?? [];
  if (requestedResource.length > 0) {
    const extra = requestedResource.filter((r) => !codeResource.includes(r));
    if (extra.length > 0) {
      await fastify.repositories.auditLogs.create({
        userId: authCode.userId,
        oauthClientId: client.id,
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          error: 'invalid_target: resource outside the authorization-code binding',
          extra,
        },
      });
      throw new InvalidTargetError('requested resource is outside the authorization-code binding');
    }
  }
  const effectiveResource = requestedResource.length > 0 ? requestedResource : codeResource;

  await fastify.repositories.authorizationCodes.markUsed(authCode.id);

  const user = await fastify.repositories.users.findById(authCode.userId);
  if (!user) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'User not found' },
    });
    throw new NotFoundError('User', authCode.userId);
  }

  const scopeString = authCode.scopes.length > 0 ? authCode.scopes.join(' ') : undefined;

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client, effectiveResource),
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
        email: user.email,
        email_verified: user.emailVerified,
        name: resolveDisplayName(user),
        nonce: authCode.nonce ?? undefined,
      })
    : undefined;

  const { token: refreshToken, tokenHash } = fastify.jwtUtils.generateRefreshToken();

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();
  const refreshTokenExpiresAt = Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000;

  // Start a fresh refresh-token family. Every rotation (see
  // `handleRefreshToken`) inherits this `familyId` so replay of a revoked
  // token can be traced to — and revoke — the entire family.
  const familyId = randomUUID();

  await fastify.repositories.refreshTokens.create({
    userId: user.id,
    oauthClientId: client.id,
    tokenHash,
    familyId,
    expiresAt: refreshTokenExpiresAt,
    scopes: authCode.scopes,
    // RFC 8707: carry the resource set onto the refresh token so subsequent
    // refreshes produce access tokens with the same `aud`.
    resource: effectiveResource,
  });

  let sessionId: string | undefined;
  try {
    sessionId = randomUUID();
    await fastify.sessionUtils.setSession(
      sessionId,
      {
        userId: user.id,
        email: user.email,
        sessionId,
        createdAt: Date.now(),
      },
      accessTokenExpiresIn
    );
  } catch (sessionError) {
    fastify.log.warn({ err: sessionError }, 'Failed to manage session during token exchange');
  }

  await fastify.repositories.auditLogs.create({
    userId: user.id,
    oauthClientId: client.id,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: { authCodeId: authCode.id, grantType: 'authorization_code' },
  });

  // Token issuance metrics (#126).
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'authorization_code' });
  fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'authorization_code' });

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
    ...(idToken ? { id_token: idToken } : {}),
  };
}

/**
 * Derive the OIDC `name` claim from a user record.
 *
 * OIDC Core §5.1 defines `name` as the end-user's full display name. QAuth
 * stores `firstName` / `lastName` separately (both optional), so we join the
 * present parts. Returns `undefined` when neither is set so the claim is
 * omitted entirely rather than emitted as an empty string.
 */
function resolveDisplayName(user: {
  firstName?: string | null;
  lastName?: string | null;
}): string | undefined {
  const parts = [user.firstName, user.lastName].filter(
    (p): p is string => typeof p === 'string' && p.trim().length > 0
  );
  return parts.length > 0 ? parts.join(' ') : undefined;
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
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('client_credentials')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'client_credentials' },
    });
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
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: err instanceof Error ? err.message : 'invalid_scope',
        grantType: 'client_credentials',
      },
    });
    throw err;
  }

  // A scopeless machine token has no authorisation surface — almost always a
  // misconfiguration. Require at least one granted scope per RFC 9700 best
  // practice for client_credentials tokens.
  if (grantedScopes.length === 0) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_scope: client_credentials requires at least one scope',
        grantType: 'client_credentials',
      },
    });
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
      await fastify.repositories.auditLogs.create({
        userId: null,
        oauthClientId: client.id,
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          error: 'invalid_target: resource outside the client audience allowlist',
          extra,
          allowedAudience,
        },
      });
      throw new InvalidTargetError('requested resource is outside the client audience allowlist');
    }
  }

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: client.clientId,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client, requestedResource),
  });

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();

  // Per-agent action audit (ADR-007 §2, #186). client_credentials has no
  // subject user and no on-behalf-of `act` chain — the agent acts as itself —
  // so we attribute the agent and the effective scope mode but leave
  // `delegationChain`/`userId` null. Only an agent client (fail-closed
  // `isAgentClient`) is attributed; an ordinary machine client records no
  // agent fields, keeping existing behavior for non-agent clients unchanged.
  const isAgent = isAgentClient(client);
  await fastify.repositories.auditLogs.create({
    userId: null,
    oauthClientId: client.id,
    actorClientId: isAgent ? client.clientId : null,
    scopeMode: isAgent ? highestAgentModeInScopes(grantedScopes) : null,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: {
      grantType: 'client_credentials',
      scope: scopeString,
      resource: requestedResource,
    },
  });

  // Token issuance metrics (#126). No refresh token on client_credentials.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'client_credentials' });

  return {
    access_token: accessToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
  };
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
 * - Rotation: the presented token is marked `revoked='rotated'` BEFORE
 *   the new refresh token is persisted — never issue two concurrently
 *   live tokens for the same link in the family chain.
 * - Down-scoping: a `scope` param may request a subset of the original
 *   scopes; any scope not present in the original set → `invalid_scope`.
 *   Omitting the parameter reuses the original scopes verbatim.
 */
async function handleRefreshToken(
  ctx: HandlerContext<TokenExchangeRefreshBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  if (!client.grantTypes.includes('refresh_token')) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'unauthorized_client', grantType: 'refresh_token' },
    });
    throw new UnauthorizedClientError();
  }

  const presentedHash = fastify.jwtUtils.hashRefreshToken(body.refresh_token);

  // Fetch the row without any active-state filter so replay of a
  // revoked token is detectable; downstream checks enforce liveness.
  const storedToken =
    await fastify.repositories.refreshTokens.findByTokenHashIncludingRevoked(presentedHash);

  if (!storedToken) {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: refresh token not recognised' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Ownership check — before any replay logic, before any revocation.
  // Cross-client replay must never be able to fan out family revocation
  // on another client's tokens.
  if (storedToken.oauthClientId !== client.id) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_grant: refresh token bound to different client',
        presentingClientId: client.id,
        ownerClientId: storedToken.oauthClientId,
      },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Replay detection — a revoked token in the correct family MUST trigger
  // family-wide revocation per RFC 9700 §2.2.2 / OAuth 2.1 §4.3.1.
  if (storedToken.revoked) {
    const familyRevokedCount = await fastify.repositories.refreshTokens.revokeFamily(
      storedToken.familyId,
      'replay_detected'
    );
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'security',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: {
        error: 'invalid_grant: refresh token replay detected',
        familyId: storedToken.familyId,
        familyTokensRevoked: familyRevokedCount,
      },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  if (storedToken.expiresAt <= Date.now()) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: refresh token expired' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Load the subject user; reject if missing or disabled (RFC 9700 §4.14).
  const user = await fastify.repositories.users.findById(storedToken.userId);
  if (!user) {
    await fastify.repositories.auditLogs.create({
      userId: storedToken.userId,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: user not found' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }
  if (!user.enabled) {
    await fastify.repositories.refreshTokens.revoke(storedToken.id, 'user_disabled');
    await fastify.repositories.auditLogs.create({
      userId: user.id,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error: 'invalid_grant: user_disabled' },
    });
    throw new InvalidGrantError('Invalid or expired refresh token');
  }

  // Down-scoping: request narrower scope or keep original set.
  // Upscoping (any scope not in the original set) → invalid_scope.
  let grantedScopes: string[];
  if (body.scope !== undefined) {
    const requested = body.scope.split(/\s+/).filter((s) => s.length > 0);
    const extraneous = requested.filter((s) => !storedToken.scopes.includes(s));
    if (extraneous.length > 0) {
      await fastify.repositories.auditLogs.create({
        userId: user.id,
        oauthClientId: client.id,
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          error: 'invalid_scope: upscoping rejected',
          extraneous,
          originalScopes: storedToken.scopes,
        },
      });
      throw new InvalidScopeError(`${extraneous.join(' ')} not in original refresh token scope`);
    }
    grantedScopes = requested;
  } else {
    grantedScopes = storedToken.scopes;
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
      await fastify.repositories.auditLogs.create({
        userId: user.id,
        oauthClientId: client.id,
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          error: 'invalid_target: resource outside the refresh-token binding',
          extra,
        },
      });
      throw new InvalidTargetError('requested resource is outside the refresh-token binding');
    }
  }
  const effectiveResource = requestedResource.length > 0 ? requestedResource : storedResource;

  // Rotate atomically: revoke the presented token and insert the new one
  // inside a single transaction so a crash/failure between the two steps
  // can never leave the user with a revoked token and no replacement.
  // The revoke runs first inside the transaction so a concurrent replay
  // attempt waits on the row lock and then sees the token as already
  // revoked (→ family-revoke path). The unique index on `token_hash`
  // protects against the degenerate collision case.
  const { token: newRefreshToken, tokenHash: newRefreshTokenHash } =
    fastify.jwtUtils.generateRefreshToken();
  const refreshTokenExpiresAt = Date.now() + fastify.jwtUtils.getRefreshTokenLifespan() * 1000;

  await fastify.db.transaction(async (tx) => {
    await fastify.repositories.refreshTokens.revoke(storedToken.id, 'rotated', tx);
    await fastify.repositories.refreshTokens.create(
      {
        userId: user.id,
        oauthClientId: client.id,
        tokenHash: newRefreshTokenHash,
        familyId: storedToken.familyId,
        previousTokenHash: presentedHash,
        expiresAt: refreshTokenExpiresAt,
        scopes: grantedScopes,
        // RFC 8707: the rotated refresh token carries the (possibly
        // narrowed) resource binding — NOT the request's — so we never
        // widen the binding across a rotation.
        resource: effectiveResource,
      },
      tx
    );
  });

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    clientId: client.clientId,
    scope: scopeString,
    aud: resolveAudience(client, effectiveResource),
  });

  const accessTokenExpiresIn = fastify.jwtUtils.getAccessTokenLifespan();

  await fastify.repositories.auditLogs.create({
    userId: user.id,
    oauthClientId: client.id,
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: {
      grantType: 'refresh_token',
      familyId: storedToken.familyId,
      rotatedFromTokenId: storedToken.id,
      scope: scopeString,
    },
  });

  // Token issuance metrics (#126). Refresh-token rotation mints both.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'refresh_token' });
  fastify.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'refresh_token' });

  return {
    access_token: accessToken,
    refresh_token: newRefreshToken,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
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

/** Count the delegation depth of an `act` chain (1 = single actor). */
function actDepth(act: ActClaim | undefined): number {
  let depth = 0;
  let cursor: ActClaim | undefined = act;
  while (cursor) {
    depth += 1;
    cursor = cursor.act;
  }
  return depth;
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
 */
async function handleTokenExchange(
  ctx: HandlerContext<TokenExchangeTokenExchangeBody>
): Promise<TokenExchangeResponse> {
  const { fastify, request, client, body } = ctx;

  const auditFailure = async (error: string, extra?: Record<string, unknown>): Promise<void> => {
    await fastify.repositories.auditLogs.create({
      userId: null,
      oauthClientId: client.id,
      event: 'oauth.token.exchange.failure',
      eventType: 'token',
      success: false,
      ipAddress: request.ip,
      userAgent: request.headers['user-agent'] || null,
      metadata: { error, grantType: 'token-exchange', ...extra },
    });
  };

  // GATE 1 — agent classification + grant authorisation (default-deny).
  // `isAgentClient` is fail-closed; a client that omitted `is_agent` reads as
  // a non-agent and is rejected here.
  if (!isAgentClient(client)) {
    await auditFailure('unauthorized_client: token-exchange is restricted to agent clients');
    throw new UnauthorizedClientError();
  }
  if (!client.grantTypes.includes(TOKEN_EXCHANGE_GRANT_TYPE)) {
    await auditFailure('unauthorized_client: client not allowed the token-exchange grant');
    throw new UnauthorizedClientError();
  }

  // GATE 2 — token-type support. We only mint/consume OAuth access tokens.
  // OAuth error codes are the BARE token (RFC 6749 §5.2 / RFC 8693 §2.2.2);
  // human detail goes in `error_description` via InvalidRequestError.
  if (body.subject_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
    await auditFailure('invalid_request: unsupported subject_token_type', {
      subjectTokenType: body.subject_token_type,
    });
    throw new InvalidRequestError('unsupported subject_token_type');
  }
  if (
    body.requested_token_type !== undefined &&
    body.requested_token_type !== TOKEN_TYPE_ACCESS_TOKEN
  ) {
    await auditFailure('invalid_request: unsupported requested_token_type', {
      requestedTokenType: body.requested_token_type,
    });
    throw new InvalidRequestError('unsupported requested_token_type');
  }
  // RFC 8693 §2.1: actor_token_type is REQUIRED when actor_token is present.
  if (body.actor_token !== undefined && body.actor_token_type === undefined) {
    await auditFailure('invalid_request: actor_token_type required when actor_token present');
    throw new InvalidRequestError('actor_token_type is required when actor_token is present');
  }
  if (body.actor_token !== undefined && body.actor_token_type !== TOKEN_TYPE_ACCESS_TOKEN) {
    await auditFailure('invalid_request: unsupported actor_token_type', {
      actorTokenType: body.actor_token_type,
    });
    throw new InvalidRequestError('unsupported actor_token_type');
  }

  // GATE 3 — verify the subject token (EdDSA signature + exp). Only QAuth's
  // signing key verifies, so a valid signature establishes provenance; an
  // unverifiable or expired token is "unacceptable" → invalid_request.
  let subjectPayload: Awaited<ReturnType<typeof fastify.jwtUtils.verifyAccessToken>>;
  try {
    subjectPayload = await fastify.jwtUtils.verifyAccessToken(body.subject_token);
  } catch {
    await auditFailure('invalid_request: subject_token failed verification');
    throw new InvalidRequestError('subject_token is not a valid access token');
  }
  if (!subjectPayload.sub) {
    await auditFailure('invalid_request: subject_token missing sub');
    throw new InvalidRequestError('subject_token has no subject');
  }

  // GATE 3b — token-confusion defence. `verifyAccessToken` proves the EdDSA
  // signature + exp only; it does NOT assert issuer or token purpose. Without
  // this check, ANY JWT QAuth signs with the same key (e.g. a future ID token)
  // would verify and, if its `sub` resolved to a user, be accepted as a
  // subject token. Require (a) our own issuer and (b) the access-token
  // `token_use` marker. The marker is absent on legacy access tokens minted
  // before it existed, so we accept its absence only when the structural
  // access-token markers (`client_id` + `aud`) are present — never accept a
  // token that positively declares a non-access `token_use`.
  const expectedIssuer = fastify.jwtUtils.getIssuer();
  const issuerOk = subjectPayload.iss === expectedIssuer;
  const tokenUse = subjectPayload.token_use;
  const isAccessToken =
    tokenUse === 'access' ||
    (tokenUse === undefined &&
      subjectPayload.clientId !== undefined &&
      subjectPayload.aud !== undefined);
  if (!issuerOk || !isAccessToken) {
    await auditFailure('invalid_request: subject_token is not a QAuth access token', {
      issuerOk,
      tokenUse: tokenUse ?? null,
    });
    throw new InvalidRequestError('subject_token is not a QAuth-issued access token');
  }

  // If an actor_token is supplied, verify it too. We do not trust the agent's
  // self-declared identity from an unverified token — the actor identity used
  // in the `act` claim is the authenticated agent's own client_id (below).
  let actorPayload: Awaited<ReturnType<typeof fastify.jwtUtils.verifyAccessToken>> | undefined;
  if (body.actor_token !== undefined) {
    try {
      actorPayload = await fastify.jwtUtils.verifyAccessToken(body.actor_token);
    } catch {
      await auditFailure('invalid_request: actor_token failed verification');
      throw new InvalidRequestError('actor_token is not a valid access token');
    }
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
    await auditFailure('invalid_request: subject_token not issued for this agent', {
      subjectAudience,
    });
    throw new InvalidRequestError('subject_token was not issued for this client');
  }

  // The subject user must still exist and be enabled (RFC 9700 §4.14). We bind
  // the delegated token's `sub` to the *current* user record, not blindly to
  // the token's `sub` string.
  const user = await fastify.repositories.users.findById(subjectPayload.sub);
  if (!user) {
    await auditFailure('invalid_request: subject user not found');
    throw new InvalidRequestError('subject_token subject is unknown');
  }
  if (!user.enabled) {
    await auditFailure('invalid_request: subject user disabled', { userId: user.id });
    throw new InvalidRequestError('subject_token subject is not active');
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
      await auditFailure('invalid_scope: requested scope exceeds subject token', {
        extraneous,
        subjectScopes,
      });
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
    await auditFailure('invalid_scope: delegated scope exceeds the agent scope mode', {
      grantedScopes,
      maxAgentMode: client.maxAgentMode ?? null,
    });
    throw err;
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
      await auditFailure('invalid_target: requested audience outside subject token audience', {
        extra,
        subjectAudience,
      });
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
    await auditFailure('invalid_request: delegation chain too deep', {
      depth,
      max: MAX_DELEGATION_DEPTH,
    });
    throw new InvalidRequestError('delegation chain exceeds the maximum depth');
  }

  const scopeString = grantedScopes.length > 0 ? grantedScopes.join(' ') : undefined;
  const aud = arrayToAud(effectiveAudience);

  // Clamp lifespan so the delegated token NEVER outlives the subject token's
  // authority (and so it cannot be re-exchanged to extend it indefinitely).
  // `exp` is in seconds; verifyAccessToken already rejected an expired token,
  // so remaining is > 0 here, but we guard against the boundary defensively.
  const configuredLifespan = fastify.jwtUtils.getAccessTokenLifespan();
  const subjectRemaining =
    subjectPayload.exp !== undefined
      ? subjectPayload.exp - Math.floor(Date.now() / 1000)
      : configuredLifespan;
  const accessTokenExpiresIn = Math.max(0, Math.min(configuredLifespan, subjectRemaining));
  if (accessTokenExpiresIn <= 0) {
    await auditFailure('invalid_request: subject_token has no remaining lifetime');
    throw new InvalidRequestError('subject_token has expired');
  }

  const accessToken = await fastify.jwtUtils.signAccessToken({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    clientId: client.clientId,
    scope: scopeString,
    aud,
    act,
    expiresInOverride: accessTokenExpiresIn,
  });

  // Per-agent action audit (ADR-007 §2, #186). The delegated token was minted
  // on behalf of `user` BY this agent — record the attribution as structured,
  // queryable columns (agent client_id, the flattened `act` delegation chain,
  // and the effective agent scope mode) on top of the existing metadata. Only
  // public identifiers are stored; no subject/actor token, secret, or scope
  // secret is ever persisted.
  await fastify.repositories.auditLogs.create({
    userId: user.id,
    oauthClientId: client.id,
    actorClientId: client.clientId,
    delegationChain: flattenActChain(act),
    scopeMode: highestAgentModeInScopes(grantedScopes),
    event: 'oauth.token.exchange.success',
    eventType: 'token',
    success: true,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: {
      grantType: 'token-exchange',
      actor: client.clientId,
      delegationDepth: depth,
      hasActorToken: body.actor_token !== undefined,
      actorTokenSubject: actorPayload?.sub,
      scope: scopeString,
      audience: effectiveAudience,
      expiresIn: accessTokenExpiresIn,
    },
  });

  // Token issuance metrics (#126). Token-exchange mints an access token only.
  fastify.metrics.tokensIssued.inc({ type: 'access', grant_type: 'token-exchange' });

  // RFC 8693 §2.2.1: token-exchange responses MUST include `issued_token_type`.
  return {
    access_token: accessToken,
    issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
    expires_in: accessTokenExpiresIn,
    token_type: 'Bearer' as const,
    ...(scopeString ? { scope: scopeString } : {}),
  };
}
