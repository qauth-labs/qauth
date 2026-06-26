import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { findExceedingAgentScopesForClient, resolveAudience } from '../../helpers/client-auth';
import { resolveClient } from '../../helpers/client-resolution';
import { canSkipConsent, filterRequestedScopes } from '../../helpers/consent';
import { resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import { buildRedirectUrl, isRedirectUriAllowedForPolicy } from '../../helpers/oauth-redirect';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import {
  evaluateStepUp,
  isDangerousScope,
  parsePromptMode,
  stepUpErrorForPromptNone,
} from '../../helpers/step-up';
import { type AuthorizeQuery, authorizeQuerySchema } from '../../schemas/oauth';

/**
 * RFC 8707: parse every `resource=` query param directly from the request
 * URL instead of relying on `request.query.resource`.
 *
 * Why: fastify-type-provider-zod@6.1.0 drops the `resource` field from the
 * parsed query when its Zod schema is a union + transform (e.g.
 * `z.union([z.url(), z.array(z.url())]).transform(...)`) — the raw-string
 * variant from Fastify's querystring parser does not survive the validator.
 * The field IS validated (invalid URIs fail the whole request), but the
 * validator does not write the parsed array back into request.query.
 *
 * Reading from `request.url` sidesteps the validator entirely. Zod has
 * already rejected invalid inputs at schema time, so whatever reaches this
 * code point is already shape-safe.
 */
function parseResourceFromUrl(url: string): string[] {
  const q = url.indexOf('?');
  if (q < 0) return [];
  const params = new URLSearchParams(url.slice(q + 1));
  return params.getAll('resource');
}

/**
 * GET /oauth/authorize
 * OAuth 2.1 Authorization Code Flow with PKCE.
 *
 * Accepts two user-auth mechanisms:
 *   1. Browser-driven (issue #150): signed __Host-qauth_session cookie.
 *      No session → redirect to /ui/login with return_to. Session + no
 *      prior consent covering the requested scopes → redirect to the
 *      consent screen at /ui/consent. Otherwise issue a code directly.
 *   2. Legacy/machine: Authorization: Bearer <access_token>. Retained for
 *      backwards compatibility with first-party callers that have not yet
 *      migrated to the browser flow. MUST NOT be relied on once dynamic
 *      client registration is opened up.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint. Issues authorization code with PKCE. Requires Bearer access token for user context. Redirects to client redirect_uri.',
        tags: ['OAuth', 'Authorization'],
        querystring: authorizeQuerySchema,
      },
      config: {
        rateLimit: {
          // Environment-aware cap (ADR-008 §5, #209): a production realm ceiling
          // forces the strict cap; a development/staging ceiling permits the
          // lenient cap. Resolved at the realm level because rate limiting runs
          // before the client is authenticated. Fail-safe to strict.
          max: () =>
            resolveRealmRateLimitMax(fastify, {
              lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
              strictMax: env.AUTHORIZE_RATE_LIMIT,
            }),
          timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const query = request.query as AuthorizeQuery;
      const redirectUri = query.redirect_uri;
      const state = query.state;

      const realm = await getOrCreateDefaultRealm(fastify);

      // Client resolution priority (MCP 2025-11-25): pre-registered (DB) →
      // CIMD (https-URL client_id, fetched + SSRF-guarded + validated, then
      // idempotently materialised as a row) → unknown. A resolved CIMD
      // client is a real persisted row, so the existing audit / auth-code /
      // refresh-token foreign keys work unchanged. See client-resolution.ts.
      const { client, reason } = await resolveClient(fastify, realm.id, query.client_id);

      if (!client) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: reason ?? 'invalid_client', client_id: query.client_id },
        });
        throw new BadRequestError('invalid_client');
      }

      // CIMD §: the authorization request's redirect_uri MUST exactly match
      // one of the document's redirect_uris (this list came from the
      // metadata document for a CIMD client, or the registered set for a
      // pre-registered one). No wildcards.
      if (!client.redirectUris.includes(redirectUri)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'redirect_uri not registered', client_id: query.client_id },
        });
        throw new BadRequestError('redirect_uri not registered');
      }

      // ADR-008 §5/§7 (#197): resolve the effective environment policy now that
      // both the client and its realm are in scope, and apply the localhost
      // redirect gate. `http://localhost` (loopback) redirect URIs are a
      // `development`-only convenience; `staging`/`production` are https-only.
      // This is a SECOND gate after the exact-match check above — the URI is
      // registered, but a plain-HTTP loopback target is withheld outside
      // development. Fail-safe: an unset client/realm resolves to `production`,
      // which rejects it. We reject BEFORE redirecting (the redirect target is
      // the very thing under suspicion), matching the unregistered-URI handling.
      const policy = resolveEnvironmentPolicy(client, realm);
      if (!isRedirectUriAllowedForPolicy(redirectUri, policy)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: 'redirect_uri not permitted for this environment',
            reason: 'http_localhost_redirect_requires_development',
            client_id: query.client_id,
            environment: policy.environment,
          },
        });
        throw new BadRequestError('redirect_uri not permitted for this environment');
      }

      if (!client.enabled) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      if (!client.grantTypes.includes('authorization_code')) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      if (!client.responseTypes.includes('code')) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { error: 'unauthorized_client', client_id: query.client_id },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'unauthorized_client',
            state: state ?? undefined,
          }),
          302
        );
      }

      // -----------------------------------------------------------------
      // User authentication. Prefer the session cookie; fall back to
      // Bearer for backwards compat. When both are absent we kick to the
      // login page with a return_to URL so the user can establish a
      // session and come back.
      // -----------------------------------------------------------------
      const browserSession = await resolveBrowserSession(fastify, request, reply);
      const bearer = fastify.jwtUtils.extractFromHeader(request.headers.authorization);

      if (!browserSession && !bearer) {
        // No auth at all → browser flow. Redirect to login, then the user
        // lands back on this very URL and the session cookie path takes
        // over. We preserve the exact query string so PKCE challenge,
        // scope, and state survive the round-trip.
        const returnTo = `${request.url}`;
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
      }

      let userId: string;
      if (browserSession) {
        userId = browserSession.userId;
      } else {
        // bearer path
        try {
          const systemClient = await getOrCreateSystemClient(realm.id, fastify);
          const payload = await fastify.jwtUtils.verifyAccessToken(bearer as string, {
            audience: resolveAudience(systemClient),
          });
          userId = payload.sub;
        } catch {
          await fastify.repositories.auditLogs.create({
            userId: null,
            oauthClientId: client.id,
            event: 'oauth.authorize.failure',
            eventType: 'token',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: { error: 'access_denied', client_id: query.client_id },
          });
          return reply.redirect(
            buildRedirectUrl(redirectUri, {
              error: 'access_denied',
              error_description: 'Invalid or expired token',
              state: state ?? undefined,
            }),
            302
          );
        }
      }

      // ADR-007 §2 (#184): deny-by-default agent scope-mode cap. A reserved
      // agent-mode scope (`agent:readonly|admin|exec`) is permitted ONLY for a
      // verified agent within its server-side `maxAgentMode`. A non-agent
      // client (incl. one that omitted `is_agent`) or one over its cap is
      // rejected up front with `invalid_scope` (RFC 6749 §4.1.2.1) rather than
      // having the offending scope silently dropped, so an over-asking agent
      // gets a clear error. `filterRequestedScopes` then applies the ordinary
      // allowlist to whatever survives.
      const exceedingAgentScopes = findExceedingAgentScopesForClient(query.scope, client);
      if (exceedingAgentScopes.length > 0) {
        await fastify.repositories.auditLogs.create({
          userId,
          oauthClientId: client.id,
          event: 'oauth.authorize.failure',
          eventType: 'token',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {
            error: 'invalid_scope',
            reason: 'agent_scope_mode_exceeded',
            client_id: query.client_id,
            exceeding: exceedingAgentScopes.join(' '),
          },
        });
        return reply.redirect(
          buildRedirectUrl(redirectUri, {
            error: 'invalid_scope',
            error_description: 'requested scope exceeds the agent scope mode for this client',
            state: state ?? undefined,
          }),
          302
        );
      }

      // Deny-by-default: when a client has no scope allowlist configured we
      // grant nothing, matching `validateScopes` on the client_credentials
      // path. Previously an empty allowlist silently over-granted every
      // requested scope on the auth-code flow.
      const scopes = filterRequestedScopes(query.scope, client);

      // ADR-007 §2 (#185): step-up on the legacy Bearer path. The Bearer path
      // authenticates the user from an existing access token and CANNOT run an
      // interactive step-up (no login / consent screen for a machine caller),
      // so it must not be a back door that mints a dangerous-scope code with no
      // fresh authentication. Default-deny: a Bearer authorize request carrying
      // any dangerous scope (write:* / agent:admin / agent:exec) is refused
      // with `access_denied` and the client is told to use the interactive
      // browser flow (which enforces the dangerous-op re-auth gate). Bearer is
      // legacy first-party and not exposed to dynamically-registered clients,
      // so this only affects first-party callers requesting dangerous scopes.
      // ADR-008 §5 (#197): the automatic dangerous-scope refusal is gated by the
      // environment policy. Staging/production (and the fail-safe default) keep
      // it; a `development` client relaxes it so local Bearer-path iteration
      // with dangerous scopes is not forced through the browser flow. This only
      // relaxes the SERVER-inferred dangerous gate — every other Bearer check
      // (token validity, scope allowlist, agent cap) still applies.
      if (!browserSession && policy.agentStepUpEnforced) {
        const bearerDangerous = scopes.filter(isDangerousScope);
        if (bearerDangerous.length > 0) {
          await fastify.repositories.auditLogs.create({
            userId,
            oauthClientId: client.id,
            event: 'oauth.stepup.required',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              client_id: query.client_id,
              reason: 'bearer_path_dangerous_scope_requires_interactive_stepup',
              dangerous: bearerDangerous,
            },
          });
          return reply.redirect(
            buildRedirectUrl(redirectUri, {
              error: 'access_denied',
              error_description:
                'dangerous scopes require interactive step-up; use the browser authorization flow',
              state: state ?? undefined,
            }),
            302
          );
        }
      }

      // Browser-driven flow: show the consent screen unless a previous
      // grant already covers the requested scopes. Bearer-token callers
      // skip the consent step entirely — they are first-party and the
      // Bearer path is not exposed to dynamically-registered clients.
      if (browserSession) {
        const existingConsent = await fastify.repositories.oauthConsents.findActive(
          userId,
          client.id
        );

        // ADR-007 §2 (#185): step-up authentication before dangerous
        // operations / on elevation. A request that widens the granted scope
        // set (incremental consent, MCP 2025-11-25), or that asks for a
        // dangerous scope (write:* / agent:admin / agent:exec), or that sends
        // `prompt`/`max_age`, must NOT be served from the existing session +
        // prior consent silently. We re-authenticate and/or re-consent. The
        // decision is default-deny: a dangerous elevation forces a fresh login
        // with no client opt-in required.
        const prompt = parsePromptMode(query.prompt);
        const stepUp = evaluateStepUp({
          requestedScopes: scopes,
          priorConsentScopes:
            existingConsent && existingConsent.revokedAt === null ? existingConsent.scopes : [],
          prompt,
          maxAgeSeconds: query.max_age ?? null,
          authTimeMs: browserSession.createdAt,
          nowMs: Date.now(),
          freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
          // ADR-008 §5 (#197): relax the automatic dangerous-scope fresh-login
          // for a development client; explicit prompt/max_age still enforced.
          enforceDangerousStepUp: policy.agentStepUpEnforced,
        });

        // OIDC Core §3.1.2.1: `prompt=none` forbids ANY user-facing UI. If
        // step-up would otherwise show the login or consent screen, return the
        // matching bare OIDC error to the client instead of redirecting to UI.
        if (prompt === 'none') {
          const oidcError = stepUpErrorForPromptNone(stepUp);
          if (oidcError) {
            await fastify.repositories.auditLogs.create({
              userId,
              oauthClientId: client.id,
              event: 'oauth.stepup.required',
              eventType: 'auth',
              success: false,
              ipAddress: request.ip,
              userAgent: request.headers['user-agent'] || null,
              metadata: {
                client_id: query.client_id,
                reason: 'prompt_none_interaction_required',
                error: oidcError,
                elevated: stepUp.elevated,
                dangerous: stepUp.dangerous,
              },
            });
            return reply.redirect(
              buildRedirectUrl(redirectUri, {
                error: oidcError,
                error_description: 'step-up interaction is required but prompt=none was requested',
                state: state ?? undefined,
              }),
              302
            );
          }
          // No interaction required → fall through to ordinary issuance.
        }

        if (prompt !== 'none' && stepUp.requiresFreshLogin) {
          // Force a fresh end-user authentication: bounce through /ui/login,
          // which always mints a brand-new session (session-fixation defense),
          // resetting auth_time so the elevation is granted only right after
          // the user proves presence. The full authorize URL (incl. prompt /
          // max_age / scope / PKCE) is preserved so the round-trip is lossless.
          await fastify.repositories.auditLogs.create({
            userId,
            oauthClientId: client.id,
            event: 'oauth.stepup.required',
            eventType: 'auth',
            success: false,
            ipAddress: request.ip,
            userAgent: request.headers['user-agent'] || null,
            metadata: {
              client_id: query.client_id,
              reason: 'fresh_authentication_required',
              elevated: stepUp.elevated,
              dangerous: stepUp.dangerous,
              prompt: prompt ?? null,
              maxAge: query.max_age ?? null,
            },
          });
          const returnTo = `${request.url}`;
          return reply.redirect(`/ui/login?return_to=${encodeURIComponent(returnTo)}`, 302);
        }

        // Re-consent when the request elevates scope or explicitly asks for it,
        // even if a prior grant would otherwise let us skip the screen — a
        // wider scope set must be explicitly re-affirmed, never auto-widened.
        // (`prompt=none` already returned consent_required above if needed.)
        if (
          prompt !== 'none' &&
          (stepUp.requiresConsent || !canSkipConsent(existingConsent, client, scopes))
        ) {
          if (stepUp.elevated.length > 0) {
            await fastify.repositories.auditLogs.create({
              userId,
              oauthClientId: client.id,
              event: 'oauth.stepup.required',
              eventType: 'auth',
              success: false,
              ipAddress: request.ip,
              userAgent: request.headers['user-agent'] || null,
              metadata: {
                client_id: query.client_id,
                reason: 'incremental_consent_required',
                elevated: stepUp.elevated,
                dangerous: stepUp.dangerous,
              },
            });
          }
          return reply.redirect(`/ui/consent${request.url.slice(request.url.indexOf('?'))}`, 302);
        }
      }

      const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL_MS;

      const createCode = async (): Promise<string> => {
        const code = randomBytes(32).toString('base64url');
        await fastify.repositories.authorizationCodes.create({
          code,
          oauthClientId: client.id,
          userId,
          redirectUri,
          codeChallenge: query.code_challenge,
          codeChallengeMethod: 'S256',
          nonce: query.nonce ?? null,
          scopes,
          // RFC 8707: bind the resource indicator(s) to the authorization
          // code so /oauth/token can set the access token's `aud` claim to
          // exactly what the client requested. Reached on the consent-skip
          // path (returning user, prior consent covers requested scopes);
          // the consent-screen path creates codes in ui/consent.ts.
          resource: parseResourceFromUrl(request.url),
          state: query.state ?? null,
          expiresAt,
        });
        return code;
      };

      const MAX_CREATE_ATTEMPTS = 3;
      let code: string | null = null;
      for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
        try {
          code = await createCode();
          break;
        } catch (err) {
          if (!isUniqueConstraintError(err)) throw err;
          if (attempt === MAX_CREATE_ATTEMPTS - 1) throw err;
        }
      }
      if (!code) throw new Error('Unreachable');

      await fastify.repositories.auditLogs.create({
        userId,
        oauthClientId: client.id,
        event: 'oauth.authorize.success',
        eventType: 'token',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { redirectUri },
      });

      return reply.redirect(
        buildRedirectUrl(redirectUri, { code, state: state ?? undefined }),
        302
      );
    }
  );
}
