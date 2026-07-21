import { randomBytes } from 'node:crypto';

import { BadRequestError, isUniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import { AUTHORIZATION_CODE_TTL_MS, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { findExceedingAgentScopesForClient, resolveAudience } from '../../helpers/client-auth';
import { resolveClient } from '../../helpers/client-resolution';
import { canSkipConsent, filterRequestedScopes } from '../../helpers/consent';
import { resolveIssuerIdentifier } from '../../helpers/discovery';
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
 * The authorize request expressed as a URL with its parameters in the query
 * string. On GET this is simply `request.url`. On POST (OIDC Core §3.1.2.1)
 * the parameters arrived form-encoded in the body, so we reconstruct an
 * equivalent authorize URL from the validated body. This keeps two paths
 * byte-identical: the RFC 8707 `resource` parse (which reads from the URL) and
 * the /ui/login + /ui/consent round-trips, which bounce the user back to the
 * authorization endpoint via a GET — so a POST request must round-trip through
 * a query string all the same.
 */
function buildAuthorizeUrlWithParams(request: FastifyRequest): string {
  if (request.method !== 'POST') {
    return request.url;
  }
  const path = request.url.split('?')[0];
  const body = (request.body ?? {}) as Record<string, unknown>;
  const usp = new URLSearchParams();
  for (const [key, value] of Object.entries(body)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) usp.append(key, String(item));
    } else {
      usp.append(key, String(value));
    }
  }
  const qs = usp.toString();
  return qs.length > 0 ? `${path}?${qs}` : path;
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
  // OIDC Core §3.1.2.1: the authorization endpoint MUST support BOTH GET (params
  // in the query string) and POST (params form-encoded in the body). ONE shared
  // config and ONE shared handler back both methods, so their behaviour —
  // validation, PKCE, redirect-uri checks, step-up, rate limiting, error shapes —
  // is byte-for-byte identical; only where the parameters are read differs.
  const config = {
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
      keyGenerator: (req: FastifyRequest) => req.ip || 'unknown',
    },
  };

  const handler = async (request: FastifyRequest, reply: FastifyReply) => {
    // OIDC Core §3.1.2.1: read the validated params from the body on POST and
    // the query on GET. The SAME Zod schema (`authorizeQuerySchema`) validates
    // both, so `query` is identically shaped and every check below is unchanged.
    const query = (request.method === 'POST' ? request.body : request.query) as AuthorizeQuery;
    // For the RFC 8707 `resource` parse and the /ui/login + /ui/consent
    // round-trips we need the request as a query string. On GET that is
    // `request.url`; on POST the params live in the body, so reconstruct an
    // equivalent authorize URL (see `buildAuthorizeUrlWithParams`).
    const requestUrlWithParams = buildAuthorizeUrlWithParams(request);
    const redirectUri = query.redirect_uri;
    const state = query.state;

    // RFC 9207 §2 (#282): the issuer identifier echoed as `iss` in EVERY
    // authorization response below. Derived from the same `getIssuer()` +
    // `resolveIssuerIdentifier()` pair that builds the `issuer` member of the
    // discovery documents, so the value a client compares against its cached
    // metadata is byte-identical. Resolved once, up front, so no branch can
    // reach a redirect with a differently-shaped issuer.
    const iss = resolveIssuerIdentifier(fastify.jwtUtils.getIssuer());

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
          iss,
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
          iss,
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
          iss,
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
      const returnTo = `${requestUrlWithParams}`;
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
          // RFC 9700 mix-up defence: only accept a token this AS issued.
          issuer: fastify.jwtUtils.getIssuer(),
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
            iss,
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
          iss,
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
            iss,
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
              iss,
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
        const returnTo = `${requestUrlWithParams}`;
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
        // Carry the authorize params to the consent screen. Guard the `?`
        // index: `buildAuthorizeUrlWithParams` can return a query-less path
        // (empty reconstructed POST body), and `slice(-1)` would yield a
        // corrupt `/ui/consent<lastchar>` — same defensive check as
        // `parseResourceFromUrl`.
        const qIndex = requestUrlWithParams.indexOf('?');
        const returnQuery = qIndex >= 0 ? requestUrlWithParams.slice(qIndex) : '';
        return reply.redirect(`/ui/consent${returnQuery}`, 302);
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
        // OIDC Core §2 `auth_time`: persist the REAL end-user authentication
        // time (browser-session establishment, epoch MS) — never the code-mint
        // time — so /oauth/token can assert it in the ID token and a `max_age`
        // check evaluates the actual session age. Null on the legacy Bearer
        // path (no interactive session) → the claim is simply omitted there.
        authTime: browserSession?.createdAt ?? null,
        scopes,
        // RFC 8707: bind the resource indicator(s) to the authorization
        // code so /oauth/token can set the access token's `aud` claim to
        // exactly what the client requested. Reached on the consent-skip
        // path (returning user, prior consent covers requested scopes);
        // the consent-screen path creates codes in ui/consent.ts.
        resource: parseResourceFromUrl(requestUrlWithParams),
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
      buildRedirectUrl(redirectUri, { code, state: state ?? undefined, iss }),
      302
    );
  };

  const app = fastify.withTypeProvider<ZodTypeProvider>();
  app.get(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint (GET). Issues an authorization code with PKCE and redirects to the client redirect_uri.',
        tags: ['OAuth', 'Authorization'],
        querystring: authorizeQuerySchema,
      },
      config,
    },
    handler
  );
  // OIDC Core §3.1.2.1: the POST form of the SAME endpoint. Identical schema
  // (validated as the body), config, and handler — only the parameter source
  // differs (form-encoded body vs query string).
  app.post(
    '/authorize',
    {
      schema: {
        description:
          'OAuth 2.1 authorization endpoint (POST). Identical to GET; parameters are form-encoded in the request body (OIDC Core §3.1.2.1).',
        tags: ['OAuth', 'Authorization'],
        body: authorizeQuerySchema,
      },
      config,
    },
    handler
  );
}
