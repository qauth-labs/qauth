import { randomBytes } from 'node:crypto';

import { refuseBoundTokenAsBearer } from '@qauth-labs/fastify-plugin-jwt';
import {
  isUniqueConstraintError,
  JWTInvalidError,
  UnauthorizedClientError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';

import { env } from '../../../config/env';
import {
  AUTHORIZATION_CODE_TTL_MS,
  AUTHORIZE_BODY_LIMIT_BYTES,
  STEP_UP_FRESH_AUTH_WINDOW_MS,
} from '../../constants';
import { toStoredAssuranceLevel } from '../../helpers/acr-claims';
import { sendAuthorizationError } from '../../helpers/authorization-error';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { findExceedingAgentScopesForClient, resolveAudience } from '../../helpers/client-auth';
import { resolveClient, unresolvedClientError } from '../../helpers/client-resolution';
import { isClientUsable, unusableClientError } from '../../helpers/client-status';
import { canSkipConsent, filterRequestedScopes } from '../../helpers/consent';
import { resolveIssuerIdentifier } from '../../helpers/discovery';
import { MALFORMED_DPOP_JKT_DESCRIPTION, readAuthorizationDpopJkt } from '../../helpers/dpop';
import { resolveEnvironmentPolicy } from '../../helpers/environment-policy';
import { assertManagementToken } from '../../helpers/management-token';
import { getOrCreateSystemClient } from '../../helpers/oauth-client';
import {
  buildRedirectUrl,
  isAllowedRedirectUriScheme,
  isHttpLocalhostRedirect,
  isRedirectUriAllowedForPolicy,
  redirectUriMatchesRegistered,
  redirectUriNotPermittedError,
  unregisteredRedirectUriError,
} from '../../helpers/oauth-redirect';
import { redirectToLoginWithPendingAuthorization } from '../../helpers/pending-authorization';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import {
  evaluateStepUp,
  isDangerousScope,
  parsePromptMode,
  stepUpErrorForPromptNone,
} from '../../helpers/step-up';
import { isJtiRevoked } from '../../helpers/token-revocation';
import { inactiveSubjectError } from '../../helpers/token-subject';
import { emitUserEvent, type UserEventOptions } from '../../helpers/user-events';
import { type AuthorizeQuery, authorizeQuerySchema } from '../../schemas/oauth';

/** A `snake_case` code, the form an event's `reason` takes. */
const REASON_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The `reason` of the failure event for a `client_id` that resolved to no
 * client. `resolveClient` answers `invalid_client` for an unknown client, a
 * code for a CIMD resolution that failed, and the refusal's prose (for the
 * operator's log) for a CIMD document it refused.
 */
function unresolvedClientReason(reason: string | undefined): string {
  if (reason === undefined || reason === 'invalid_client') return 'unknown_client';
  return REASON_CODE.test(reason) ? reason : 'cimd_client_refused';
}

/**
 * The authorize request expressed as a URL with its parameters in the query
 * string. On GET this is simply `request.url`. On POST (OIDC Core §3.1.2.1)
 * the parameters arrived form-encoded in the body, so we reconstruct an
 * equivalent authorize URL from the validated body: the /ui/login +
 * /ui/consent round-trips bounce the user back to the authorization endpoint
 * via a GET — so a POST request must round-trip through a query string all the
 * same.
 *
 * This string is ONLY ever forwarded, for the receiving route to parse and
 * validate again. Never read a parameter back out of it: a second parser does
 * not split every string the way Fastify's does, so it can find a value the
 * schema never saw. Parameters come from the validated `query`.
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
 *      No session → redirect to /ui/login with a `return_to` pointing at
 *      `/ui/resume/<handle>`; the authorize URL itself is parked server-side
 *      (see helpers/pending-authorization.ts, #316). Session + no
 *      prior consent covering the requested scopes → redirect to the
 *      consent screen at /ui/consent. Otherwise issue a code directly.
 *   2. Legacy/machine: Authorization: Bearer <access_token>. Retained for
 *      backwards compatibility with first-party callers that have not yet
 *      migrated to the browser flow. It cannot show the consent screen, so
 *      it issues a code ONLY under a stored consent that already covers the
 *      request (the same `canSkipConsent` gate as the browser flow); any
 *      other request is refused with `access_denied`.
 */
export default async function (fastify: FastifyInstance) {
  // OIDC Core §3.1.2.1: the authorization endpoint MUST support BOTH GET (params
  // in the query string) and POST (params form-encoded in the body). ONE shared
  // config and ONE shared handler back both methods, so their behaviour —
  // validation, PKCE, redirect-uri checks, step-up, rate limiting, error shapes —
  // is byte-for-byte identical; only where the parameters are read differs.
  const config = {
    // Reads and sets the browser session cookie: the realm host only (#486).
    surface: 'browser' as const,
    // An OAuth protocol endpoint: an error it does not redirect answers the
    // RFC 6749 body, not a problem document (ADR-019 Decision 7, #513).
    errorFormat: 'oauth' as const,
    rateLimit: {
      // Environment-aware cap (ADR-008 §5, #209): a production realm ceiling
      // forces the strict cap; a development/staging ceiling permits the
      // lenient cap. Resolved from the request's realm (#487) because rate
      // limiting runs before the client is authenticated. Fail-safe to strict.
      max: (request: FastifyRequest) =>
        resolveRealmRateLimitMax(request.realm, {
          lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
          strictMax: env.AUTHORIZE_RATE_LIMIT,
        }),
      timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };

  const handler = async (request: FastifyRequest, reply: FastifyReply) => {
    // OIDC Core §3.1.2.1: read the validated params from the body on POST and
    // the query on GET. The SAME Zod schema (`authorizeQuerySchema`) validates
    // both, so `query` is identically shaped and every check below is unchanged.
    const query = (request.method === 'POST' ? request.body : request.query) as AuthorizeQuery;
    // For the /ui/login + /ui/consent round-trips we need the request as a
    // query string. On GET that is `request.url`; on POST the params live in
    // the body, so reconstruct an equivalent authorize URL (see
    // `buildAuthorizeUrlWithParams`).
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

    const realm = requestRealm(request);

    // Client resolution priority (MCP 2025-11-25): pre-registered (DB) →
    // CIMD (https-URL client_id, fetched + SSRF-guarded + validated, then
    // idempotently materialised as a row) → unknown. A resolved CIMD
    // client is a real persisted row, so the existing auth-code /
    // refresh-token foreign keys work unchanged. See client-resolution.ts.
    const { client, reason } = await resolveClient(fastify, realm.id, query.client_id);

    if (!client) {
      // No client resolved: the `client_id` the request named is not one,
      // so the event names no client. Its `error` is the one the caller is
      // answered, `invalid_request` (RFC 6749 §4.1.2.1; #513).
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: unresolvedClientReason(reason) },
        { realmId: realm.id, actor: 'client' }
      );
      throw unresolvedClientError();
    }

    // Who the events below name until a user is known: the requesting client.
    const clientEvent: UserEventOptions = {
      realmId: realm.id,
      clientId: client.clientId,
      actor: 'client',
    };

    // CIMD §: the authorization request's redirect_uri MUST exactly match
    // one of the document's redirect_uris (this list came from the
    // metadata document for a CIMD client, or the registered set for a
    // pre-registered one). No wildcards. The one exception is the port of a
    // loopback redirect, which RFC 8252 §7.3 requires us to let vary (#414);
    // everything downstream uses the REQUESTED URI, so the code is bound to
    // and the response goes to the port the client is listening on.
    if (!redirectUriMatchesRegistered(redirectUri, client.redirectUris)) {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'redirect_uri_not_registered' },
        clientEvent
      );
      throw unregisteredRedirectUriError();
    }

    // ADR-008 §5/§7 (#197): resolve the effective environment policy now that
    // both the client and its realm are in scope, and apply the plain-HTTP
    // redirect gate. This is a SECOND gate after the exact-match check above:
    // an `http://` loopback redirect is allowed only where PKCE is enforced or
    // the environment is `development`, a non-loopback `http://` redirect
    // is refused everywhere (ANT-2026-D0XJAT8S), and so is any scheme other
    // than https, http, an RFC 8252 private-use one and a bare one the
    // deployment lists in REDIRECT_URI_CUSTOM_SCHEMES (#774), which a row
    // registered before registration refused them could still hold. Fail-safe:
    // an unset client/realm resolves to `production`. We reject BEFORE
    // redirecting (the redirect target is the very thing under suspicion),
    // matching the unregistered-URI handling.
    const policy = resolveEnvironmentPolicy(client, realm);
    if (!isRedirectUriAllowedForPolicy(redirectUri, policy, env.REDIRECT_URI_CUSTOM_SCHEMES)) {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        {
          error: 'invalid_request',
          reason: !isAllowedRedirectUriScheme(redirectUri, env.REDIRECT_URI_CUSTOM_SCHEMES)
            ? 'redirect_uri_scheme_not_allowed'
            : isHttpLocalhostRedirect(redirectUri)
              ? 'http_localhost_redirect_requires_development'
              : 'http_redirect_requires_loopback',
        },
        clientEvent
      );
      throw redirectUriNotPermittedError();
    }

    // A client that may not use this endpoint at all (disabled, or not
    // registered for the code grant / `code` response type) is answered with
    // a 400 and never redirected, whoever provisioned it (RFC 9700 §4.11.2).
    // These checks run before any user interaction, so a redirect here would
    // send a visitor straight off the issuer; open DCR can register a client
    // that fails them (`grant_types: ["refresh_token"]`) with any redirect
    // URI, and no working flow depends on receiving this error by redirect.
    let unauthorized: UnauthorizedClientError | null = null;
    if (!isClientUsable(client)) {
      // A client its owner disabled and one an operator suspended
      // (ANT-2026-DR5XI3LV) get the same answer, as on the consent page.
      unauthorized = unusableClientError();
    } else if (!client.grantTypes.includes('authorization_code')) {
      unauthorized = new UnauthorizedClientError(
        'client is not registered for the authorization_code grant'
      );
    } else if (!client.responseTypes.includes('code')) {
      unauthorized = new UnauthorizedClientError(
        'client is not registered for the code response type'
      );
    }
    if (unauthorized) {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'unauthorized_client' },
        clientEvent
      );
      throw unauthorized;
    }

    // RFC 9449 §10 (#480): `dpop_jkt` binds the code to a DPoP key, whose
    // proof the token request must then carry. Read only while DPoP is on. A
    // value that is not a SHA-256 thumbprint is refused here, before any user
    // interaction, rather than turned into an unbound code.
    const dpopJkt = readAuthorizationDpopJkt(fastify, query.dpop_jkt);
    if (dpopJkt.kind === 'malformed') {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_request', reason: 'dpop_jkt_malformed' },
        clientEvent
      );
      return sendAuthorizationError(reply, client, redirectUri, {
        error: 'invalid_request',
        error_description: MALFORMED_DPOP_JKT_DESCRIPTION,
        state: state ?? undefined,
        iss,
      });
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
      // OIDC Core §3.1.2.1: `prompt=none` forbids ANY user-facing UI, so an
      // unauthenticated silent-renewal request MUST come back as
      // `error=login_required` on the client's redirect_uri rather than as a
      // redirect to the login page — which, in the hidden iframe these requests
      // are made from, renders a login form the user can never see and leaves
      // the client hanging until its timeout. The same check exists for the
      // authenticated step-up path further down; this is the branch that runs
      // BEFORE any session is resolved, and it also keeps a logged-out
      // client's silent-renewal polling from creating a pending-authorization
      // stash on every poll.
      //
      // `redirect_uri` matched the client's registration above, but unless an
      // operator provisioned the client, whoever registered it (open DCR, a
      // CIMD document, a self-registered developer account) chose that URI:
      // this would be a no-UI redirect off the issuer to any URL of their
      // choosing. `sendAuthorizationError` shows the error on the issuer for
      // such a client instead (RFC 9700 §4.11.2, ANT-2026-O8U3P920).
      if (query.prompt === 'none') {
        await emitUserEvent(
          request,
          'urn:qauth:event:step_up.required:v1-rc.0',
          { reason: 'prompt_none_no_session', error: 'login_required' },
          clientEvent
        );
        return sendAuthorizationError(reply, client, redirectUri, {
          error: 'login_required',
          error_description: 'authentication is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        });
      }

      // No auth at all → browser flow. Redirect to login, then the user
      // lands back on this very URL and the session cookie path takes
      // over. The exact query string is preserved so PKCE challenge, scope,
      // state and nonce survive the round-trip — but it is parked SERVER-SIDE
      // under a short handle rather than nested into `return_to` (#316
      // follow-up): a 2048-char raw-JSON `state` nested into the login URL
      // produced a ~10.4 KB Location header, which a reverse proxy rejects
      // before the login page ever renders.
      return redirectToLoginWithPendingAuthorization(fastify, reply, requestUrlWithParams);
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
        // Audience alone does not prove this is the first-party login token:
        // any code whose bound `resource` resolves to the system audience
        // mints a user token that passes the check above. Pin `client_id`
        // (and refuse delegated tokens) exactly as the management API does.
        await assertManagementToken(fastify, realm, payload);
        // RFC 9449 §7.2 (#480): this path reads a Bearer token, and a
        // DPoP-bound token is never one.
        refuseBoundTokenAsBearer(payload);
        // RFC 7009: `requireJwt` and token exchange consult the per-`jti`
        // denylist; this path issues codes from the same token, so it must
        // too. A Redis failure throws into the catch below (fails closed).
        if (await isJtiRevoked(fastify, payload.jti)) {
          throw new JWTInvalidError('Access token has been revoked');
        }
        // The token outlives the login that minted it; a user disabled in
        // between must not get a code from it, as the session path (via
        // `resolveBrowserSession`) and every grant at `/oauth/token` refuse.
        const user = await fastify.repositories.users.findById(realm.id, payload.sub);
        if (!user || !user.enabled) {
          throw inactiveSubjectError();
        }
        userId = payload.sub;
      } catch {
        await emitUserEvent(
          request,
          'urn:qauth:event:authorization.failed:v1-rc.0',
          { error: 'access_denied' },
          clientEvent
        );
        return sendAuthorizationError(reply, client, redirectUri, {
          error: 'access_denied',
          error_description: 'Invalid or expired token',
          state: state ?? undefined,
          iss,
        });
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
    // The signed-in user is the subject and the actor of the events below.
    const userEvent: UserEventOptions = {
      realmId: realm.id,
      userId,
      clientId: client.clientId,
      actor: 'user',
    };

    const exceedingAgentScopes = findExceedingAgentScopesForClient(query.scope, client);
    if (exceedingAgentScopes.length > 0) {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
        userEvent
      );
      return sendAuthorizationError(reply, client, redirectUri, {
        error: 'invalid_scope',
        error_description: 'requested scope exceeds the agent scope mode for this client',
        state: state ?? undefined,
        iss,
      });
    }

    // Deny-by-default: when a client has no scope allowlist configured we
    // grant nothing, matching `validateScopes` on the client_credentials
    // path. Previously an empty allowlist silently over-granted every
    // requested scope on the auth-code flow.
    const scopes = filterRequestedScopes(query.scope, client);

    // RFC 8707: the requested resource set becomes the token's `aud`, so it is
    // part of what a stored consent must cover. Read once, from the VALIDATED
    // params (`resourceParamSchema` has checked every entry and normalized
    // them to an array), so the set checked against the consent below is the
    // set bound to the code. Never re-parse `request.url`: `URLSearchParams`
    // drops a leading `?`, so `/oauth/authorize??resource=system` is the
    // unknown key `?resource` to Fastify's parser (stripped, never validated)
    // but `resource` to that one, which put an arbitrary string into `aud`.
    const resources = query.resource ?? [];

    // ADR-007 §2 (#185): step-up on the legacy Bearer path. The Bearer path
    // authenticates the user from an existing access token and CANNOT run an
    // interactive step-up (no login / consent screen for a machine caller),
    // so it must not be a back door that mints a dangerous-scope code with no
    // fresh authentication. Default-deny: a Bearer authorize request carrying
    // any dangerous scope (write:* / agent:admin / agent:exec) is refused
    // with `access_denied` and the client is told to use the interactive
    // browser flow (which enforces the dangerous-op re-auth gate).
    // ADR-008 §5 (#197): the automatic dangerous-scope refusal is gated by the
    // environment policy. Staging/production (and the fail-safe default) keep
    // it; a `development` client relaxes it so local Bearer-path iteration
    // with dangerous scopes is not forced through the browser flow. This only
    // relaxes the SERVER-inferred dangerous gate — every other Bearer check
    // (token validity, scope allowlist, agent cap) still applies.
    if (!browserSession && policy.agentStepUpEnforced) {
      const bearerDangerous = scopes.filter(isDangerousScope);
      if (bearerDangerous.length > 0) {
        await emitUserEvent(
          request,
          'urn:qauth:event:step_up.required:v1-rc.0',
          {
            reason: 'bearer_path_dangerous_scope_requires_interactive_stepup',
            error: 'access_denied',
            dangerousScopes: bearerDangerous,
          },
          userEvent
        );
        return sendAuthorizationError(reply, client, redirectUri, {
          error: 'access_denied',
          error_description:
            'dangerous scopes require interactive step-up; use the browser authorization flow',
          state: state ?? undefined,
          iss,
        });
      }
    }

    const existingConsent = await fastify.repositories.oauthConsents.findActive(
      realm.id,
      userId,
      client.id
    );

    // The consent decision does not depend on HOW the user authenticated.
    // Any client that resolved above can be named on the Bearer path too —
    // one registered a moment ago through open Dynamic Client Registration, a
    // CIMD client, another developer's public client. The Bearer path cannot
    // show the consent screen, so it issues a code only under a stored,
    // unrevoked grant that already covers this request, scopes and RFC 8707
    // resources (the same `canSkipConsent` question the browser flow asks
    // below, badge window included); anything else is refused (ADR-017
    // Decision 9: every path other than an operator-flagged first-party
    // client requires consent).
    if (!browserSession && !canSkipConsent(existingConsent, client, scopes, resources)) {
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        { error: 'access_denied', reason: 'bearer_path_no_covering_consent' },
        userEvent
      );
      return sendAuthorizationError(reply, client, redirectUri, {
        error: 'access_denied',
        error_description:
          'no stored consent covers this request; use the browser authorization flow',
        state: state ?? undefined,
        iss,
      });
    }

    // Browser-driven flow: show the consent screen unless a previous
    // grant already covers the requested scopes.
    if (browserSession) {
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
        authTimeMs: browserSession.authTime,
        nowMs: Date.now(),
        freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
        // ADR-008 §5 (#197): relax the automatic dangerous-scope fresh-login
        // for a development client; explicit prompt/max_age still enforced.
        enforceDangerousStepUp: policy.agentStepUpEnforced,
      });

      // OIDC Core §3.1.2.1: `prompt=none` forbids ANY user-facing UI. If
      // step-up would otherwise show the login or consent screen, return the
      // matching bare OIDC error to the client instead of redirecting to UI.
      //
      // Step-up only compares the requested scopes against a prior grant, so
      // it reports nothing when the scope set is empty (every CIMD client, or
      // any client that omits `scope`). The consent screen below is gated on
      // `canSkipConsent` as well, and `prompt=none` must answer the same
      // question: no stored, unrevoked grant covering this request (or a
      // dynamic client still in its badge window) means `consent_required`.
      // "Covering" includes the RFC 8707 resources: a grant remembered for
      // one resource server is no consent to tokens for another.
      if (prompt === 'none') {
        const oidcError =
          stepUpErrorForPromptNone(stepUp) ??
          (canSkipConsent(existingConsent, client, scopes, resources) ? null : 'consent_required');
        if (oidcError) {
          await emitUserEvent(
            request,
            'urn:qauth:event:step_up.required:v1-rc.0',
            {
              reason: 'prompt_none_interaction_required',
              error: oidcError,
              elevatedScopes: stepUp.elevated,
              dangerousScopes: stepUp.dangerous,
            },
            userEvent
          );
          return sendAuthorizationError(reply, client, redirectUri, {
            error: oidcError,
            error_description: 'user interaction is required but prompt=none was requested',
            state: state ?? undefined,
            iss,
          });
        }
        // No interaction required → fall through to ordinary issuance.
      }

      if (prompt !== 'none' && stepUp.requiresFreshLogin) {
        // Force a fresh end-user authentication: bounce through /ui/login,
        // which always mints a brand-new session (session-fixation defense),
        // resetting auth_time so the elevation is granted only right after
        // the user proves presence. The full authorize URL (incl. prompt /
        // max_age / scope / PKCE) is preserved so the round-trip is lossless —
        // stashed server-side under a handle, same as the no-session branch
        // above (#316 follow-up), so this path cannot regrow the header either.
        await emitUserEvent(
          request,
          'urn:qauth:event:step_up.required:v1-rc.0',
          {
            reason: 'fresh_authentication_required',
            elevatedScopes: stepUp.elevated,
            dangerousScopes: stepUp.dangerous,
            ...(prompt === null ? {} : { prompt }),
            ...(query.max_age === undefined ? {} : { maxAge: query.max_age }),
          },
          userEvent
        );
        return redirectToLoginWithPendingAuthorization(fastify, reply, requestUrlWithParams);
      }

      // Re-consent when the request elevates scope or explicitly asks for it,
      // even if a prior grant would otherwise let us skip the screen — a
      // wider scope set must be explicitly re-affirmed, never auto-widened.
      // The same holds for a `resource` the grant does not cover.
      // (`prompt=none` already returned consent_required above if needed.)
      if (
        prompt !== 'none' &&
        (stepUp.requiresConsent || !canSkipConsent(existingConsent, client, scopes, resources))
      ) {
        if (stepUp.elevated.length > 0) {
          await emitUserEvent(
            request,
            'urn:qauth:event:step_up.required:v1-rc.0',
            {
              reason: 'incremental_consent_required',
              elevatedScopes: stepUp.elevated,
              dangerousScopes: stepUp.dangerous,
            },
            userEvent
          );
        }
        // Carry the authorize params to the consent screen. Guard the `?`
        // index: `buildAuthorizeUrlWithParams` can return a query-less path
        // (empty reconstructed POST body), and `slice(-1)` would yield a
        // corrupt `/ui/consent<lastchar>`.
        const qIndex = requestUrlWithParams.indexOf('?');
        const returnQuery = qIndex >= 0 ? requestUrlWithParams.slice(qIndex) : '';
        return reply.redirect(`/ui/consent${returnQuery}`, 302);
      }
    }

    const expiresAt = Date.now() + AUTHORIZATION_CODE_TTL_MS;

    // Every path that reaches this point skipped the consent screen on the
    // strength of `existingConsent`. That read is only a snapshot: a
    // revocation can commit between it and the insert, and the code would be
    // issued on a consent that no longer exists (DELETE /api/consents/:id
    // already answered 204). So the decision is taken again on the row,
    // locked `FOR SHARE` in the transaction that inserts the code: a
    // revocation either waits for this transaction to commit, or committed
    // first and the re-read finds no covering consent, in which case no code
    // is issued (`null`). The issued code's event commits with it.
    const createCode = async (): Promise<string | null> => {
      const code = randomBytes(32).toString('base64url');
      return fastify.db.transaction(async (tx) => {
        const lockedConsent = await fastify.repositories.oauthConsents.findActiveForShare(
          realm.id,
          userId,
          client.id,
          tx
        );
        if (!canSkipConsent(lockedConsent, client, scopes, resources)) return null;
        await fastify.repositories.authorizationCodes.create(
          {
            code,
            oauthClientId: client.id,
            userId,
            redirectUri,
            codeChallenge: query.code_challenge,
            codeChallengeMethod: 'S256',
            nonce: query.nonce ?? null,
            // OIDC Core §2 `auth_time`: persist the REAL end-user authentication
            // time (the browser session's `auth_time`, epoch MS) — never the code-mint
            // time — so /oauth/token can assert it in the ID token and a `max_age`
            // check evaluates the actual session age. Null on the legacy Bearer
            // path (no interactive session) → the claim is simply omitted there.
            authTime: browserSession?.authTime ?? null,
            // #237 (ADR-004/ADR-010): bind the authentication's eIDAS LoA to the
            // code so /oauth/token can assert `acr` in the ID token. NULL on the
            // password path (`'low'`, no claim) and on the legacy Bearer path (no
            // interactive session), which is the same "omit the claim" outcome.
            assuranceLevel: toStoredAssuranceLevel(browserSession?.assuranceLevel),
            // ADR-019 Decision 3 (#552): the session's absolute end, so the
            // refresh family this code starts never outlives the session. Null
            // on the legacy Bearer path (no interactive session).
            sessionExpiresAt: browserSession?.expiresAt ?? null,
            scopes,
            // RFC 8707: bind the resource indicator(s) to the authorization
            // code so /oauth/token can set the access token's `aud` claim to
            // exactly what the client requested. Reached on the consent-skip
            // path (returning user, prior consent covers the requested scopes at
            // these resources); the consent-screen path creates codes in
            // ui/consent.ts. The same validated set the consent was checked
            // against above.
            resource: resources,
            state: query.state ?? null,
            // RFC 9449 §10 (#480): the DPoP key the token request must prove.
            dpopJkt: dpopJkt.kind === 'bound' ? dpopJkt.jkt : null,
            expiresAt,
          },
          tx
        );
        await emitUserEvent(
          request,
          'urn:qauth:event:authorization.completed:v1-rc.0',
          {},
          { ...userEvent, tx }
        );
        return code;
      });
    };

    const MAX_CREATE_ATTEMPTS = 3;
    let code: string | null = null;
    let consentWithdrawn = false;
    for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
      try {
        code = await createCode();
        consentWithdrawn = code === null;
        break;
      } catch (err) {
        if (!isUniqueConstraintError(err)) throw err;
        if (attempt === MAX_CREATE_ATTEMPTS - 1) throw err;
      }
    }

    if (consentWithdrawn) {
      // The consent went away under this request. Fail closed, once — never
      // by re-running the handler — with the answer a request arriving after
      // the revocation gets: `access_denied` on the Bearer path (no screen
      // to show), `consent_required` under `prompt=none`, else the consent
      // screen (whose POST runs its own step-up gate).
      await emitUserEvent(
        request,
        'urn:qauth:event:authorization.failed:v1-rc.0',
        {
          error: browserSession ? 'consent_required' : 'access_denied',
          reason: 'consent_withdrawn_during_authorization',
        },
        userEvent
      );
      if (!browserSession) {
        return sendAuthorizationError(reply, client, redirectUri, {
          error: 'access_denied',
          error_description:
            'no stored consent covers this request; use the browser authorization flow',
          state: state ?? undefined,
          iss,
        });
      }
      if (parsePromptMode(query.prompt) === 'none') {
        return sendAuthorizationError(reply, client, redirectUri, {
          error: 'consent_required',
          error_description: 'user interaction is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        });
      }
      const qIndex = requestUrlWithParams.indexOf('?');
      const returnQuery = qIndex >= 0 ? requestUrlWithParams.slice(qIndex) : '';
      return reply.redirect(`/ui/consent${returnQuery}`, 302);
    }
    if (!code) throw new Error('Unreachable');

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
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
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
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        body: authorizeQuerySchema,
      },
      config,
      // The authorize endpoint is unauthenticated and its body is a handful of
      // short form fields, all individually bounded by `authorizeQuerySchema`.
      // Fastify's 1 MB default has no purpose here and would let a caller push
      // a megabyte through body parsing and Zod on every request before any of
      // those bounds apply. Matches PENDING_AUTHORIZATION_MAX_URL_BYTES's
      // reasoning: bound the pre-authentication surface at the edge.
      bodyLimit: AUTHORIZE_BODY_LIMIT_BYTES,
    },
    handler
  );
}
