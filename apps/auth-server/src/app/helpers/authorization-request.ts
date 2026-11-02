import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import { UnauthorizedClientError } from '@qauth-labs/shared-errors';
import { resolveFirstPartyProfile } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { MINT_TRANSACTION, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../constants';
import type { AuthorizeQuery } from '../schemas/oauth';
import { toStoredAssuranceLevel } from './acr-claims';
import { mintAuthorizationCode } from './authorization-code';
import type { AuthorizationErrorParams } from './authorization-error';
import { findExceedingAgentScopesForClient, unlistedReservedAudiences } from './client-auth';
import { resolveClient, type ResolvedClient, unresolvedClientError } from './client-resolution';
import { isClientUsable, unusableClientError } from './client-status';
import {
  administrativeConsentFor,
  administrativeConsentScopes,
  canSkipConsent,
  filterRequestedScopes,
  forcesLoginPrompt,
} from './consent';
import { MALFORMED_DPOP_JKT_DESCRIPTION, readAuthorizationDpopJkt } from './dpop';
import { type EnvironmentPolicy, resolveEnvironmentPolicy } from './environment-policy';
import {
  buildRedirectUrl,
  isAllowedRedirectUriScheme,
  isHttpLocalhostRedirect,
  isRedirectUriAllowedForPolicy,
  redirectUriMatchesRegistered,
  redirectUriNotPermittedError,
  unregisteredRedirectUriError,
} from './oauth-redirect';
import { realmIssuer } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import { evaluateStepUp, parsePromptMode, stepUpErrorForPromptNone } from './step-up';
import { emitUserEvent, type UserEventOptions } from './user-events';

/**
 * THE AUTHORIZATION REQUEST (#628): the checks and the decision of
 * `/oauth/authorize`, in the order the endpoint has always run them, shared by
 * the endpoint and by the Interaction API, which finishes a request once the
 * interaction the endpoint started for it ends.
 *
 * 1. {@link checkAuthorizationRequest}: the client, its redirect URI, the
 *    environment policy, the grant and response type, then `dpop_jkt`. These
 *    need no user. A failure of the first four is a `400` that never
 *    redirects; a malformed `dpop_jkt` is an error for the client's
 *    `redirect_uri`.
 * 2. {@link decideAuthorization}, for the browser session the request comes
 *    with (or none): `prompt=none` without a session, the agent scope cap, the
 *    scope allowlist, the QAuth API audiences, the consent, the step-up gate,
 *    `prompt=none` again, and, when nothing is left for the person to do, the
 *    authorization code, minted in one transaction with the consent re-read.
 *
 * Neither writes the reply: each returns what the request comes to, and the
 * caller answers it. Where the person must act ({@link AuthorizationOutcome}
 * `sign_in` or `consent`), the endpoint sends them to the server-rendered
 * pages, or with `INTERACTION_UI_ENABLED` on starts an interaction
 * (`authorization-interaction.ts`); the Interaction API starts the next one.
 * Every event the endpoint has written is written here, unchanged.
 */

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

/** What the checks that need no user established about a request. */
export interface AuthorizationTarget {
  readonly realm: RealmRow;
  /**
   * RFC 9207 §2 (#282): the issuer identifier echoed as `iss` in every
   * authorization response. The request realm's issuer from its row (ADR-019
   * Decision 1, #490), the same value the realm's discovery documents publish
   * as `issuer`, so the value a client compares against its cached metadata
   * is byte-identical.
   */
  readonly iss: string;
  readonly client: ResolvedClient;
  readonly policy: EnvironmentPolicy;
  /** The DPoP key thumbprint the code is bound to (RFC 9449 §10), or `null`. */
  readonly dpopJkt: string | null;
  /** Who the events name until a user is known: the requesting client. */
  readonly clientEvent: UserEventOptions;
}

/** What {@link checkAuthorizationRequest} found. */
export type CheckedAuthorizationRequest =
  | { readonly kind: 'checked'; readonly target: AuthorizationTarget }
  /** An error for the client's `redirect_uri`: the request is refused. */
  | {
      readonly kind: 'refused';
      readonly client: ResolvedClient;
      readonly params: AuthorizationErrorParams;
    };

/**
 * The checks of an authorization request that need no user, in the
 * endpoint's order: client resolution, the redirect URI, the environment
 * policy, the grant and response type, then `dpop_jkt`. Each refusal is
 * audited (`authorization.failed`).
 *
 * @throws InvalidRequestError for a `client_id` that names no client, a
 *   `redirect_uri` the client did not register, or one no environment permits
 * @throws UnauthorizedClientError for a client that may not use the endpoint
 */
export async function checkAuthorizationRequest(
  fastify: FastifyInstance,
  request: FastifyRequest,
  query: AuthorizeQuery
): Promise<CheckedAuthorizationRequest> {
  const redirectUri = query.redirect_uri;
  const realm = requestRealm(request);
  // Resolved once, up front, so no branch can reach a redirect with a
  // differently-shaped issuer.
  const iss = realmIssuer(realm);

  // Client resolution priority (MCP 2025-11-25): pre-registered (DB) →
  // CIMD (https-URL client_id, fetched + SSRF-guarded + validated, then
  // idempotently materialised as a row) → unknown. A resolved CIMD
  // client is a real persisted row, so the existing auth-code /
  // refresh-token foreign keys work unchanged. See client-resolution.ts.
  const { client, reason } = await resolveClient(fastify, realm, query.client_id);

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
    return {
      kind: 'refused',
      client,
      params: {
        error: 'invalid_request',
        error_description: MALFORMED_DPOP_JKT_DESCRIPTION,
        state: query.state ?? undefined,
        iss,
      },
    };
  }

  return {
    kind: 'checked',
    target: {
      realm,
      iss,
      client,
      policy,
      dpopJkt: dpopJkt.kind === 'bound' ? dpopJkt.jkt : null,
      clientEvent,
    },
  };
}

/** What an authorization request comes to, for the caller to answer. */
export type AuthorizationOutcome =
  /** An error for the client's `redirect_uri` (RFC 6749 §4.1.2.1, with `iss`). */
  | { readonly kind: 'error'; readonly params: AuthorizationErrorParams }
  /**
   * The person must sign in: there is no session, or the step-up gate asks
   * for a fresh sign-in, or the session ended while the code was minted.
   */
  | { readonly kind: 'sign_in' }
  /**
   * The person must consent: to `scopes` (the requested ones the client's
   * allowlist holds) at `resources` (RFC 8707). Only with a session.
   */
  | {
      readonly kind: 'consent';
      readonly scopes: readonly string[];
      readonly resources: readonly string[];
    }
  /** A code was issued: the redirect to the client, with `code`, `state` and `iss`. */
  | { readonly kind: 'code'; readonly location: string };

/**
 * Decide an authorization request that passed {@link checkAuthorizationRequest},
 * for `session`, the browser session it comes with (`null` for none), and
 * issue the code when nothing is left for the person to do.
 *
 * The checks run in the endpoint's order and each event is the endpoint's: the
 * agent scope cap, the scope allowlist, the QAuth API audiences, the stored or
 * administrative consent, the step-up gate, `prompt=none`, then the code,
 * minted under the consent and the session, both re-read in its transaction.
 * A request with `prompt=none` never comes to `sign_in` or `consent`: it gets
 * the matching OpenID Connect error instead.
 */
export async function decideAuthorization(
  fastify: FastifyInstance,
  request: FastifyRequest,
  target: AuthorizationTarget,
  query: AuthorizeQuery,
  session: BrowserSession | null
): Promise<AuthorizationOutcome> {
  const { realm, iss, client, policy, clientEvent } = target;
  const redirectUri = query.redirect_uri;
  const state = query.state;

  if (!session) {
    // OIDC Core §3.1.2.1: `prompt=none` forbids ANY user-facing UI, so an
    // unauthenticated silent-renewal request MUST come back as
    // `error=login_required` on the client's redirect_uri rather than as a
    // redirect to the login page — which, in the hidden iframe these requests
    // are made from, renders a login form the user can never see and leaves
    // the client hanging until its timeout. The same check exists for the
    // authenticated step-up path further down; this is the branch that runs
    // BEFORE any session is resolved, and it also keeps a logged-out
    // client's silent-renewal polling from creating a pending-authorization
    // stash or an interaction on every poll.
    //
    // `redirect_uri` matched the client's registration above, but unless an
    // operator provisioned the client, whoever registered it (open DCR, a
    // CIMD document, a self-registered developer account) chose that URI:
    // this would be a no-UI redirect off the issuer to any URL of their
    // choosing. The endpoint shows the error on the issuer for such a client
    // instead (`sendAuthorizationError`, RFC 9700 §4.11.2, ANT-2026-O8U3P920).
    if (query.prompt === 'none') {
      await emitUserEvent(
        request,
        'urn:qauth:event:step_up.required:v1-rc.0',
        { reason: 'prompt_none_no_session', error: 'login_required' },
        clientEvent
      );
      return {
        kind: 'error',
        params: {
          error: 'login_required',
          error_description: 'authentication is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        },
      };
    }
    // No auth at all → the person signs in, and the request is decided again
    // with the session that sign-in creates.
    return { kind: 'sign_in' };
  }

  const userId = session.userId;

  // The signed-in user is the subject and the actor of the events below.
  const userEvent: UserEventOptions = {
    realmId: realm.id,
    userId,
    clientId: client.clientId,
    actor: 'user',
  };

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
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_scope', reason: 'agent_scope_mode_exceeded' },
      userEvent
    );
    return {
      kind: 'error',
      params: {
        error: 'invalid_scope',
        error_description: 'requested scope exceeds the agent scope mode for this client',
        state: state ?? undefined,
        iss,
      },
    };
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

  // RFC 8707 §2 (#509): a QAuth API audience (`urn:qauth:aud:`) is issued
  // only to a client whose `audience` lists it, so a request naming one the
  // client does not list is refused here with `invalid_target`, before a
  // consent screen offers what the token endpoint would refuse. The token
  // endpoint checks again: this one is for the user, that one is the gate.
  if (unlistedReservedAudiences(client, resources).length > 0) {
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'invalid_target', reason: 'reserved_audience_not_listed' },
      userEvent
    );
    return {
      kind: 'error',
      params: {
        error: 'invalid_target',
        error_description: 'a QAuth API audience is issued only to a client that lists it',
        state: state ?? undefined,
        iss,
      },
    };
  }

  const existingConsent = await fastify.repositories.oauthConsents.findActive(
    realm.id,
    userId,
    client.id
  );

  // ADR-017 Decision 9: an operator-flagged first-party client's
  // administrative consent. It stands for a stored consent to the requested
  // scopes when none of them is dangerous, and writes no `oauth_consents`
  // row; `null` for every other client and request. Every code it lets
  // through is audited below, in the transaction that mints the code.
  const administrativeConsent = administrativeConsentFor(client, scopes);

  // Show the consent screen unless a previous grant already covers the
  // requested scopes. An agent client always sees it (ADR-015 Decision
  // 11): `canSkipConsent` is false for an agent.
  // ADR-007 §2 (#185): step-up authentication before dangerous
  // operations / on elevation. A request that widens the granted scope
  // set (incremental consent, MCP 2025-11-25), or that asks for a
  // dangerous scope (write:* / agent:admin / agent:exec), or that sends
  // `prompt`/`max_age`, must NOT be served from the existing session +
  // prior consent silently. We re-authenticate and/or re-consent. The
  // decision is default-deny: a dangerous elevation forces a fresh login
  // with no client opt-in required.
  //
  // ADR-017 Decision 9: a first-party client's prior-consent scopes are its
  // administrative consent set, the requested scopes minus dangerous ones,
  // and never its stored consent, so a dangerous scope is always an
  // elevation: the consent screen shows it, however it was granted before.
  // A `native_backend` client's request asks for a fresh login as
  // `prompt=login` does, whatever its own `prompt` says (`prompt=none` is
  // answered below): the backend builds that URL, and QAuth does not rely
  // on the parameter arriving intact. Its browser leg then completes only
  // on a sign-in within STEP_UP_FRESH_AUTH_WINDOW_MS, the window
  // `prompt=login` gives every client, never on an older live session. The
  // request's own `prompt` stays as sent, so `prompt=consent` still shows
  // the consent screen.
  const prompt = parsePromptMode(query.prompt);
  const forcedLogin = forcesLoginPrompt(client);
  const firstParty = resolveFirstPartyProfile(client) !== null;
  const stepUp = evaluateStepUp({
    requestedScopes: scopes,
    priorConsentScopes: firstParty
      ? administrativeConsentScopes(client, scopes)
      : existingConsent && existingConsent.revokedAt === null
        ? existingConsent.scopes
        : [],
    prompt,
    maxAgeSeconds: query.max_age ?? null,
    authTimeMs: session.authTime,
    nowMs: Date.now(),
    freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
    // ADR-008 §5 (#197): relax the automatic dangerous-scope fresh-login
    // for a development client; explicit prompt/max_age still enforced.
    enforceDangerousStepUp: policy.agentStepUpEnforced,
    forceFreshLogin: forcedLogin,
  });

  // OIDC Core §3.1.2.1: `prompt=none` forbids ANY user-facing UI. If
  // step-up would otherwise show the login or consent screen, return the
  // matching bare OIDC error to the client instead of redirecting to UI.
  //
  // Step-up only compares the requested scopes against a prior grant, so
  // it reports nothing when the scope set is empty (every CIMD client, or
  // any client that omits `scope`). The consent screen below is gated on
  // `canSkipConsent` as well, and `prompt=none` must answer the same
  // question: no stored, unrevoked grant covering this request, a dynamic
  // client still in its badge window, or an agent client, which never
  // skips the screen (ADR-015 Decision 11), means `consent_required`.
  // A fresh-login requirement still answers `login_required` first.
  // "Covering" includes the RFC 8707 resources: a grant remembered for
  // one resource server is no consent to tokens for another.
  //
  // A `native_backend` client always needs the login page (its request is
  // `prompt=login` whatever it says), which `prompt=none` forbids, so it
  // answers `login_required` however fresh the session is (ADR-017
  // Decision 9; OpenID Connect Core 1.0 §3.1.2.6).
  if (prompt === 'none') {
    const oidcError = forcedLogin
      ? 'login_required'
      : (stepUpErrorForPromptNone(stepUp) ??
        (canSkipConsent(existingConsent, client, scopes, resources) ? null : 'consent_required'));
    if (oidcError) {
      await emitUserEvent(
        request,
        'urn:qauth:event:step_up.required:v1-rc.0',
        {
          reason: forcedLogin
            ? 'native_profile_login_required'
            : 'prompt_none_interaction_required',
          error: oidcError,
          elevatedScopes: stepUp.elevated,
          dangerousScopes: stepUp.dangerous,
        },
        userEvent
      );
      return {
        kind: 'error',
        params: {
          error: oidcError,
          error_description: 'user interaction is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        },
      };
    }
    // No interaction required → fall through to ordinary issuance.
  }

  if (prompt !== 'none' && stepUp.requiresFreshLogin) {
    // Force a fresh end-user authentication: the sign-in always mints a
    // brand-new session (session-fixation defense), resetting auth_time so
    // the elevation is granted only right after the user proves presence.
    //
    // The reason says when the client's `native_backend` profile asked for
    // the login; the event still lists the request's dangerous scopes and
    // its own `prompt` and `max_age`.
    await emitUserEvent(
      request,
      'urn:qauth:event:step_up.required:v1-rc.0',
      {
        reason: forcedLogin ? 'native_profile_login_required' : 'fresh_authentication_required',
        elevatedScopes: stepUp.elevated,
        dangerousScopes: stepUp.dangerous,
        ...(prompt === null ? {} : { prompt }),
        ...(query.max_age === undefined ? {} : { maxAge: query.max_age }),
      },
      userEvent
    );
    return { kind: 'sign_in' };
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
    return { kind: 'consent', scopes, resources };
  }

  // Every path that reaches this point skipped the consent screen on the
  // strength of `existingConsent`, or of the administrative consent of a
  // first-party client, which needs no row and is recorded below with the
  // code (`consent.administrative`). The waiver is decided on the client
  // as this request read it: a profile an operator removes while the
  // request runs is not locked against. The row read is only a snapshot: a
  // revocation can commit between it and the insert, and the code would be
  // issued on a consent that no longer exists (DELETE /api/consents/:id
  // already answered 204). So the decision is taken again on the row,
  // locked `FOR SHARE` in the transaction that inserts the code: a
  // revocation either waits for this transaction to commit, or committed
  // first and the re-read finds no covering consent, in which case no code
  // is issued (`consent_withdrawn`). The issued code's event commits with it.
  //
  // The browser session gets the same treatment (#549), inside
  // `mintAuthorizationCode`: its row is locked `FOR SHARE` while the
  // transaction records which client it served and stores its `sid` on the
  // code; a sign-out that committed first leaves no code (`session_ended`).
  // READ COMMITTED (`MINT_TRANSACTION`), so a re-read that waited sees the
  // revocation that made it wait.
  const outcome = await fastify.db.transaction(async (tx) => {
    const lockedConsent = await fastify.repositories.oauthConsents.findActiveForShare(
      realm.id,
      userId,
      client.id,
      tx
    );
    if (!canSkipConsent(lockedConsent, client, scopes, resources)) {
      return 'consent_withdrawn' as const;
    }
    const minted = await mintAuthorizationCode(
      fastify,
      {
        oauthClientId: client.id,
        userId,
        redirectUri,
        codeChallenge: query.code_challenge,
        codeChallengeMethod: query.code_challenge_method,
        nonce: query.nonce ?? null,
        // OIDC Core §2 `auth_time`: persist the REAL end-user authentication
        // time (the browser session's `auth_time`, epoch MS) — never the code-mint
        // time — so /oauth/token can assert it in the ID token and a `max_age`
        // check evaluates the actual session age.
        authTime: session.authTime,
        // #237 (ADR-004/ADR-010): bind the authentication's eIDAS LoA to the
        // code so /oauth/token can assert `acr` in the ID token. NULL on the
        // password path (`'low'`, no claim), the "omit the claim" outcome.
        assuranceLevel: toStoredAssuranceLevel(session.assuranceLevel),
        // ADR-019 Decision 3 (#552): the session's absolute end, so the
        // refresh family this code starts never outlives the session.
        sessionExpiresAt: session.expiresAt,
        // ADR-019 Decisions 3 and 4 (#549): the session whose `sid` the code
        // exchange puts in the ID token, and which records this client.
        session: { realmId: session.realmId, sid: session.sid },
        scopes,
        // RFC 8707: bind the resource indicator(s) to the authorization
        // code so /oauth/token can set the access token's `aud` claim to
        // exactly what the client requested. Reached on the consent-skip
        // path (returning user, prior consent covers the requested scopes at
        // these resources); the consent-screen path mints its codes in
        // ui/consent.ts. The same validated set the consent was checked
        // against above.
        resource: resources,
        state: query.state ?? null,
        // RFC 9449 §10 (#480): the DPoP key the token request must prove.
        dpopJkt: target.dpopJkt,
      },
      tx
    );
    if (minted === 'session_ended') return minted;
    // ADR-017 Decision 9: every code the administrative consent let through
    // is audited, in the transaction that mints it: the profile it rests
    // on, the scopes and resources it covered, and the endpoint. The
    // waiver comes first in `canSkipConsent`, so a first-party client's
    // stored consent never stands in for it unrecorded.
    if (administrativeConsent !== null) {
      await emitUserEvent(
        request,
        'urn:qauth:event:consent.administrative:v1-rc.0',
        {
          basis: administrativeConsent.basis,
          scopes: [...administrativeConsent.scopes],
          ...(resources.length > 0 ? { resources: [...resources] } : {}),
          path: '/oauth/authorize',
        },
        { ...userEvent, tx }
      );
    }
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.completed:v1-rc.0',
      {},
      { ...userEvent, tx }
    );
    return minted;
  }, MINT_TRANSACTION);

  if (outcome === 'session_ended') {
    // The session ended under this request (#549). Fail closed, once, with
    // the answer a request arriving after the sign-out gets: no session, so
    // `login_required` under `prompt=none`, else the sign-in.
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'login_required', reason: 'session_ended_during_authorization' },
      userEvent
    );
    if (prompt === 'none') {
      return {
        kind: 'error',
        params: {
          error: 'login_required',
          error_description: 'authentication is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        },
      };
    }
    return { kind: 'sign_in' };
  }

  if (outcome === 'consent_withdrawn') {
    // The consent went away under this request. Fail closed, once — never
    // by re-running the decision — with the answer a request arriving after
    // the revocation gets: `consent_required` under `prompt=none`, else the
    // consent screen (whose answer runs its own step-up gate).
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'consent_required', reason: 'consent_withdrawn_during_authorization' },
      userEvent
    );
    if (prompt === 'none') {
      return {
        kind: 'error',
        params: {
          error: 'consent_required',
          error_description: 'user interaction is required but prompt=none was requested',
          state: state ?? undefined,
          iss,
        },
      };
    }
    return { kind: 'consent', scopes, resources };
  }

  return {
    kind: 'code',
    location: buildRedirectUrl(redirectUri, { code: outcome.code, state: state ?? undefined, iss }),
  };
}
