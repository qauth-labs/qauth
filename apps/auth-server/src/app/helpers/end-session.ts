import type { IdTokenHint } from '@qauth-labs/fastify-plugin-jwt';
import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import { interactionPersonalView } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { JWTInvalidError } from '@qauth-labs/shared-errors';
import {
  ceremonyPagePath,
  INTERACTION_API_PREFIX,
  stepUrn,
} from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import type { EndSessionParams, LogoutRequest } from '../schemas/end-session';
import { endBrowserSession, liveBrowserSession, resolveBrowserSession } from './browser-session';
import { clientDisplay } from './client-display';
import { resolveClient, type ResolvedClient } from './client-resolution';
import { isClientUsable } from './client-status';
import { sendEndSessionPage } from './end-session-pages';
import { resolveEnvironmentPolicy } from './environment-policy';
import { readInteractionStep, startLogoutInteraction } from './interaction';
import type {
  CarriedSession,
  InteractionPersonalData,
  InteractionStep,
} from './interaction-record';
import { eventClientIdOf } from './interaction-record';
import { isRedirectUriAllowedForPolicy } from './oauth-redirect';
import { buildRealmUrl, tokenRealm } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import {
  clearSessionCookie,
  readCookie,
  readSessionCookie,
  SESSION_COOKIE_NAME,
} from './session-cookie';
import { readSessionSideRecord } from './session-side-record';
import { emitUserEvent } from './user-events';

/**
 * RP-INITIATED LOGOUT (#675; OpenID Connect RP-Initiated Logout 1.0; ADR-017
 * phase F0, ADR-019 Decision 4): the rules of `GET`/`POST /oauth/end-session`
 * and of the `logout_confirm` interaction it starts. The flow graph is
 * `graphs/flows/core/logout`.
 *
 * - **The hint.** An `id_token_hint` must be an ID token of this realm: its
 *   signature, its issuer and its `typ` verify; an expired one is accepted
 *   (§2). One that does not verify counts as no hint: it names no client and
 *   no account.
 * - **The client.** `client_id`, or the hint's audience. With both, they must
 *   match (§2), or the request is refused.
 * - **The return URI.** `post_logout_redirect_uri` must be, exactly, one of the
 *   named client's `post_logout_redirect_uris` (§3.1), allowed by the redirect
 *   policy, while the client may be used. Otherwise the request is refused: an
 *   information page, nothing ended, and never a redirect. A client that
 *   registered none never gets one.
 * - **The session.** Only when a valid hint names the account of the browser's
 *   session does it end at once. Otherwise a signed-in browser gets the
 *   `logout_confirm` step and nothing ends until the person answers: a
 *   cross-site image tag, which carries no valid hint, ends nothing.
 * - **Ending it.** The session service revokes the one session (`sign_out`):
 *   its row is marked revoked, its cache entry tombstoned, its registry rows
 *   and unredeemed codes go with it, and its listeners hear of it with the
 *   clients it served, for back-channel logout (#624). No refresh token is
 *   revoked: an app revokes its own at `/oauth/revoke` before it sends the
 *   browser here. The response clears the session cookie.
 * - **Audit.** `user.signed_out` with the ended session's `sid`, or
 *   `user.sign_out_failed` with why nothing ended.
 *
 * Today a session cookie names one session, so `logout_all` ends the same
 * session as `logout`; once several accounts share a browser (#548), `logout`
 * ends only the account the request is for and `logout_all` every one.
 */

/** The end-session endpoint, on the realm's issuer. */
export const END_SESSION_PATH = '/oauth/end-session';

/** The sign-out status page: where a logout ends when there is nowhere to return. */
export const END_SESSION_STATUS_PATH = '/oauth/end-session/status';

/** The confirm step of an RP-initiated logout. */
export const LOGOUT_CONFIRM_STEP = stepUrn('logout_confirm');

/** Why a request was refused before anything was looked up for the session. */
export type EndSessionRefusal =
  /** `client_id` is not the hint's audience (§2). */
  | 'client_id_mismatch'
  /** A return URI, and neither `client_id` nor a valid hint names a client. */
  | 'post_logout_redirect_uri_without_client'
  /** The client is unknown, or does not register exactly that URI. */
  | 'post_logout_redirect_uri_not_registered'
  /** The client is disabled or suspended. */
  | 'client_unusable';

/** Why a logout ended nothing, as `user.sign_out_failed` records it. */
type SignOutFailure = EndSessionRefusal | 'no_session' | 'declined';

/** What the person answered at the confirm step. */
export type LogoutDecision = 'logout' | 'logout_all' | 'stay';

/** What {@link checkEndSessionRequest} made of the parameters. */
export type EndSessionCheck =
  | {
      readonly kind: 'checked';
      /** The hint, once it verified; `null` without one. */
      readonly hint: IdTokenHint | null;
      /** The client the request named, when it resolved and may be used. */
      readonly client: ResolvedClient | null;
      /** What a confirm step holds: the client, the registered return URI and `state`. */
      readonly logout: LogoutRequest;
    }
  | {
      readonly kind: 'refused';
      readonly reason: EndSessionRefusal;
      /** The client the request named, when it resolved: for the event. */
      readonly client: ResolvedClient | null;
    };

/**
 * The hint, verified with the realm's token keys and issuer and accepted
 * expired, or `null` when there is none or it does not verify. A hint that
 * does not verify is logged, never echoed. A signer that cannot answer throws.
 */
async function verifiedHint(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realm: RealmRow,
  token: string | undefined
): Promise<IdTokenHint | null> {
  if (token === undefined) return null;
  try {
    return await fastify.jwtUtils.verifyIdTokenHint(tokenRealm(realm), token);
  } catch (error) {
    // By name as well: a test's module registry can load a second copy.
    if (
      error instanceof JWTInvalidError ||
      (error instanceof Error && error.name === 'JWTInvalidError')
    ) {
      request.log.info('id_token_hint does not verify; the request goes on without it');
      return null;
    }
    throw error;
  }
}

/**
 * Whether `uri` is, exactly, one of the client's registered post-logout
 * redirect URIs (§3.1), and the redirect policy allows it: the scheme gate
 * and the plain-HTTP rule every redirect passes (`isRedirectUriAllowedForPolicy`),
 * since a row seeded by an operator never passed registration's checks.
 */
export function isRegisteredReturnUri(
  client: ResolvedClient,
  realm: RealmRow,
  uri: string
): boolean {
  if (!client.postLogoutRedirectUris.includes(uri)) return false;
  return isRedirectUriAllowedForPolicy(
    uri,
    resolveEnvironmentPolicy(client, realm),
    env.REDIRECT_URI_CUSTOM_SCHEMES
  );
}

/**
 * Check an end-session request, in the graph's order: the hint, `client_id`
 * against it, then the return URI against the client's registration. Nothing
 * of the browser's session is read here.
 */
export async function checkEndSessionRequest(
  fastify: FastifyInstance,
  request: FastifyRequest,
  params: EndSessionParams
): Promise<EndSessionCheck> {
  const realm = requestRealm(request);
  const hint = await verifiedHint(fastify, request, realm, params.id_token_hint);
  if (hint !== null && params.client_id !== undefined && !hint.aud.includes(params.client_id)) {
    return { kind: 'refused', reason: 'client_id_mismatch', client: null };
  }
  // The hint names its client when it has one audience, as QAuth's ID tokens do.
  const named =
    params.client_id ?? (hint !== null && hint.aud.length === 1 ? hint.aud[0] : undefined);
  const resolved = named === undefined ? null : (await resolveClient(fastify, realm, named)).client;
  const usable = resolved !== null && isClientUsable(resolved) ? resolved : null;
  const uri = params.post_logout_redirect_uri;
  if (uri !== undefined) {
    if (named === undefined) {
      return { kind: 'refused', reason: 'post_logout_redirect_uri_without_client', client: null };
    }
    if (resolved === null || !isRegisteredReturnUri(resolved, realm, uri)) {
      return {
        kind: 'refused',
        reason: 'post_logout_redirect_uri_not_registered',
        client: resolved,
      };
    }
    if (usable === null) {
      return { kind: 'refused', reason: 'client_unusable', client: resolved };
    }
  }
  return {
    kind: 'checked',
    hint,
    client: usable,
    logout: {
      ...(usable === null ? {} : { client_id: usable.clientId }),
      ...(uri === undefined ? {} : { post_logout_redirect_uri: uri }),
      // `state` goes back with the return URI only (§2).
      ...(uri === undefined || params.state === undefined ? {} : { state: params.state }),
    },
  };
}

/** The return URI with `state` in its query, when the request carried one (§3). */
export function returnLocation(uri: string, state: string | undefined): string {
  if (state === undefined) return uri;
  const url = new URL(uri);
  url.searchParams.set('state', state);
  return url.toString();
}

/** The sign-out status page of the realm. */
export function statusPageUrl(realm: RealmRow): string {
  return buildRealmUrl(realm, END_SESSION_STATUS_PATH);
}

/**
 * Where a logout's interaction sends the browser once it is answered or
 * cancelled: back to the app's registered URI with `state`, checked again now
 * (a client deleted, disabled or suspended since, or one that dropped the
 * URI, gets no redirect), or to the status page.
 */
export async function logoutReturnLocation(
  fastify: FastifyInstance,
  realm: RealmRow,
  logout: LogoutRequest
): Promise<string> {
  const uri = logout.post_logout_redirect_uri;
  if (uri === undefined || logout.client_id === undefined) return statusPageUrl(realm);
  const { client } = await resolveClient(fastify, realm, logout.client_id);
  if (client === null || !isClientUsable(client) || !isRegisteredReturnUri(client, realm, uri)) {
    return statusPageUrl(realm);
  }
  return returnLocation(uri, logout.state);
}

/** Record why a logout ended nothing. */
async function recordSignOutFailed(
  request: FastifyRequest,
  realmId: string,
  reason: SignOutFailure,
  clientId: string | null,
  userId: string | null
): Promise<void> {
  await emitUserEvent(
    request,
    'urn:qauth:event:user.sign_out_failed:v1-rc.0',
    { reason },
    { realmId, clientId, userId, actor: 'user' }
  );
}

/**
 * End one browser session: the person signs themselves out of it. By its
 * user, so the service ends only that user's session. Its listeners hear of it
 * with the clients it served (back-channel logout, #624).
 */
async function endLogoutSession(
  fastify: FastifyInstance,
  realmId: string,
  session: CarriedSession
): Promise<void> {
  await endBrowserSession(
    fastify,
    realmId,
    session.sid,
    'sign_out',
    { type: 'user', id: session.userId },
    session.userId
  );
}

/** Record the sign-out of one session, naming it, so its SET names the session (#889). */
async function recordSignedOut(
  request: FastifyRequest,
  realmId: string,
  session: CarriedSession,
  clientId: string | null
): Promise<void> {
  await emitUserEvent(
    request,
    'urn:qauth:event:user.signed_out:v1-rc.0',
    { sid: session.sid },
    { realmId, clientId, userId: session.userId, actor: 'user' }
  );
}

/**
 * The account a confirm step shows: the identifier the session signed in
 * with (its side record, #230), else the user id, as the consent page shows
 * it after the side record was lost.
 */
async function confirmPersonal(
  fastify: FastifyInstance,
  step: InteractionStep,
  session: BrowserSession
): Promise<{ readonly personal: InteractionPersonalData; readonly identifier: string }> {
  const { identifier } = await readSessionSideRecord(fastify, session);
  for (const shown of identifier === undefined ? [session.userId] : [identifier, session.userId]) {
    const personal = { accounts: [{ identifier: shown, current: true }] };
    try {
      interactionPersonalView(step, personal);
      return { personal, identifier: shown };
    } catch {
      // Not one the step's grammar can carry: the next one.
    }
  }
  throw new Error('the confirm step cannot show the account');
}

/**
 * Answer an end-session request (`GET` and `POST /oauth/end-session`):
 * refuse it, end the session at once, or start the confirm step.
 */
export async function answerEndSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  params: EndSessionParams
): Promise<FastifyReply> {
  const realm = requestRealm(request);
  const checked = await checkEndSessionRequest(fastify, request, params);
  if (checked.kind === 'refused') {
    await recordSignOutFailed(
      request,
      realm.id,
      checked.reason,
      checked.client === null
        ? null
        : eventClientIdOf({ request: { client_id: checked.client.clientId } }),
      null
    );
    return sendEndSessionPage(reply, 400, { kind: 'refused', traceId: request.id });
  }
  const { hint, client, logout } = checked;
  const clientId = eventClientIdOf({ request: logout });
  const back =
    logout.post_logout_redirect_uri === undefined
      ? undefined
      : returnLocation(logout.post_logout_redirect_uri, logout.state);

  const session = await resolveBrowserSession(fastify, request, reply);
  if (session === null) {
    await recordSignOutFailed(request, realm.id, 'no_session', clientId, null);
    return back === undefined
      ? sendEndSessionPage(reply, 200, { kind: 'signed_out' })
      : reply.redirect(back, 303);
  }

  const carried: CarriedSession = { userId: session.userId, sid: session.sid };
  if (hint !== null && hint.sub === session.userId) {
    // The app's own ID token names the account signed in here: no
    // confirmation is asked.
    await endLogoutSession(fastify, realm.id, carried);
    clearSessionCookie(reply);
    await recordSignedOut(request, realm.id, carried, clientId);
    return back === undefined
      ? sendEndSessionPage(reply, 200, { kind: 'signed_out' })
      : reply.redirect(back, 303);
  }

  // No valid hint names this account: the person is asked, and nothing ends
  // until they answer.
  const step: InteractionStep = { name: LOGOUT_CONFIRM_STEP, params: {}, alternatives: [] };
  const shown = await confirmPersonal(fastify, step, session);
  const display = client === null ? undefined : clientDisplay(client);
  const started = await startLogoutInteraction(request, reply, {
    request: logout,
    step,
    personal: shown.personal,
    carriedSession: carried,
    ...(display === undefined ? {} : { client: display }),
  });
  if (env.INTERACTION_UI_ENABLED) {
    return reply.header('Cache-Control', 'no-store').redirect(ceremonyPagePath(started.id), 303);
  }
  const view = await readInteractionStep(request, started.id);
  return sendEndSessionPage(
    reply,
    200,
    {
      kind: 'confirm',
      action: `${INTERACTION_API_PREFIX}/${started.id}/answer`,
      step: LOGOUT_CONFIRM_STEP,
      csrf: view.csrf,
      identifier: shown.identifier,
      ...(display === undefined ? {} : { client: display }),
    },
    logout.post_logout_redirect_uri
  );
}

/** The browser's session cookie names `sid` as its active session. */
async function cookieNames(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realmId: string,
  sid: string
): Promise<boolean> {
  try {
    const contents = await readSessionCookie(
      fastify,
      realmId,
      readCookie(request, SESSION_COOKIE_NAME)
    );
    return contents?.activeSessionId === sid;
  } catch (error) {
    // The realm's cookie keys cannot be read now (#493): the cookie stays,
    // and the next page that reads it clears it, since its session ended.
    request.log.warn(
      { reason: error instanceof Error ? error.name : 'unknown_error' },
      'the session cookie could not be checked after a logout; it stays'
    );
    return false;
  }
}

/** A finished logout interaction: what the Interaction API hands back. */
export interface FinishedLogout {
  readonly request: LogoutRequest;
  readonly carriedSession?: CarriedSession;
}

/**
 * Decide a confirm step the person answered, once its interaction has ended
 * (#616): the return location is checked again first, then the decision is
 * read. `stay` ends nothing; `logout` and `logout_all` end the session the
 * step was started for, if it is still live, and clear the cookie when it
 * names that session.
 *
 * @returns where the browser goes: the app's registered URI with `state`, or
 *   the status page
 */
export async function finishLogout(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  finished: FinishedLogout,
  decision: LogoutDecision
): Promise<string> {
  const realm = requestRealm(request);
  const location = await logoutReturnLocation(fastify, realm, finished.request);
  const clientId = eventClientIdOf(finished);
  const carried = finished.carriedSession;
  if (decision === 'stay') {
    await recordSignOutFailed(request, realm.id, 'declined', clientId, carried?.userId ?? null);
    return location;
  }
  // One session per cookie today: `logout_all` ends the same one (#548).
  const live =
    carried === undefined
      ? null
      : await liveBrowserSession(fastify, realm.id, carried.sid, carried.userId);
  if (carried === undefined || live === null) {
    await recordSignOutFailed(request, realm.id, 'no_session', clientId, carried?.userId ?? null);
    return location;
  }
  await endLogoutSession(fastify, realm.id, carried);
  if (await cookieNames(fastify, request, realm.id, carried.sid)) clearSessionCookie(reply);
  await recordSignedOut(request, realm.id, carried, clientId);
  return location;
}

/**
 * A confirm step the person cancelled: a decision to stay. Nothing ends.
 *
 * @returns where the browser goes, as {@link finishLogout}
 */
export async function cancelLogout(
  fastify: FastifyInstance,
  request: FastifyRequest,
  cancelled: FinishedLogout
): Promise<string> {
  const realm = requestRealm(request);
  const location = await logoutReturnLocation(fastify, realm, cancelled.request);
  await recordSignOutFailed(
    request,
    realm.id,
    'declined',
    eventClientIdOf(cancelled),
    cancelled.carriedSession?.userId ?? null
  );
  return location;
}

/** The parameters a POST carries over to its GET, in order. */
const END_SESSION_PARAMETERS = [
  'id_token_hint',
  'client_id',
  'post_logout_redirect_uri',
  'state',
  'ui_locales',
  'logout_hint',
] as const satisfies readonly (keyof EndSessionParams)[];

/**
 * A `POST /oauth/end-session` the browser sent without its session cookie, as
 * it sends a cross-site POST: the cookie is `SameSite=Lax`, so the request
 * cannot tell whether the browser is signed in. It is sent again as a `GET`
 * with the same validated parameters, which a top-level navigation sends the
 * cookie with. Nothing is checked, recorded or ended on this leg. `undefined`
 * when the POST carries the cookie, and is answered as it is.
 */
export function resendAsGet(
  request: FastifyRequest,
  reply: FastifyReply,
  params: EndSessionParams
): FastifyReply | undefined {
  if (readCookie(request, SESSION_COOKIE_NAME) !== undefined) return undefined;
  const query = new URLSearchParams();
  for (const name of END_SESSION_PARAMETERS) {
    const value = params[name];
    if (value !== undefined) query.set(name, value);
  }
  const search = query.toString();
  const location = buildRealmUrl(
    requestRealm(request),
    search === '' ? END_SESSION_PATH : `${END_SESSION_PATH}?${search}`
  );
  return reply.header('Cache-Control', 'no-store').redirect(location, 303);
}

/**
 * The status page (`GET /oauth/end-session/status`): whether this browser is
 * still signed in. It takes no parameter, so nobody can make it say anything
 * but the truth about this browser.
 */
export async function answerEndSessionStatus(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> {
  const session = await resolveBrowserSession(fastify, request, reply);
  return sendEndSessionPage(reply, 200, { kind: session === null ? 'signed_out' : 'signed_in' });
}
