import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import {
  interactionPersonalView,
  interactionStepView,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import type { AuthorizeQuery } from '../schemas/oauth';
import type { AuthorizationErrorParams } from './authorization-error';
import {
  type AuthorizationOutcome,
  type AuthorizationTarget,
  checkAuthorizationRequest,
  decideAuthorization,
} from './authorization-request';
import { liveBrowserSession } from './browser-session';
import {
  continueInteraction,
  type InteractionContinuation,
  type StartInteractionInput,
} from './interaction';
import {
  IDENTIFIER_STEP,
  type InteractionPersonalData,
  type InteractionRequest,
  type InteractionStep,
  type InteractionTransaction,
} from './interaction-record';
import { interactionCancelRedirect } from './interaction-redirect';
import { buildRedirectUrl } from './oauth-redirect';
import { buildRealmUrl } from './realm-url';
import { requestRealm } from './request-realm';
import { isDangerousScope } from './step-up';
import { emitUserEvent } from './user-events';

/**
 * THE AUTHORIZATION REQUEST'S INTERACTIONS (#628, ADR-019 Decision 6): with
 * `INTERACTION_UI_ENABLED` on, where `/oauth/authorize` used to send the
 * person to `/ui/login` or `/ui/consent`, it starts an interaction instead and
 * redirects to the ceremony page with the interaction id only. No URL carries
 * the authorization request's parameters: the interaction record holds the
 * validated request.
 *
 * - **Sign-in** ({@link AuthorizationOutcome} `sign_in`): the identifier step,
 *   with an empty transaction; the request's `login_hint`, when the step's
 *   personal data can show it, is the identifier field's prefill.
 * - **Consent** (`consent`): the consent step, with the requested scopes and
 *   resources, bound to the browser session the request came with. #629
 *   answers it; until then an answer to it is refused, and the person can
 *   only cancel.
 *
 * An interaction started for a browser that is already signed in, a consent
 * or a sign-in the request asks for again (`max_age`, `prompt=login`, a
 * dangerous scope), records that browser session as carried in
 * (`carriedSession`, #964): "Not you?" ends it when the screen shows its
 * account, as it ends a session a sign-in during the interaction started
 * (#896), and the account chooser's "Use another account" does not
 * (`switchInteractionUser`).
 *
 * When the interaction finishes, {@link finishAuthorization} decides the
 * request again, as the endpoint does, for the session the interaction holds,
 * and issues the code (`mintAuthorizationCode`) or starts the next interaction
 * of the request. It runs only after the interaction ended: the code is never
 * minted while the interaction is still answerable, and a finish the expiry
 * sweep beat issues nothing (`answerInteraction` refuses it first). When the
 * person cancels, {@link cancelAuthorization} checks the request again the
 * same way before it sends the browser to the client.
 */

/** The consent step's name (`urn:qauth:ia:consent:v1-rc.0`). */
export const CONSENT_STEP = stepUrn('consent');

/** The identifier step every sign-in of an authorization request starts at. */
function identifierStep(): InteractionStep {
  return { name: IDENTIFIER_STEP, params: {}, alternatives: [] };
}

/**
 * The identifier step's personal data for `loginHint` (OpenID Connect Core 1.0
 * §3.1.2.1): the hint as the identifier field's prefill when the step's
 * personal data can hold it (a display value, ADR-019 Decision 6), and
 * nothing otherwise. A prefill only: the person answers the identifier step
 * as always, with the hint or with another identifier.
 */
export function identifierPrefill(loginHint: string | undefined): InteractionPersonalData {
  if (loginHint === undefined) return {};
  const personal = { login_hint: loginHint };
  try {
    interactionPersonalView(identifierStep(), personal);
  } catch {
    return {};
  }
  return personal;
}

/**
 * The consent step for `scopes` at `resources`, or the error the request gets
 * when the step cannot show them: more scopes or resources than it lists, or a
 * scope outside its alphabet (the contract: "A requested scope outside it
 * never reaches this step: the request is refused first"). Whether a scope is
 * dangerous is the server's own classification; no realm scope catalog exists
 * yet, so no scope is marked sensitive and none has a consent text (#629).
 */
export function consentStep(
  scopes: readonly string[],
  resources: readonly string[]
): InteractionStep | 'invalid_scope' | 'invalid_target' {
  const step = (shown: readonly string[]): InteractionStep => ({
    name: CONSENT_STEP,
    params: {
      scopes: scopes.map((scope) => ({
        scope,
        sensitive: false,
        dangerous: isDangerousScope(scope),
      })),
      resources: [...shown],
      // "Remember this decision" starts checked, as on the consent page.
      remember_default: true,
    },
    alternatives: [],
  });
  const shows = (candidate: InteractionStep): boolean => {
    try {
      interactionStepView(candidate);
      return true;
    } catch {
      return false;
    }
  };
  if (!shows(step([]))) return 'invalid_scope';
  const full = step(resources);
  return shows(full) ? full : 'invalid_target';
}

/** The first step of the interaction an outcome that needs the person starts. */
export type AuthorizationInteractionStart = Pick<
  StartInteractionInput,
  'step' | 'personal' | 'transaction' | 'carriedSession'
>;

/**
 * The interaction a `sign_in` or `consent` outcome starts: its first step,
 * its personal data, its transaction and the browser session it is started
 * for (#964); or the error for the client's `redirect_uri` when the consent
 * step cannot show the request.
 *
 * @param session - the browser session the request came with, `null` for a
 *   browser that is not signed in; a consent is for it, and a consent
 *   outcome always has one
 */
export function authorizationInteractionStart(
  outcome: Extract<AuthorizationOutcome, { kind: 'sign_in' | 'consent' }>,
  query: AuthorizeQuery,
  iss: string,
  session: BrowserSession | null
): AuthorizationInteractionStart | { readonly error: AuthorizationErrorParams } {
  const carried =
    session === null ? {} : { carriedSession: { userId: session.userId, sid: session.sid } };
  if (outcome.kind === 'sign_in') {
    return { step: identifierStep(), personal: identifierPrefill(query.login_hint), ...carried };
  }
  if (session === null) {
    // `decideAuthorization` answers `consent` only for a session.
    throw new Error('a consent interaction is for a signed-in browser');
  }
  const step = consentStep(outcome.scopes, outcome.resources);
  if (typeof step === 'string') {
    return {
      error: {
        error: step,
        error_description:
          step === 'invalid_scope'
            ? 'the requested scopes cannot be shown for consent'
            : 'the requested resources cannot be shown for consent',
        state: query.state ?? undefined,
        iss,
      },
    };
  }
  const transaction: InteractionTransaction = {
    userId: session.userId,
    sid: session.sid,
    authTime: session.authTime,
    amr: [],
  };
  return { step, personal: {}, transaction, ...carried };
}

/**
 * Record the refusal of a request the consent step cannot show, as the
 * endpoint records every other refusal (`authorization.failed`), for the
 * signed-in user the consent was for.
 */
export async function recordUnshowableConsent(
  request: FastifyRequest,
  target: AuthorizationTarget,
  session: BrowserSession,
  error: AuthorizationErrorParams
): Promise<void> {
  await emitUserEvent(
    request,
    'urn:qauth:event:authorization.failed:v1-rc.0',
    { error: error.error, reason: 'consent_step_unshowable' },
    {
      realmId: target.realm.id,
      userId: session.userId,
      clientId: target.client.clientId,
      actor: 'user',
    }
  );
}

/** What an interaction that finished hands back (`answerInteraction` `finished`). */
export interface FinishedAuthorization {
  readonly request: InteractionRequest;
  readonly transaction: InteractionTransaction;
  readonly continuation: InteractionContinuation;
}

/**
 * The browser session an interaction's transaction holds, while it is live,
 * still its user's and the account may still use it; `null` otherwise, and
 * for a transaction in which nobody signed in.
 */
async function transactionSession(
  fastify: FastifyInstance,
  realmId: string,
  transaction: InteractionTransaction
): Promise<BrowserSession | null> {
  if (transaction.sid === undefined || transaction.userId === undefined) return null;
  return liveBrowserSession(fastify, realmId, transaction.sid, transaction.userId);
}

/**
 * Finish the authorization request of an interaction that just finished
 * (#628): check it again as the endpoint checks it (the client may have been
 * disabled since, or its redirect URI removed), decide it for the session the
 * interaction holds, and return where the browser goes:
 *
 * - the client's `redirect_uri` with the code, `state` and `iss` (RFC 9207),
 *   minted by `mintAuthorizationCode` under the consent and the session;
 * - the client's `redirect_uri` with an error, `state` and `iss`. The person
 *   has interacted with QAuth, so it is a redirect, as a cancel's
 *   `access_denied` is;
 * - the ceremony page of the request's next interaction, when the person must
 *   act again: a consent after the sign-in, or a sign-in again when the session
 *   ended meanwhile.
 *
 * @throws InvalidRequestError or UnauthorizedClientError, as the endpoint,
 *   when the client or its redirect URI no longer qualify: no redirect goes
 *   to a URI the client no longer holds
 */
export async function finishAuthorization(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  finished: FinishedAuthorization
): Promise<string> {
  const query = finished.request;
  const checked = await checkAuthorizationRequest(fastify, request, query);
  if (checked.kind === 'refused') return buildRedirectUrl(query.redirect_uri, checked.params);
  const { target } = checked;
  const session = await transactionSession(fastify, target.realm.id, finished.transaction);
  const outcome = await decideAuthorization(fastify, request, target, query, session);
  switch (outcome.kind) {
    case 'code':
      return outcome.location;
    case 'error':
      return buildRedirectUrl(query.redirect_uri, outcome.params);
    case 'sign_in':
    case 'consent': {
      const start = authorizationInteractionStart(outcome, query, target.iss, session);
      if ('error' in start) {
        // `authorizationInteractionStart` answers an error only for a consent,
        // which is always for a session.
        if (session !== null) await recordUnshowableConsent(request, target, session, start.error);
        return buildRedirectUrl(query.redirect_uri, start.error);
      }
      const next = await continueInteraction(request, reply, finished.continuation, {
        request: query,
        ...start,
      });
      return buildRealmUrl(target.realm, ceremonyPagePath(next.id));
    }
  }
}

/**
 * Where a cancelled interaction of an authorization request ends (#616,
 * #628): the client's `redirect_uri` with `error=access_denied`, its `state`
 * and `iss`, once the request is checked again as the endpoint checks it, as
 * {@link finishAuthorization} does. The interaction may have started long
 * before (`INTERACTION_TTL`): a client disabled since, or a redirect URI
 * removed since, gets no redirect.
 *
 * @throws InvalidRequestError or UnauthorizedClientError, as the endpoint,
 *   when the client or its redirect URI no longer qualify
 */
export async function cancelAuthorization(
  fastify: FastifyInstance,
  request: FastifyRequest,
  cancelled: InteractionRequest
): Promise<string> {
  // A `refused` request (a dpop_jkt DPoP, switched on since, cannot read)
  // still has a redirect URI the client holds: the person's cancel stands.
  await checkAuthorizationRequest(fastify, request, cancelled);
  return interactionCancelRedirect(requestRealm(request), cancelled);
}
