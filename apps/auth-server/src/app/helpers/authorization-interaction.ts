import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import {
  interactionPersonalView,
  interactionStepView,
  type UpstreamProviderEntry,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { MINT_TRANSACTION, STEP_UP_FRESH_AUTH_WINDOW_MS } from '../constants';
import type { AuthorizeQuery } from '../schemas/oauth';
import { accountCredentialRefusal } from './account-validity';
import { mintAuthorizationCode } from './authorization-code';
import type { AuthorizationErrorParams } from './authorization-error';
import {
  type AuthorizationOutcome,
  type AuthorizationTarget,
  checkAuthorizationRequest,
  decideAuthorization,
} from './authorization-request';
import {
  type AuthorizationSubject,
  isRegisteredSubject,
  subjectAuthTimeMs,
  subjectEnforcesDangerousStepUp,
  subjectGrant,
} from './authorization-subject';
import { liveBrowserSession } from './browser-session';
import {
  findExceedingAgentScopesForClient,
  unlistedReservedAudiences,
  userGrantDefaultAudience,
} from './client-auth';
import { clientDisplay } from './client-display';
import { isAgentClient } from './client-resolution';
import { filterRequestedScopes, forcesLoginPrompt, standardScopeText } from './consent';
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
import { buildRealmUrl, realmIssuer } from './realm-url';
import { requestRealm } from './request-realm';
import { highestAgentModeInScopes } from './scope-modes';
import { readSessionSideRecord } from './session-side-record';
import { evaluateStepUp, isDangerousScope, parsePromptMode } from './step-up';
import { upstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent, type UserEventOptions } from './user-events';

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
 *   resources, bound to the browser session the request came with, and the
 *   client's display data (#593). The scope set the step shows is the one the
 *   interaction holds, and the only one an `allow` grants
 *   ({@link finishConsent}, #629).
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
 * same way before it sends the browser to the client. When the person answers
 * the consent step, {@link finishConsent} decides the answer, once the
 * interaction has ended, with every guard of the consent page (#629).
 */

/** The consent step's name (`urn:qauth:ia:consent:v1-rc.0`). */
export const CONSENT_STEP = stepUrn('consent');

/** The `upstream` step's name (`urn:qauth:ia:upstream:v1-rc.0`, #639). */
export const UPSTREAM_STEP = stepUrn('upstream');

/**
 * The identifier step every sign-in of an authorization request starts at,
 * with the realm's upstream providers beside it (#639): the `upstream`
 * alternative and its list, as the engine's first round offers them. A list
 * the step cannot show leaves the alternative out.
 */
function identifierStep(providers: readonly UpstreamProviderEntry[] = []): InteractionStep {
  const step: InteractionStep = { name: IDENTIFIER_STEP, params: {}, alternatives: [] };
  if (providers.length === 0) return step;
  const offered: InteractionStep = {
    ...step,
    alternatives: [UPSTREAM_STEP],
    alternativeParams: { [UPSTREAM_STEP]: { providers: providers.map((entry) => ({ ...entry })) } },
  };
  try {
    interactionStepView(offered);
  } catch {
    return step;
  }
  return offered;
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
 * The interaction `prompt=create` starts (#640; ADR-017 Decision 8): the
 * identifier step, with no upstream provider beside it (a registration sets a
 * password), `login_hint` as its prefill. Its transaction is empty: the
 * engine's rounds are a registration's because the request it holds asks for
 * `create`. A browser that is already signed in carries its session in, as a
 * sign-in does (#964), and keeps it: a registration creates no session.
 */
export function registrationInteractionStart(
  query: AuthorizeQuery,
  session: BrowserSession | null
): AuthorizationInteractionStart {
  return {
    step: identifierStep(),
    personal: identifierPrefill(query.login_hint),
    ...(session === null ? {} : { carriedSession: { userId: session.userId, sid: session.sid } }),
  };
}

/**
 * The authorization request without `prompt=create` (#640): once the
 * interaction that registered the account (or signed in the address's owner)
 * finished, the request is decided as an ordinary one, and a next interaction
 * of it (a consent, a sign-in a dangerous scope asks for) is not a
 * registration again.
 */
export function withoutCreatePrompt(query: AuthorizeQuery): AuthorizeQuery {
  if (query.prompt !== 'create') return query;
  const held = { ...query };
  delete held.prompt;
  return held;
}

/** What the consent step shows, beside the scopes and resources the request comes to. */
export interface ConsentStepSubject {
  /**
   * The tokens' `aud` when the request names no resource, from the audience an
   * operator configured for the client, as `/oauth/token` resolves it
   * (`userGrantDefaultAudience`): empty when the tokens are for the client
   * itself.
   */
  readonly clientAudience: readonly string[];
  /** Whether the client is an AI agent (`isAgentClient`, fail-closed). */
  readonly agent: boolean;
  /** The realm's `sso_max_lifespan`, in seconds, `null` when it sets none. */
  readonly ssoMaxLifespan: number | null;
}

/**
 * The consent step for `scopes` at `resources` (#629), or the error the
 * request gets when the step cannot show them: more scopes or resources than
 * it lists, a scope outside its alphabet (the contract: "A requested scope
 * outside it never reaches this step: the request is refused first"), or an
 * audience it cannot carry.
 *
 * - Each scope carries QAuth's own text for a scope it defines
 *   (`standardScopeText`), and whether it is dangerous, by the server's own
 *   classification (`isDangerousScope`). No realm scope catalog exists yet, so
 *   no scope is marked sensitive.
 * - `audience`: where the tokens may be used when the request names no
 *   resource, exactly the `aud` `/oauth/token` gives them from the client's
 *   configured audience (the resources are the audience otherwise).
 * - `agent`: present for an AI agent client (ADR-014 §11): the screen names it
 *   as one in QAuth's words, and says how long it may keep working, from the
 *   realm's `sso_max_lifespan`. Nothing in it comes from the client.
 * - "Remember this decision" starts checked, as on the consent page.
 */
export function consentStep(
  scopes: readonly string[],
  resources: readonly string[],
  subject: ConsentStepSubject
): InteractionStep | 'invalid_scope' | 'invalid_target' {
  const audience =
    resources.length === 0 && subject.clientAudience.length > 0
      ? [...subject.clientAudience]
      : undefined;
  const step = (where: {
    readonly resources: readonly string[];
    readonly audience?: readonly string[];
  }): InteractionStep => ({
    name: CONSENT_STEP,
    params: {
      scopes: scopes.map((scope) => {
        const text = standardScopeText(scope);
        return {
          scope,
          ...(text === undefined ? {} : { text }),
          sensitive: false,
          dangerous: isDangerousScope(scope),
        };
      }),
      resources: [...where.resources],
      ...(where.audience === undefined ? {} : { audience: [...where.audience] }),
      ...(subject.agent
        ? {
            agent: subject.ssoMaxLifespan === null ? {} : { max_lifespan: subject.ssoMaxLifespan },
          }
        : {}),
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
  if (!shows(step({ resources: [] }))) return 'invalid_scope';
  const full = step({ resources, ...(audience === undefined ? {} : { audience }) });
  return shows(full) ? full : 'invalid_target';
}

/** The first step of the interaction an outcome that needs the person starts. */
export type AuthorizationInteractionStart = Pick<
  StartInteractionInput,
  'step' | 'personal' | 'transaction' | 'carriedSession' | 'client'
>;

/**
 * The consent step's personal data: the identifier the user signed in with
 * (the session's side record, #230), when the step's personal data can hold
 * it, and nothing otherwise. Personal data: only the personal-data read
 * returns it, to the browser holding the flow cookie.
 */
async function consentPersonal(
  fastify: FastifyInstance,
  step: InteractionStep,
  session: BrowserSession
): Promise<InteractionPersonalData> {
  const { identifier } = await readSessionSideRecord(fastify, session);
  if (identifier === undefined) return {};
  const personal = { identifier };
  try {
    interactionPersonalView(step, personal);
  } catch {
    return {};
  }
  return personal;
}

/**
 * The interaction a `sign_in` or `consent` outcome starts: its first step,
 * its personal data, its transaction, the browser session it is started for
 * (#964) and, for a consent, the client's display data (#593); or the error
 * for the client's `redirect_uri` when the consent step cannot show the
 * request.
 *
 * @param session - the browser session the request came with, `null` for a
 *   browser that is not signed in, or the user an interaction just registered
 *   (#640), who has no session; a consent is for it, and a consent outcome
 *   always has one
 * @throws InvalidRequestError when the consent step cannot show where the
 *   code goes (`clientDisplay`), as the consent page refuses to render
 */
export async function authorizationInteractionStart(
  fastify: FastifyInstance,
  outcome: Extract<AuthorizationOutcome, { kind: 'sign_in' | 'consent' }>,
  query: AuthorizeQuery,
  target: Pick<AuthorizationTarget, 'realm' | 'iss' | 'client'>,
  session: AuthorizationSubject | null
): Promise<AuthorizationInteractionStart | { readonly error: AuthorizationErrorParams }> {
  // A registered user has no session to carry in.
  const carried =
    session === null || isRegisteredSubject(session)
      ? {}
      : { carriedSession: { userId: session.userId, sid: session.sid } };
  if (outcome.kind === 'sign_in') {
    const providers = await upstreamProviderCatalog(fastify).offered(target.realm.id);
    return {
      step: identifierStep(providers),
      personal: identifierPrefill(query.login_hint),
      ...carried,
    };
  }
  if (session === null) {
    // `decideAuthorization` answers `consent` only for a session.
    throw new Error('a consent interaction is for a signed-in browser');
  }
  const { client } = target;
  // ADR-019 Decision 6 (#593): who the client is, from the server's own
  // records, kept with the interaction so every read of the step shows what
  // it started with. First, as on the consent page: a redirect it cannot show
  // refuses the step, and no error is sent to it.
  const display = clientDisplay(client, { redirectUri: query.redirect_uri });
  const step = consentStep(outcome.scopes, outcome.resources, {
    clientAudience: userGrantDefaultAudience(client),
    agent: isAgentClient(client),
    ssoMaxLifespan: target.realm.ssoMaxLifespan,
  });
  if (typeof step === 'string') {
    return {
      error: {
        error: step,
        error_description:
          step === 'invalid_scope'
            ? 'the requested scopes cannot be shown for consent'
            : outcome.resources.length > 0
              ? 'the requested resources cannot be shown for consent'
              : // No resource named: the client's configured audience is what the step could not carry.
                "the client's audience cannot be shown for consent",
        state: query.state ?? undefined,
        iss: target.iss,
      },
    };
  }
  if (isRegisteredSubject(session)) {
    // The consent of a user just registered (#640): for the account, with no
    // session and no authentication time, as the registration finished.
    return {
      step,
      personal: {},
      transaction: { userId: session.userId, amr: [], registered: true },
      client: display,
    };
  }
  const transaction: InteractionTransaction = {
    userId: session.userId,
    sid: session.sid,
    authTime: session.authTime,
    amr: [],
  };
  return {
    step,
    personal: await consentPersonal(fastify, step, session),
    transaction,
    client: display,
    ...carried,
  };
}

/**
 * Record the refusal of a request the consent step cannot show, as the
 * endpoint records every other refusal (`authorization.failed`), for the
 * signed-in user the consent was for.
 */
export async function recordUnshowableConsent(
  request: FastifyRequest,
  target: AuthorizationTarget,
  session: { readonly userId: string },
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
 * Who an interaction's transaction decides the request for: the browser
 * session it holds, while it is live, still its user's and the account may
 * still use it; or the account it registered (#640) or reset (#642), while
 * the account is enabled and no reset came after (its session epoch, read
 * from Postgres, is still the one the transaction finished at). `null`
 * otherwise, and for a transaction in which nobody signed in.
 */
async function transactionSubject(
  fastify: FastifyInstance,
  realmId: string,
  transaction: InteractionTransaction
): Promise<AuthorizationSubject | null> {
  if (transaction.userId === undefined) return null;
  if (transaction.registered === true) {
    const user = await fastify.repositories.users.findById(realmId, transaction.userId);
    // An account disabled since it was registered gets nothing; the request
    // goes on at a sign-in, which refuses it.
    if (user === undefined || accountCredentialRefusal(user, Date.now()) !== null) return null;
    // A reset since the interaction finished ended whatever it finished: a
    // consent still pending is no longer decided for the account.
    const epoch = await fastify.repositories.userSessionEpochs.find(realmId, transaction.userId);
    if ((epoch?.epoch ?? 0) > (transaction.sessionEpoch ?? 0)) return null;
    return { registered: true, realmId, userId: transaction.userId };
  }
  if (transaction.sid === undefined) return null;
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
  finishedInteraction: FinishedAuthorization
): Promise<string> {
  // A registration's request is an ordinary one from here (#640).
  const finished = {
    ...finishedInteraction,
    request: withoutCreatePrompt(finishedInteraction.request),
  };
  const query = finished.request;
  const checked = await checkAuthorizationRequest(fastify, request, query);
  if (checked.kind === 'refused') return buildRedirectUrl(query.redirect_uri, checked.params);
  const { target } = checked;
  const session = await transactionSubject(fastify, target.realm.id, finished.transaction);
  const outcome = await decideAuthorization(fastify, request, target, query, session);
  return continueAuthorization(fastify, request, reply, finished, target, session, outcome);
}

/**
 * Where the browser goes for what the request of a finished interaction came
 * to: the client's `redirect_uri` with the code or an error, or the ceremony
 * page of the request's next interaction, started on the same reply
 * ({@link continueInteraction}).
 */
async function continueAuthorization(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  finished: FinishedAuthorization,
  target: AuthorizationTarget,
  session: AuthorizationSubject | null,
  outcome: AuthorizationOutcome
): Promise<string> {
  const query = finished.request;
  switch (outcome.kind) {
    case 'code':
      return outcome.location;
    case 'error':
      return buildRedirectUrl(query.redirect_uri, outcome.params);
    case 'sign_in':
    case 'consent': {
      const start = await authorizationInteractionStart(fastify, outcome, query, target, session);
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

/** The person's answer to the consent step, as the step grammar read it. */
export interface ConsentAnswer {
  readonly decision: 'allow' | 'deny';
  /** Whether to remember an `allow` for later requests that fit it. */
  readonly remember: boolean;
}

/** A consent interaction that finished: the step it showed, and the answer. */
export interface FinishedConsent extends FinishedAuthorization {
  /** The consent step the interaction held: what the person saw. */
  readonly step: InteractionStep;
  readonly answer: ConsentAnswer;
}

/** The scope values a consent step shows, in its order. */
function shownScopes(step: InteractionStep): string[] {
  const scopes = step.params['scopes'] as readonly { readonly scope: string }[];
  return scopes.map((entry) => entry.scope);
}

/** The resource indicators a consent step shows. */
function shownResources(step: InteractionStep): string[] {
  return [...(step.params['resources'] as readonly string[])];
}

/** Whether a consent step named its client as an AI agent. */
function shownAsAgent(step: InteractionStep): boolean {
  return step.params['agent'] !== undefined;
}

/** Order-independent equality of two scope or resource sets. */
function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...right].every((value) => left.has(value));
}

/**
 * Decide the person's answer to the consent step (#629, ADR-019 Decision 6),
 * once the interaction has ended (`answerInteraction` `finished`), with every
 * guard of the consent page's POST, and return where the browser goes.
 *
 * 1. The request is checked again, as the endpoint checks it
 *    (`checkAuthorizationRequest`).
 * 2. `deny`: `consent.denied`, and `access_denied` with `state` and `iss`.
 * 3. `allow`, for the browser session the interaction holds, read again with
 *    its account: none left, and the request needs a sign-in, which a new
 *    interaction starts.
 * 4. The agent scope cap (ADR-007 §2) and the QAuth API audiences (#509),
 *    checked again: `invalid_scope` / `invalid_target`, no code.
 * 5. A client that changed whether it is an AI agent since the step was shown
 *    gets nothing: the request is decided again, so the person sees the step
 *    the client needs now (ADR-014 §11).
 * 6. The grant is the scope set the step showed, which the interaction holds,
 *    never a field of the answer; it must still be in the client's allowlist,
 *    and the resources must be the request's (`consent_scope_mismatch`,
 *    `consent_resource_mismatch`).
 * 7. The step-up gate on the mint path (ADR-007 §2): a sign-in too old for
 *    what is granted (a dangerous scope, `prompt=login`, `max_age`, a
 *    `native_backend` client) gets no code, and the request continues at a
 *    fresh sign-in.
 * 8. The code (`mintAuthorizationCode`), the remembered grant and the events
 *    (`step_up.elevated` for a dangerous scope, `consent.granted`) commit in
 *    one transaction (#549): a session that ended under the request leaves
 *    none of them, and the request continues at a sign-in.
 *
 * @throws InvalidRequestError or UnauthorizedClientError, as the endpoint,
 *   when the client or its redirect URI no longer qualify: no redirect goes
 *   to a URI the client no longer holds
 */
export async function finishConsent(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  finishedConsent: FinishedConsent
): Promise<string> {
  // A registration's request is an ordinary one from here (#640).
  const finished = { ...finishedConsent, request: withoutCreatePrompt(finishedConsent.request) };
  const query = finished.request;
  const { transaction, step, answer } = finished;
  const userId = transaction.userId;
  if (userId === undefined) {
    // `authorizationInteractionStart` starts a consent only for a session.
    throw new Error('a consent interaction is for a signed-in user');
  }
  const checked = await checkAuthorizationRequest(fastify, request, query);
  const realm = requestRealm(request);
  const iss = realmIssuer(realm);
  const state = query.state ?? undefined;
  const userEvent: UserEventOptions = {
    realmId: realm.id,
    userId,
    clientId: (checked.kind === 'checked' ? checked.target.client : checked.client).clientId,
    actor: 'user',
  };

  // RFC 6749 §4.1.2.1: the person declined. A request the checks now refuse
  // (a dpop_jkt that DPoP, switched on since, cannot read) still has a
  // redirect URI the client holds: the person's decision stands, as a
  // cancel's does.
  if (answer.decision === 'deny') {
    await emitUserEvent(
      request,
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error: 'access_denied' },
      userEvent
    );
    return buildRedirectUrl(query.redirect_uri, {
      error: 'access_denied',
      error_description: 'User denied the authorization request.',
      state,
      iss,
    });
  }
  if (checked.kind === 'refused') return buildRedirectUrl(query.redirect_uri, checked.params);
  const { target } = checked;
  const { client, policy } = target;

  // The session again, with its account: one disabled since cannot consent.
  // The request goes on at a sign-in, as one with no session does. A user
  // just registered (#640) consents for the account, with no session.
  const session = await transactionSubject(fastify, realm.id, transaction);
  if (session === null) {
    return continueAuthorization(fastify, request, reply, finished, target, null, {
      kind: 'sign_in',
    });
  }

  /** Refuse the grant: `consent.denied` and the error at the client's `redirect_uri`. */
  const refuse = async (
    error: 'invalid_scope' | 'invalid_target',
    reason: string,
    errorDescription: string
  ): Promise<string> => {
    await emitUserEvent(
      request,
      'urn:qauth:event:consent.denied:v1-rc.0',
      { error, reason },
      userEvent
    );
    return buildRedirectUrl(query.redirect_uri, {
      error,
      error_description: errorDescription,
      state,
      iss,
    });
  };

  // ADR-007 §2 (#184): the agent scope-mode cap, on the path that mints the
  // code, against the request the interaction holds. Deny-by-default: a
  // non-agent client asking for an agent mode is refused too.
  if (findExceedingAgentScopesForClient(query.scope, client).length > 0) {
    return refuse(
      'invalid_scope',
      'agent_scope_mode_exceeded',
      'requested scope exceeds the agent scope mode for this client'
    );
  }

  // #509: a QAuth API audience is issued only to a client that lists it; an
  // operator may have removed it since the step was shown.
  const resources = query.resource ?? [];
  if (unlistedReservedAudiences(client, resources).length > 0) {
    return refuse(
      'invalid_target',
      'reserved_audience_not_listed',
      'a QAuth API audience is issued only to a client that lists it'
    );
  }

  // ADR-014 §11 (#845): a code is minted only for the client the step showed.
  // A CIMD document can change `is_agent` while the step is shown: an agent
  // the step did not name as one, or a client it named as one that is no
  // longer, gets nothing, and the request is decided again, so the person
  // sees the step the client needs now.
  if (shownAsAgent(step) !== isAgentClient(client)) {
    request.log.warn(
      { realmId: realm.id, clientId: client.clientId, shownAsAgent: shownAsAgent(step) },
      'the client changed whether it is an agent since its consent step; deciding the request again'
    );
    const outcome = await decideAuthorization(fastify, request, target, query, session);
    return continueAuthorization(fastify, request, reply, finished, target, session, outcome);
  }

  // Scope-presentation integrity (#150): the grant is the scope set the step
  // showed, which the interaction holds; the answer carries no scope. Each of
  // them must still be in the client's allowlist: an owner who removed one
  // since the step was shown gets no code for it.
  const scopes = shownScopes(step);
  if (!sameSet(filterRequestedScopes(scopes.join(' '), client), scopes)) {
    return refuse(
      'invalid_scope',
      'consent_scope_mismatch',
      'a scope the consent step showed is no longer allowed for the client'
    );
  }
  // RFC 8707: the resources the step named, which become the token's `aud`,
  // are the request's.
  if (!sameSet(shownResources(step), resources)) {
    return refuse(
      'invalid_target',
      'consent_resource_mismatch',
      'the consent step showed other resources than the request names'
    );
  }

  // ADR-007 §2 (#185): the step-up gate on the mint path. The sign-in must be
  // fresh enough for every scope about to be granted (prior consent is not
  // consulted), for `prompt=login` and `max_age`, and for a `native_backend`
  // client, whose request asks for a fresh login whatever it says (ADR-017
  // Decision 9). A stale one gets no code: the person signs in again, in a
  // new interaction that carries the session in, and the request is decided
  // again after it.
  const prompt = parsePromptMode(query.prompt);
  const forcedLogin = forcesLoginPrompt(client);
  const stepUp = evaluateStepUp({
    requestedScopes: scopes,
    priorConsentScopes: [],
    prompt,
    maxAgeSeconds: query.max_age ?? null,
    authTimeMs: subjectAuthTimeMs(session),
    nowMs: Date.now(),
    freshAuthWindowMs: STEP_UP_FRESH_AUTH_WINDOW_MS,
    // ADR-008 §5 (#197): a development client is spared the dangerous-scope
    // rule only; `prompt` and `max_age` hold everywhere. A registration
    // (#640) never is: no sign-in authenticated it.
    enforceDangerousStepUp: subjectEnforcesDangerousStepUp(session, policy),
    forceFreshLogin: forcedLogin,
  });
  if (stepUp.requiresFreshLogin) {
    await emitUserEvent(
      request,
      'urn:qauth:event:step_up.required:v1-rc.0',
      {
        reason: forcedLogin ? 'native_profile_login_required' : 'fresh_authentication_required',
        ...(stepUp.dangerous.length > 0 ? { dangerousScopes: stepUp.dangerous } : {}),
        ...(prompt === null ? {} : { prompt }),
        ...(query.max_age === undefined ? {} : { maxAge: query.max_age }),
      },
      userEvent
    );
    return continueAuthorization(fastify, request, reply, finished, target, session, {
      kind: 'sign_in',
    });
  }

  // The code, the session's record of this client (#549), the remembered
  // grant and the events commit together, in one READ COMMITTED transaction
  // (`MINT_TRANSACTION`). A sign-out that committed first leaves no live
  // session, and nothing is written. A grant that is not remembered is
  // one-time: /oauth/token mints a refresh token only under a stored consent.
  const dangerous = scopes.filter(isDangerousScope);
  const minted = await fastify.db.transaction(async (tx) => {
    const outcome = await mintAuthorizationCode(
      fastify,
      {
        oauthClientId: client.id,
        userId,
        redirectUri: query.redirect_uri,
        codeChallenge: query.code_challenge,
        codeChallengeMethod: query.code_challenge_method,
        nonce: query.nonce ?? null,
        // The session's `auth_time`, `acr`, end and `sid`, or none of them
        // for a user just registered (#640; ADR-017 Decision 10).
        ...subjectGrant(session),
        scopes,
        resource: [...resources],
        state: query.state ?? null,
        // RFC 9449 §10 (#480): the DPoP key the token request must prove.
        dpopJkt: target.dpopJkt,
      },
      tx
    );
    if (outcome === 'session_ended') return outcome;
    if (answer.remember) {
      await fastify.repositories.oauthConsents.upsertGrant(
        realm.id,
        userId,
        client.id,
        scopes,
        [...resources],
        tx
      );
    }
    // ADR-007 §2 (#185, #186): a grant of a dangerous scope is recorded as an
    // elevation, with the fresh sign-in's time, and the agent's scope mode
    // when the client is an agent.
    if (dangerous.length > 0) {
      // The step-up gate above sends a registration (#640) to a sign-in
      // before any dangerous scope: reaching here without one is a bug, and
      // the transaction rolls back.
      if (isRegisteredSubject(session)) {
        throw new Error('a dangerous scope granted to a registration without a sign-in');
      }
      const scopeMode = isAgentClient(client) ? highestAgentModeInScopes(scopes) : null;
      await emitUserEvent(
        request,
        'urn:qauth:event:step_up.elevated:v1-rc.0',
        {
          scopes,
          dangerousScopes: dangerous,
          ...(scopeMode === null ? {} : { scopeMode }),
          authenticatedAt: new Date(session.authTime).toISOString(),
        },
        { ...userEvent, tx }
      );
    }
    await emitUserEvent(
      request,
      'urn:qauth:event:consent.granted:v1-rc.0',
      {
        scopes,
        remembered: answer.remember,
        ...(dangerous.length > 0 ? { dangerousScopes: dangerous } : {}),
      },
      { ...userEvent, tx }
    );
    return outcome;
  }, MINT_TRANSACTION);

  if (minted === 'session_ended') {
    // The session ended under the request: the answer a request arriving
    // after the sign-out gets, a sign-in.
    await emitUserEvent(
      request,
      'urn:qauth:event:authorization.failed:v1-rc.0',
      { error: 'login_required', reason: 'session_ended_during_authorization' },
      userEvent
    );
    return continueAuthorization(fastify, request, reply, finished, target, null, {
      kind: 'sign_in',
    });
  }
  return buildRedirectUrl(query.redirect_uri, { code: minted.code, state, iss: target.iss });
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
