import { PASSWORD_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-federation';
import { type RoundContext, signInAuditEvent } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { accountPoliciesOf } from './account-policies';
import { identifierPrefill, identifierStep } from './authorization-interaction';
import type { BackgroundTasks } from './background-tasks';
import type { EngineMailer } from './engine-mail';
import {
  continueAtStep,
  type InteractionCancelResult,
  type InteractionFinished,
  type InteractionState,
  startAccountInteraction,
  type StartAccountInteractionInput,
} from './interaction';
import {
  createInteractionEngines,
  decisionOf,
  type InteractionEngines,
} from './interaction-engines';
import {
  ACCOUNT_PAGES_ENGINE_CLIENT_ID,
  type AccountIntent,
  type AccountRequest,
  type AccountReturnPath,
  type InteractionPersonalData,
  type InteractionStep,
} from './interaction-record';
import { ladderEndUserIp } from './password-attempts';
import { buildRealmUrl } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import { roundEnvironment } from './round-limits';
import { finishHeldUpstreamLink } from './upstream-links';
import { upstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent } from './user-events';

/**
 * THE ACCOUNT PAGE'S INTERACTIONS (#844; ADR-017 Decisions 4 and 8, ADR-020
 * §1): every ceremony the hosted account page needs runs as an interaction of
 * the Interaction API, of purpose `account`, on the realm origin, on the one
 * sign-in engine. The page never checks a factor itself.
 *
 * - A browser with no session signs in (`sign_in`) and comes back.
 * - A change that asks for a fresh authentication sends the person through a
 *   fresh sign-in first (`reauthenticate`): the engine's downgrade rule makes
 *   it hold the account's strongest bound factor, and passkey-first asks for
 *   a passkey before anything else while passkey sign-in is on.
 * - Adding a passkey or setting up an authenticator app is the same fresh
 *   sign-in, after which the engine binds the factor through its own
 *   enrolment step (`RoundContext.enrol`), with its own rules.
 * - Linking an upstream account (#670) starts at the provider; the fresh
 *   sign-in to this account in the same interaction attaches the identity it
 *   proved. That sign-in may go through another provider the account
 *   already holds (#1080), never the one it links. Nothing is matched by an
 *   email or anything else.
 *
 * The engine binds an account interaction's transaction to
 * {@link ACCOUNT_PAGES_ENGINE_CLIENT_ID}, which no client can hold, and every
 * round asks for a fresh sign-in: no password reset stands in for one, and
 * nobody registers. Each finishes at the account page its record names, a
 * fixed path (`ACCOUNT_RETURN_PATHS`); a cancel goes back to it.
 */

/** The engine client id of an interaction's rounds: the request's client, or none for the account page. */
export function engineClientIdOf(
  state: Extract<InteractionState, { readonly purpose: 'authorization' | 'account' }>
): string {
  return state.purpose === 'account' ? ACCOUNT_PAGES_ENGINE_CLIENT_ID : state.request.client_id;
}

/**
 * What an account interaction's every round adds to the context: a fresh
 * sign-in, and the factor its intent binds.
 */
export function accountRoundOf(
  request: AccountRequest
): Pick<RoundContext, 'freshSignIn' | 'enrol'> {
  return {
    freshSignIn: true,
    ...(request.intent === 'passkey' || request.intent === 'totp' ? { enrol: request.intent } : {}),
  };
}

/** The notice the account page shows once an interaction of `intent` finished. */
export const ACCOUNT_FINISH_NOTICES = {
  sign_in: undefined,
  reauthenticate: 'confirmed',
  passkey: 'passkey',
  totp: 'totp',
  link: 'linked',
} as const satisfies Record<AccountIntent, string | undefined>;

/** The account page `path` on the realm's origin, with the notice to show, if any. */
export function accountPageUrl(
  realm: Pick<RealmRow, 'issuer'>,
  path: AccountReturnPath,
  notice?: string
): string {
  return buildRealmUrl(
    realm,
    notice === undefined ? path : `${path}?${new URLSearchParams({ notice }).toString()}`
  );
}

/** What {@link startAccountCeremony} starts. */
export interface AccountCeremony {
  readonly intent: AccountIntent;
  readonly returnTo: AccountReturnPath;
  /** The browser session the page was opened with: absent for `sign_in`. */
  readonly session?: { readonly userId: string; readonly sid: string };
  /** For `link`: the upstream provider's type, which the realm has on. */
  readonly provider?: string;
}

/** Starts the account page's interactions; built once, while the routes register. */
export interface AccountCeremonies {
  /**
   * Start one and answer where the browser goes: its ceremony page, or, for
   * a `link`, the route that starts the provider in it.
   *
   * @throws {InvalidRequestError} when the interaction cannot be held
   */
  readonly start: (
    request: FastifyRequest,
    reply: FastifyReply,
    ceremony: AccountCeremony
  ) => Promise<string>;
  /** The sign-in engines, for the page's own reads (the mailer). */
  readonly engines: () => InteractionEngines;
}

/**
 * The account page's ceremonies. `tasks` must be created while the routes
 * register: the engines' mail registers a hook.
 */
export function accountCeremonies(
  fastify: FastifyInstance,
  tasks: BackgroundTasks
): AccountCeremonies {
  let built: InteractionEngines | undefined;
  const engines = (): InteractionEngines => {
    built ??= createInteractionEngines(fastify, { tasks });
    return built;
  };

  /**
   * The first step: passkey-first while passkey sign-in is on (#651), the
   * engine's round 0, which asks for a discoverable passkey before anything
   * else and offers the password, the identifier and the realm's providers
   * beside it; otherwise the identifier step, the session's address as its
   * prefill, with the providers beside it.
   */
  const firstStep = async (
    request: FastifyRequest,
    reply: FastifyReply,
    realm: RealmRow,
    account: AccountRequest,
    session: AccountCeremony['session']
  ): Promise<{
    readonly step: InteractionStep;
    readonly personal: InteractionPersonalData;
    readonly signInTransaction?: StartAccountInteractionInput['signInTransaction'];
  }> => {
    if (fastify.passkeySignIn === true && account.intent !== 'link') {
      const engine = engines();
      // The round limits' environment is the realm's: the page is no client.
      const environment = await roundEnvironment(fastify, realm, ACCOUNT_PAGES_ENGINE_CLIENT_ID);
      const result = await engine.forRequest(request, () =>
        engine.of(accountPoliciesOf(fastify, realm).requireVerifiedAccount).advance(null, null, {
          realm: { id: realm.id },
          client: { id: ACCOUNT_PAGES_ENGINE_CLIENT_ID },
          ...accountRoundOf(account),
          receivedAt: Date.now(),
          ...ladderEndUserIp(request),
          environment,
          // As at the authorization endpoint's first round: the providers are
          // offered beside the passkey; the answer round starts the one picked.
          startUpstream: async () => {
            throw new Error('the first sign-in round starts no upstream provider');
          },
          audit: async (record) => {
            const event = signInAuditEvent(record);
            await emitUserEvent(request, event.type, event.data, {
              realmId: realm.id,
              clientId: null,
              userId: event.userId,
              actor: 'user',
            });
          },
        })
      );
      if (result.kind === 'step') {
        const decided = decisionOf(reply, result, Date.now());
        if (decided.kind === 'step' && decided.signInTransaction != null) {
          return {
            step: decided.step,
            personal: decided.personal ?? {},
            signInTransaction: decided.signInTransaction,
          };
        }
      }
      fastify.log.warn(
        { realmId: realm.id, result: result.kind },
        'the first account sign-in round offered no step: the interaction starts at the identifier'
      );
    }
    const providers = await upstreamProviderCatalog(fastify).offered(realm.id);
    return {
      step: identifierStep(providers),
      personal: identifierPrefill(
        session === undefined ? undefined : await addressOf(fastify, realm.id, session.userId)
      ),
    };
  };

  return Object.freeze({
    engines,
    async start(request: FastifyRequest, reply: FastifyReply, ceremony: AccountCeremony) {
      const realm = requestRealm(request);
      const account: AccountRequest = { intent: ceremony.intent, returnTo: ceremony.returnTo };
      if (ceremony.intent === 'link' && ceremony.provider === undefined) {
        throw new Error('an upstream link names its provider');
      }
      const first = await firstStep(request, reply, realm, account, ceremony.session);
      const started = await startAccountInteraction(request, reply, {
        request: account,
        ...first,
        ...(ceremony.session === undefined ? {} : { carriedSession: ceremony.session }),
        ...(ceremony.intent === 'link' && ceremony.provider !== undefined
          ? { upstreamLink: { state: 'requested', provider: ceremony.provider } }
          : {}),
      });
      if (ceremony.intent === 'link' && ceremony.provider !== undefined) {
        const type = encodeURIComponent(ceremony.provider);
        return buildRealmUrl(
          realm,
          `/ui/upstream/${type}/start?interaction=${encodeURIComponent(started.id)}`
        );
      }
      return buildRealmUrl(realm, ceremonyPagePath(started.id));
    },
  });
}

/** The address the account's password credential holds in the realm, if any. */
async function addressOf(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<string | undefined> {
  const credential = await fastify.repositories.userCredentials.findByUserIdAndType(
    userId,
    PASSWORD_PROVIDER_TYPE
  );
  return credential !== undefined && credential.realmId === realmId
    ? credential.externalSub
    : undefined;
}

/** How a finished account sign-in proved the person, for `user.signed_in`'s method. */
export type AccountSignInMethod = 'password' | 'upstream' | 'passkey';

/**
 * Finish an account interaction (#844): the sign-in it ended with is
 * recorded (`user.signed_in`, for no client), an upstream identity the
 * interaction holds is linked to the account it signed in to (#670), and the
 * browser goes back to the account page, with the notice of its intent. A
 * refused link goes instead to the `upstream_link` step with its reason
 * (#1081), the first step of a next account interaction on `reply`, whose
 * cancel goes back to the account page.
 */
export async function finishAccountInteraction(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  result: Extract<InteractionFinished, { readonly purpose: 'account' }>,
  options: { readonly method: AccountSignInMethod; readonly mailer: EngineMailer }
): Promise<string> {
  const realm = requestRealm(request);
  const { userId, registered } = result.transaction;
  // An account interaction always asks for a sign-in, and never registers.
  if (userId === undefined || registered === true) {
    throw new Error('an account interaction finished without a sign-in');
  }
  await fastify.repositories.users.updateLastLogin(realm.id, userId);
  await emitUserEvent(
    request,
    'urn:qauth:event:user.signed_in:v1-rc.0',
    { method: options.method },
    { realmId: realm.id, userId, clientId: null, actor: 'user' }
  );
  // A link whose provider proved nobody yet holds no identity: the person
  // came back from the provider, and signed in another way. Nothing is
  // attached.
  const held = await finishHeldUpstreamLink(fastify, request, {
    realm,
    link: result.upstreamLink,
    transaction: result.transaction,
    clientId: null,
    mailer: options.mailer,
  });
  if (held.kind === 'refused') return continueAtStep(request, reply, result, held.step);
  if (held.kind === 'linked') {
    return accountPageUrl(realm, result.request.returnTo, ACCOUNT_FINISH_NOTICES.link);
  }
  return accountPageUrl(
    realm,
    result.request.returnTo,
    result.request.intent === 'link' ? undefined : ACCOUNT_FINISH_NOTICES[result.request.intent]
  );
}

/** Where a cancelled account interaction goes: back to its account page. */
export function cancelAccountInteraction(
  request: FastifyRequest,
  result: Extract<InteractionCancelResult, { readonly purpose: 'account' }>
): string {
  return accountPageUrl(requestRealm(request), result.request.returnTo);
}
