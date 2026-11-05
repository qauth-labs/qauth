import { createHash } from 'node:crypto';

import {
  type AuthMethod,
  AuthMethodFaultError,
  type AuthMethodRouteHost,
  completeUpstreamStep,
  startUpstreamStep,
  UPSTREAM_CREDENTIAL_KIND,
  upstreamCredentialDataSchema,
  type UpstreamStepCompletion,
  type UserAttribute,
  type VerifiedIdentity,
} from '@qauth-labs/fastify-plugin-federation';
import {
  type RoundContext,
  type RoundResult,
  signInAuditEvent,
  type UpstreamProof,
  type UpstreamStarter,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  TemporarilyUnavailableError,
  TooManyRequestsError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { accountPoliciesOf } from './account-policies';
import { finishAuthorization } from './authorization-interaction';
import { matchFlowSecret, readFlowSecrets } from './flow-cookie';
import {
  answerInteraction,
  type InteractionAnswerResult,
  interactionFlowBinding,
  type InteractionState,
} from './interaction';
import { decisionOf, type InteractionEngines } from './interaction-engines';
import { InteractionExpiredError } from './interaction-expired';
import { eventClientIdOf, type InteractionRequest } from './interaction-record';
import { ladderEndUserIp } from './password-attempts';
import { normalizeInternalAuthorizeUrl } from './pending-authorization';
import { realmRateLimitKey } from './realm-rate-limit';
import { buildRealmUrl } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import { roundEnvironment } from './round-limits';
import {
  sendUpstreamPage,
  upstreamErrorPage,
  upstreamProviderErrorPage,
  upstreamWaitingPage,
} from './upstream-pages';
import type { RealmUpstreamProviderOf, UpstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent } from './user-events';

/**
 * THE UPSTREAM SIGN-IN FLOW (#639; ADR-020 §3 and its Appendix, ADR-017
 * Decision 4, ADR-002, ADR-003): a person signs in through one of the
 * realm's upstream identity providers.
 *
 * 1. Start. The `upstream` step is answered (the Interaction API), or the
 *    authorization request routes to a provider (`qauth_upstream`, through
 *    `GET /ui/upstream/<type>/start`). The engine records which provider may
 *    complete the step; {@link upstreamStarter} calls the provider's `start()`
 *    and keeps what it answers (`state`, `nonce`, the PKCE verifier) in
 *    Redis, keyed by the binding the provider sends back, bound to the
 *    interaction and to the flow cookie that binds it, for ten minutes.
 * 2. Callback, at `/upstream/<type>/callback` ({@link upstreamRouteHost}).
 *    The pending sign-in is read only by the browser whose flow cookie the
 *    start bound, and taken once. A callback replayed in another browser, or
 *    forged, leaves it alone. The method validates the response (the generic
 *    OpenID Connect client: `iss`, the code with its verifier, the ID token
 *    and its `nonce`).
 * 3. The account, by `(realm, provider type, sub)` alone, never by an
 *    attribute: a known credential signs its user in when the ID token's
 *    `iss` is the one it was created under; an unknown one creates a user,
 *    the credential and the provider's claims as attributes (`source` the
 *    provider type), in one transaction, when the realm allows sign-up. The
 *    account counts as verified unless the provider's verified switch is off;
 *    the `email` attribute is verified only when the provider said so and the
 *    switch is on.
 * 4. The engine takes the account as proved by the `upstream` step, which
 *    ranks with the password (below a passkey), and goes on: the passkey of
 *    an account that has one, the MFA policy, the inline verification of an
 *    address nobody vouched for.
 *
 * Every refusal is audited as `user.sign_in_failed` (`method: upstream`).
 * A cancel or an error at the provider shows the provider-error page, with
 * the way back to the first step; anything else shows the one error page
 * with the request's trace id. Neither sends anything to the client.
 */

/** How long a started provider waits for its callback, in seconds. */
export const UPSTREAM_SIGN_IN_TTL_SECONDS = 10 * 60;

/** The Redis key prefix of a pending upstream sign-in. */
const PENDING_KEY_PREFIX = 'upstream-sign-in:';

/** The longest way back a pending sign-in keeps: an authorize URL the stash would park. */
const MAX_WAY_BACK_LENGTH = 16 * 1024;

/**
 * Where the sign-in goes on once the provider proved the account:
 *
 * - `interaction`: the Interaction API's ceremony page, which shows any
 *   further step, and the authorization request finishes as an
 *   interaction's does.
 * - `pages`: the server-rendered pages (`INTERACTION_UI_ENABLED` off). The
 *   sign-in completes here or fails closed, since no page shows a further
 *   step; the authorization request starts again under the new session.
 */
export type UpstreamSignInMode = 'interaction' | 'pages';

const pendingSchema = z.strictObject({
  v: z.literal(1),
  realmId: z.string().min(1).max(64),
  type: z.string().min(1).max(64),
  binding: z.string().min(22).max(512),
  transaction: z.record(z.string(), z.unknown()),
  interactionId: z.string().min(1).max(64),
  revision: z.int().min(0),
  flowBinding: z.string().min(1).max(128),
  mode: z.enum(['interaction', 'pages']),
  wayBack: z.string().min(1).max(MAX_WAY_BACK_LENGTH),
});

/** A started upstream sign-in, until its callback takes it. */
type PendingUpstreamSignIn = z.infer<typeof pendingSchema>;

function pendingKey(realmId: string, binding: string): string {
  return `${PENDING_KEY_PREFIX}${realmId}:${createHash('sha256').update(binding).digest('hex')}`;
}

/** The pending sign-in `binding` names in the realm, read or taken; `null` when there is none. */
async function readPending(
  fastify: Pick<FastifyInstance, 'redis' | 'log'>,
  realmId: string,
  binding: string,
  take: boolean
): Promise<PendingUpstreamSignIn | null> {
  const key = pendingKey(realmId, binding);
  const raw = take ? await fastify.redis.getdel(key) : await fastify.redis.get(key);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  const checked = pendingSchema.safeParse(parsed);
  if (!checked.success) {
    fastify.log.error({ key }, 'a pending upstream sign-in that is not well formed');
    return null;
  }
  return checked.data;
}

/** The way back of an authorization request: the request itself, at the authorization endpoint. */
export function authorizeUrlOf(request: InteractionRequest): string {
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(request as Record<string, unknown>)) {
    if (value === undefined || value === null) continue;
    for (const item of Array.isArray(value) ? value : [value]) search.append(name, String(item));
  }
  const url = normalizeInternalAuthorizeUrl(`/oauth/authorize?${search.toString()}`);
  if (url === null) throw new Error('an authorization request that is no authorize URL');
  return url;
}

/** The ceremony page of the interaction `id`, on the realm's issuer. */
export function ceremonyPageUrlOf(realm: RealmRow, id: string): string {
  return buildRealmUrl(realm, ceremonyPagePath(id));
}

/** Where a started sign-in comes back to, and how it goes on. */
export interface UpstreamStartTarget {
  readonly interactionId: string;
  /** The interaction's revision once the round that starts the provider is written. */
  readonly revision: number;
  readonly mode: UpstreamSignInMode;
  /** The first sign-in step: the provider-error page's way back. */
  readonly wayBack: string;
}

/** What a start answered the browser: where it goes, and the provider's button name. */
export interface UpstreamStarted {
  readonly redirectTo: string;
  readonly providerName: string;
}

/**
 * The engine's start of an upstream provider for one request (#639): the
 * provider's `start()` through `startUpstreamStep`, and what it answered
 * kept in Redis, bound to the interaction and to its flow cookie. A provider
 * that is off, whose context cannot be built or whose `start()` fails, is
 * `unavailable` and nothing is kept; a Redis write that fails throws, which
 * the engine reports as a store outage.
 */
export function upstreamStarter(
  fastify: Pick<FastifyInstance, 'redis' | 'log'>,
  request: FastifyRequest,
  catalog: UpstreamProviderCatalog,
  target: UpstreamStartTarget,
  started: (start: UpstreamStarted) => void
): UpstreamStarter {
  return async (entry) => {
    const realm = requestRealm(request);
    const provider = await catalog.find(realm.id, entry.provider);
    if (provider === undefined) return { kind: 'unavailable' };
    let start: Awaited<ReturnType<typeof startUpstreamStep>>;
    try {
      start = await startUpstreamStep(
        provider.method,
        { uiLocales: [] },
        await provider.context(request)
      );
    } catch (error) {
      request.log.warn(
        { err: error, upstreamProvider: entry.provider },
        'an upstream provider could not start'
      );
      return { kind: 'unavailable' };
    }
    if (target.wayBack.length > MAX_WAY_BACK_LENGTH) {
      throw new Error('a way back too long to keep');
    }
    const record: PendingUpstreamSignIn = {
      v: 1,
      realmId: realm.id,
      type: provider.method.type,
      binding: start.binding,
      transaction: start.transaction as Record<string, unknown>,
      interactionId: target.interactionId,
      revision: target.revision,
      flowBinding: await interactionFlowBinding(request, target.interactionId),
      mode: target.mode,
      wayBack: target.wayBack,
    };
    await fastify.redis.set(
      pendingKey(realm.id, start.binding),
      JSON.stringify(record),
      'EX',
      UPSTREAM_SIGN_IN_TTL_SECONDS
    );
    started({ redirectTo: start.redirectTo, providerName: provider.entry.name });
    return { kind: 'started', redirectTo: start.redirectTo };
  };
}

/**
 * The engine round's context for a request of the flow, as the Interaction
 * API builds its own: the engine's audit records become user events.
 */
export function upstreamRoundContext(
  request: FastifyRequest,
  state: InteractionState & { readonly purpose: 'authorization' },
  extra: Omit<RoundContext, 'realm' | 'client' | 'audit'>
): RoundContext {
  const realmId = requestRealm(request).id;
  const clientId = eventClientIdOf(state);
  return {
    realm: { id: realmId },
    client: { id: state.request.client_id },
    ...ladderEndUserIp(request),
    ...extra,
    audit: async (record) => {
      const event = signInAuditEvent(record);
      await emitUserEvent(request, event.type, event.data, {
        realmId,
        clientId,
        userId: event.userId,
        actor: 'user',
      });
    },
  };
}

/** Why the flow refused: a `user.sign_in_failed` reason, and whether the engine audited it already. */
export class UpstreamSignInRefusal extends Error {
  override readonly name = 'UpstreamSignInRefusal';
  constructor(
    readonly reason: string,
    readonly audited = false,
    readonly userId?: string
  ) {
    super(`upstream sign-in refused: ${reason}`);
  }
}

/** Record a refused upstream sign-in as the user event every refusal is. */
export async function auditUpstreamRefusal(
  request: FastifyRequest,
  reason: string,
  userId?: string
): Promise<void> {
  await emitUserEvent(
    request,
    'urn:qauth:event:user.sign_in_failed:v1-rc.0',
    { method: 'upstream', reason },
    { realmId: requestRealm(request).id, userId: userId ?? null, actor: 'user' }
  );
}

/** The one error page, with the request's trace id. */
export function sendUpstreamErrorPage(
  request: FastifyRequest,
  reply: FastifyReply,
  wayBack?: string
): FastifyReply {
  return sendUpstreamPage(
    reply,
    upstreamErrorPage({
      cspNonce: reply.cspNonce.style,
      traceId: request.id,
      ...(wayBack === undefined ? {} : { wayBack }),
    }),
    400
  );
}

/** The waiting page of a started provider. */
export function sendUpstreamWaitingPage(
  reply: FastifyReply,
  started: UpstreamStarted,
  wayBack: string
): FastifyReply {
  return sendUpstreamPage(
    reply,
    upstreamWaitingPage({
      cspNonce: reply.cspNonce.style,
      providerName: started.providerName,
      redirectTo: started.redirectTo,
      wayBack,
    })
  );
}

/** What the callback found of the account behind a provider's identity. */
type ResolvedAccount =
  | {
      readonly kind: 'account';
      readonly userId: string;
      readonly enabled: boolean;
      readonly verified: boolean;
      readonly created: boolean;
    }
  | { readonly kind: 'refused'; readonly reason: string; readonly userId?: string };

/** The longest issuer a credential keeps: its data schema's bound. */
const MAX_ISSUER_LENGTH = 2048;

/**
 * The account that holds the provider's identity (#639): looked up by
 * `(realm, provider type, external sub)` alone, never by an attribute. A
 * known credential stands only under the issuer it was created with (OIDC
 * Core §5.7: a `sub` is unique only within its issuer). An unknown identity
 * creates a new account, when the realm allows sign-up, even when another
 * account holds the same email: nothing matches or merges.
 */
async function resolveAccount(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realm: RealmRow,
  provider: RealmUpstreamProviderOf,
  identity: VerifiedIdentity,
  attributes: readonly UserAttribute[],
  mode: UpstreamSignInMode
): Promise<ResolvedAccount> {
  const { repositories } = fastify;
  const type = provider.method.type;
  // Every identity names the issuer that assigned its subject (the AuthMethod
  // contract, `rawClaims.iss`): one that does not could never be told apart
  // from another issuer's subject of the same value, so it is refused.
  const iss = identity.rawClaims['iss'];
  if (typeof iss !== 'string' || iss.length === 0 || iss.length > MAX_ISSUER_LENGTH) {
    return { kind: 'refused', reason: 'invalid_response' };
  }
  // Twice at most: a callback that loses the race to create the same
  // identity reads the account the other one created.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const credential = await repositories.userCredentials.findByRealmProviderSub(
      realm.id,
      type,
      identity.externalSub
    );
    if (credential !== undefined) {
      const data = upstreamCredentialDataSchema.safeParse(credential.credentialData);
      if (!data.success) {
        request.log.error(
          { credentialId: credential.id },
          'an upstream credential whose data is not well formed'
        );
        return { kind: 'refused', reason: 'credential_invalid', userId: credential.userId };
      }
      if (data.data.iss !== iss) {
        return { kind: 'refused', reason: 'issuer_mismatch', userId: credential.userId };
      }
      if (credential.disabledAt !== null && credential.disabledAt !== undefined) {
        return { kind: 'refused', reason: 'credential_disabled', userId: credential.userId };
      }
      const user = await repositories.users.findById(realm.id, credential.userId);
      if (user === undefined) {
        request.log.error({ credentialId: credential.id }, 'an upstream credential without a user');
        return { kind: 'refused', reason: 'credential_invalid' };
      }
      return {
        kind: 'account',
        userId: user.id,
        enabled: user.enabled,
        verified: data.data.verified,
        created: false,
      };
    }
    if (!accountPoliciesOf(fastify, realm).allowSignUp) {
      return { kind: 'refused', reason: 'sign_up_disabled' };
    }
    // An account the provider's verified switch leaves unverified is verified
    // inline with an emailed code before it may sign in (the engine's rule 8,
    // ADR-017 Decision 8), at the address the provider gave. With no address,
    // or on the pages, which show no such step, it could never sign in:
    // refuse before anything is written rather than leave such an account.
    if (
      !provider.marksVerified &&
      (mode === 'pages' || !attributes.some((attribute) => attribute.attrKey === 'email'))
    ) {
      return { kind: 'refused', reason: 'verification_unavailable' };
    }
    try {
      const userId = await fastify.db.transaction(async (tx) => {
        const user = await repositories.users.create({ realmId: realm.id }, tx);
        await repositories.userCredentials.create(
          {
            userId: user.id,
            realmId: realm.id,
            providerType: type,
            externalSub: identity.externalSub,
            credentialData: {
              kind: UPSTREAM_CREDENTIAL_KIND,
              iss,
              verified: provider.marksVerified,
            },
          },
          tx
        );
        await repositories.userAttributes.upsertMany(
          user.id,
          attributes.map((attribute) => ({
            source: type,
            attrKey: attribute.attrKey,
            attrValue: attribute.attrValue,
            // The provider vouched for it, and its verified switch is on.
            verified: attribute.verified && provider.marksVerified,
            expiresAt: attribute.expiresAt === undefined ? null : attribute.expiresAt.getTime(),
          })),
          tx
        );
        // The account's event commits with the account, as registration's does.
        await emitUserEvent(
          request,
          'urn:qauth:event:user.registered:v1-rc.0',
          { method: 'upstream' },
          { tx, realmId: realm.id, userId: user.id, actor: 'user' }
        );
        return user.id;
      });
      return {
        kind: 'account',
        userId,
        enabled: true,
        verified: provider.marksVerified,
        created: true,
      };
    } catch (error) {
      if (!(error instanceof UniqueConstraintError)) throw error;
    }
  }
  throw new Error('an upstream credential that was neither found nor created');
}

/** The address the provider gave, as the account's `email` attribute of its source holds it. */
async function providerAddress(
  fastify: FastifyInstance,
  userId: string,
  type: string
): Promise<string | undefined> {
  const rows = await fastify.repositories.userAttributes.findByUserIdAndSource(userId, type);
  return rows.find((row) => row.attrKey === 'email')?.attrValue;
}

/** What the callback host needs beyond the server. */
export interface UpstreamRouteHostParts {
  readonly catalog: UpstreamProviderCatalog;
  /** The sign-in engines, built at the first callback. */
  readonly engines: () => InteractionEngines;
}

/**
 * The host of the providers' callback routes (#639): it builds a provider's
 * context, keeps and hands over its pending sign-in, and ends the step.
 */
export function upstreamRouteHost(
  fastify: FastifyInstance,
  parts: UpstreamRouteHostParts
): AuthMethodRouteHost {
  const { catalog } = parts;
  /** The pending sign-in each request took, for its completion. */
  const takenBy = new WeakMap<FastifyRequest, PendingUpstreamSignIn>();

  /**
   * The provider of `method`'s type in the request's realm, while it is on.
   * By type, not by object: a plugin's routes are mounted from the provider
   * registry's frozen snapshot of its method, which is another object than
   * the plugin's own (the registry checked it), of the same type.
   */
  const providerOf = async (
    method: AuthMethod,
    request: FastifyRequest
  ): Promise<RealmUpstreamProviderOf | undefined> => {
    const provider = await catalog.find(requestRealm(request).id, method.type);
    return provider?.method.type === method.type ? provider : undefined;
  };

  /**
   * The pending sign-in of `method` the binding names, when this browser's
   * flow cookie is the one its start bound; read, or taken once.
   */
  const pendingFor = async (
    method: AuthMethod,
    request: FastifyRequest,
    binding: string | undefined,
    take: boolean
  ): Promise<PendingUpstreamSignIn | undefined> => {
    if (binding === undefined) return undefined;
    const realmId = requestRealm(request).id;
    // Read before it is taken: a callback in another browser never takes it.
    const pending = await readPending(fastify, realmId, binding, false);
    if (
      pending === null ||
      pending.realmId !== realmId ||
      pending.type !== method.type ||
      pending.binding !== binding ||
      matchFlowSecret(pending.flowBinding, readFlowSecrets(request)) === undefined
    ) {
      return undefined;
    }
    if (!take) return pending;
    const taken = await readPending(fastify, realmId, binding, true);
    if (taken === null || taken.flowBinding !== pending.flowBinding) return undefined;
    return taken;
  };

  const complete = async (
    method: AuthMethod,
    outcome: unknown,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<unknown> => {
    const receivedAt = Date.now();
    const realm = requestRealm(request);
    const pending = takenBy.get(request);
    const wayBack = pending?.wayBack;
    const refuse = async (reason: string, userId?: string, audited = false) => {
      if (!audited) await auditUpstreamRefusal(request, reason, userId);
      return sendUpstreamErrorPage(request, reply, wayBack);
    };

    let completion: UpstreamStepCompletion;
    try {
      completion = await completeUpstreamStep(method, outcome, { maxAssurance: 'low' });
    } catch (error) {
      if (!(error instanceof AuthMethodFaultError)) throw error;
      request.log.error({ err: error, upstreamProvider: method.type }, 'upstream method fault');
      return refuse('method_fault');
    }
    if (pending === undefined) {
      return refuse(completion.kind === 'failed' ? completion.reason : 'transaction_mismatch');
    }
    const provider = await providerOf(method, request);
    if (
      completion.kind === 'declined' ||
      (completion.kind === 'failed' && completion.reason === 'provider_error')
    ) {
      // The person cancelled or declined at the provider, or it answered an
      // error: nothing goes to the client, and the way back is the first step.
      await auditUpstreamRefusal(
        request,
        completion.kind === 'declined' ? 'declined' : 'provider_error'
      );
      return sendUpstreamPage(
        reply,
        upstreamProviderErrorPage({
          cspNonce: reply.cspNonce.style,
          providerName: provider?.entry.name ?? 'Your sign-in provider',
          wayBack: pending.wayBack,
        })
      );
    }
    if (completion.kind === 'failed') {
      if (completion.cause !== undefined) {
        request.log.warn(
          { err: completion.cause, upstreamProvider: method.type },
          'upstream verification refused'
        );
      }
      return refuse(completion.reason);
    }
    if (provider === undefined) return refuse('upstream_unavailable');

    const account = await resolveAccount(
      fastify,
      request,
      realm,
      provider,
      completion.identity,
      completion.attributes,
      pending.mode
    );
    if (account.kind === 'refused') return refuse(account.reason, account.userId);
    const address = await providerAddress(fastify, account.userId, method.type);
    const proof: UpstreamProof = {
      provider: provider.entry,
      account: { userId: account.userId, enabled: account.enabled, verified: account.verified },
      ...(address === undefined ? {} : { address }),
    };

    const engines = parts.engines();
    const engine = engines.of(accountPoliciesOf(fastify, realm).requireVerifiedAccount);
    let result: InteractionAnswerResult;
    try {
      result = await answerInteraction(
        request,
        reply,
        { id: pending.interactionId, revision: pending.revision },
        async (state) => {
          if (state.purpose !== 'authorization') {
            throw new UpstreamSignInRefusal('transaction_mismatch');
          }
          const round: RoundResult = await engine.completeUpstream(
            state.signInTransaction,
            proof,
            upstreamRoundContext(request, state, {
              receivedAt,
              environment: await roundEnvironment(fastify, realm, state.request.client_id),
              // The pages show no further step: the sign-in completes here,
              // or fails closed (a passkey, a code to verify the address).
              ...(pending.mode === 'pages'
                ? { serves: ['upstream'] }
                : { sendCode: engines.sendCode(request) }),
            })
          );
          if (round.kind === 'redirect') throw new UpstreamSignInRefusal('step_not_available');
          // The engine audited its own refusal.
          if (round.kind === 'refused' && round.reason === 'invalid_answer') {
            throw new UpstreamSignInRefusal('invalid_answer', true);
          }
          if (round.kind === 'refused' && round.reason === 'transaction_ended') {
            throw new UpstreamSignInRefusal('transaction_ended', true);
          }
          return decisionOf(reply, round, receivedAt);
        }
      );
    } catch (error) {
      if (error instanceof UpstreamSignInRefusal) {
        return refuse(error.reason, account.userId, error.audited);
      }
      if (error instanceof InteractionExpiredError) return refuse('interaction_expired');
      if (error instanceof TooManyRequestsError) return refuse('throttled', account.userId);
      if (error instanceof TemporarilyUnavailableError) return refuse('unavailable');
      throw error;
    }
    switch (result.kind) {
      case 'stale':
        return refuse('interaction_expired');
      case 'step':
        // A further step (the passkey, a code): the ceremony page shows it.
        return reply.redirect(ceremonyPageUrlOf(realm, pending.interactionId), 303);
      case 'finished': {
        if (result.purpose !== 'authorization') return refuse('transaction_mismatch');
        const userId = result.transaction.userId ?? account.userId;
        await fastify.repositories.users.updateLastLogin(realm.id, userId);
        await emitUserEvent(
          request,
          'urn:qauth:event:user.signed_in:v1-rc.0',
          { method: 'upstream' },
          { realmId: realm.id, userId, clientId: eventClientIdOf(result), actor: 'user' }
        );
        // The pages start the authorization request again under the new
        // session; an interaction finishes it as the Interaction API does.
        const location =
          pending.mode === 'pages'
            ? pending.wayBack
            : await finishAuthorization(fastify, request, reply, result);
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(location, 303);
      }
    }
  };

  return Object.freeze({
    async contextFor(method: AuthMethod, request: FastifyRequest) {
      const provider = await providerOf(method, request);
      if (provider === undefined) {
        throw new Error(`The AuthMethod ${method.type} is not an enabled provider of the realm`);
      }
      return provider.context(request);
    },
    async peekTransaction(method: AuthMethod, request: FastifyRequest, binding?: string) {
      const pending = await pendingFor(method, request, binding, false);
      return pending === undefined
        ? undefined
        : { binding: pending.binding, transaction: pending.transaction };
    },
    async takeTransaction(method: AuthMethod, request: FastifyRequest, binding?: string) {
      const taken = await pendingFor(method, request, binding, true);
      if (taken === undefined) return undefined;
      takenBy.set(request, taken);
      return { binding: taken.binding, transaction: taken.transaction };
    },
    complete,
  });
}

/** The callback's rate limit: the sign-in form's budget, per address and realm. */
export function upstreamCallbackRateLimit(): Readonly<Record<string, unknown>> {
  return {
    rateLimit: {
      max: env.LOGIN_RATE_LIMIT,
      timeWindow: env.LOGIN_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    },
  };
}
