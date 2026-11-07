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
  type SignInEngine,
  type UpstreamProof,
  type UpstreamProviderEntry,
  type UpstreamStarter,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  TemporarilyUnavailableError,
  TooManyRequestsError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import { ceremonyPagePath, stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../../config/env';
import { accountRoundOf, engineClientIdOf, finishAccountInteraction } from './account-interaction';
import { accountPoliciesOf } from './account-policies';
import { finishAuthorization } from './authorization-interaction';
import { matchFlowSecret, readFlowSecrets } from './flow-cookie';
import {
  answerInteraction,
  type InteractionAnswerResult,
  type InteractionDecision,
  interactionFlowBinding,
  type InteractionState,
} from './interaction';
import { decisionOf, type InteractionEngines } from './interaction-engines';
import { InvalidAnswerError } from './interaction-errors';
import { InteractionExpiredError } from './interaction-expired';
import {
  eventClientIdOf,
  type InteractionRequest,
  type InteractionStep,
  keepsUpstreamAttributes,
  type KeptUpstreamAttribute,
  type UpstreamLink,
} from './interaction-record';
import { ladderEndUserIp } from './password-attempts';
import { normalizeInternalAuthorizeUrl } from './pending-authorization';
import { realmRateLimitKey } from './realm-rate-limit';
import { buildRealmUrl } from './realm-url';
import { type RealmRow, requestRealm } from './request-realm';
import { roundEnvironment } from './round-limits';
import type { UpstreamLinkRefusal } from './upstream-links';
import {
  sendUpstreamPage,
  upstreamErrorPage,
  upstreamLinkRefusedPage,
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
 *    `iss` is the one it was created under. An unknown one (#670, ADR-020
 *    §3), in an interaction, is the `upstream_link` step: the person chooses
 *    a new account, which creates a user, the credential and the provider's
 *    claims as attributes (`source` the provider type) in one transaction
 *    when the realm allows sign-up, or the existing account they sign in to
 *    next, which the identity joins once that sign-in finishes
 *    (`helpers/upstream-links.ts`). On the pages, which show no such step,
 *    it creates the account at once. The account counts as verified unless
 *    the provider's verified switch is off; the `email` attribute is verified
 *    only when the provider said so and the switch is on. An authorization
 *    request that asks to link (`qauth_link`) goes straight to the sign-in
 *    to the existing account, and refuses an identity another account holds.
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
  state: InteractionState & { readonly purpose: 'authorization' | 'account' },
  extra: Omit<RoundContext, 'realm' | 'client' | 'audit'>
): RoundContext {
  const realmId = requestRealm(request).id;
  const clientId = eventClientIdOf(state);
  return {
    realm: { id: realmId },
    client: { id: engineClientIdOf(state) },
    ...ladderEndUserIp(request),
    // An account page's round (#844): a fresh sign-in, and the factor it binds.
    ...(state.purpose === 'account' ? accountRoundOf(state.request) : {}),
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

/** A link refused (#670), recorded as `user.upstream_link_failed`, its page shown. */
export class UpstreamLinkRefusedError extends Error {
  override readonly name = 'UpstreamLinkRefusedError';
  constructor(
    readonly reason: UpstreamLinkRefusal,
    readonly userId?: string
  ) {
    super(`upstream link refused: ${reason}`);
  }
}

/**
 * Record a refused link (#670): the subject is the account the person signed
 * in to, or the one that holds the identity when nobody has signed in yet.
 */
export async function auditUpstreamLinkRefusal(
  request: FastifyRequest,
  provider: string,
  reason: UpstreamLinkRefusal,
  userId?: string
): Promise<void> {
  await emitUserEvent(
    request,
    'urn:qauth:event:user.upstream_link_failed:v1-rc.0',
    { provider, reason },
    { realmId: requestRealm(request).id, userId: userId ?? null, actor: 'user' }
  );
}

/** The page of a refused link: why, in the person's terms, and nothing sent to the client. */
export function sendUpstreamLinkRefusedPage(
  reply: FastifyReply,
  reason: UpstreamLinkRefusal,
  providerName: string
): FastifyReply {
  return sendUpstreamPage(
    reply,
    upstreamLinkRefusedPage({ cspNonce: reply.cspNonce.style, reason, providerName }),
    409
  );
}

/** The `upstream_link` step's name (`urn:qauth:ia:upstream_link:v1-rc.0`, #670). */
export const UPSTREAM_LINK_STEP = stepUrn('upstream_link');

/**
 * The `upstream_link` step (#670): the provider that proved an identity no
 * account holds, and whether a new account is offered beside the existing
 * one. Nothing of the identity, nor any account, is on it.
 */
export function upstreamLinkStep(entry: UpstreamProviderEntry, create: boolean): InteractionStep {
  return {
    name: UPSTREAM_LINK_STEP,
    params: { provider: { provider: entry.provider, name: entry.name }, create },
    alternatives: [],
  };
}

/**
 * What a round of the sign-in to the account to link changes (#670): it asks
 * for a fresh sign-in, so no password reset stands in for one (ADR-017
 * Decision 8); it offers no upstream provider, so the person proves the
 * account with its own factors; it registers nobody. The MFA policy and the
 * account's second factor apply as to every sign-in.
 */
export function linkSignInRound(
  engines: Pick<InteractionEngines, 'sendCode'>,
  request: FastifyRequest
): Pick<RoundContext, 'freshSignIn' | 'sendCode'> {
  return { freshSignIn: true, sendCode: engines.sendCode(request) };
}

/** The identity a `signing_in` link carries to the finish. */
export type LinkedUpstreamIdentity = Omit<Extract<UpstreamLink, { state: 'signing_in' }>, 'state'>;

/**
 * The first step of the sign-in to the account to link (#670), from the
 * engine's round 0, with the link the finish attaches. A round 0 that shows
 * no step is a sign-in this flow cannot run.
 */
export function linkSignInDecision(
  reply: FastifyReply,
  round: RoundResult,
  receivedAt: number,
  linked: LinkedUpstreamIdentity
): InteractionDecision {
  const decision = decisionOf(reply, round, receivedAt);
  if (decision.kind !== 'step') throw new UpstreamSignInRefusal('step_not_available');
  return { ...decision, upstreamLink: { state: 'signing_in', ...linked } };
}

/**
 * The interaction's next state for the engine's round over a provider's
 * proof. A redirect, an answer the engine refused and a transaction that
 * ended are refusals of the flow; the engine audited the last two.
 */
export function upstreamRoundDecision(
  reply: FastifyReply,
  round: RoundResult,
  receivedAt: number
): InteractionDecision {
  if (round.kind === 'redirect') throw new UpstreamSignInRefusal('step_not_available');
  if (round.kind === 'refused' && round.reason === 'invalid_answer') {
    throw new UpstreamSignInRefusal('invalid_answer', true);
  }
  if (round.kind === 'refused' && round.reason === 'transaction_ended') {
    throw new UpstreamSignInRefusal('transaction_ended', true);
  }
  return decisionOf(reply, round, receivedAt);
}

/** The user an account the flow found or created names, if any. */
function accountIdOf(account: ResolvedAccount | null): string | undefined {
  return account?.userId;
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
export type ResolvedAccount =
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

/** A provider's identity as the flow keys it: its subject, under the issuer that named it. */
export interface UpstreamSubject {
  readonly externalSub: string;
  readonly iss: string;
}

/**
 * The subject of a verified identity, with its issuer. Every identity names
 * the issuer that assigned its subject (the AuthMethod contract,
 * `rawClaims.iss`): one that does not could never be told apart from another
 * issuer's subject of the same value, so it is `undefined`, and refused.
 */
function subjectOf(identity: VerifiedIdentity): UpstreamSubject | undefined {
  const iss = identity.rawClaims['iss'];
  if (typeof iss !== 'string' || iss.length === 0 || iss.length > MAX_ISSUER_LENGTH) {
    return undefined;
  }
  return { externalSub: identity.externalSub, iss };
}

/** The provider's attributes as a new account stores them, and as a choice keeps them. */
function keptAttributesOf(attributes: readonly UserAttribute[]): KeptUpstreamAttribute[] {
  return attributes.map((attribute) => ({
    attrKey: attribute.attrKey,
    attrValue: attribute.attrValue,
    verified: attribute.verified,
    ...(attribute.expiresAt === undefined ? {} : { expiresAt: attribute.expiresAt.getTime() }),
  }));
}

/**
 * The account that holds the provider's identity (#639): looked up by
 * `(realm, provider type, external sub)` alone, never by an attribute such
 * as an email address (#670). A known credential stands only under the
 * issuer it was created with (OIDC Core §5.7: a `sub` is unique only within
 * its issuer). `null` when no account holds it. Nothing is written.
 * Exported for its unit test.
 */
export async function lookUpAccount(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realm: RealmRow,
  type: string,
  subject: UpstreamSubject
): Promise<ResolvedAccount | null> {
  const { repositories } = fastify;
  const credential = await repositories.userCredentials.findByRealmProviderSub(
    realm.id,
    type,
    subject.externalSub
  );
  if (credential === undefined) return null;
  const data = upstreamCredentialDataSchema.safeParse(credential.credentialData);
  if (!data.success) {
    request.log.error(
      { credentialId: credential.id },
      'an upstream credential whose data is not well formed'
    );
    return { kind: 'refused', reason: 'credential_invalid', userId: credential.userId };
  }
  if (data.data.iss !== subject.iss) {
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

/**
 * Why an unknown identity may not start a new account, or `null` when it
 * may: the realm allows sign-up, and an account the provider's verified
 * switch leaves unverified can be verified inline with an emailed code
 * before it signs in (the engine's rule 8, ADR-017 Decision 8), at the
 * address the provider gave. With no address, or on the pages, which show no
 * such step, it could never sign in.
 */
function newAccountRefusal(
  fastify: FastifyInstance,
  realm: RealmRow,
  provider: RealmUpstreamProviderOf,
  attributes: readonly Pick<KeptUpstreamAttribute, 'attrKey'>[],
  mode: UpstreamSignInMode
): 'sign_up_disabled' | 'verification_unavailable' | null {
  if (!accountPoliciesOf(fastify, realm).allowSignUp) return 'sign_up_disabled';
  if (
    !provider.marksVerified &&
    (mode === 'pages' || !attributes.some((attribute) => attribute.attrKey === 'email'))
  ) {
    return 'verification_unavailable';
  }
  return null;
}

/**
 * The account that holds the provider's identity, or a new one (#639): an
 * unknown identity creates a user, the credential and the provider's claims
 * as attributes (`source` the provider type), in one transaction, when the
 * realm allows sign-up, even when another account holds the same email:
 * nothing matches or merges. The account counts as verified unless the
 * provider's verified switch is off; an attribute is verified only when the
 * provider said so and the switch is on.
 */
export async function resolveUpstreamAccount(
  fastify: FastifyInstance,
  request: FastifyRequest,
  realm: RealmRow,
  provider: RealmUpstreamProviderOf,
  subject: UpstreamSubject,
  attributes: readonly KeptUpstreamAttribute[],
  mode: UpstreamSignInMode
): Promise<ResolvedAccount> {
  const { repositories } = fastify;
  const type = provider.method.type;
  // Twice at most: a callback that loses the race to create the same
  // identity reads the account the other one created.
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const found = await lookUpAccount(fastify, request, realm, type, subject);
    if (found !== null) return found;
    const refusal = newAccountRefusal(fastify, realm, provider, attributes, mode);
    if (refusal !== null) return { kind: 'refused', reason: refusal };
    try {
      const userId = await fastify.db.transaction(async (tx) => {
        const user = await repositories.users.create({ realmId: realm.id }, tx);
        await repositories.userCredentials.create(
          {
            userId: user.id,
            realmId: realm.id,
            providerType: type,
            externalSub: subject.externalSub,
            credentialData: {
              kind: UPSTREAM_CREDENTIAL_KIND,
              iss: subject.iss,
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
            expiresAt: attribute.expiresAt ?? null,
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
export async function providerAddress(
  fastify: FastifyInstance,
  userId: string,
  type: string
): Promise<string | undefined> {
  const rows = await fastify.repositories.userAttributes.findByUserIdAndSource(userId, type);
  return rows.find((row) => row.attrKey === 'email')?.attrValue;
}

/** The input of {@link decideUpstreamLinkChoice}. */
export interface UpstreamLinkChoice {
  readonly engine: SignInEngine;
  readonly catalog: UpstreamProviderCatalog;
  readonly state: InteractionState & { readonly purpose: 'authorization' | 'account' };
  readonly decision: 'create' | 'link';
  readonly receivedAt: number;
  /**
   * The context of a round of this interaction, as the Interaction API builds
   * it; `linking`, for the sign-in to the account to link
   * ({@link linkSignInRound}): no upstream provider, no reset, no
   * registration.
   */
  readonly context: (receivedAt: number, options: { readonly linking: boolean }) => RoundContext;
  /** The new account signed in: an upstream provider proved it. */
  readonly signedIn: () => void;
}

/**
 * Decide the answer to the `upstream_link` step (#670; ADR-020 §3): the host
 * decides it, as it decides a consent, and the engine runs the round the
 * choice leads to.
 *
 * - `link`: the sign-in to the existing account starts afresh at the
 *   engine's round 0, with no upstream provider and no reset
 *   ({@link linkSignInRound}); the identity waits in the record as a
 *   `signing_in` link until that sign-in finishes the interaction.
 * - `create`: only while the step offered it and the realm still allows
 *   sign-up; the new account is created as a first upstream sign-in creates
 *   one, and the engine takes the provider's proof for it.
 *
 * A refusal of the flow ends the answer as an expired interaction, recorded
 * as `user.sign_in_failed`.
 *
 * @throws InvalidAnswerError for `create` where the step offered none
 * @throws InteractionExpiredError for a refusal of the flow
 */
export async function decideUpstreamLinkChoice(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  input: UpstreamLinkChoice
): Promise<InteractionDecision> {
  const { state, receivedAt } = input;
  const link = state.upstreamLink;
  // The step is written only with its link: anything else is a record no
  // server writes.
  if (link?.state !== 'choosing') throw new InteractionExpiredError();
  const linked: LinkedUpstreamIdentity = {
    provider: link.provider,
    name: link.name,
    externalSub: link.externalSub,
    iss: link.iss,
  };
  try {
    if (input.decision === 'link') {
      return linkSignInDecision(
        reply,
        await input.engine.advance(null, null, input.context(receivedAt, { linking: true })),
        receivedAt,
        linked
      );
    }
    if (!link.create) throw new InvalidAnswerError('the step offered no new account');
    const realm = requestRealm(request);
    const provider = await input.catalog.find(realm.id, link.provider);
    if (provider?.method.type !== link.provider) {
      throw new UpstreamSignInRefusal('upstream_unavailable');
    }
    const account = await resolveUpstreamAccount(
      fastify,
      request,
      realm,
      provider,
      { externalSub: link.externalSub, iss: link.iss },
      link.attributes,
      'interaction'
    );
    if (account.kind === 'refused') {
      throw new UpstreamSignInRefusal(account.reason, false, account.userId);
    }
    const address = await providerAddress(fastify, account.userId, link.provider);
    const round = await input.engine.completeUpstream(
      state.signInTransaction,
      {
        provider: provider.entry,
        account: { userId: account.userId, enabled: account.enabled, verified: account.verified },
        ...(address === undefined ? {} : { address }),
      },
      input.context(receivedAt, { linking: false })
    );
    const decided = upstreamRoundDecision(reply, round, receivedAt);
    if (round.kind === 'complete') input.signedIn();
    return decided.kind === 'step' || decided.kind === 'authenticated'
      ? { ...decided, upstreamLink: null }
      : decided;
  } catch (error) {
    if (!(error instanceof UpstreamSignInRefusal)) throw error;
    if (!error.audited) await auditUpstreamRefusal(request, error.reason, error.userId);
    throw new InteractionExpiredError();
  }
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

    const subject = subjectOf(completion.identity);
    if (subject === undefined) return refuse('invalid_response');
    const type = method.type;
    const attributes = keptAttributesOf(completion.attributes);
    // Read before the interaction's turn is taken; nothing is written until
    // it is: a new account only once the turn is this callback's.
    const known = await lookUpAccount(fastify, request, realm, type, subject);
    if (known?.kind === 'refused') return refuse(known.reason, known.userId);
    let account: ResolvedAccount | null = known;

    const engines = parts.engines();
    const engine = engines.of(accountPoliciesOf(fastify, realm).requireVerifiedAccount);
    let result: InteractionAnswerResult;
    try {
      result = await answerInteraction(
        request,
        reply,
        { id: pending.interactionId, revision: pending.revision },
        async (state) => {
          if (state.purpose !== 'authorization' && state.purpose !== 'account') {
            throw new UpstreamSignInRefusal('transaction_mismatch');
          }
          const environment = await roundEnvironment(fastify, realm, engineClientIdOf(state));
          const link = state.upstreamLink;
          if (link !== undefined) {
            // A link the request asked for (`qauth_link`, #670): only the
            // provider it named, only before the provider proved anyone.
            if (
              link.state !== 'requested' ||
              link.provider !== type ||
              pending.mode !== 'interaction'
            ) {
              throw new UpstreamSignInRefusal('transaction_mismatch');
            }
            if (account !== null)
              throw new UpstreamLinkRefusedError('already_linked', account.userId);
            return linkSignInDecision(
              reply,
              await engine.advance(
                null,
                null,
                upstreamRoundContext(request, state, {
                  receivedAt,
                  environment,
                  ...linkSignInRound(engines, request),
                })
              ),
              receivedAt,
              { provider: type, name: provider.entry.name, ...subject }
            );
          }
          if (account === null && pending.mode === 'interaction') {
            // An identity no account holds (#670; ADR-020 §3): the person
            // chooses between a new account and the existing one they sign
            // in to next. Nothing is matched, by an email or anything else.
            const create =
              newAccountRefusal(fastify, realm, provider, attributes, 'interaction') === null &&
              keepsUpstreamAttributes(attributes);
            return {
              kind: 'step',
              step: upstreamLinkStep(provider.entry, create),
              personal: {},
              upstreamLink: {
                state: 'choosing',
                provider: type,
                name: provider.entry.name,
                ...subject,
                create,
                attributes: create ? attributes : [],
              },
            };
          }
          if (account === null) {
            account = await resolveUpstreamAccount(
              fastify,
              request,
              realm,
              provider,
              subject,
              attributes,
              pending.mode
            );
          }
          if (account.kind === 'refused') {
            throw new UpstreamSignInRefusal(account.reason, false, account.userId);
          }
          const address = await providerAddress(fastify, account.userId, type);
          const proof: UpstreamProof = {
            provider: provider.entry,
            account: {
              userId: account.userId,
              enabled: account.enabled,
              verified: account.verified,
            },
            ...(address === undefined ? {} : { address }),
          };
          const round: RoundResult = await engine.completeUpstream(
            state.signInTransaction,
            proof,
            upstreamRoundContext(request, state, {
              receivedAt,
              environment,
              // The pages show no further step: the sign-in completes here,
              // or fails closed (a passkey, a code to verify the address).
              ...(pending.mode === 'pages'
                ? { serves: ['upstream'] }
                : { sendCode: engines.sendCode(request) }),
            })
          );
          return upstreamRoundDecision(reply, round, receivedAt);
        }
      );
    } catch (error) {
      if (error instanceof UpstreamLinkRefusedError) {
        await auditUpstreamLinkRefusal(request, type, error.reason, error.userId);
        return sendUpstreamLinkRefusedPage(reply, error.reason, provider.entry.name);
      }
      if (error instanceof UpstreamSignInRefusal) {
        return refuse(error.reason, error.userId ?? accountIdOf(account), error.audited);
      }
      if (error instanceof InteractionExpiredError) return refuse('interaction_expired');
      if (error instanceof TooManyRequestsError) return refuse('throttled', accountIdOf(account));
      if (error instanceof TemporarilyUnavailableError) return refuse('unavailable');
      throw error;
    }
    switch (result.kind) {
      case 'stale':
        return refuse('interaction_expired');
      case 'step':
        // A further step (the passkey, a code, the choice of #670, the
        // sign-in to the account to link): the ceremony page shows it.
        return reply.redirect(ceremonyPageUrlOf(realm, pending.interactionId), 303);
      case 'finished': {
        if (result.purpose === 'account') {
          // A sign-in of the account page (#844) the provider proved: it is
          // recorded there, and the browser goes back to the page.
          const location = await finishAccountInteraction(fastify, request, result, {
            method: 'upstream',
            mailer: engines.mailer,
          });
          reply.header('Cache-Control', 'no-store');
          return reply.redirect(location, 303);
        }
        if (result.purpose !== 'authorization') return refuse('transaction_mismatch');
        const userId = result.transaction.userId ?? accountIdOf(account);
        if (userId === undefined) throw new Error('an upstream sign-in finished for nobody');
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
