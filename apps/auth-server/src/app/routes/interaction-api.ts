import {
  type AnswerEncoding,
  type EmailCodeSender,
  interactionPersonalView,
  interactionStepView,
  readInteractionAnswer,
  type RoundContext,
  type RoundResult,
  signInAuditEvent,
  type SignInEngine,
  StepAnswerError,
  WEBAUTHN_CREATE_STEP_URN,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { BadRequestError } from '@qauth-labs/shared-errors';
import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { accountPoliciesOf } from '../helpers/account-policies';
import { UnsupportedMediaTypeError } from '../helpers/api-request-errors';
import {
  cancelAuthorization,
  CONSENT_STEP,
  type ConsentAnswer,
  finishAuthorization,
  finishConsent,
} from '../helpers/authorization-interaction';
import {
  cancelLogout,
  finishLogout,
  LOGOUT_CONFIRM_STEP,
  type LogoutDecision,
} from '../helpers/end-session';
import {
  answerInteraction,
  cancelInteraction,
  type InteractionDecision,
  type InteractionState,
  type InteractionView,
  readInteractionPersonalData,
  readInteractionStep,
  refuseForbidden,
} from '../helpers/interaction';
import { createInteractionEngines, decisionOf } from '../helpers/interaction-engines';
import { ContentTooLargeError, InvalidAnswerError } from '../helpers/interaction-errors';
import { InteractionExpiredError } from '../helpers/interaction-expired';
import type { InteractionStep } from '../helpers/interaction-record';
import { eventClientIdOf, interactionIdHash, isInteractionId } from '../helpers/interaction-record';
import { ladderEndUserIp } from '../helpers/password-attempts';
import { createPeerAddressList, type PeerAddressList } from '../helpers/peer-address-list';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../helpers/realm-rate-limit';
import { buildRealmUrl, realmIssuer } from '../helpers/realm-url';
import { type RealmRow, requestRealm } from '../helpers/request-realm';
import { roundEnvironment } from '../helpers/round-limits';
import { linkUpstreamIdentity } from '../helpers/upstream-links';
import {
  type UpstreamProviderCatalog,
  upstreamProviderCatalog,
} from '../helpers/upstream-providers';
import {
  decideUpstreamLinkChoice,
  UPSTREAM_LINK_STEP,
  type UpstreamStarted,
  upstreamStarter,
} from '../helpers/upstream-sign-in';
import { emitUserEvent } from '../helpers/user-events';

/**
 * THE INTERACTION API (#616, ADR-019 Decision 6): the four operations of
 * `/interaction/v1-rc.0` (`libs/shared/interaction-contract`), which the
 * ceremony app's pages call and a plain HTML form posts to.
 *
 * | Operation                    | Needs                                        |
 * | ---------------------------- | -------------------------------------------- |
 * | `GET  …/{id}`                | the id: the step, its CSRF value, no personal data |
 * | `GET  …/{id}/personal`       | not another origin, the flow cookie          |
 * | `POST …/{id}/answer`         | the realm origin, the flow cookie, the CSRF value |
 * | `POST …/{id}/cancel`         | the realm origin, the flow cookie, the CSRF value |
 *
 * An answer is checked in this order, and nothing of the sign-in engine runs
 * before all of it passes: the body's media type, its 64 KiB cap and its form
 * (no repeated field), the same origin (`Sec-Fetch-Site`, else `Origin`), the
 * body's bound for the step it names (16 KiB, 64 KiB for `webauthn_create`),
 * the flow cookie, the step's CSRF value (`helpers/interaction.ts`), then the
 * answer against the step grammar. A request from another origin and a wrong CSRF value get one
 * generic `403`, audited as `request.csrf_rejected`. Then the engine runs one
 * round (`@qauth-labs/fastify-plugin-sign-in-engine`) and its result becomes
 * the next state. An answer to the consent step runs no round (#629): it
 * finishes the interaction, and `finishConsent` decides it for the scope set
 * the step showed. An answer to the `logout_confirm` step of an RP-initiated
 * logout (#675) runs no round either: it finishes the interaction, and
 * `finishLogout` ends the session, or not, as the person decided. An
 * answer to the `upstream_link` step (#670) is decided by the host too
 * (`decideUpstreamLinkChoice`): a new account, or the sign-in to the existing
 * one, whose rounds offer no upstream provider and no reset. When that
 * sign-in finishes the interaction, the identity the provider proved joins
 * the account it signed in to (`linkUpstreamIdentity`) before the
 * authorization request goes on; a refused link goes to its page, and
 * nothing goes to the client.
 *
 * A JSON answer gets the next step view, or the final redirect, as JSON. A
 * form post gets `303 See Other` to the ceremony page of the interaction,
 * where the next step is read, or to the final redirect: the page needs no
 * JavaScript. Both targets are built from the interaction record and the
 * realm row, never from the request (`helpers/interaction-redirect.ts`), once
 * the authorization request it holds is checked again
 * (`helpers/authorization-interaction.ts`, #628).
 *
 * Every response is `Cache-Control: no-store`, sends no CORS header (the
 * routes are on the `browser` surface, which the CORS plugin never answers)
 * and every error is a bare problem document, which names nothing about the
 * request (`isBareProblem`).
 *
 * The paths are written out, not built from `INTERACTION_API_PREFIX`, so the
 * docs site's endpoint-coverage guard sees them; `interaction-api.test.ts`
 * holds the two equal.
 */

/** An answer's body bound (ADR-017 Decision 7). */
export const ANSWER_BODY_LIMIT = 16 * 1024;

/** The body bound of an answer to `webauthn_create` (ADR-017 Decision 7), and the parser's. */
export const WEBAUTHN_CREATE_BODY_LIMIT = 64 * 1024;

/** At most this many members in a form post: no step's answer has more than a few. */
export const FORM_FIELD_LIMIT = 32;

/** The longest member name a form post may carry: longer than any the grammar declares. */
export const FORM_FIELD_NAME_LIMIT = 64;

/** The realm's brand while the admin console sets none (#593): the contract's defaults. */
const DEFAULT_BRAND = Object.freeze({ font: 'system', darkMode: 'enabled' });

const FORM_MEDIA_TYPE = 'application/x-www-form-urlencoded';
const JSON_MEDIA_TYPE = 'application/json';

/** What the module's own parsers learned of a body: its encoding and its size in bytes. */
interface ParsedBody {
  readonly encoding: AnswerEncoding;
  readonly bytes: number;
}

/** Each parsed request's {@link ParsedBody}, kept beside the request. */
const parsedBodies = new WeakMap<FastifyRequest, ParsedBody>();

/**
 * A form post's members, as a null-prototype object of strings. A member
 * repeated, too many members or a name too long is refused: a form post
 * carries each member once (ADR-017 Decision 7).
 *
 * @throws InvalidAnswerError for a repeated member, too many, or a name too long
 */
export function parseAnswerForm(text: string): Record<string, string> {
  const fields: Record<string, string> = Object.create(null);
  let count = 0;
  for (const [name, value] of new URLSearchParams(text)) {
    count += 1;
    if (count > FORM_FIELD_LIMIT) throw new InvalidAnswerError('too many form fields');
    if (name.length > FORM_FIELD_NAME_LIMIT) throw new InvalidAnswerError('a field name too long');
    if (Object.hasOwn(fields, name)) throw new InvalidAnswerError('a repeated form field');
    fields[name] = value;
  }
  return fields;
}

/**
 * The bound of a body: 64 KiB for an answer to `webauthn_create`, 16 KiB for
 * anything else (ADR-017 Decision 7). The parser already refused anything
 * over 64 KiB.
 *
 * @throws ContentTooLargeError over the bound
 */
export function checkAnswerBodySize(body: unknown, bytes: number): void {
  const type =
    typeof body === 'object' && body !== null
      ? (body as Record<string, unknown>)['type']
      : undefined;
  const limit = type === WEBAUTHN_CREATE_STEP_URN ? WEBAUTHN_CREATE_BODY_LIMIT : ANSWER_BODY_LIMIT;
  if (bytes > limit) throw new ContentTooLargeError();
}

/** How strictly a request must show that it comes from the realm origin. */
type OriginRule =
  /**
   * An answer or a cancel: `Sec-Fetch-Site: same-origin`; from a browser that
   * sends no `Sec-Fetch-Site`, an `Origin` of the realm. Neither: refused.
   */
  | 'required'
  /**
   * The personal-data read: refused when a header names another origin. A
   * request with neither header passes (the contract's rule for the read).
   */
  | 'unless_absent';

/**
 * Whether the request comes from the realm origin (ADR-019 Decision 6), by
 * the headers a browser sets and a page cannot.
 *
 * An answer or a cancel (`required`) follows the contract's rule: when the
 * browser sent `Sec-Fetch-Site`, it decides, and must be `same-origin`; only
 * when it did not, `Origin` must be the realm origin (`null` and any other
 * origin refused), and a request with neither is refused. `Sec-Fetch-Site`
 * decides alone because a form post from a page whose referrer policy is
 * `no-referrer`, as the ceremony pages' is, sends `Origin: null` (Fetch,
 * "append a request Origin header") with `Sec-Fetch-Site: same-origin`; and
 * an opaque-origin document, such as a sandboxed frame, sends
 * `Sec-Fetch-Site: cross-site`.
 *
 * The personal-data read (`unless_absent`) refuses a request either header
 * names another origin by, and lets one with neither through.
 */
export function comesFromRealmOrigin(
  headers: FastifyRequest['headers'],
  realm: Pick<RealmRow, 'issuer'>,
  rule: OriginRule
): boolean {
  const site = headers['sec-fetch-site'];
  const origin = headers.origin;
  const realmOrigin = new URL(realmIssuer(realm)).origin;
  if (rule === 'required') {
    if (site !== undefined) return site === 'same-origin';
    return origin === realmOrigin;
  }
  if (site !== undefined && site !== 'same-origin') return false;
  return origin === undefined || origin === realmOrigin;
}

/** Refuse the request with the generic `403` unless it comes from the realm origin. */
async function requireRealmOrigin(request: FastifyRequest, rule: OriginRule): Promise<void> {
  if (!comesFromRealmOrigin(request.headers, requestRealm(request), rule)) {
    await refuseForbidden(request, 'origin');
  }
}

/**
 * The step read of a view: the contract's `Interaction`, with the client's
 * display data for a step that names its client (the consent step, #629).
 *
 * @throws InteractionExpiredError for a consent step whose record holds no
 *   client, which no server of #629 writes: the contract requires `client`
 *   there, and the person must see who the client is (ADR-019 Decision 6)
 */
function stepRead(view: InteractionView) {
  if (view.step.name === CONSENT_STEP && view.client === undefined) {
    throw new InteractionExpiredError();
  }
  return {
    ...interactionStepView(view.step),
    csrf: view.csrf,
    ...(view.client === undefined ? {} : { client: view.client }),
    // The sign-in links an upstream account (#670): the screens say which.
    ...(view.upstreamLink === undefined ? {} : { upstreamLink: view.upstreamLink }),
    brand: DEFAULT_BRAND,
    expiresAt: new Date(view.deadline).toISOString(),
  };
}

/**
 * The body as the module's parsers left it, with how it came.
 *
 * @throws {UnsupportedMediaTypeError} when no parser ran: Fastify runs the
 *   handler without one only for a request with no `Content-Type` and no body
 */
function answerBodyOf(request: FastifyRequest): {
  readonly fields: unknown;
  readonly parsed: ParsedBody;
} {
  const parsed = parsedBodies.get(request);
  if (parsed === undefined)
    throw new UnsupportedMediaTypeError('An answer is JSON or a form post.');
  return { fields: request.body ?? {}, parsed };
}

/**
 * The answer members that carry a credential: a password, a one-time code of
 * any step, a recovery code, a passkey response (ADR-017 Decision 7's
 * credential rounds), and a device's user code, which can be guessed as well.
 */
const CREDENTIAL_MEMBERS: readonly string[] = [
  'password',
  'otp',
  'recovery_code',
  'webauthn_response',
  'user_code',
];

/**
 * Whether a parsed answer body carries a credential: a member of
 * {@link CREDENTIAL_MEMBERS} at its top level, whatever step it names.
 */
export function carriesCredential(body: unknown): boolean {
  if (typeof body !== 'object' || body === null) return false;
  return CREDENTIAL_MEMBERS.some((name) => Object.hasOwn(body, name));
}

/** The suffix of an answer's rate-limit key when it carries a credential. */
const CREDENTIAL_BUCKET = ':credential';

/** A member of a body read as an object; `undefined` for any other body. */
function memberOf(body: unknown, name: string): unknown {
  return typeof body === 'object' && body !== null && !Array.isArray(body)
    ? (body as Record<string, unknown>)[name]
    : undefined;
}

/** `interactionId` of the route's path. */
function interactionIdOf(request: FastifyRequest): string {
  return (request.params as { interactionId: string }).interactionId;
}

/** The window of `CEREMONY_APP_PEER_RATE_LIMIT`, which counts per minute. */
const CEREMONY_APP_PEER_WINDOW_MS = 60_000;

/** The ceremony app server's addresses (`CEREMONY_APP_PEERS`, #982), read once. */
let ceremonyAppPeerList: PeerAddressList | undefined;

/** {@link ceremonyAppPeerList}, built from the env on first use. */
function ceremonyAppPeers(): PeerAddressList {
  ceremonyAppPeerList ??= createPeerAddressList(env.CEREMONY_APP_PEERS);
  return ceremonyAppPeerList;
}

/**
 * Whether a step read counts per interaction (#982): its id is well formed
 * and its client address, `request.ip`, is one of the ceremony app server's
 * addresses the operator listed (`CEREMONY_APP_PEERS`). `request.ip` is the
 * TCP peer, or behind a proxy the address `TRUST_PROXY` resolves, so the
 * ceremony app server's own address and never the proxy's; no other
 * forwarded header is read for it.
 */
export function readsPerInteraction(
  request: FastifyRequest,
  peers: PeerAddressList = ceremonyAppPeers()
): boolean {
  return isInteractionId(interactionIdOf(request)) && peers.has(request.ip);
}

/**
 * The step read's rate-limit key (#982). The ceremony app's server reads the
 * step for every browser (ADR-019 Decision 6), so its address would put every
 * person signing in behind one bucket: a read from one of its listed
 * addresses ({@link readsPerInteraction}) counts per realm and interaction,
 * by the id's hash, as the record is kept, under
 * `CEREMONY_APP_PEER_RATE_LIMIT`. Every other read, and a junk id, which
 * never reaches Redis, counts per realm and address through
 * {@link realmRateLimitKey}, at the authorization endpoint's budget: one
 * address cannot spend a fresh bucket on each random id.
 */
export function interactionReadRateLimitKey(
  request: FastifyRequest,
  peers: PeerAddressList = ceremonyAppPeers()
): string {
  if (!readsPerInteraction(request, peers)) return realmRateLimitKey(request);
  return `${request.realm?.id ?? ''}:interaction:${interactionIdHash(interactionIdOf(request))}`;
}

/**
 * An answer's rate-limit key: {@link realmRateLimitKey} with the bucket the
 * parsed body falls in, {@link CREDENTIAL_BUCKET} when it carries a
 * credential and `:step` otherwise.
 */
export function interactionAnswerRateLimitKey(request: FastifyRequest): string {
  return `${realmRateLimitKey(request)}${carriesCredential(request.body) ? CREDENTIAL_BUCKET : ':step'}`;
}

/**
 * Answer a processed request: JSON gets the next step view or the final
 * redirect; a form post gets `303` to the ceremony page or to the final
 * redirect.
 */
function respond(
  request: FastifyRequest,
  reply: FastifyReply,
  encoding: AnswerEncoding,
  outcome: { readonly view: InteractionView } | { readonly location: string }
) {
  if ('location' in outcome) {
    if (encoding === 'form') return reply.redirect(outcome.location, 303);
    return reply.send({ result: 'redirect', location: outcome.location });
  }
  if (encoding === 'form') return reply.redirect(ceremonyPageUrl(request), 303);
  return reply.send({ result: 'step', interaction: stepRead(outcome.view) });
}

/** The absolute URL of the interaction's ceremony page, on the realm's issuer. */
function ceremonyPageUrl(request: FastifyRequest): string {
  return buildRealmUrl(requestRealm(request), ceremonyPagePath(interactionIdOf(request)));
}

/**
 * An answer another answer to the same step beat: the turn was taken. A form
 * post goes back to the ceremony page, which reads the step as it now is; a
 * JSON answer gets that step at once.
 */
async function respondStale(
  request: FastifyRequest,
  reply: FastifyReply,
  encoding: AnswerEncoding
) {
  if (encoding === 'form') return reply.redirect(ceremonyPageUrl(request), 303);
  const view = await readInteractionStep(request, interactionIdOf(request));
  return respond(request, reply, encoding, { view });
}

/** A consent answer that finished its interaction: the step it answered, and what it said. */
interface AnsweredConsent {
  readonly step: InteractionStep;
  readonly answer: ConsentAnswer;
}

/**
 * Read an answer against the step it answers, by the step grammar.
 *
 * @throws InvalidAnswerError for an answer the grammar refuses
 */
function readAnswer(
  step: InteractionStep,
  answer: { readonly fields: unknown; readonly encoding: AnswerEncoding }
): ReturnType<typeof readInteractionAnswer> {
  try {
    return readInteractionAnswer(step, answer.fields, answer.encoding);
  } catch (error) {
    if (error instanceof StepAnswerError) throw new InvalidAnswerError(error.message);
    throw error;
  }
}

/**
 * Decide an answer to the consent step (#629): read it by the step grammar,
 * whose answer holds the decision and "remember" and nothing else, so no
 * answer can name a scope. The interaction then finishes, with nothing issued
 * yet: `finishConsent` decides the answer once it has ended, for the step the
 * interaction held, which `answered` keeps.
 */
function decideConsent(
  state: InteractionState,
  answer: { readonly fields: unknown; readonly encoding: AnswerEncoding },
  answered: (consent: AnsweredConsent) => void
): InteractionDecision {
  // A consent record from before #629 holds no client: the person was never
  // shown who it is, so nothing is decided for it (`stepRead`).
  if (state.client === undefined) throw new InteractionExpiredError();
  const read = readAnswer(state.step, answer);
  const { decision, remember } = read.answer as { decision: 'allow' | 'deny'; remember: boolean };
  answered({ step: state.step, answer: { decision, remember } });
  return { kind: 'finished' };
}

/**
 * Decide an answer to a logout's confirm step (#675): read it by the step
 * grammar, whose answer holds the decision and nothing else. The interaction
 * then finishes, with nothing ended yet: `finishLogout` decides once it has
 * ended, as a consent is decided.
 */
function decideLogout(
  state: Extract<InteractionState, { purpose: 'logout' }>,
  answer: { readonly fields: unknown; readonly encoding: AnswerEncoding },
  answered: (decision: LogoutDecision) => void
): InteractionDecision {
  // A logout's only step: anything else is a record no server writes.
  if (state.step.name !== LOGOUT_CONFIRM_STEP) throw new InteractionExpiredError();
  const read = readAnswer(state.step, answer);
  answered((read.answer as { decision: LogoutDecision }).decision);
  return { kind: 'finished' };
}

/**
 * Decide an answer: read it against the step it answers, run one round of
 * the engine, and turn its result into the interaction's next state. Runs
 * once the turn is taken: a refusal thrown here gives the turn back, so the
 * step and its CSRF value stay as they were. An answer to the consent step
 * runs no engine round ({@link decideConsent}), nor does one to a logout's
 * confirm step ({@link decideLogout}).
 */
/** How a completed sign-in proved the person, for `user.signed_in`'s method. */
type SignedInMethod = 'password' | 'upstream' | 'passkey';

/**
 * The method of a completed sign-in: an upstream provider when one proved the
 * account in an earlier round (#639); a passkey when the `amr` holds `pop`,
 * which only a passkey assertion adds (#651), alone or after the password
 * (the downgrade rule); else the password.
 */
export function signedInMethodOf(
  verified: readonly { readonly step: string }[],
  amr: readonly string[]
): SignedInMethod {
  if (verified.some((step) => step.step === 'upstream')) return 'upstream';
  return amr.includes('pop') ? 'passkey' : 'password';
}

async function decideAnswer(
  request: FastifyRequest,
  reply: FastifyReply,
  engine: SignInEngine,
  sendCode: EmailCodeSender,
  answer: {
    readonly fields: unknown;
    readonly encoding: AnswerEncoding;
    readonly receivedAt: number;
  },
  state: InteractionState,
  answered: {
    readonly consent: (consent: AnsweredConsent) => void;
    readonly logout: (decision: LogoutDecision) => void;
    /** An upstream provider the answer picked, and where the browser goes (#639). */
    readonly upstream: (started: UpstreamStarted) => void;
    /**
     * The sign-in completed: whether an upstream provider proved the account
     * (#639), for `user.signed_in`'s method.
     */
    readonly signedIn: (method: SignedInMethod) => void;
  },
  catalog: UpstreamProviderCatalog
): Promise<InteractionDecision> {
  if (state.purpose === 'logout') return decideLogout(state, answer, answered.logout);
  if (state.step.name === CONSENT_STEP) return decideConsent(state, answer, answered.consent);
  const read = readAnswer(state.step, answer);
  // The sign-in to the account an upstream identity joins (#670): the
  // person proves the account with its own factors, afresh.
  const signingInToLink = state.upstreamLink?.state === 'signing_in';
  const realmId = requestRealm(request).id;
  // The engine counts by the client id as it is; an event carries it only
  // when the envelope's bound allows (a CIMD URL can be longer).
  const eventClientId = eventClientIdOf(state);
  // The round limits' environment (#636; ADR-008 §5): development relaxes them.
  const environment = await roundEnvironment(
    request.server,
    requestRealm(request),
    state.request.client_id
  );
  const context = (
    receivedAt: number,
    { linking }: { readonly linking: boolean } = { linking: signingInToLink }
  ): RoundContext => ({
    realm: { id: realmId },
    client: { id: state.request.client_id },
    // `prompt=create` (#640): the engine's rounds are a registration's; a
    // sign-in to link an upstream account (#670) registers nobody.
    ...(state.request.prompt === 'create' && !linking ? { flow: 'register' as const } : {}),
    // `prompt=login` and `max_age` ask for a fresh sign-in, which a password
    // reset never is (#642; ADR-017 Decision 8): no reset is offered. A
    // sign-in to link an upstream account (#670) is always a fresh one.
    ...(state.request.prompt === 'login' || state.request.max_age !== undefined || linking
      ? { freshSignIn: true }
      : {}),
    receivedAt,
    ...ladderEndUserIp(request),
    environment,
    sendCode,
    // A pick of an upstream provider (#639) starts it, bound to this
    // interaction once the round's state is written; the way back from the
    // provider is this ceremony page. A sign-in to link an upstream account
    // (#670) offers none: the account's own factors prove it.
    ...(linking
      ? {}
      : {
          startUpstream: upstreamStarter(
            request.server,
            request,
            catalog,
            {
              interactionId: interactionIdOf(request),
              revision: state.revision + 1,
              mode: 'interaction',
              wayBack: ceremonyPageUrl(request),
            },
            answered.upstream
          ),
        }),
    audit: async (record) => {
      const event = signInAuditEvent(record);
      await emitUserEvent(request, event.type, event.data, {
        realmId,
        clientId: eventClientId,
        userId: event.userId,
        actor: 'user',
      });
    },
  });
  if (state.step.name === UPSTREAM_LINK_STEP) {
    // The choice of #670: a new account, or the existing one.
    return decideUpstreamLinkChoice(request.server, request, reply, {
      engine,
      catalog,
      state,
      decision: (read.answer as { decision: 'create' | 'link' }).decision,
      receivedAt: answer.receivedAt,
      context,
      signedIn: () => answered.signedIn('upstream'),
    });
  }
  let result: RoundResult = await engine.advance(
    state.signInTransaction,
    {
      step: memberOf(answer.fields, 'type') as string,
      fields: answer.fields,
      encoding: answer.encoding,
    },
    context(answer.receivedAt)
  );
  if (result.kind === 'refused' && result.reason === 'transaction_ended') {
    // The engine's transaction outlived its age, or could not be read: the
    // sign-in starts again at its first step, within the same interaction.
    result = await engine.advance(null, null, context(Date.now()));
  } else if (result.kind === 'redirect' && state.signInTransaction?.flow === 'reset') {
    // A password reset needs a step these pages cannot ask for yet: the
    // account holds an authenticator (a passkey, TOTP) no registered step
    // proves (#642; ADR-017 Decision 8). Email never stands in for it, so the
    // reset ends as an expired interaction does, and nothing was changed.
    throw new InteractionExpiredError();
  } else if (
    result.kind === 'complete' &&
    result.signIn.registered !== true &&
    result.signIn.recovered !== true
  ) {
    // A sign-in an upstream provider proved, that a later step (a code)
    // completed here: the provider is how the person signed in. A
    // registration (#640) and a password reset (#642) sign nobody in.
    answered.signedIn(
      signedInMethodOf(state.signInTransaction?.verified ?? [], result.signIn.amr ?? [])
    );
  }
  return decisionOf(reply, result, answer.receivedAt);
}

export default async function (fastify: FastifyInstance) {
  const engines = createInteractionEngines(fastify);
  const catalog = upstreamProviderCatalog(fastify);

  // The module's own body parsers: JSON and a plain form post, nothing else
  // (another media type is 415). Each keeps the body's size for the bound of
  // its step, and the form parser refuses a repeated member. Registered in
  // this module only.
  fastify.removeAllContentTypeParsers();
  const parseJson = fastify.getDefaultJsonParser('error', 'error');
  fastify.addContentTypeParser(JSON_MEDIA_TYPE, { parseAs: 'buffer' }, (request, body, done) => {
    const buffer = body as Buffer;
    parsedBodies.set(request, { encoding: 'json', bytes: buffer.length });
    parseJson(request, buffer.toString('utf8'), done);
  });
  fastify.addContentTypeParser(FORM_MEDIA_TYPE, { parseAs: 'buffer' }, (request, body, done) => {
    const buffer = body as Buffer;
    parsedBodies.set(request, { encoding: 'form', bytes: buffer.length });
    try {
      done(null, parseAnswerForm(buffer.toString('utf8')));
    } catch (error) {
      done(error as Error, undefined);
    }
  });
  fastify.addContentTypeParser('*', (_request, _payload, done) => {
    done(new UnsupportedMediaTypeError('An answer is JSON or a form post.'), undefined);
  });

  // Nothing of an interaction is kept by a cache: a step view carries a CSRF
  // value, the personal read personal data, and a redirect the next page.
  fastify.addHook('onSend', async (_request, reply, payload) => {
    reply.header('Cache-Control', 'no-store');
    return payload;
  });

  // The authorization endpoint's budget, with its environment-aware cap
  // (ADR-008 §5): a page reads once per step, and answers a step that
  // carries no credential once.
  const authorizeMax = (request: FastifyRequest) =>
    resolveRealmRateLimitMax(request.realm, {
      lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
      strictMax: env.AUTHORIZE_RATE_LIMIT,
    });
  // A step read in two budgets (#982): one from a listed ceremony app peer
  // counts per interaction under CEREMONY_APP_PEER_RATE_LIMIT, per minute;
  // any other counts per address at the authorization endpoint's budget. See
  // interactionReadRateLimitKey.
  const stepReadRateLimit = {
    keyGenerator: interactionReadRateLimitKey,
    max: (request: FastifyRequest) =>
      readsPerInteraction(request)
        ? (env.CEREMONY_APP_PEER_RATE_LIMIT ?? authorizeMax(request))
        : authorizeMax(request),
    timeWindow: (request: FastifyRequest) =>
      readsPerInteraction(request) ? CEREMONY_APP_PEER_WINDOW_MS : env.AUTHORIZE_RATE_WINDOW * 1000,
  };
  const personalReadRateLimit = {
    max: authorizeMax,
    timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
    keyGenerator: realmRateLimitKey,
  };
  // An answer per address, in two buckets read once the body is parsed: one
  // that carries a credential spends the sign-in form's budget, as one
  // `POST /ui/login` does, and any other answer, such as the identifier
  // before a password, the authorization endpoint's.
  const answerRateLimit = {
    hook: 'preHandler' as const,
    keyGenerator: interactionAnswerRateLimitKey,
    max: (request: FastifyRequest, key: string) =>
      key.endsWith(CREDENTIAL_BUCKET) ? env.LOGIN_RATE_LIMIT : authorizeMax(request),
    timeWindow: (_request: FastifyRequest, key: string) =>
      (key.endsWith(CREDENTIAL_BUCKET) ? env.LOGIN_RATE_WINDOW : env.AUTHORIZE_RATE_WINDOW) * 1000,
  };
  const contract =
    'The Interaction API v1-rc.0 (ADR-019 Decision 6); its contract, with every step’s schema, is the document at /interaction/v1-rc.0/openapi.json.';

  fastify.get(
    '/interaction/v1-rc.0/:interactionId',
    {
      schema: {
        description: `Read the current step: the step, the alternatives and their params, a CSRF value for one answer and the realm's brand. The interaction id alone is enough; no personal data. ${contract}`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [410, 429],
      },
      config: { surface: 'browser', rateLimit: stepReadRateLimit },
    },
    async (request, reply) => {
      const view = await readInteractionStep(request, interactionIdOf(request));
      return reply.send(stepRead(view));
    }
  );

  fastify.get(
    '/interaction/v1-rc.0/:interactionId/personal',
    {
      schema: {
        description: `Read the personal data of the current step. Needs the flow cookie; refused from another origin. ${contract}`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [403, 410, 429],
      },
      config: { surface: 'browser', rateLimit: personalReadRateLimit },
    },
    async (request, reply) => {
      await requireRealmOrigin(request, 'unless_absent');
      const personal = await readInteractionPersonalData(request, interactionIdOf(request));
      return reply.send(interactionPersonalView(personal.current, personal.data));
    }
  );

  fastify.post(
    '/interaction/v1-rc.0/:interactionId/answer',
    {
      bodyLimit: WEBAUTHN_CREATE_BODY_LIMIT,
      schema: {
        description: `Answer the current step with the CSRF value of the step read, as JSON or as a plain HTML form post. Needs the realm origin and the flow cookie. A form post gets 303 to the ceremony page or to the final redirect. ${contract}`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 403, 410, 413, 415, 429, 503],
      },
      config: { surface: 'browser', rateLimit: answerRateLimit },
    },
    async (request, reply) => {
      const receivedAt = Date.now();
      await requireRealmOrigin(request, 'required');
      const { fields, parsed } = answerBodyOf(request);
      checkAnswerBodySize(fields, parsed.bytes);
      const realm = requestRealm(request);
      const engine = engines.of(accountPoliciesOf(fastify, realm).requireVerifiedAccount);
      let consent: AnsweredConsent | undefined;
      let logout: LogoutDecision | undefined;
      let upstream: UpstreamStarted | undefined;
      let signedInMethod: SignedInMethod = 'password';
      const result = await answerInteraction(
        request,
        reply,
        { id: interactionIdOf(request), csrf: memberOf(fields, 'csrf') },
        (state) =>
          engines.forRequest(request, () =>
            decideAnswer(
              request,
              reply,
              engine,
              engines.sendCode(request),
              { fields, encoding: parsed.encoding, receivedAt },
              state,
              {
                consent: (answered) => {
                  consent = answered;
                },
                logout: (decision) => {
                  logout = decision;
                },
                upstream: (started) => {
                  upstream = started;
                },
                signedIn: (method) => {
                  signedInMethod = method;
                },
              },
              catalog
            )
          )
      );
      switch (result.kind) {
        case 'stale':
          return respondStale(request, reply, parsed.encoding);
        case 'step':
          // An upstream provider was picked (#639): the browser goes to it,
          // and its callback comes back to this interaction.
          if (upstream !== undefined) {
            return respond(request, reply, parsed.encoding, { location: upstream.redirectTo });
          }
          return respond(request, reply, parsed.encoding, { view: result.view });
        case 'finished': {
          if (result.purpose === 'logout') {
            // The confirm step finished the interaction (#675): the session
            // ends now, or stays, as the person decided.
            if (logout === undefined) throw new Error('a logout finished without a decision');
            return respond(request, reply, parsed.encoding, {
              location: await finishLogout(fastify, request, reply, result, logout),
            });
          }
          if (consent !== undefined) {
            // The consent answer finished the interaction (#629): nobody
            // signed in. It is decided now, with the step the interaction
            // held: the code, an error for the client, or the request's next
            // interaction.
            return respond(request, reply, parsed.encoding, {
              location: await finishConsent(fastify, request, reply, { ...result, ...consent }),
            });
          }
          const { userId, registered } = result.transaction;
          // A registration (#640) signed nobody in: the account's own event,
          // `user.registered`, committed with it. Nor did a password reset
          // (#642), finished the same way: `user.password_reset` committed
          // with the new password.
          if (userId !== undefined && registered !== true) {
            await fastify.repositories.users.updateLastLogin(realm.id, userId);
            await emitUserEvent(
              request,
              'urn:qauth:event:user.signed_in:v1-rc.0',
              { method: signedInMethod },
              { realmId: realm.id, userId, clientId: eventClientIdOf(result), actor: 'user' }
            );
          }
          const link = result.upstreamLink;
          if (link !== undefined) {
            // The interaction holds an upstream identity (#670): only the
            // sign-in to an existing account, just finished in this browser
            // and this interaction, attaches it, to the account it proved.
            if (link.state !== 'signing_in' || userId === undefined || registered === true) {
              throw new Error('an interaction finished with a link it never signed in for');
            }
            const linked = await linkUpstreamIdentity(fastify, request, {
              realm,
              userId,
              identity: { provider: link.provider, externalSub: link.externalSub, iss: link.iss },
              providerName: link.name,
              clientId: eventClientIdOf(result),
              mailer: engines.mailer,
            });
            if (linked.kind === 'refused') {
              const search = new URLSearchParams({
                provider: link.provider,
                reason: linked.reason,
              });
              return respond(request, reply, parsed.encoding, {
                location: buildRealmUrl(realm, `/ui/upstream-link-refused?${search.toString()}`),
              });
            }
          }
          // The authorization request goes on (#628): the code, minted only
          // now that the interaction has ended, or the request's next
          // interaction (a consent after the sign-in).
          return respond(request, reply, parsed.encoding, {
            location: await finishAuthorization(fastify, request, reply, result),
          });
        }
      }
    }
  );

  fastify.post(
    '/interaction/v1-rc.0/:interactionId/cancel',
    {
      bodyLimit: WEBAUTHN_CREATE_BODY_LIMIT,
      schema: {
        description: `Cancel the interaction with the CSRF value of the step read: the client gets access_denied. Needs the realm origin and the flow cookie. ${contract}`,
        tags: ['Interaction'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 403, 410, 413, 415, 429],
      },
      config: { surface: 'browser', rateLimit: answerRateLimit },
    },
    async (request, reply) => {
      await requireRealmOrigin(request, 'required');
      const { fields, parsed } = answerBodyOf(request);
      checkAnswerBodySize(fields, parsed.bytes);
      if (
        typeof fields !== 'object' ||
        fields === null ||
        Array.isArray(fields) ||
        Object.keys(fields).some((name) => name !== 'csrf')
      ) {
        throw new BadRequestError('A cancel carries its CSRF value and nothing else.');
      }
      const result = await cancelInteraction(request, reply, interactionIdOf(request), {
        csrf: memberOf(fields, 'csrf'),
      });
      // Another answer holds the turn: the page goes back to the step as it
      // now is, where the person can cancel again. A JSON cancel gets that
      // page as its redirect, the one result the contract gives a cancel.
      if (result.kind === 'stale') {
        return respond(request, reply, parsed.encoding, { location: ceremonyPageUrl(request) });
      }
      return respond(request, reply, parsed.encoding, {
        location:
          result.purpose === 'logout'
            ? await cancelLogout(fastify, request, result)
            : await cancelAuthorization(fastify, request, result.request),
      });
    }
  );
}
