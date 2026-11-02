import {
  type AnswerEncoding,
  createArgon2PasswordVerifier,
  createCheckedSignInEngine,
  createRepositoryAccountDirectory,
  interactionPersonalView,
  interactionStepView,
  NO_SECOND_FACTOR_POLICY,
  readInteractionAnswer,
  type RoundContext,
  type RoundResult,
  signInAuditEvent,
  type SignInEngine,
  StepAnswerError,
  storedStepOf,
  WEBAUTHN_CREATE_STEP_URN,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import {
  BadRequestError,
  TemporarilyUnavailableError,
  TooManyRequestsError,
} from '@qauth-labs/shared-errors';
import { ceremonyPagePath } from '@qauth-labs/shared-interaction-contract';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { accountPoliciesOf } from '../helpers/account-policies';
import { UnsupportedMediaTypeError } from '../helpers/api-request-errors';
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
import { ContentTooLargeError, InvalidAnswerError } from '../helpers/interaction-errors';
import {
  interactionCancelRedirect,
  interactionFinishRedirect,
} from '../helpers/interaction-redirect';
import { createServerLadderParts, ladderEndUserIp } from '../helpers/password-attempts';
import { realmRateLimitKey, resolveRealmRateLimitMax } from '../helpers/realm-rate-limit';
import { buildRealmUrl, realmIssuer } from '../helpers/realm-url';
import { type RealmRow, requestRealm } from '../helpers/request-realm';
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
 * before all of it passes: the body's media type, size and form (no repeated
 * field), the same origin (`Sec-Fetch-Site`, `Origin`), the flow cookie, the
 * step's CSRF value (`helpers/interaction.ts`), then the answer against the
 * step grammar. A request from another origin and a wrong CSRF value get one
 * generic `403`, audited as `request.csrf_rejected`. Then the engine runs one
 * round (`@qauth-labs/fastify-plugin-sign-in-engine`) and its result becomes
 * the next state.
 *
 * A JSON answer gets the next step view, or the final redirect, as JSON. A
 * form post gets `303 See Other` to the ceremony page of the interaction,
 * where the next step is read, or to the final redirect: the page needs no
 * JavaScript. Both targets are built from the interaction record and the
 * realm row, never from the request (`helpers/interaction-redirect.ts`).
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

/** The `Retry-After` of an answer the engine refused because a store it needs failed. */
const ENGINE_UNAVAILABLE_RETRY_SECONDS = 5;

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
  /** An answer or a cancel: `Sec-Fetch-Site: same-origin`, or else an `Origin` of the realm. */
  | 'required'
  /** The personal-data read: refused only when a header names another origin. */
  | 'unless_absent';

/**
 * Whether the request comes from the realm origin (ADR-019 Decision 6), by
 * the headers a browser sets and a page cannot: `Sec-Fetch-Site` and
 * `Origin`. Each that is present must say the same origin. Under `required`,
 * a request with neither is refused: a browser that sends no
 * `Sec-Fetch-Site` sends `Origin` on every POST.
 */
export function comesFromRealmOrigin(
  headers: FastifyRequest['headers'],
  realm: Pick<RealmRow, 'issuer'>,
  rule: OriginRule
): boolean {
  const site = headers['sec-fetch-site'];
  const origin = headers.origin;
  if (site !== undefined && site !== 'same-origin') return false;
  if (origin !== undefined && origin !== new URL(realmIssuer(realm)).origin) return false;
  return rule === 'unless_absent' || site !== undefined || origin !== undefined;
}

/** Refuse the request with the generic `403` unless it comes from the realm origin. */
async function requireRealmOrigin(request: FastifyRequest, rule: OriginRule): Promise<void> {
  if (!comesFromRealmOrigin(request.headers, requestRealm(request), rule)) {
    await refuseForbidden(request, 'origin');
  }
}

/** The step read of a view: the contract's `Interaction`. */
function stepRead(view: InteractionView) {
  return {
    ...interactionStepView(view.step),
    csrf: view.csrf,
    brand: DEFAULT_BRAND,
    expiresAt: new Date(view.deadline).toISOString(),
  };
}

/** The body as the module's parsers left it, with how it came; `{}` when none came. */
function answerBodyOf(request: FastifyRequest): {
  readonly fields: unknown;
  readonly parsed: ParsedBody;
} {
  const parsed = parsedBodies.get(request) ?? { encoding: 'json', bytes: 0 };
  return { fields: request.body ?? {}, parsed };
}

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

/** The engines of a process, one per verified-account policy of a realm (#528). */
interface InteractionEngines {
  readonly of: (requireVerifiedAccount: boolean) => SignInEngine;
}

/**
 * The sign-in engine over the process's repositories, password hasher and
 * the per-account failure ladder its legacy login routes share (#615): one
 * account run of failures counts across every front door.
 */
function createInteractionEngines(fastify: FastifyInstance): InteractionEngines {
  const ladder = createServerLadderParts(fastify);
  const build = (requireVerifiedAccount: boolean) =>
    createCheckedSignInEngine({
      accounts: createRepositoryAccountDirectory(
        {
          users: fastify.repositories.users,
          userCredentials: fastify.repositories.userCredentials,
          adminGrants: fastify.repositories.adminGrants,
        },
        fastify.log,
        { hardActionArmed: ladder.hardActionArmed }
      ),
      passwords: createArgon2PasswordVerifier(fastify.passwordHasher, fastify.log),
      // No MFA policy is stored yet: the password is the whole sign-in.
      policy: NO_SECOND_FACTOR_POLICY,
      identifierDigest: ladder.identifierDigest,
      requireVerifiedAccount,
      hooks: { ladder: ladder.ladder },
      passwordHardAction: ladder.hardAction,
      onUnavailable: (error) =>
        fastify.log.error({ err: error, port: error.port }, 'sign-in engine store unavailable'),
    });
  const verified = build(true);
  const unverified = build(false);
  return { of: (requireVerifiedAccount) => (requireVerifiedAccount ? verified : unverified) };
}

/**
 * Decide an answer: read it against the step it answers, run one round of
 * the engine, and turn its result into the interaction's next state. Runs
 * once the turn is taken: a refusal thrown here gives the turn back, so the
 * step and its CSRF value stay as they were.
 */
async function decideAnswer(
  request: FastifyRequest,
  reply: FastifyReply,
  engine: SignInEngine,
  answer: {
    readonly fields: unknown;
    readonly encoding: AnswerEncoding;
    readonly receivedAt: number;
  },
  state: InteractionState
): Promise<InteractionDecision> {
  try {
    readInteractionAnswer(state.step, answer.fields, answer.encoding);
  } catch (error) {
    if (error instanceof StepAnswerError) throw new InvalidAnswerError(error.message);
    throw error;
  }
  const realmId = requestRealm(request).id;
  const clientId = state.request.client_id;
  const context = (receivedAt: number): RoundContext => ({
    realm: { id: realmId },
    client: { id: clientId },
    receivedAt,
    ...ladderEndUserIp(request),
    audit: async (record) => {
      const event = signInAuditEvent(record);
      await emitUserEvent(request, event.type, event.data, {
        realmId,
        clientId,
        userId: event.userId,
        actor: 'user',
      });
    },
  });
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
  }
  return decisionOf(reply, result, answer.receivedAt);
}

/** The interaction's next state for an engine round's result. */
function decisionOf(
  reply: FastifyReply,
  result: RoundResult,
  receivedAt: number
): InteractionDecision {
  switch (result.kind) {
    case 'step': {
      const stored = storedStepOf(result.offer);
      return {
        kind: 'step',
        step: {
          ...stored,
          params: { ...stored.params },
          alternatives: [...stored.alternatives],
          ...(stored.alternativeParams === undefined
            ? {}
            : { alternativeParams: { ...stored.alternativeParams } }),
        },
        personal: { ...result.personal },
        signInTransaction: result.transaction,
      };
    }
    case 'complete':
      // The sign-in is done: the interaction finishes with it, under a new
      // browser session (`authenticated` with no next step). The session's
      // issue time is when the request came, before the account was read
      // (#748).
      return {
        kind: 'authenticated',
        signIn: {
          userId: result.signIn.subject,
          ...(result.signIn.identifier === undefined
            ? {}
            : { identifier: result.signIn.identifier }),
          amr: [...result.signIn.amr],
          issuedAt: receivedAt,
        },
      };
    case 'refused':
      switch (result.reason) {
        case 'throttled':
          reply.header('Retry-After', String(result.retryAfterSeconds));
          throw new TooManyRequestsError('The sign-in is throttled.');
        case 'unavailable':
          throw new TemporarilyUnavailableError(ENGINE_UNAVAILABLE_RETRY_SECONDS, {
            reason: 'sign-in engine store unavailable',
          });
        case 'invalid_answer':
          throw new InvalidAnswerError('the engine refused the answer');
        default:
          // `transaction_ended` again after a fresh start, or a request check
          // this transport does not register: an engine fault.
          throw new Error(`the sign-in engine refused a round: ${result.reason}`);
      }
    case 'redirect':
      // The Interaction API serves every step and registers no request check.
      throw new Error(`the sign-in engine asked to continue elsewhere: ${result.reason}`);
  }
}

export default async function (fastify: FastifyInstance) {
  const engines = createInteractionEngines(fastify);

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

  const readRateLimit = {
    // The ceremony app's pages read once per step: the authorization
    // endpoint's budget, with its environment-aware cap (ADR-008 §5).
    max: (request: FastifyRequest) =>
      resolveRealmRateLimitMax(request.realm, {
        lenientMax: env.AUTHORIZE_RATE_LIMIT_LENIENT,
        strictMax: env.AUTHORIZE_RATE_LIMIT,
      }),
    timeWindow: env.AUTHORIZE_RATE_WINDOW * 1000,
    keyGenerator: realmRateLimitKey,
  };
  // An answer can carry a credential: the sign-in form's budget, per address.
  const answerRateLimit = {
    max: env.LOGIN_RATE_LIMIT,
    timeWindow: env.LOGIN_RATE_WINDOW * 1000,
    keyGenerator: realmRateLimitKey,
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
      config: { surface: 'browser', rateLimit: readRateLimit },
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
      config: { surface: 'browser', rateLimit: readRateLimit },
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
      const result = await answerInteraction(
        request,
        reply,
        { id: interactionIdOf(request), csrf: memberOf(fields, 'csrf') },
        (state) =>
          decideAnswer(
            request,
            reply,
            engine,
            { fields, encoding: parsed.encoding, receivedAt },
            state
          )
      );
      switch (result.kind) {
        case 'stale':
          return respondStale(request, reply, parsed.encoding);
        case 'step':
          return respond(request, reply, parsed.encoding, { view: result.view });
        case 'finished': {
          const { userId } = result.transaction;
          if (userId !== undefined) {
            await fastify.repositories.users.updateLastLogin(realm.id, userId);
            await emitUserEvent(
              request,
              'urn:qauth:event:user.signed_in:v1-rc.0',
              { method: 'password' },
              { realmId: realm.id, userId, clientId: result.request.client_id, actor: 'user' }
            );
          }
          return respond(request, reply, parsed.encoding, {
            location: interactionFinishRedirect(realm, result.request),
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
      if (result.kind === 'stale') return respondStale(request, reply, parsed.encoding);
      return respond(request, reply, parsed.encoding, {
        location: interactionCancelRedirect(requestRealm(request), result.request),
      });
    }
  );
}
