import type { ActClaim } from '@qauth-labs/fastify-plugin-jwt';
import {
  BadRequestError,
  ForbiddenError,
  InvalidClientError,
  InvalidClientMetadataError,
  InvalidCredentialsError,
  InvalidDpopProofError,
  InvalidGrantError,
  InvalidRedirectUriError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
  JWTExpiredError,
  JWTInvalidError,
  MissingAccessTokenError,
  NotFoundError,
  TemporarilyUnavailableError,
  TokenExpiredError,
  TooManyRequestsError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from '@qauth-labs/shared-errors';
import {
  type EventDataOf,
  type EventEnvelope,
  eventRequest,
  getEventType,
  type RegisteredEventType,
} from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { delegationChainColumn } from './agent-audit';
import { requestRealm } from './request-realm';

/** The transaction an event commits in: the one of the change it records. */
export type EventTransaction = Parameters<FastifyInstance['repositories']['events']['emit']>[0];

type EventActor = NonNullable<EventEnvelope['actor']>;
type EventSubject = NonNullable<EventEnvelope['subject']>;

/** What {@link emitUserEvent} takes beside the type and the payload. */
export interface UserEventOptions {
  /**
   * The transaction of the change the event records. The event commits with
   * it, or neither does. Without one the event is written in a transaction of
   * its own (an event that records no change, such as a refusal).
   */
  readonly tx?: EventTransaction;
  /**
   * The realm the event happened in: the realm of the row it records, its
   * client's or its user's, when the handler has one. The request's realm
   * (`request.realm`, #487) when absent, so a request's events land in the
   * realm of the rows they name and otherwise in the realm of its host.
   */
  readonly realmId?: string | null;
  /**
   * The user the event is about. It becomes the subject of a type whose
   * subject is a user, and is ignored for any other type.
   */
  readonly userId?: string | null;
  /** The subject of a type whose subject is a client or an API key. */
  readonly subject?: EventSubject;
  /** The public `client_id` of the OAuth client the request came through. */
  readonly clientId?: string | null;
  /**
   * Who caused the event: `'user'` for the user of {@link userId}, `'client'`
   * for the client of {@link clientId}, or the actor itself. Overridden by a
   * delegation chain in {@link act}.
   */
  readonly actor?: 'user' | 'client' | EventActor;
  /**
   * The RFC 8693 `act` claim of a delegated request. When it names an actor,
   * the event's actor is the acting client, with the whole chain as
   * `delegationChain` (the acting agent first).
   */
  readonly act?: ActClaim;
}

/** The actor the options name, or `undefined` when they name none. */
function actorOf(options: UserEventOptions): EventActor | undefined {
  const chain = delegationChainColumn(options.act);
  if (chain !== null) {
    return { type: 'client', id: chain[0], delegationChain: chain };
  }
  if (options.actor === 'user') {
    return options.userId ? { type: 'user', id: options.userId } : undefined;
  }
  if (options.actor === 'client') {
    return options.clientId ? { type: 'client', id: options.clientId } : undefined;
  }
  return options.actor;
}

/** The subject the options name, for a type of the given subject kind. */
function subjectOf(
  subjectType: EventSubject['type'] | undefined,
  options: UserEventOptions
): EventSubject | undefined {
  if (options.subject !== undefined) return options.subject;
  if (subjectType === 'user' && options.userId) return { type: 'user', id: options.userId };
  return undefined;
}

/**
 * The event the event store's `emit` takes: the envelope without its id, time
 * and category, which the store makes.
 */
export interface UserEvent<Type extends RegisteredEventType> {
  type: Type;
  realm: string;
  actor?: EventActor;
  subject?: EventSubject;
  client?: EventEnvelope['client'];
  request?: EventEnvelope['request'];
  data: EventDataOf<Type>;
}

/**
 * The event {@link emitUserEvent} writes, in the realm given: the request
 * member (its id as `traceId`, the client address and the `User-Agent`,
 * sized by `eventRequest`), the subject, the client and the actor, from the
 * options. Pure: it reads the request and writes nothing.
 */
export function userEventFor<Type extends RegisteredEventType>(
  request: FastifyRequest,
  type: Type,
  data: EventDataOf<Type>,
  options: UserEventOptions,
  realmId: string
): UserEvent<Type> {
  const userAgent = request.headers['user-agent'];
  const actor = actorOf(options);
  const subject = subjectOf(getEventType(type)?.subject, options);
  const requestMember = eventRequest({
    traceId: request.id,
    ip: request.ip,
    userAgent: typeof userAgent === 'string' ? userAgent : undefined,
  });
  return {
    type,
    realm: realmId,
    data,
    ...(actor === undefined ? {} : { actor }),
    ...(subject === undefined ? {} : { subject }),
    ...(options.clientId ? { client: { id: options.clientId } } : {}),
    ...(requestMember === undefined ? {} : { request: requestMember }),
  };
}

/**
 * Record a user event in the event store (ADR-019 Decision 8, issue #458):
 * the one way the auth server records what a person or a client did. It
 * replaces the writes to `audit_logs`, which stays in place, read-only, until
 * a later release drops it.
 *
 * It fills what every event of a request carries (see {@link userEventFor}):
 * the realm (the handler's, else the request's), the request, the
 * subject, the client the request came through and the actor, with the
 * RFC 8693 delegation chain of a delegated request (`delegationChainColumn`).
 *
 * The write is awaited, and a failed write fails the request, as the audit
 * write did. An event that does not match its type's schema or the payload
 * rules is refused the same way (`EventValidationError`), and nothing is
 * written. With `tx` the event commits in the handler's transaction.
 *
 * The structured log lines of `logAuthEvent` stay: they are logs, not events.
 *
 * @param request - the request that caused the event
 * @param type - a registered event type
 * @param data - the type's payload
 * @param options - see {@link UserEventOptions}
 * @returns the event id, a UUIDv7
 */
export async function emitUserEvent<Type extends RegisteredEventType>(
  request: FastifyRequest,
  type: Type,
  data: EventDataOf<Type>,
  options: UserEventOptions = {}
): Promise<string> {
  const fastify = request.server;
  const realmId = options.realmId ?? requestRealm(request).id;
  const event = userEventFor(request, type, data, options, realmId);
  const events = fastify.repositories.events;
  return options.tx === undefined
    ? events.emitInOwnTransaction(event)
    : events.emit(options.tx, event);
}

/** The OAuth error classes whose `message` is the registered `error` code. */
const OAUTH_CODE_ERRORS = [
  InvalidClientError,
  InvalidClientMetadataError,
  InvalidDpopProofError,
  InvalidGrantError,
  InvalidRedirectUriError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTargetError,
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
] as const;

/** A `snake_case` code, the form an event's `error` and `reason` take. */
const SNAKE_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/**
 * The OAuth or OpenID Connect `error` code a thrown error stands for, for the
 * `error` member of a failure event. It is the code the error handler answers
 * with, never the error's prose: an OAuth error class names its code, a
 * `BadRequestError` thrown with a code (`unsupported_grant_type`) keeps it, a
 * refused token is `invalid_token`, and anything unexpected is
 * `server_error`.
 */
export function oauthErrorCode(error: unknown): string {
  if (OAUTH_CODE_ERRORS.some((ErrorClass) => error instanceof ErrorClass)) {
    return (error as Error).message;
  }
  if (error instanceof BadRequestError) {
    return SNAKE_CODE.test(error.message) ? error.message : 'invalid_request';
  }
  if (
    error instanceof JWTInvalidError ||
    error instanceof JWTExpiredError ||
    error instanceof MissingAccessTokenError ||
    error instanceof InvalidTokenError ||
    error instanceof TokenExpiredError
  ) {
    return 'invalid_token';
  }
  if (error instanceof ForbiddenError || error instanceof InvalidCredentialsError) {
    return 'access_denied';
  }
  if (error instanceof NotFoundError) return 'invalid_request';
  if (error instanceof TooManyRequestsError || error instanceof TemporarilyUnavailableError) {
    return 'temporarily_unavailable';
  }
  return 'server_error';
}

/** Where {@link withEventReason} keeps a refusal's reason on the error it throws. */
const EVENT_REASON = Symbol('qauth.eventReason');

/**
 * Tag an error with the `reason` its failure event carries, for a handler
 * whose catch block emits the event: the throw site knows why, the catch
 * block does not. The reason is a `snake_case` code, never the error's
 * message, which stays prose for the log.
 *
 * @returns the same error, to throw
 */
export function withEventReason<E extends Error>(error: E, reason: string): E {
  Object.defineProperty(error, EVENT_REASON, { value: reason, enumerable: false });
  return error;
}

/**
 * The `error` and `reason` members of a failure event for a thrown error: its
 * OAuth `error` code ({@link oauthErrorCode}) and the reason given here or
 * tagged at the throw site ({@link withEventReason}), when there is one.
 */
export function failureData(error: unknown, reason?: string): { error: string; reason?: string } {
  const tagged =
    error instanceof Error
      ? (error as Error & { [EVENT_REASON]?: string })[EVENT_REASON]
      : undefined;
  const why = reason ?? tagged;
  return { error: oauthErrorCode(error), ...(why === undefined ? {} : { reason: why }) };
}
