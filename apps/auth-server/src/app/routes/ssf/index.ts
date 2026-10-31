import { randomUUID } from 'node:crypto';

import {
  addSubjectRequestSchema,
  assertTransmitterMembers,
  authorizationHeaderContext,
  canonicalSubject,
  canonicalSubjectKey,
  checkDelivery,
  eventSubjectOf,
  keptDescription,
  receiverErrorClass,
  removeSubjectRequestSchema,
  SSF_MIN_VERIFICATION_INTERVAL,
  SSF_STREAM_SUBJECTS_MAX,
  SsfRequestError,
  type SsfTransmitter,
  statusUpdateRequestSchema,
  type StreamConfigRequest,
  streamConfigRequestSchema,
  streamConfiguration,
  streamConfigurationSchema,
  streamStatusSchema,
  SUBJECT_KEY_MAX,
  verificationRequestSchema,
} from '@qauth-labs/fastify-plugin-ssf';
import { ForbiddenError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import { scanValues, ssfStreamVerificationRequested } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { JWKS_CACHE_CONTROL } from '../../constants';
import { REDIS_KEYS } from '../../constants/redis-keys';
import { realmIssuer } from '../../helpers/realm-url';
import { answerRouteNotFound } from '../../helpers/request-bounds';
import { requestRealm } from '../../helpers/request-realm';
import { SsfNotFoundError, SsfStreamExistsError } from '../../helpers/ssf-errors';
import {
  createRequireSsfReceiver,
  realmRunsTransmitter,
  type SsfReceiver,
  ssfReceiverOf,
} from '../../helpers/ssf-receiver';
import { emitUserEvent } from '../../helpers/user-events';

/**
 * The Shared Signals Framework transmitter's stream management (SSF 1.0
 * §8.1, issue #410), mounted at `/ssf`:
 *
 *   POST   /ssf/stream            — create the receiver's stream (201; 409 when it has one)
 *   GET    /ssf/stream            — read it, or list the receiver's streams without `stream_id`
 *   PATCH  /ssf/stream            — update receiver-supplied members
 *   PUT    /ssf/stream            — replace them
 *   DELETE /ssf/stream            — delete it (204)
 *   GET    /ssf/status            — its status, with the delivery status beside it
 *   POST   /ssf/status            — set its status
 *   POST   /ssf/subjects/add      — add a subject (200)
 *   POST   /ssf/subjects/remove   — remove a subject (204)
 *   POST   /ssf/verify            — ask for a verification event (204)
 *   GET    /ssf/jwks.json         — the keys that verify the realm's SETs (public)
 *
 * Registered only while SSF_TRANSMITTER_ENABLED is on; a realm whose own
 * switch is off answers the 404 of a route that does not exist, before the
 * request is validated. A receiver is an OAuth client with the
 * `ssf:stream` scope, authenticating with its own access token (see
 * `helpers/ssf-receiver.ts`). It reaches only its own stream: another
 * receiver's `stream_id` answers 404.
 *
 * The receiver's `endpoint_url` is checked through the egress client here, at
 * registration, and the push route checks it again at every delivery. Its
 * `authorization_header` is stored encrypted with the realm's `data_at_rest`
 * key and never returned.
 *
 * ERRORS (#513). SSF 1.0 §8.1 and RFC 8935 give stream management statuses
 * but define no error body, so none of these is an OAuth protocol endpoint:
 * every error is an RFC 9457 problem document (ADR-019 Decision 7). A request
 * the protocol refuses is an `SsfRequestError` (400 `bad_request`), a stream
 * the receiver does not have an `SsfNotFoundError` (404 `not_found`), a second
 * stream an `SsfStreamExistsError` (409 `conflict`); the registry in
 * `api-conventions/error-classes.ts` maps each. The routes declare the
 * `bearerAuth` security requirement, so a refused token's 401 and a missing
 * scope's 403 carry an RFC 6750 §3 challenge too.
 */
export const autoPrefix = '/ssf';

const TAGS = ['Shared Signals'];

const streamIdQuerySchema = z.object({ stream_id: z.string().min(1).max(255) });

/**
 * The error statuses a stream management route answers by design (#513): a
 * request the schema or the protocol refuses, a refused token, a token without
 * `ssf:stream` or a user the receiver may not add as a subject (#540), and a
 * stream the receiver does not have or a realm that does not run the
 * transmitter. The OpenAPI document adds 421, 429 and 500.
 */
const STREAM_ERRORS = [400, 401, 403, 404] as const;

/** The receiver's access token (RFC 6750), as the OpenAPI document names it. */
const BEARER = [{ bearerAuth: [] }];

/** The transmitter; the routes exist only when it does. */
function transmitterOf(fastify: FastifyInstance): SsfTransmitter {
  if (!fastify.ssf) throw new SsfNotFoundError();
  return fastify.ssf;
}

/**
 * The realm's issuer from its row (ADR-019 Decision 1, #490): the SETs' `iss`.
 * The realm resolver lets no realm without one through.
 */
function issuerOf(receiver: SsfReceiver): string {
  return realmIssuer(receiver.realm);
}

export default async function (fastify: FastifyInstance) {
  if (!fastify.ssf) return;

  const requireSsfReceiver = createRequireSsfReceiver(fastify);
  const streams = fastify.repositories.ssfStreams;
  const routes = fastify.withTypeProvider<ZodTypeProvider>();

  // A realm that does not run the transmitter answers as if these routes did
  // not exist: the `not_found` problem document of a path no route serves,
  // before the body is parsed or validated, so a malformed request gets no 400
  // that would give the routes away.
  fastify.addHook('onRequest', async (request, reply) => {
    if (realmRunsTransmitter(request)) return;
    return answerRouteNotFound(request, reply);
  });

  const keyOf = (receiver: SsfReceiver, streamId: string) => ({
    realmId: receiver.realm.id,
    receiverClientId: receiver.client.id,
    streamId,
  });

  /** The receiver's stream with this id, or a 404. */
  async function ownStream(receiver: SsfReceiver, streamId: string) {
    const stream = await streams.find(keyOf(receiver, streamId));
    if (!stream) throw new SsfNotFoundError('Stream not found');
    return stream;
  }

  const configurationOf = (
    receiver: SsfReceiver,
    stream: Parameters<typeof streamConfiguration>[0]
  ) => streamConfiguration(stream, issuerOf(receiver), transmitterOf(fastify).eventsSupported);

  /**
   * Check a requested delivery and encrypt its header for `streamId`: the
   * endpoint's form, then its addresses through the egress client.
   */
  async function deliveryFor(
    receiver: SsfReceiver,
    streamId: string,
    delivery: StreamConfigRequest['delivery']
  ) {
    const checkedDelivery = checkDelivery(delivery);
    await transmitterOf(fastify).checkEndpoint(checkedDelivery.endpointUrl);
    const authorizationHeader =
      checkedDelivery.authorizationHeader === null
        ? null
        : await fastify.signer.encrypt('api', {
            realmId: receiver.realm.id,
            plaintext: new TextEncoder().encode(checkedDelivery.authorizationHeader),
            context: authorizationHeaderContext(streamId),
          });
    return {
      deliveryMethod: checkedDelivery.method,
      endpointUrl: checkedDelivery.endpointUrl,
      authorizationHeader,
    };
  }

  const common = {
    preHandler: requireSsfReceiver,
    config: { surface: 'api' as const },
  };
  const streamSchema = {
    tags: TAGS,
    'x-qauth-stability': 'experimental' as const,
    security: BEARER,
  };

  // The transmitter's own JWKS (d-1026-09): the realm's active and retired
  // SET verification keys (`event_signing`, ADR-019 Decision 9), never a
  // compromised one. They are published apart from the realm JWKS, so a
  // verifier that reads the realm JWKS and skips the `typ` check cannot take
  // a SET-signed token for an access token. Public, as every JWKS is: no
  // receiver token. The `onRequest` hook above answers 404 for a realm that
  // does not run the transmitter. A key store that cannot be read fails the
  // request; the realm JWKS does not depend on it.
  routes.get(
    '/jwks.json',
    {
      config: { surface: 'meta' },
      schema: {
        description:
          'The JSON Web Key Set (RFC 7517) that verifies the realm’s Security Event Tokens: its active and retired `event_signing` keys. The `jwks_uri` of the transmitter metadata. Unauthenticated, cacheable for five minutes. The realm JWKS at `/.well-known/jwks.json` holds no SET key.',
        tags: TAGS,
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [404],
      },
    },
    async (request, reply) => {
      const keys = await fastify.signer.getVerificationKeys(
        'api',
        requestRealm(request).id,
        'event_signing'
      );
      reply
        .header('Cache-Control', JWKS_CACHE_CONTROL)
        .header('Content-Type', 'application/jwk-set+json; charset=utf-8');
      return reply.send({ keys: keys.map((key) => key.publicJwk) });
    }
  );

  routes.post(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Create the receiver’s Shared Signals Framework stream (SSF 1.0 §8.1.1.1). Push delivery only; `endpoint_url` must be an https URL on a public address. A receiver has one stream per realm: a second create answers 409.',
        ...streamSchema,
        'x-qauth-errors': [...STREAM_ERRORS, 409],
        body: streamConfigRequestSchema,
        response: { 201: streamConfigurationSchema },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const id = randomUUID();
      const delivery = await deliveryFor(receiver, id, request.body.delivery);
      const stream = await streams.create({
        id,
        realmId: receiver.realm.id,
        receiverClientId: receiver.client.id,
        audience: receiver.client.clientId,
        eventsRequested: request.body.events_requested ?? [],
        ...delivery,
        description: keptDescription(request.body.description),
      });
      if (!stream) throw new SsfStreamExistsError();
      reply.header('Cache-Control', 'no-store').code(201);
      return reply.send(configurationOf(receiver, stream));
    }
  );

  routes.get(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Read the receiver’s stream (SSF 1.0 §8.1.1.2), or, without `stream_id`, list the streams it has in this realm.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        querystring: z.object({ stream_id: z.string().min(1).max(255).optional() }),
        response: { 200: z.union([streamConfigurationSchema, z.array(streamConfigurationSchema)]) },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      reply.header('Cache-Control', 'no-store');
      const streamId = request.query.stream_id;
      if (streamId === undefined) {
        const all = await streams.list(receiver.realm.id, receiver.client.id);
        return reply.send(all.map((stream) => configurationOf(receiver, stream)));
      }
      return reply.send(configurationOf(receiver, await ownStream(receiver, streamId)));
    }
  );

  /** PATCH and PUT: one handler, differing in what a member left out means. */
  async function changeStream(request: FastifyRequest, replace: boolean) {
    const receiver = ssfReceiverOf(request);
    const body = request.body as StreamConfigRequest;
    if (body.stream_id === undefined) throw new SsfRequestError('stream_id is required');
    const current = await ownStream(receiver, body.stream_id);
    assertTransmitterMembers(body, configurationOf(receiver, current));
    let delivery =
      body.delivery !== undefined || replace
        ? await deliveryFor(receiver, current.id, body.delivery)
        : {};
    // QAuth never returns the stored header, so a receiver that reads its
    // stream and PATCHes `delivery` back cannot send it again. A PATCH that
    // leaves the header out and keeps the endpoint keeps the stored header; a
    // new endpoint never gets the old one, and a PUT replaces it.
    if (
      !replace &&
      body.delivery !== undefined &&
      body.delivery.authorization_header === undefined &&
      'endpointUrl' in delivery &&
      delivery.endpointUrl === current.endpointUrl
    ) {
      delivery = { ...delivery, authorizationHeader: current.authorizationHeader };
    }
    const updated = await streams.update(
      keyOf(receiver, current.id),
      {
        ...delivery,
        ...(body.events_requested !== undefined || replace
          ? { eventsRequested: body.events_requested ?? [] }
          : {}),
        ...(body.description !== undefined || replace
          ? { description: keptDescription(body.description) }
          : {}),
      },
      Date.now()
    );
    if (!updated) throw new SsfNotFoundError('Stream not found');
    return configurationOf(receiver, updated);
  }

  routes.patch(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Update the receiver-supplied members of the stream (SSF 1.0 §8.1.1.3); a member left out stays. A transmitter-supplied member may be sent only with the value QAuth holds.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        body: streamConfigRequestSchema,
        response: { 200: streamConfigurationSchema },
      },
    },
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      return reply.send(await changeStream(request, false));
    }
  );

  routes.put(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Replace the receiver-supplied members of the stream (SSF 1.0 §8.1.1.4); a member left out is removed, and `delivery` is required.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        body: streamConfigRequestSchema,
        response: { 200: streamConfigurationSchema },
      },
    },
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      return reply.send(await changeStream(request, true));
    }
  );

  routes.delete(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Delete the stream and its subjects (SSF 1.0 §8.1.1.5). Its deliveries still pending end without being sent.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        querystring: streamIdQuerySchema,
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      if (!(await streams.remove(keyOf(receiver, request.query.stream_id)))) {
        throw new SsfNotFoundError('Stream not found');
      }
      reply.code(204);
      return reply.send(null);
    }
  );

  /** The status document of a stream, with its deliveries beside it. */
  async function statusOf(stream: { id: string; status: string; statusReason: string | null }) {
    const deliveries = await streams.deliveryStatus(stream.id, Date.now());
    const failure = deliveries.lastFailure;
    return {
      stream_id: stream.id,
      status: stream.status as z.infer<typeof streamStatusSchema>['status'],
      ...(stream.statusReason === null ? {} : { reason: stream.statusReason }),
      delivery_status: {
        pending: deliveries.pending,
        ...(failure === undefined
          ? {}
          : {
              last_failure: {
                event_id: failure.eventId,
                attempts: failure.attempts,
                ...(failure.statusCode === null ? {} : { status_code: failure.statusCode }),
                // Coarser than what the history keeps: see receiverErrorClass.
                error: receiverErrorClass(failure.errorClass),
                time: new Date(failure.at).toISOString(),
                state: failure.state,
                ...(failure.nextAttemptAt === undefined
                  ? {}
                  : { next_attempt_at: new Date(failure.nextAttemptAt).toISOString() }),
              },
            }),
      },
    };
  }

  routes.get(
    '/status',
    {
      ...common,
      schema: {
        description:
          'Read the stream’s status (SSF 1.0 §8.1.2.1). `delivery_status`, QAuth’s extension, reports the deliveries still pending and the latest failed attempt from the delivery history. An endpoint QAuth refused to reach and one it could not reach both read `destination_unreachable`.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        querystring: streamIdQuerySchema,
        response: { 200: streamStatusSchema },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const stream = await ownStream(receiver, request.query.stream_id);
      reply.header('Cache-Control', 'no-store');
      return reply.send(await statusOf(stream));
    }
  );

  routes.post(
    '/status',
    {
      ...common,
      schema: {
        description:
          'Set the stream’s status (SSF 1.0 §8.1.2.2): `enabled`, `paused` (events are held, however long, without spending attempts, and sent within 30 seconds of it being enabled again) or `disabled` (nothing is held).',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        body: statusUpdateRequestSchema,
        response: { 200: streamStatusSchema },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const { stream_id: streamId, status, reason } = request.body;
      const updated = await streams.setStatus(
        keyOf(receiver, streamId),
        status,
        reason ?? null,
        Date.now()
      );
      if (!updated) throw new SsfNotFoundError('Stream not found');
      reply.header('Cache-Control', 'no-store');
      return reply.send(await statusOf(updated));
    }
  );

  /**
   * A subject's stored form: the subject with a user's UUID in lower case, its
   * canonical key and the event subject it stands for. Both spellings of a
   * user's id are then one subject, which matches the user's events.
   */
  function subjectRow(
    receiver: SsfReceiver,
    received: z.infer<typeof addSubjectRequestSchema>['subject']
  ) {
    const issuer = issuerOf(receiver);
    const subject = canonicalSubject(received, issuer);
    const subjectKey = canonicalSubjectKey(subject);
    // Bytes, not characters: the key is indexed, and a long multibyte subject
    // would pass a character count and fail the index.
    if (Buffer.byteLength(subjectKey) > SUBJECT_KEY_MAX) {
      throw new SsfRequestError('The subject is too long');
    }
    return { subject, subjectKey, eventSubject: eventSubjectOf(subject, issuer) };
  }

  routes.post(
    '/subjects/add',
    {
      ...common,
      schema: {
        description:
          'Add a subject to the stream (SSF 1.0 §8.1.3.2). The transmitter’s `default_subjects` is `NONE`: the stream receives events only about the subjects added. A user is named `iss_sub` with the realm’s issuer, a client `uri` or `opaque` by its `client_id`; another subject is kept and matches no event. A user must be related to the receiver’s client: an active consent for it, or a live refresh token it was issued. Any other user, an unknown one included, is refused with 403.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        body: addSubjectRequestSchema,
        response: { 200: z.void().describe('An empty body (SSF 1.0 §8.1.3.2).') },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const stream = await ownStream(receiver, request.body.stream_id);
      const { subject, subjectKey, eventSubject } = subjectRow(receiver, request.body.subject);
      // A receiver learns only of the users related to its own client (#540,
      // decided 2026-10-26): one who consented to it, or holds a live refresh
      // token it was issued. Any other user is refused as SSF 1.0 §8.1.3.2
      // prescribes for a subject the receiver may not add (403), an unknown
      // id alike, so the answer tells no one which users exist.
      if (
        eventSubject?.type === 'user' &&
        !(await streams.isRelatedUser(
          receiver.realm.id,
          receiver.client.id,
          eventSubject.id,
          Date.now()
        ))
      ) {
        throw new ForbiddenError('The receiver may not add this subject');
      }
      const added = await streams.addSubject(
        stream.id,
        {
          subjectKey,
          subject,
          eventSubject,
          verified: request.body.verified ?? true,
        },
        SSF_STREAM_SUBJECTS_MAX
      );
      // The receiver deleted the stream meanwhile.
      if (added === 'missing') throw new SsfNotFoundError('Stream not found');
      if (added === 'full') {
        throw new SsfRequestError(`A stream holds at most ${SSF_STREAM_SUBJECTS_MAX} subjects`);
      }
      return reply.code(200).send();
    }
  );

  routes.post(
    '/subjects/remove',
    {
      ...common,
      schema: {
        description:
          'Remove a subject from the stream (SSF 1.0 §8.1.3.3). A subject the stream does not have answers 204 as well.',
        ...streamSchema,
        'x-qauth-errors': STREAM_ERRORS,
        body: removeSubjectRequestSchema,
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const stream = await ownStream(receiver, request.body.stream_id);
      await streams.removeSubject(stream.id, subjectRow(receiver, request.body.subject).subjectKey);
      reply.code(204);
      return reply.send(null);
    }
  );

  routes.post(
    '/verify',
    {
      ...common,
      schema: {
        description:
          'Ask for a verification event on the stream (SSF 1.0 §8.1.4.2). QAuth records the request as an event and pushes the verification Security Event Token to this stream only, with `state` returned as sent. A second request within `min_verification_interval` (10 seconds) answers 429.',
        ...streamSchema,
        'x-qauth-errors': [...STREAM_ERRORS, 429],
        body: verificationRequestSchema,
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const stream = await ownStream(receiver, request.body.stream_id);
      const state = request.body.state;
      // The event store refuses a value shaped like a token or a key; refuse
      // it here with a 400 rather than fail the request with a 500.
      if (state !== undefined && scanValues(state).length > 0) {
        throw new SsfRequestError('state must not be shaped like a token or a key');
      }
      // Per receiver, not per stream: deleting the stream and creating
      // another does not reset the interval.
      const limitKey = REDIS_KEYS.SSF_VERIFICATION(receiver.realm.id, receiver.client.id);
      const allowed = await fastify.redis.set(
        limitKey,
        '1',
        'EX',
        SSF_MIN_VERIFICATION_INTERVAL,
        'NX'
      );
      if (allowed !== 'OK') {
        reply.header('Retry-After', String(SSF_MIN_VERIFICATION_INTERVAL));
        throw new TooManyRequestsError('Verification was requested too recently');
      }
      // A request that recorded nothing does not count against the interval.
      const release = (error: unknown) =>
        fastify.redis
          .del(limitKey)
          .catch(() => undefined)
          .then(() => Promise.reject(error));
      await fastify.db
        .transaction(async (tx) => {
          const eventId = await emitUserEvent(
            request,
            ssfStreamVerificationRequested.type,
            state === undefined ? {} : { state },
            {
              tx,
              realmId: receiver.realm.id,
              subject: { type: 'ssf_stream', id: stream.id },
              clientId: receiver.client.clientId,
              actor: 'client',
            }
          );
          const enqueued = await streams.enqueueForEvent(tx, {
            streamId: stream.id,
            eventId,
            now: Date.now(),
          });
          // The only stream the row could be for is gone: the receiver
          // deleted it meanwhile. The event is rolled back with the request.
          if (!enqueued) throw new SsfNotFoundError('Stream not found');
        })
        .catch(release);
      reply.code(204);
      return reply.send(null);
    }
  );
}
