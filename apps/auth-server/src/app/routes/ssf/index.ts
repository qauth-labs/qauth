import { randomUUID } from 'node:crypto';

import {
  addSubjectRequestSchema,
  assertTransmitterMembers,
  authorizationHeaderContext,
  canonicalSubjectKey,
  checkDelivery,
  eventSubjectOf,
  keptDescription,
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
import { BadRequestError, TooManyRequestsError } from '@qauth-labs/shared-errors';
import { scanValues, ssfStreamVerificationRequested } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { REDIS_KEYS } from '../../constants/redis-keys';
import {
  createRequireSsfReceiver,
  SsfNotFoundError,
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
 *
 * Registered only while SSF_TRANSMITTER_ENABLED is on; a realm whose own
 * switch is off answers 404. A receiver is an OAuth client with the
 * `ssf:stream` scope, authenticating with its own access token (see
 * `helpers/ssf-receiver.ts`). It reaches only its own stream: another
 * receiver's `stream_id` answers 404.
 *
 * The receiver's `endpoint_url` is checked through the egress client here, at
 * registration, and the push route checks it again at every delivery. Its
 * `authorization_header` is stored encrypted with the realm's `data_at_rest`
 * key and never returned.
 */
export const autoPrefix = '/ssf';

const TAGS = ['Shared Signals'];

const streamIdQuerySchema = z.object({ stream_id: z.string().min(1).max(255) });

/** A stream that already exists for the receiver (SSF 1.0 §8.1.1.1). */
class StreamExistsError extends Error {
  readonly statusCode = 409;

  constructor() {
    super('The receiver already has a stream in this realm');
  }
}

/** Run `check`, turning a refusal of the SSF protocol into a 400. */
async function checked<T>(check: () => T | Promise<T>): Promise<T> {
  try {
    return await check();
  } catch (error) {
    if (error instanceof SsfRequestError) throw new BadRequestError(error.message);
    throw error;
  }
}

/** The transmitter; the routes exist only when it does. */
function transmitterOf(fastify: FastifyInstance): SsfTransmitter {
  if (!fastify.ssf) throw new SsfNotFoundError();
  return fastify.ssf;
}

/** The realm's issuer: the SETs' `iss`. The realm resolver lets no realm without one through. */
function issuerOf(receiver: SsfReceiver): string {
  if (receiver.realm.issuer === null) throw new SsfNotFoundError();
  return receiver.realm.issuer;
}

export default async function (fastify: FastifyInstance) {
  if (!fastify.ssf) return;

  const requireSsfReceiver = createRequireSsfReceiver(fastify);
  const streams = fastify.repositories.ssfStreams;
  const routes = fastify.withTypeProvider<ZodTypeProvider>();

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
    const checkedDelivery = await checked(() => checkDelivery(delivery));
    await checked(() => transmitterOf(fastify).checkEndpoint(checkedDelivery.endpointUrl));
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

  routes.post(
    '/stream',
    {
      ...common,
      schema: {
        description:
          'Create the receiver’s Shared Signals Framework stream (SSF 1.0 §8.1.1.1). Push delivery only; `endpoint_url` must be an https URL on a public address. A receiver has one stream per realm: a second create answers 409.',
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
      if (!stream) throw new StreamExistsError();
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
    if (body.stream_id === undefined) throw new BadRequestError('stream_id is required');
    const current = await ownStream(receiver, body.stream_id);
    await checked(() => assertTransmitterMembers(body, configurationOf(receiver, current)));
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
    const deliveries = await streams.deliveryStatus(stream.id);
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
                error: failure.errorClass,
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
          'Read the stream’s status (SSF 1.0 §8.1.2.1). `delivery_status`, QAuth’s extension, reports the deliveries still pending and the latest failed attempt from the delivery history.',
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
          'Set the stream’s status (SSF 1.0 §8.1.2.2): `enabled`, `paused` (events are held and sent once it is enabled again, until their attempts run out) or `disabled` (nothing is held).',
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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

  /** A subject's stored form: its canonical key and the event subject it stands for. */
  function subjectRow(
    receiver: SsfReceiver,
    subject: z.infer<typeof addSubjectRequestSchema>['subject']
  ) {
    const subjectKey = canonicalSubjectKey(subject);
    // Bytes, not characters: the key is indexed, and a long multibyte subject
    // would pass a character count and fail the index.
    if (Buffer.byteLength(subjectKey) > SUBJECT_KEY_MAX) {
      throw new BadRequestError('The subject is too long');
    }
    return { subjectKey, eventSubject: eventSubjectOf(subject, issuerOf(receiver)) };
  }

  routes.post(
    '/subjects/add',
    {
      ...common,
      schema: {
        description:
          'Add a subject to the stream (SSF 1.0 §8.1.3.2). The transmitter’s `default_subjects` is `NONE`: the stream receives events only about the subjects added. A user is named `iss_sub` with the realm’s issuer, a client `uri` or `opaque` by its `client_id`; another subject is kept and matches no event.',
        tags: TAGS,
        'x-qauth-stability': 'experimental',
        body: addSubjectRequestSchema,
        response: { 200: z.void().describe('An empty body (SSF 1.0 §8.1.3.2).') },
      },
    },
    async (request, reply) => {
      const receiver = ssfReceiverOf(request);
      const stream = await ownStream(receiver, request.body.stream_id);
      const { subjectKey, eventSubject } = subjectRow(receiver, request.body.subject);
      const added = await streams.addSubject(
        stream.id,
        {
          subjectKey,
          subject: request.body.subject,
          eventSubject,
          verified: request.body.verified ?? true,
        },
        SSF_STREAM_SUBJECTS_MAX
      );
      if (added === 'full') {
        throw new BadRequestError(`A stream holds at most ${SSF_STREAM_SUBJECTS_MAX} subjects`);
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
        tags: TAGS,
        'x-qauth-stability': 'experimental',
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
        throw new BadRequestError('state must not be shaped like a token or a key');
      }
      const limitKey = REDIS_KEYS.SSF_VERIFICATION(receiver.realm.id, stream.id);
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
          if (!enqueued)
            throw new Error('ssf: the verification event was not queued for its stream');
        })
        .catch(release);
      reply.code(204);
      return reply.send(null);
    }
  );
}
