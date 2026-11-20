import { randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { WebhookSecrets } from '@qauth-labs/fastify-plugin-signer';
import {
  NotFoundError,
  PreconditionFailedError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import { webhookTest } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import {
  ifMatchHeadersSchema,
  MERGE_PATCH_MEDIA_TYPE,
  requireMergePatch,
} from '../../api-conventions/conditional-requests';
import { readPage } from '../../api-conventions/cursor';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { emitUserEvent } from '../../helpers/user-events';
import { WebhookSubscriptionDisabledError } from '../../helpers/webhook-errors';
import { requestClassification } from '../../plugins/admin-operations';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  adminEventActor,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { fitsApprovalLine } from './approval-lines';
import {
  assertWebhookDestination,
  assertWebhookUpdate,
  createSettingsOf,
  eventTypeProblems,
  MAX_LISTED_EVENT_TYPES,
  MAX_SECRET_OVERLAP_SECONDS,
  overlapSecondsOf,
  readWebhookSubscriptionState,
  WEBHOOK_CATEGORIES,
  WEBHOOK_OPERATION_IDS,
  WEBHOOK_SUBSCRIPTION_ENTITY,
  type WebhookSettings,
} from './operations';
import {
  type AdminWebhookSubscription,
  adminWebhookSubscriptionOf,
  adminWebhookSubscriptionSchema,
  adminWebhookSubscriptionVersion,
  adminWebhookSubscriptionWithSecretSchema,
  ALL_EVENT_TYPES,
  DISABLED_BY_ADMIN,
  type WebhookSubscriptionRecord,
} from './representation';

/**
 * THE WEBHOOK SUBSCRIPTION ROUTES OF THE ADMIN API (ADR-018 §3, ADR-019
 * Decisions 7 to 9, issue #537):
 *
 *   GET    /admin/v1-rc.0/realms/{realmId}/webhooks                                 — webhooks.list
 *   POST   /admin/v1-rc.0/realms/{realmId}/webhooks                                 — webhooks.create, the secret answered once
 *   GET    /admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}                — webhooks.get, with its ETag
 *   PATCH  /admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}                — webhooks.update,
 *                                                                                     a JSON Merge Patch, If-Match required
 *   DELETE /admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}                — webhooks.delete, If-Match required
 *   POST   /admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}/rotate-secret  — webhooks.rotateSecret, the secret answered once
 *   POST   /admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}/test           — webhooks.test, 202
 *
 * A subscription of another realm is 404, as one that does not exist. The
 * operations that generate, rotate or delete a signing secret go through the
 * signer's custody (`fastify.webhookSecrets`), in the call's transaction, so
 * the keys and the row commit together; a process that holds no KEK answers
 * them 503.
 *
 * Every handler that writes reads the subscription again under
 * `FOR NO KEY UPDATE` in its transaction; an update and a deletion write only
 * while it is the version the call was classified and approved against (412
 * otherwise). The call's audit row records the change, before and after,
 * with the secret masked, and commits with it.
 */

const WEBHOOKS_PATH = '/admin/v1-rc.0/realms/:realmId/webhooks';
const WEBHOOK_PATH = `${WEBHOOKS_PATH}/:subscriptionId`;

/** The cursors of the admin webhook subscription list carry this name. */
const WEBHOOK_LIST = 'admin.webhooks';

/** The longest URL a subscription takes, in characters, as given and as stored. */
const URL_MAX_LENGTH = 2048;
/** The longest description a subscription takes, in characters. */
const DESCRIPTION_MAX_LENGTH = 500;
/** The longest event type identifier a list takes. */
const EVENT_TYPE_MAX_LENGTH = 255;

const realmParams = z.object({ realmId: z.uuid() });
const subscriptionParams = z.object({ realmId: z.uuid(), subscriptionId: z.uuid() });

/** A JSON Pointer of the operations' problems as a Zod issue path. */
const pathOf = (pointer: string): (string | number)[] =>
  pointer === ''
    ? []
    : pointer
        .slice(1)
        .split('/')
        .map((part) => (/^\d+$/.test(part) ? Number(part) : part));

/**
 * The destination: an absolute `https` URL, with no user name or password
 * and no fragment. Whether its host resolves to public addresses is the
 * egress client's check, in the handler (422).
 */
const webhookUrlSchema = z
  .string()
  .min(1)
  .max(URL_MAX_LENGTH)
  .superRefine((value, context) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      context.addIssue({ code: 'custom', message: 'url must be an absolute https URL' });
      return;
    }
    if (url.protocol !== 'https:') {
      context.addIssue({ code: 'custom', message: 'url must be an https URL' });
    }
    if (url.username !== '' || url.password !== '') {
      context.addIssue({
        code: 'custom',
        message: 'url must not carry a user name or password',
      });
    }
    if (value.includes('#')) {
      context.addIssue({ code: 'custom', message: 'url must not carry a fragment' });
    }
    if (url.href.length > URL_MAX_LENGTH) {
      context.addIssue({
        code: 'custom',
        message: `url is longer than ${URL_MAX_LENGTH} characters once serialized`,
      });
    }
  })
  .meta({
    description:
      'The destination every delivery is POSTed to: an absolute https URL with no user name, password or fragment, whose host resolves only to public addresses unless the deployment egress allowlist opens it for the realm.',
  });

/** C0 controls and DEL: a description holds none. */
// eslint-disable-next-line no-control-regex -- matching control characters is the entire purpose of this pattern
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;

const descriptionSchema = z
  .string()
  .min(1)
  .max(DESCRIPTION_MAX_LENGTH)
  .refine((value) => !CONTROL_CHARACTERS.test(value), {
    message: 'description must not hold a control character',
  })
  .refine(fitsApprovalLine, {
    message:
      'description is too long to show an approver in full: an approval shows every value whole',
  })
  .meta({ description: 'What the subscription is for, shown to admins and approvers.' });

const eventTypesSchema = z
  .union([
    z.literal(ALL_EVENT_TYPES),
    z.array(z.string().min(1).max(EVENT_TYPE_MAX_LENGTH)).min(1).max(MAX_LISTED_EVENT_TYPES),
  ])
  .meta({
    description:
      'all, every type of the categories, or the event types sent, each by its identifier (urn:qauth:event:<name>:<version>), each registered and of a listed category. webhook.test is never listed: webhooks.test sends it.',
  });

const categoriesSchema = z
  .array(z.enum(WEBHOOK_CATEGORIES))
  .min(1)
  .max(WEBHOOK_CATEGORIES.length)
  .meta({
    description:
      'The event categories sent: user, the events of what people and clients do, and admin, the changes admins make, each diff masked.',
  });

/**
 * The body of a create. `eventTypes` defaults to all, `enabled` to true.
 * One instance, so the document holds it once.
 */
export const webhookCreateBodySchema = z
  .strictObject({
    url: webhookUrlSchema,
    description: descriptionSchema.nullable().optional(),
    eventTypes: eventTypesSchema.optional(),
    categories: categoriesSchema,
    enabled: z.boolean().optional(),
  })
  .superRefine((body, context) => {
    for (const problem of eventTypeProblems(body.eventTypes ?? ALL_EVENT_TYPES, body.categories)) {
      context.addIssue({ code: 'custom', message: problem.message, path: pathOf(problem.pointer) });
    }
  })
  .meta({ id: 'AdminWebhookSubscriptionCreateRequest' });

/**
 * The body of an update: a JSON Merge Patch (RFC 7396). Each member named
 * replaces the stored one whole; `description: null` removes the
 * description, and `null` for any other member is refused (422): it has no
 * default to be removed to. No other member (400).
 */
export const webhookPatchBodySchema = z
  .strictObject({
    url: webhookUrlSchema.nullable().optional(),
    description: descriptionSchema.nullable().optional(),
    eventTypes: eventTypesSchema.nullable().optional(),
    categories: categoriesSchema.nullable().optional(),
    enabled: z.boolean().nullable().optional(),
  })
  .meta({ id: 'AdminWebhookSubscriptionPatch' });

/**
 * The body of a rotation: the overlap, in seconds, during which the old
 * secret signs beside the new one; 86400 (24 hours) when left out, 0 to stop
 * the old one now. No body is the default overlap. Either way a signer node
 * sees the change when it next reads the subscription's keys, within a
 * minute.
 */
export const webhookRotateBodySchema = z
  .strictObject({
    overlapSeconds: z.int().min(0).max(MAX_SECRET_OVERLAP_SECONDS).optional().meta({
      description:
        'How long the old secret keeps signing beside the new one, in seconds: 86400 (24 hours) when left out, at most 604800 (7 days); 0 stops it now, as after a leak. A signer node reads a subscription’s keys again within a minute, so the change reaches every delivery within that minute.',
    }),
  })
  .nullable()
  .optional()
  .meta({ id: 'AdminWebhookSecretRotationRequest' });

/**
 * No body, or an empty object. A call that sends no body reaches the handler
 * with `null` (Fastify), as the approval it carries files it (`null` too).
 */
const deleteBody = z.strictObject({}).nullable().optional().meta({
  id: 'AdminWebhookSubscriptionDeleteRequest',
  description: 'No body, or an empty object.',
});

const testBody = z
  .strictObject({})
  .nullable()
  .optional()
  .meta({ id: 'AdminWebhookTestRequest', description: 'No body, or an empty object.' });

const testQueuedSchema = z
  .object({
    eventId: z.uuid().meta({
      description:
        "The test event's id, which its delivery carries as the webhook-id header and as the body's id.",
    }),
  })
  .meta({ id: 'AdminWebhookTestQueued' });

const subscriptionPageSchema = pageSchema(adminWebhookSubscriptionSchema).meta({
  id: 'AdminWebhookSubscriptionPage',
});

/** The `ETag` of a subscription. */
const etagOf = (subscription: AdminWebhookSubscription): string =>
  `"${adminWebhookSubscriptionVersion(subscription)}"`;

/** The stored event types of `settings`: `null` for all. */
const storedEventTypes = (eventTypes: WebhookSettings['eventTypes']): string[] | null =>
  eventTypes === ALL_EVENT_TYPES ? null : [...eventTypes];

/** The signer's custody of the subscriptions' secrets on this process, or 503 when it holds no KEK. */
function secretCustody(request: FastifyRequest, operationId: string): WebhookSecrets {
  const secrets = request.server.webhookSecrets;
  if (secrets === null || secrets === undefined) {
    throw new TemporarilyUnavailableError(60, {
      reason: 'signer_service_not_reachable',
      operation: operationId,
    });
  }
  return secrets;
}

/** The subscription the path names, locked in the call's transaction, or 404. */
async function lockedSubscription(
  request: FastifyRequest,
  realmId: string,
  subscriptionId: string
): Promise<WebhookSubscriptionRecord> {
  const row = await request.server.repositories.webhookSubscriptions.findByIdForUpdate(
    realmId,
    subscriptionId,
    adminTransaction(request)
  );
  if (row === undefined) throw new NotFoundError(WEBHOOK_SUBSCRIPTION_ENTITY, subscriptionId);
  return row;
}

/**
 * The subscription as the call was classified, and approved, against: read
 * again under the lock in the call's transaction. A change in between is 412.
 */
async function classifiedSubscription(
  request: FastifyRequest,
  operationId: string,
  realmId: string,
  subscriptionId: string
): Promise<{ readonly row: WebhookSubscriptionRecord; readonly state: AdminWebhookSubscription }> {
  const row = await lockedSubscription(request, realmId, subscriptionId);
  const state = adminWebhookSubscriptionOf(row);
  if (adminWebhookSubscriptionVersion(state) !== requestClassification(request).stateVersion) {
    throw new PreconditionFailedError({ operation: operationId });
  }
  return { row, state };
}

/** The webhook operations, by their key in {@link WEBHOOK_OPERATION_IDS}. */
type WebhookOperations = Record<keyof typeof WEBHOOK_OPERATION_IDS, AdminOperation>;

/**
 * The webhook operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * webhook route, and the server's own registry (`OPERATION_REGISTRY`) holds
 * them all.
 *
 * @throws {Error} when it holds some and not the others
 */
function webhookOperations(fastify: FastifyInstance): WebhookOperations | undefined {
  const entries = Object.entries(WEBHOOK_OPERATION_IDS).map(
    ([key, id]) => [key, fastify.adminApi.registry.get(id)] as const
  );
  const missing = entries.filter(([, operation]) => operation === undefined);
  if (missing.length === entries.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `The admin operation registry holds only some webhook operations; it lacks ${missing
        .map(([key]) => WEBHOOK_OPERATION_IDS[key as keyof typeof WEBHOOK_OPERATION_IDS])
        .join(', ')}`
    );
  }
  return Object.fromEntries(entries) as WebhookOperations;
}

/** Register the webhook subscription routes behind the admin pipeline. */
export const webhookRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = webhookOperations(fastify);
  if (operations === undefined) return;
  const common = {
    'x-qauth-stability': 'experimental' as const,
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
  };

  typed.get(
    WEBHOOKS_PATH,
    {
      config: { operation: operations.list.id },
      schema: {
        ...operationSchemaExtensions(operations.list),
        ...common,
        summary: 'List the webhook subscriptions of a realm',
        description:
          'Every webhook subscription of the realm, newest first, one page at a time: each destination, the events it receives, whether it is enabled and its delivery failures. No answer carries a signing secret.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        querystring: pageQuerySchema,
        response: { 200: subscriptionPageSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const tx = adminTransaction(request);
      const { limit, cursor } = request.query;
      const page = await readPage(
        {
          list: WEBHOOK_LIST,
          limit,
          cursor,
          position: (row: WebhookSubscriptionRecord) => ({ at: row.createdAt, id: row.id }),
          item: adminWebhookSubscriptionOf,
        },
        (keyset) =>
          request.server.repositories.webhookSubscriptions.pageByRealm(realmId, keyset, tx)
      );
      reply.header('cache-control', 'no-store');
      return page;
    }
  );

  typed.get(
    WEBHOOK_PATH,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: 'Read a webhook subscription',
        description:
          'The ETag is the version of the subscription: an update and a deletion name it in If-Match. The answer never carries the signing secret.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: subscriptionParams,
        response: { 200: adminWebhookSubscriptionSchema },
      },
    },
    async (request, reply) => {
      const subscription = await readWebhookSubscriptionState(
        request.server,
        requestAdminCaller(request).targetRealm.id,
        request.params.subscriptionId,
        adminTransaction(request)
      );
      reply.header('etag', etagOf(subscription)).header('cache-control', 'no-store');
      return subscription;
    }
  );

  typed.post(
    WEBHOOKS_PATH,
    {
      config: { operation: operations.create.id },
      schema: {
        ...operationSchemaExtensions(operations.create),
        ...common,
        summary: 'Add a webhook subscription',
        description:
          "Adds a webhook subscription: the realm's events of the categories it lists, and of the event types it lists (all by default), are sent to its URL as Standard Webhooks, signed with its secret. The secret is generated in the signer and answered here once, in the whsec_ form; no later answer, event, log or audit diff shows it. The URL must be https, carry no user name, password or fragment (400), and name a host that resolves only to public addresses unless the deployment egress allowlist opens it for the realm (422). A security operation: it needs webhooks.security and an approval, filed with approvals.create for this body. 503 when this process holds no signer.",
        'x-qauth-errors': [400, 401, 403, 404, 422, 503],
        params: realmParams,
        body: webhookCreateBodySchema,
        response: { 201: adminWebhookSubscriptionWithSecretSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const realm = caller.targetRealm;
      const secrets = secretCustody(request, operations.create.id);
      const settings = createSettingsOf(request.body);
      await assertWebhookDestination(request.server, settings.url, realm.name);

      const tx = adminTransaction(request);
      const id = randomUUID();
      const generated = await secrets.create({ realmId: realm.id, subscriptionId: id, tx });
      const row = await request.server.repositories.webhookSubscriptions.create(
        realm.id,
        {
          id,
          url: settings.url,
          description: settings.description,
          eventTypes: storedEventTypes(settings.eventTypes),
          categories: [...settings.categories],
          enabled: settings.enabled,
          disabledReason: settings.enabled ? null : DISABLED_BY_ADMIN,
          secretRef: generated.kid,
          createdBy: caller.userId,
        },
        tx
      );
      const subscription = adminWebhookSubscriptionOf(row);
      // The secret is in the change only to show that one was set: the
      // audit log masks it before it stores the diff.
      recordAdminChange(request, {
        change: { before: null, after: { ...subscription, secret: generated.secret } },
        annotations: { secret: 'secret' },
      } as AdminChange);
      reply
        .code(201)
        .header('etag', etagOf(subscription))
        .header('location', `/admin/v1-rc.0/realms/${realm.id}/webhooks/${id}`)
        .header('cache-control', 'no-store');
      return { ...subscription, secret: generated.secret };
    }
  );

  typed.patch(
    WEBHOOK_PATH,
    {
      config: { operation: operations.update.id },
      // After the pipeline's stages: a route of the admin listener has no
      // early hook of its own.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.update),
        ...common,
        summary: 'Change a webhook subscription',
        description:
          'A JSON Merge Patch (RFC 7396) of the subscription: url, description, eventTypes, categories and enabled, when named, replace the stored value whole; description: null removes the description, and null removes no other member (422). A new URL is checked as at creation (400, 422). Event types its categories would never send are refused (422). Disabling marks the subscription disabled_by_admin; enabling it again starts its consecutive failure count anew. The signing secret does not change: webhooks.rotateSecret rotates it. A security operation, a narrowing too: it needs webhooks.security and an approval. If-Match names the ETag of the subscription (428 without it, 412 when it moved).',
        'x-qauth-errors': [400, 401, 403, 404, 412, 415, 422, 428],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: subscriptionParams,
        headers: ifMatchHeadersSchema,
        body: webhookPatchBodySchema,
        response: { 200: adminWebhookSubscriptionSchema },
      },
    },
    async (request, reply) => {
      const realm = requestAdminCaller(request).targetRealm;
      const tx = adminTransaction(request);
      const { row, state } = await classifiedSubscription(
        request,
        operations.update.id,
        realm.id,
        request.params.subscriptionId
      );
      const settings = assertWebhookUpdate(state, request.body);
      // Checked again here: the name may resolve elsewhere since the
      // approval was filed.
      if (settings.url !== state.url) {
        await assertWebhookDestination(request.server, settings.url, realm.name);
      }
      let after = state;
      const current = {
        url: state.url,
        description: state.description,
        eventTypes: state.eventTypes,
        categories: state.categories,
        enabled: state.enabled,
      };
      if (!isDeepStrictEqual(current, settings)) {
        const disabledReason = settings.enabled
          ? null
          : state.enabled
            ? DISABLED_BY_ADMIN
            : (row.disabledReason ?? DISABLED_BY_ADMIN);
        const updated = await request.server.repositories.webhookSubscriptions.update(
          realm.id,
          row.id,
          {
            url: settings.url,
            description: settings.description,
            eventTypes: storedEventTypes(settings.eventTypes),
            categories: [...settings.categories],
            enabled: settings.enabled,
            disabledReason,
          },
          { expectedVersion: row.version, resetFailures: settings.enabled && !state.enabled },
          tx
        );
        if (updated === undefined) {
          throw new PreconditionFailedError({ operation: operations.update.id });
        }
        after = adminWebhookSubscriptionOf(updated);
      }
      recordAdminChange(request, {
        change: { before: state, after },
        annotations: {},
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return after;
    }
  );

  typed.delete(
    WEBHOOK_PATH,
    {
      config: { operation: operations.delete.id },
      schema: {
        ...operationSchemaExtensions(operations.delete),
        ...common,
        summary: 'Delete a webhook subscription',
        description:
          'Deletes the subscription with its signing secrets, in one transaction: no event is sent to its URL from now on, and nothing queued for it can be signed. A security operation: it needs webhooks.security and an approval, filed against the subscription as it stands; If-Match names its ETag (428 without it, 412 when it moved). 503 when this process holds no signer.',
        'x-qauth-errors': [400, 401, 403, 404, 412, 428, 503],
        params: subscriptionParams,
        headers: ifMatchHeadersSchema,
        // No body; an approval binds the request as it is sent, so one that
        // sends `{}` is approved only as filed with `{}`.
        body: deleteBody,
        response: { 204: z.null().meta({ description: 'The subscription is deleted.' }) },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const secrets = secretCustody(request, operations.delete.id);
      const tx = adminTransaction(request);
      const { row, state } = await classifiedSubscription(
        request,
        operations.delete.id,
        realmId,
        request.params.subscriptionId
      );
      await secrets.delete({ realmId, subscriptionId: row.id, tx });
      const removed = await request.server.repositories.webhookSubscriptions.delete(
        realmId,
        row.id,
        row.version,
        tx
      );
      if (!removed) throw new PreconditionFailedError({ operation: operations.delete.id });
      recordAdminChange(request, {
        change: { before: state, after: null },
        annotations: {},
      } as AdminChange);
      reply.code(204);
      return undefined;
    }
  );

  typed.post(
    `${WEBHOOK_PATH}/rotate-secret`,
    {
      config: { operation: operations.rotateSecret.id },
      schema: {
        ...operationSchemaExtensions(operations.rotateSecret),
        ...common,
        summary: "Rotate a webhook subscription's signing secret",
        description:
          'Generates a new signing secret in the signer and answers it here once, in the whsec_ form. For the overlap the request names (24 hours by default, at most 7 days) the old secret keeps signing beside the new one, so each delivery carries both signatures and the receiver can switch without a gap; previousSecretExpiresAt says when the old one stops. overlapSeconds 0 stops it now, as after a leak. Each signer node reads the subscription’s keys again within a minute, so a delivery signed in that minute may still carry only the old signature: a receiver keeps the old secret that long. A rotation during an overlap ends that overlap first, so at most two secrets ever sign. A security operation: it needs webhooks.security and an approval. 503 when this process holds no signer.',
        'x-qauth-errors': [400, 401, 403, 404, 503],
        params: subscriptionParams,
        body: webhookRotateBodySchema,
        response: { 200: adminWebhookSubscriptionWithSecretSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const secrets = secretCustody(request, operations.rotateSecret.id);
      const tx = adminTransaction(request);
      const row = await lockedSubscription(request, realmId, request.params.subscriptionId);
      const before = adminWebhookSubscriptionOf(row);
      const overlapSeconds = overlapSecondsOf(request.body);
      const rotated = await secrets.rotate({
        realmId,
        subscriptionId: row.id,
        overlap: overlapSeconds > 0,
        tx,
      });
      const updated = await request.server.repositories.webhookSubscriptions.recordSecretRotation(
        realmId,
        row.id,
        {
          secretRef: rotated.kid,
          previousSecretExpiresAt: overlapSeconds > 0 ? Date.now() + overlapSeconds * 1000 : null,
        },
        row.version,
        tx
      );
      // The row is locked since it was read: no other writer moved it.
      if (updated === undefined) {
        throw new Error('The webhook subscription changed under its own lock');
      }
      const after = adminWebhookSubscriptionOf(updated);
      // As at creation, the secret is in the change only to show that it
      // changed; the audit log masks it.
      recordAdminChange(request, {
        change: { before, after: { ...after, secret: rotated.secret } },
        annotations: { secret: 'secret' },
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return { ...after, secret: rotated.secret };
    }
  );

  typed.post(
    `${WEBHOOK_PATH}/test`,
    {
      config: { operation: operations.test.id },
      schema: {
        ...operationSchemaExtensions(operations.test),
        ...common,
        summary: 'Send a test event to a webhook subscription',
        description:
          'Queues a webhook.test event, with no data, for this subscription and no other: it is delivered and signed like every other event, so the receiver can check that it gets and verifies the realm’s webhooks. The answer names the event’s id; the delivery follows. Until this server sends webhooks (a later release), the delivery waits in the queue, and the realm’s event retention keeps every event from it on. A disabled subscription is refused (409): nothing would be sent. A security operation: it needs webhooks.security and an approval.',
        'x-qauth-errors': [400, 401, 403, 404, 409],
        params: subscriptionParams,
        body: testBody,
        response: { 202: testQueuedSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const realmId = caller.targetRealm.id;
      const tx = adminTransaction(request);
      const row = await lockedSubscription(request, realmId, request.params.subscriptionId);
      if (!row.enabled) throw new WebhookSubscriptionDisabledError();
      const eventId = await emitUserEvent(
        request,
        webhookTest.type,
        {},
        {
          tx,
          realmId,
          subject: { type: 'webhook_subscription', id: row.id },
          actor: adminEventActor(caller),
        }
      );
      const queued = await request.server.repositories.webhookSubscriptions.enqueueForEvent(tx, {
        subscriptionId: row.id,
        eventId,
        now: Date.now(),
      });
      if (!queued) {
        throw new Error('The test event was not queued for its own subscription');
      }
      recordAdminChange(request, {
        change: { before: null, after: { subscription: row.id, event: eventId } },
        annotations: {},
      } as AdminChange);
      reply.code(202).header('cache-control', 'no-store');
      return { eventId };
    }
  );
};
