import { isEgressError } from '@qauth-labs/fastify-plugin-egress';
import { NotFoundError } from '@qauth-labs/shared-errors';
import { EVENT_TYPES, getEventType, webhookTest } from '@qauth-labs/shared-events';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import type {
  AdminOperationDefinition,
  ClassifyInput,
  RenderedOperation,
  RenderInput,
} from '../../helpers/admin-operations';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import { changeLines, settingsLines, type WebhookShownSettings } from './approval-lines';
import {
  type AdminWebhookSubscription,
  adminWebhookSubscriptionOf,
  adminWebhookSubscriptionVersion,
  ALL_EVENT_TYPES,
} from './representation';

/**
 * THE WEBHOOK SUBSCRIPTION OPERATIONS OF THE ADMIN API (ADR-018 §3, ADR-019
 * Decisions 7 to 9, ADR-020 §4, issue #537): list and read a realm's webhook
 * subscriptions, add one, change it, delete it, rotate its signing secret and
 * send it a test event.
 *
 * A subscription sends the realm's events, signed, to a destination an admin
 * chooses, so every write is a security operation with the effect
 * `token-content`, reserved in `admin-operations-reserved.ts`: each request
 * needs `webhooks.security`, so `qauth:admin:security`, and an approval.
 * `qauth:admin:write` reaches none of them. `webhooks.list` and
 * `webhooks.get` are reads (`webhooks.read`, `qauth:admin:read`).
 *
 * - The destination is an `https` URL with no user name or password (the
 *   body schema refuses any other, 400, before an approval is filed), whose
 *   host resolves only to public addresses unless the deployment's egress
 *   allowlist opens it for the realm (the egress client, 422): checked when
 *   it is set, and again before every delivery by the sender.
 * - The signing secret is generated in the signer, in the Standard Webhooks
 *   form, and returned once, by `webhooks.create` and
 *   `webhooks.rotateSecret`; the audit row and the admin event show it as
 *   `***`. A rotation keeps the replaced secret signing beside the new one
 *   for its overlap, 24 hours unless the request says otherwise.
 * - `webhooks.update` takes a JSON Merge Patch and `webhooks.delete` names
 *   the version it removes: both read the subscription (`loadState`), whose
 *   row version is its `ETag`, which the request names in `If-Match`, and an
 *   approval approves the request against that version only.
 * - `webhooks.test` queues a `webhook.test` event for that subscription and
 *   no other.
 *
 * A subscription of another realm is 404, as one that does not exist.
 */

/** The ids of the webhook subscription operations. */
export const WEBHOOK_OPERATION_IDS = Object.freeze({
  list: 'webhooks.list',
  get: 'webhooks.get',
  create: 'webhooks.create',
  update: 'webhooks.update',
  delete: 'webhooks.delete',
  rotateSecret: 'webhooks.rotateSecret',
  test: 'webhooks.test',
} as const);

/** The egress purpose of a webhook destination: its checks and, later, its deliveries. */
export const WEBHOOK_EGRESS_PURPOSE = 'webhook';

/** The entity a missing subscription is named as. */
export const WEBHOOK_SUBSCRIPTION_ENTITY = 'WebhookSubscription';

/** How long a rotation's replaced secret keeps signing unless the request says otherwise: 24 hours. */
export const DEFAULT_SECRET_OVERLAP_SECONDS = 86_400;

/** The longest overlap a rotation takes: 7 days. */
export const MAX_SECRET_OVERLAP_SECONDS = 7 * 86_400;

/** The event categories a subscription receives. */
export const WEBHOOK_CATEGORIES = ['user', 'admin'] as const;

/** An event category a subscription receives. */
export type WebhookCategory = (typeof WEBHOOK_CATEGORIES)[number];

/** The repositories the state reads, with the transaction they read in. */
type StateServer = Pick<FastifyInstance, 'repositories'>;
type Transaction = Parameters<
  FastifyInstance['repositories']['webhookSubscriptions']['findById']
>[2];

/** RFC 9562: the form of the id the admin API names a subscription by. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The subscription `id` of the realm, as the admin API shows it, read in `tx`
 * when given.
 *
 * @throws NotFoundError when the realm has no such subscription: one of
 *   another realm is not found either
 */
export async function readWebhookSubscriptionState(
  server: StateServer,
  realmId: string,
  id: string,
  tx?: Transaction
): Promise<AdminWebhookSubscription> {
  if (!UUID.test(id)) throw new NotFoundError(WEBHOOK_SUBSCRIPTION_ENTITY, id);
  const row = await server.repositories.webhookSubscriptions.findById(realmId, id, tx);
  if (row === undefined) throw new NotFoundError(WEBHOOK_SUBSCRIPTION_ENTITY, id);
  return adminWebhookSubscriptionOf(row);
}

/** One refused member: a JSON Pointer into the body, and why. */
export interface WebhookProblem {
  readonly pointer: string;
  readonly message: string;
}

/** The event types a subscription may list: every registered type but `webhook.test`. */
const LISTABLE_EVENT_TYPES: ReadonlySet<string> = new Set(
  EVENT_TYPES.map((definition) => definition.type).filter((type) => type !== webhookTest.type)
);

/** The most event types one subscription lists: every type it may list. */
export const MAX_LISTED_EVENT_TYPES = LISTABLE_EVENT_TYPES.size;

/**
 * What is wrong with `eventTypes` beside `categories`: a type listed twice,
 * one the registry does not hold, `webhook.test` (sent only by
 * `webhooks.test`), and one of a category the subscription does not receive,
 * which would never be sent. Each as a JSON Pointer into the body.
 */
export function eventTypeProblems(
  eventTypes: typeof ALL_EVENT_TYPES | readonly string[],
  categories: readonly string[]
): WebhookProblem[] {
  const problems: WebhookProblem[] = [];
  const seenCategories = new Set<string>();
  categories.forEach((category, index) => {
    if (seenCategories.has(category)) {
      problems.push({ pointer: `/categories/${index}`, message: `${category} is listed twice` });
    }
    seenCategories.add(category);
  });
  if (eventTypes === ALL_EVENT_TYPES) return problems;
  const seen = new Set<string>();
  eventTypes.forEach((type, index) => {
    const pointer = `/eventTypes/${index}`;
    if (seen.has(type)) {
      problems.push({ pointer, message: `${type} is listed twice` });
      return;
    }
    seen.add(type);
    if (type === webhookTest.type) {
      problems.push({
        pointer,
        message: `${type} is sent only by webhooks.test, to the subscription it names: it is never listed`,
      });
      return;
    }
    if (!LISTABLE_EVENT_TYPES.has(type)) {
      problems.push({
        pointer,
        message: `${type} is not a registered event type: name each by its identifier, urn:qauth:event:<name>:<version>`,
      });
      return;
    }
    const category = getEventType(type)?.category;
    if (category !== undefined && !seenCategories.has(category)) {
      problems.push({
        pointer,
        message: `${type} is ${category === 'admin' ? 'an' : 'a'} ${category} event, a category the subscription does not receive: list ${category} in categories`,
      });
    }
  });
  return problems;
}

/** What a subscription's write sets. */
export interface WebhookSettings {
  readonly url: string;
  readonly description: string | null;
  readonly eventTypes: typeof ALL_EVENT_TYPES | readonly string[];
  readonly categories: readonly WebhookCategory[];
  readonly enabled: boolean;
}

/**
 * The URL as it is stored and shown: the WHATWG serialization, so the host is
 * in lower case and in ASCII, and dot segments are resolved. The body schema
 * parsed it already.
 */
export function normalisedUrl(url: string): string {
  return new URL(url).href;
}

/** A subscription's settings, plain copies. */
export function settingsOf(state: AdminWebhookSubscription): WebhookSettings {
  return {
    url: state.url,
    description: state.description,
    eventTypes: state.eventTypes === ALL_EVENT_TYPES ? ALL_EVENT_TYPES : [...state.eventTypes],
    categories: [...state.categories],
    enabled: state.enabled,
  };
}

/** A patch, as the route's schema parsed it. */
interface WebhookPatch {
  readonly url?: string | null;
  readonly description?: string | null;
  readonly eventTypes?: typeof ALL_EVENT_TYPES | readonly string[] | null;
  readonly categories?: readonly WebhookCategory[] | null;
  readonly enabled?: boolean | null;
}

const patchOf = (body: unknown): WebhookPatch =>
  (typeof body === 'object' && body !== null ? body : {}) as WebhookPatch;

/**
 * The settings `body`, a JSON Merge Patch (RFC 7396) of the subscription
 * `state`, gives it: each member the patch names replaces the stored one
 * whole; `description: null` removes the description. A member it leaves
 * out is kept. {@link webhookPatchProblems} refuses what it cannot apply.
 */
export function applyWebhookPatch(state: AdminWebhookSubscription, body: unknown): WebhookSettings {
  const patch = patchOf(body);
  const current = settingsOf(state);
  return {
    url: typeof patch.url === 'string' ? normalisedUrl(patch.url) : current.url,
    description: patch.description === undefined ? current.description : patch.description,
    eventTypes:
      patch.eventTypes === undefined || patch.eventTypes === null
        ? current.eventTypes
        : patch.eventTypes === ALL_EVENT_TYPES
          ? ALL_EVENT_TYPES
          : [...patch.eventTypes],
    categories:
      patch.categories === undefined || patch.categories === null
        ? current.categories
        : [...patch.categories],
    enabled: typeof patch.enabled === 'boolean' ? patch.enabled : current.enabled,
  };
}

/**
 * What is wrong with `body` as a patch of `state`, each as a JSON Pointer
 * into the body: a required member removed (`null`), and event types the
 * patched categories would never send.
 */
export function webhookPatchProblems(
  state: AdminWebhookSubscription,
  body: unknown
): WebhookProblem[] {
  const patch = patchOf(body) as Record<string, unknown>;
  const problems: WebhookProblem[] = [];
  for (const name of ['url', 'eventTypes', 'categories', 'enabled']) {
    if (Object.hasOwn(patch, name) && patch[name] === null) {
      problems.push({
        pointer: `/${name}`,
        message:
          name === 'eventTypes'
            ? 'eventTypes is required and has no default: send all for every type'
            : `${name} is required and has no default`,
      });
    }
  }
  if (problems.length > 0) return problems;
  const settings = applyWebhookPatch(state, body);
  return eventTypeProblems(settings.eventTypes, settings.categories);
}

/** The message of a refused change of a subscription. */
export const WEBHOOK_CHANGE_REFUSED_MESSAGE = 'The webhook subscription change was refused.';

/**
 * Refuse a patch {@link webhookPatchProblems} refuses, and answer the
 * settings it gives.
 *
 * @throws UnprocessableContentError naming each refused member
 */
export function assertWebhookUpdate(
  state: AdminWebhookSubscription,
  body: unknown
): WebhookSettings {
  const problems = webhookPatchProblems(state, body);
  if (problems.length > 0) {
    throw new UnprocessableContentError(problems, WEBHOOK_CHANGE_REFUSED_MESSAGE);
  }
  return applyWebhookPatch(state, body);
}

/** The message of a destination the egress client refused. */
export const WEBHOOK_DESTINATION_REFUSED_MESSAGE = 'The webhook destination was refused.';

/** What a refused destination answers, by the egress client's reason. */
function destinationMessage(reason: string): string {
  if (reason === 'scheme') return 'url must be an https URL';
  if (reason === 'credentials') return 'url must not carry a user name or password';
  // Whether the name did not resolve or resolved to a private address is
  // kept in the server's log (the egress client logs it): told apart, the
  // two would show which names resolve inside QAuth's network.
  return 'url must name a host that resolves, and only to public addresses, unless the deployment egress allowlist opens it for this realm';
}

/**
 * Check `url` as a destination an admin of `realmName` sets, through the
 * egress client (ADR-019 Decision 8): `https`, no credentials, and a host
 * whose every address is public, unless the deployment allowlist names it
 * for the realm. Nothing is sent. The sender checks again before every
 * delivery.
 *
 * @throws UnprocessableContentError naming `/url` when the client refuses it
 */
export async function assertWebhookDestination(
  server: Pick<FastifyInstance, 'egress'>,
  url: string,
  realmName: string
): Promise<void> {
  try {
    await server.egress.validateDestination(url, {
      purpose: WEBHOOK_EGRESS_PURPOSE,
      source: 'admin',
      realm: realmName,
    });
  } catch (error) {
    if (!isEgressError(error)) throw error;
    throw new UnprocessableContentError(
      [{ pointer: '/url', message: destinationMessage(error.reason) }],
      WEBHOOK_DESTINATION_REFUSED_MESSAGE
    );
  }
}

/** The caller the authority stage resolved, read off the pipeline's state. */
function pipelineCaller(request: FastifyRequest, operationId: string) {
  // Not through the pipeline module, which imports the registry.
  const caller = request.adminPipeline?.authority;
  if (caller === undefined) {
    throw new Error(`${operationId} reads its subscription only behind the admin pipeline`);
  }
  return caller;
}

/** The subscription the request's path names, in the caller's realm. */
async function subscriptionOfRequest(
  request: FastifyRequest,
  input: ClassifyInput,
  operationId: string
): Promise<AdminWebhookSubscription> {
  const caller = pipelineCaller(request, operationId);
  const { subscriptionId } = (input.params ?? {}) as { subscriptionId?: unknown };
  if (typeof subscriptionId !== 'string') {
    throw new NotFoundError(WEBHOOK_SUBSCRIPTION_ENTITY, String(subscriptionId));
  }
  // Inside a handler (approvals.create files the request from its own), the
  // read takes the handler's transaction (#887).
  return readWebhookSubscriptionState(
    request.server,
    caller.targetRealm.id,
    subscriptionId,
    request.adminPipeline?.transaction
  );
}

/**
 * `webhooks.update`'s `loadState`: the subscription the path names, once the
 * patch is checked against it. A patch that removes a required member, lists
 * event types its categories never send, or names a destination the egress
 * client refuses is refused with 422 before it is filed for an approval.
 */
async function loadWebhookUpdateState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminWebhookSubscription> {
  const state = await subscriptionOfRequest(request, input, WEBHOOK_OPERATION_IDS.update);
  const settings = assertWebhookUpdate(state, input.body);
  if (settings.url !== state.url) {
    await assertWebhookDestination(
      request.server,
      settings.url,
      pipelineCaller(request, WEBHOOK_OPERATION_IDS.update).targetRealm.name
    );
  }
  return state;
}

/** `webhooks.delete`'s `loadState`: the subscription the path names. */
async function loadWebhookDeleteState(
  request: FastifyRequest,
  input: ClassifyInput
): Promise<AdminWebhookSubscription> {
  return subscriptionOfRequest(request, input, WEBHOOK_OPERATION_IDS.delete);
}

/** The version of a subscription state, as `stateVersion` gives it. */
const webhookStateVersion = (state: unknown): string =>
  adminWebhookSubscriptionVersion(state as AdminWebhookSubscription);

/** The settings a create body asks for, with its defaults. */
export function createSettingsOf(body: unknown): WebhookSettings {
  const fields = (typeof body === 'object' && body !== null ? body : {}) as {
    url?: unknown;
    description?: unknown;
    eventTypes?: unknown;
    categories?: unknown;
    enabled?: unknown;
  };
  return {
    url: typeof fields.url === 'string' ? normalisedUrl(fields.url) : '',
    description: typeof fields.description === 'string' ? fields.description : null,
    eventTypes: Array.isArray(fields.eventTypes)
      ? (fields.eventTypes as string[]).map(String)
      : ALL_EVENT_TYPES,
    categories: Array.isArray(fields.categories) ? (fields.categories as WebhookCategory[]) : [],
    enabled: fields.enabled !== false,
  };
}

/** The settings as the approval lines read them. */
const shown = (settings: WebhookSettings): WebhookShownSettings => settings;

/** What an approver is shown of a new subscription. */
function renderWebhookCreate(input: RenderInput): RenderedOperation {
  return {
    title: 'Add a webhook subscription',
    fields: [
      {
        label: 'effect',
        value:
          "The realm's events of the types and categories below are sent, signed, to the URL below. The signing secret is answered once, to the admin who sends the request.",
      },
      ...settingsLines(shown(createSettingsOf(input.body))),
    ],
  };
}

/**
 * What an approver is shown of an update: what the patch changes against the
 * subscription as it stood when the approval was filed (`RenderInput.state`),
 * each member beside the value it replaces.
 */
function renderWebhookUpdate(input: RenderInput): RenderedOperation {
  const state = input.state as AdminWebhookSubscription | undefined;
  if (state === undefined) {
    throw new Error('A webhook update is shown against the subscription it was filed against');
  }
  return {
    title: 'Change a webhook subscription',
    fields: changeLines(shown(settingsOf(state)), shown(applyWebhookPatch(state, input.body))),
  };
}

/** What an approver is shown of a deletion: the subscription, as it stood. */
function renderWebhookDelete(input: RenderInput): RenderedOperation {
  const state = input.state as AdminWebhookSubscription | undefined;
  if (state === undefined) {
    throw new Error('A deletion is shown against the subscription it was filed against');
  }
  return {
    title: 'Delete a webhook subscription',
    fields: [
      { label: 'subscription', value: state.id },
      ...settingsLines(shown(settingsOf(state))),
      {
        label: 'effect',
        value:
          'No event is sent to the URL from now on, and its signing secrets are deleted; a delivery already queued for it has no subscription to go to and no secret to sign with.',
      },
    ],
  };
}

/** The subscription a request's path names, as an approver is shown it. */
function subscriptionIdOf(input: RenderInput): string {
  const { subscriptionId } = (input.params ?? {}) as { subscriptionId?: unknown };
  return String(subscriptionId);
}

/** The overlap a rotation body asks for, in seconds. */
export function overlapSecondsOf(body: unknown): number {
  const overlap = (typeof body === 'object' && body !== null ? body : {}) as {
    overlapSeconds?: unknown;
  };
  return typeof overlap.overlapSeconds === 'number'
    ? overlap.overlapSeconds
    : DEFAULT_SECRET_OVERLAP_SECONDS;
}

/** What an approver is shown of a rotation: the subscription and the overlap. */
function renderWebhookRotateSecret(input: RenderInput): RenderedOperation {
  const overlap = overlapSecondsOf(input.body);
  return {
    title: "Rotate a webhook subscription's signing secret",
    fields: [
      { label: 'subscription', value: subscriptionIdOf(input) },
      {
        label: 'overlap',
        value:
          overlap === 0
            ? 'none: the old secret stops signing, as after a leak, within the minute a signer node takes to read the keys again'
            : `${overlap} seconds: the old secret signs beside the new one until then`,
      },
      {
        label: 'effect',
        value:
          'A new signing secret is generated and answered once, to the admin who sends the request.',
      },
    ],
  };
}

/** What an approver is shown of a test event. */
function renderWebhookTest(input: RenderInput): RenderedOperation {
  return {
    title: 'Send a test event to a webhook subscription',
    fields: [
      { label: 'subscription', value: subscriptionIdOf(input) },
      {
        label: 'effect',
        value: `A ${webhookTest.type} event, with no data, is queued for this subscription and no other.`,
      },
    ],
  };
}

/** The definitions, for `ADMIN_OPERATIONS` (`helpers/admin-operations.ts`). */
export const WEBHOOK_OPERATION_DEFINITIONS: readonly AdminOperationDefinition[] = Object.freeze([
  {
    id: WEBHOOK_OPERATION_IDS.list,
    class: 'read',
    effects: [],
    permissions: ['webhooks.read'],
    description:
      'List the webhook subscriptions of a realm, newest first, one page at a time: each destination, the events it receives, whether it is enabled and its delivery failures, never a signing secret.',
  },
  {
    id: WEBHOOK_OPERATION_IDS.get,
    class: 'read',
    effects: [],
    permissions: ['webhooks.read'],
    description: 'Read a webhook subscription of a realm, with its ETag; never its signing secret.',
  },
  {
    id: WEBHOOK_OPERATION_IDS.create,
    class: 'security',
    effects: ['token-content'],
    permissions: ['webhooks.security'],
    description:
      "Add a webhook subscription: the https destination the realm's events are sent to, the event types and categories it receives, a description and whether it is enabled. Its signing secret is generated in the signer and answered once.",
    render: renderWebhookCreate,
  },
  {
    id: WEBHOOK_OPERATION_IDS.update,
    class: 'security',
    effects: ['token-content'],
    permissions: ['webhooks.security'],
    description:
      'Change a webhook subscription with a JSON Merge Patch against the version it names: its destination, the event types and categories it receives, its description, or whether it is enabled.',
    loadState: loadWebhookUpdateState,
    stateVersion: webhookStateVersion,
    render: renderWebhookUpdate,
  } as AdminOperationDefinition,
  {
    id: WEBHOOK_OPERATION_IDS.delete,
    class: 'security',
    effects: ['token-content'],
    permissions: ['webhooks.security'],
    description:
      'Delete a webhook subscription against the version it names, with its signing secrets.',
    loadState: loadWebhookDeleteState,
    stateVersion: webhookStateVersion,
    render: renderWebhookDelete,
  } as AdminOperationDefinition,
  {
    id: WEBHOOK_OPERATION_IDS.rotateSecret,
    class: 'security',
    effects: ['token-content'],
    permissions: ['webhooks.security'],
    description:
      "Rotate a webhook subscription's signing secret: the new one is answered once, and the old one keeps signing beside it for the overlap the request names, 24 hours by default, or stops as soon as each signer node reads the keys again, within a minute.",
    render: renderWebhookRotateSecret,
  },
  {
    id: WEBHOOK_OPERATION_IDS.test,
    class: 'security',
    effects: ['token-content'],
    permissions: ['webhooks.security'],
    description:
      'Queue a webhook.test event for a webhook subscription, and for no other, so its receiver can check that it gets and verifies the realm’s webhooks.',
    render: renderWebhookTest,
  },
]);
