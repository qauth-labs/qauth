import { EgressError } from '@qauth-labs/fastify-plugin-egress';
import { NotFoundError } from '@qauth-labs/shared-errors';
import { EVENT_TYPES, webhookTest } from '@qauth-labs/shared-events';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { classifyRequest, OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { RESERVED_OPERATIONS } from '../../helpers/admin-operations-reserved';
import { BUILT_IN_ROLES } from '../../helpers/admin-roles';
import type { AdminRateLimitCheck } from '../pipeline';
import { changeLines, fitsApprovalLine, settingsLines, urlLines } from './approval-lines';
import {
  applyWebhookPatch,
  assertWebhookDestination,
  eventTypeProblems,
  MAX_LISTED_EVENT_TYPES,
  overlapSecondsOf,
  WEBHOOK_EGRESS_PURPOSE,
  WEBHOOK_OPERATION_IDS,
  webhookPatchProblems,
} from './operations';
import {
  type AdminWebhookSubscription,
  adminWebhookSubscriptionOf,
  adminWebhookSubscriptionSchema,
  adminWebhookSubscriptionVersion,
  type WebhookSubscriptionRecord,
} from './representation';
import { webhookCreateBodySchema, webhookPatchBodySchema, webhookRotateBodySchema } from './routes';

/**
 * The webhook subscription operations of the admin API (#537), without a
 * listener: their classification and permissions, the representation, the
 * bodies and their refusals, the patch, the destination check, what an
 * approver is shown, and the routes in the admin document. The routes behind
 * the pipeline, their approvals, the secrets and the writes are exercised
 * against real containers in `admin-webhooks.integration.test.ts`.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const SUBSCRIPTION = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e91';
const ADMIN = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e02';
const URL_A = 'https://hooks.example.com/qauth';

const USER_REGISTERED = 'urn:qauth:event:user.registered:v1-rc.0';
const CHANGE_APPLIED = 'urn:qauth:event:admin.change_applied:v1-rc.0';

/** A stored subscription, as the repository returns it. */
function row(overrides: Partial<WebhookSubscriptionRecord> = {}): WebhookSubscriptionRecord {
  return {
    id: SUBSCRIPTION,
    realmId: REALM,
    url: URL_A,
    description: 'CRM sync',
    eventTypes: [USER_REGISTERED],
    categories: ['user'],
    enabled: true,
    disabledReason: null,
    secretRef: 'whk-2026-11-01',
    previousSecretExpiresAt: null,
    consecutiveFailures: 0,
    failureCount: 4,
    lastFailureAt: Date.UTC(2026, 10, 3),
    createdBy: ADMIN,
    version: 3,
    createdAt: Date.UTC(2026, 10, 1),
    updatedAt: Date.UTC(2026, 10, 2),
    ...overrides,
  };
}

const subscription = (overrides: Partial<WebhookSubscriptionRecord> = {}) =>
  adminWebhookSubscriptionOf(row(overrides));

const operation = (id: string) => {
  const found = OPERATION_REGISTRY.get(id);
  if (found === undefined) throw new Error(`${id} is not registered`);
  return found;
};

const patch = (body: unknown) => ({
  method: 'PATCH',
  params: { realmId: REALM, subscriptionId: SUBSCRIPTION },
  query: {},
  body,
});

/** A request behind the pipeline whose repository answers `found`, and whose egress client answers `egress`. */
function pipelineRequest(
  found: WebhookSubscriptionRecord | undefined,
  egress: () => Promise<unknown> = async () => ({})
) {
  const findById = vi.fn(async () => found);
  const validateDestination = vi.fn(egress);
  const request = {
    adminPipeline: {
      authority: { targetRealm: { id: REALM, name: 'acme' } },
      transaction: 'tx',
    },
    server: {
      repositories: { webhookSubscriptions: { findById } },
      egress: { validateDestination },
    },
  } as unknown as FastifyRequest;
  return { request, findById, validateDestination };
}

const refusal = (reason: 'scheme' | 'credentials' | 'address' | 'network') =>
  new EgressError({
    reason,
    outcome: reason === 'network' ? 'failed' : 'blocked',
    purpose: WEBHOOK_EGRESS_PURPOSE,
    host: 'hooks.example.com',
    message: `refused: ${reason}`,
  });

describe('the webhook operations in the registry (#537)', () => {
  it('reads with webhooks.read, and writes as security operations with token-content', () => {
    const shape = Object.values(WEBHOOK_OPERATION_IDS).map((id) => {
      const entry = operation(id);
      return [entry.id, entry.class, entry.effects, entry.permissions];
    });
    expect(shape).toEqual([
      ['webhooks.list', 'read', [], ['webhooks.read']],
      ['webhooks.get', 'read', [], ['webhooks.read']],
      ['webhooks.create', 'security', ['token-content'], ['webhooks.security']],
      ['webhooks.update', 'security', ['token-content'], ['webhooks.security']],
      ['webhooks.delete', 'security', ['token-content'], ['webhooks.security']],
      ['webhooks.rotateSecret', 'security', ['token-content'], ['webhooks.security']],
      ['webhooks.test', 'security', ['token-content'], ['webhooks.security']],
    ]);
    expect(OPERATION_REGISTRY.permissions.get('webhooks.read')?.class).toBe('read');
    expect(OPERATION_REGISTRY.permissions.get('webhooks.security')?.class).toBe('security');
  });

  it('takes the reserved ids, none classifying: every request needs its declaration', () => {
    for (const id of [
      'webhooks.create',
      'webhooks.update',
      'webhooks.delete',
      'webhooks.rotateSecret',
      'webhooks.test',
    ]) {
      const entry = RESERVED_OPERATIONS.find((candidate) => candidate.id === id);
      expect(entry, id).toMatchObject({ effects: ['token-content'] });
      expect(entry?.requestDependent, id).toBeUndefined();
      expect(entry?.source, id).toContain('#537');
    }
    const classifying = Object.values(WEBHOOK_OPERATION_IDS).filter(
      (id) => operation(id).classify !== undefined
    );
    expect(classifying).toEqual([]);
  });

  it('gives the permissions to the built-in roles that hold the client ones', () => {
    for (const role of Object.values(BUILT_IN_ROLES)) {
      const held = new Set(role.permissionIds);
      expect(held.has('webhooks.read'), role.name).toBe(held.has('clients.read'));
      expect(held.has('webhooks.security'), role.name).toBe(held.has('clients.security'));
    }
  });

  it('classifies an update as a security change on every request, a narrowing too, bound to the version', () => {
    const state = subscription();
    for (const body of [{}, { enabled: false }, { description: null }]) {
      const result = classifyRequest(
        OPERATION_REGISTRY,
        operation(WEBHOOK_OPERATION_IDS.update),
        patch(body),
        state,
        adminWebhookSubscriptionVersion(state)
      );
      expect(result, JSON.stringify(body)).toMatchObject({
        class: 'security',
        effects: ['token-content'],
        permissions: ['webhooks.security'],
        stateVersion: '3',
        failedClosed: null,
      });
    }
  });
});

describe('the webhook subscription representation (#537)', () => {
  it('shows the destination, the events, the state, the failures and the version, and no secret', () => {
    const shown = subscription({ previousSecretExpiresAt: Date.UTC(2026, 10, 4) });
    expect(shown).toEqual({
      id: SUBSCRIPTION,
      url: URL_A,
      description: 'CRM sync',
      eventTypes: [USER_REGISTERED],
      categories: ['user'],
      enabled: true,
      disabledReason: null,
      previousSecretExpiresAt: '2026-11-04T00:00:00.000Z',
      failures: { consecutive: 0, total: 4, lastFailureAt: '2026-11-03T00:00:00.000Z' },
      createdBy: ADMIN,
      version: 3,
      createdAt: '2026-11-01T00:00:00.000Z',
      updatedAt: '2026-11-02T00:00:00.000Z',
    });
    expect(adminWebhookSubscriptionSchema.parse(shown)).toEqual(shown);
    expect(JSON.stringify(shown)).not.toContain('whk-2026-11-01');
    expect(Object.keys(adminWebhookSubscriptionSchema.shape)).not.toContain('secret');
  });

  it('shows all for every type, and the reason only while disabled', () => {
    expect(subscription({ eventTypes: null }).eventTypes).toBe('all');
    expect(
      subscription({ enabled: false, disabledReason: 'delivery_failures' }).disabledReason
    ).toBe('delivery_failures');
    expect(subscription({ enabled: true, disabledReason: 'stale' }).disabledReason).toBeNull();
  });

  it('copies the row, so a change of the representation never reaches it', () => {
    const stored = row();
    const shown = adminWebhookSubscriptionOf(stored);
    (shown.eventTypes as string[]).push('other');
    (shown.categories as string[]).push('admin');
    expect(stored.eventTypes).toEqual([USER_REGISTERED]);
    expect(stored.categories).toEqual(['user']);
  });
});

describe('the body of a webhook create (#537)', () => {
  const body = (overrides: Record<string, unknown> = {}) => ({
    url: URL_A,
    categories: ['user'],
    ...overrides,
  });
  const issues = (value: unknown) => {
    const result = webhookCreateBodySchema.safeParse(value);
    return result.success ? [] : result.error.issues.map((issue) => issue.message);
  };

  it('takes an https URL, its categories, and defaults for the rest', () => {
    expect(webhookCreateBodySchema.parse(body())).toEqual(body());
    expect(
      issues(body({ eventTypes: [USER_REGISTERED, CHANGE_APPLIED], categories: ['user', 'admin'] }))
    ).toEqual([]);
    expect(issues(body({ description: 'CRM sync', enabled: false, eventTypes: 'all' }))).toEqual(
      []
    );
  });

  it('refuses http, a user name or password, a fragment and what is not a URL, before anything is filed', () => {
    expect(issues(body({ url: 'http://hooks.example.com/qauth' }))).toEqual([
      'url must be an https URL',
    ]);
    expect(issues(body({ url: 'https://user:pass@hooks.example.com/qauth' }))).toEqual([
      'url must not carry a user name or password',
    ]);
    expect(issues(body({ url: 'https://token@hooks.example.com/qauth' }))).toEqual([
      'url must not carry a user name or password',
    ]);
    expect(issues(body({ url: 'https://hooks.example.com/qauth#x' }))).toEqual([
      'url must not carry a fragment',
    ]);
    expect(issues(body({ url: 'hooks.example.com/qauth' }))).toEqual([
      'url must be an absolute https URL',
    ]);
  });

  it('refuses an unknown, a repeated or a test event type, and one of a category not listed', () => {
    expect(issues(body({ eventTypes: ['urn:qauth:event:nope:v1-rc.0'] }))).toEqual([
      'urn:qauth:event:nope:v1-rc.0 is not a registered event type: name each by its identifier, urn:qauth:event:<name>:<version>',
    ]);
    expect(issues(body({ eventTypes: [USER_REGISTERED, USER_REGISTERED] }))).toEqual([
      `${USER_REGISTERED} is listed twice`,
    ]);
    expect(issues(body({ eventTypes: [webhookTest.type] }))[0]).toContain(
      'sent only by webhooks.test'
    );
    expect(issues(body({ eventTypes: [CHANGE_APPLIED] }))).toEqual([
      `${CHANGE_APPLIED} is an admin event, a category the subscription does not receive: list admin in categories`,
    ]);
    expect(issues(body({ categories: [] })).length).toBeGreaterThan(0);
    expect(issues(body({ categories: ['user', 'user'] }))).toEqual(['user is listed twice']);
    expect(issues(body({ eventTypes: [] })).length).toBeGreaterThan(0);
  });

  it('refuses a description with a control character or one an approver could not see whole, and any other member', () => {
    expect(issues(body({ description: 'line\nbreak' }))).toEqual([
      'description must not hold a control character',
    ]);
    // 200 code points the display escapes are longer than one line shows.
    expect(issues(body({ description: '​'.repeat(200) }))).toEqual([
      'description is too long to show an approver in full: an approval shows every value whole',
    ]);
    expect(issues(body({ secret: 'whsec_mine' })).length).toBeGreaterThan(0);
  });

  it('lists at most every type a subscription may list', () => {
    expect(MAX_LISTED_EVENT_TYPES).toBe(EVENT_TYPES.length - 1);
  });
});

describe('the body of a webhook update and of a rotation (#537)', () => {
  it('takes any member, null included, and nothing else', () => {
    expect(webhookPatchBodySchema.safeParse({ description: null }).success).toBe(true);
    expect(webhookPatchBodySchema.safeParse({ url: null }).success).toBe(true);
    expect(webhookPatchBodySchema.safeParse({ url: 'http://x.example' }).success).toBe(false);
    expect(webhookPatchBodySchema.safeParse({ version: 4 }).success).toBe(false);
  });

  it('takes no body, an empty one or an overlap of 0 to 7 days, 24 hours by default', () => {
    for (const body of [null, undefined, {}]) {
      expect(webhookRotateBodySchema.safeParse(body).success).toBe(true);
      expect(overlapSecondsOf(body)).toBe(86_400);
    }
    expect(overlapSecondsOf({ overlapSeconds: 0 })).toBe(0);
    expect(webhookRotateBodySchema.safeParse({ overlapSeconds: 604_800 }).success).toBe(true);
    expect(webhookRotateBodySchema.safeParse({ overlapSeconds: 604_801 }).success).toBe(false);
    expect(webhookRotateBodySchema.safeParse({ overlapSeconds: -1 }).success).toBe(false);
    expect(webhookRotateBodySchema.safeParse({ overlapSeconds: 1.5 }).success).toBe(false);
  });
});

describe('a merge patch of a webhook subscription (#537)', () => {
  it('replaces what it names, normalises a URL, clears a description, and keeps the rest', () => {
    const state = subscription();
    expect(applyWebhookPatch(state, {})).toEqual({
      url: URL_A,
      description: 'CRM sync',
      eventTypes: [USER_REGISTERED],
      categories: ['user'],
      enabled: true,
    });
    expect(
      applyWebhookPatch(state, {
        url: 'https://HOOKS.example.com/a/../b',
        description: null,
        eventTypes: 'all',
        enabled: false,
      })
    ).toEqual({
      url: 'https://hooks.example.com/b',
      description: null,
      eventTypes: 'all',
      categories: ['user'],
      enabled: false,
    });
  });

  it('refuses a required member removed, and event types the patched categories never send', () => {
    const state = subscription();
    expect(webhookPatchProblems(state, { url: null, enabled: null })).toEqual([
      { pointer: '/url', message: 'url is required and has no default' },
      { pointer: '/enabled', message: 'enabled is required and has no default' },
    ]);
    expect(webhookPatchProblems(state, { eventTypes: null })[0]?.message).toContain(
      'send all for every type'
    );
    expect(webhookPatchProblems(state, { eventTypes: [USER_REGISTERED, CHANGE_APPLIED] })).toEqual([
      {
        pointer: '/eventTypes/1',
        message: `${CHANGE_APPLIED} is an admin event, a category the subscription does not receive: list admin in categories`,
      },
    ]);
    expect(webhookPatchProblems(state, { categories: ['admin'] })).toEqual([
      {
        pointer: '/eventTypes/0',
        message: `${USER_REGISTERED} is a user event, a category the subscription does not receive: list user in categories`,
      },
    ]);
    expect(eventTypeProblems('all', ['admin'])).toEqual([]);
  });
});

describe('the destination check of a webhook subscription (#537)', () => {
  it('asks the egress client as an admin of the realm sets it, so the deployment allowlist may open it', async () => {
    const validateDestination = vi.fn(async () => ({}));
    await assertWebhookDestination({ egress: { validateDestination } } as never, URL_A, 'acme');
    expect(validateDestination).toHaveBeenCalledWith(URL_A, {
      purpose: 'webhook',
      source: 'admin',
      realm: 'acme',
    });
  });

  it('answers a refusal with 422 naming /url, one answer for a private and an unresolved host', async () => {
    const messages: string[] = [];
    for (const reason of ['scheme', 'credentials', 'address', 'network'] as const) {
      const validateDestination = vi.fn(async () => {
        throw refusal(reason);
      });
      const error = await assertWebhookDestination(
        { egress: { validateDestination } } as never,
        URL_A,
        'acme'
      ).catch((caught: unknown) => caught);
      expect(error, reason).toMatchObject({ statusCode: 422 });
      const fields = (error as { fields: { pointer: string; message: string }[] }).fields;
      expect(fields.map((field) => field.pointer)).toEqual(['/url']);
      messages.push(fields[0]?.message ?? '');
    }
    expect(messages[0]).toBe('url must be an https URL');
    expect(messages[1]).toBe('url must not carry a user name or password');
    expect(messages[2]).toBe(messages[3]);
    expect(messages[2]).toContain('only to public addresses');
  });

  it('throws on anything that is not the egress client’s refusal', async () => {
    const validateDestination = vi.fn(async () => {
      throw new TypeError('egress purpose');
    });
    await expect(
      assertWebhookDestination({ egress: { validateDestination } } as never, URL_A, 'acme')
    ).rejects.toBeInstanceOf(TypeError);
  });
});

describe('the state of a webhook operation (#537)', () => {
  it('is 404 for a subscription the realm does not have, one of another realm included', async () => {
    const { request, findById } = pipelineRequest(undefined);
    for (const id of [WEBHOOK_OPERATION_IDS.update, WEBHOOK_OPERATION_IDS.delete]) {
      await expect(operation(id).loadState?.(request, patch({}))).rejects.toBeInstanceOf(
        NotFoundError
      );
    }
    // Keyed by the realm of the path, in the handler's transaction.
    expect(findById).toHaveBeenCalledWith(REALM, SUBSCRIPTION, 'tx');
  });

  it('checks a new destination before the update is filed, and only a new one', async () => {
    const { request, validateDestination } = pipelineRequest(row(), async () => {
      throw refusal('address');
    });
    await expect(
      operation(WEBHOOK_OPERATION_IDS.update).loadState?.(
        request,
        patch({ url: 'https://10.0.0.5/hook' })
      )
    ).rejects.toMatchObject({ statusCode: 422 });
    expect(validateDestination).toHaveBeenCalledWith('https://10.0.0.5/hook', {
      purpose: 'webhook',
      source: 'admin',
      realm: 'acme',
    });
    validateDestination.mockClear();
    await expect(
      operation(WEBHOOK_OPERATION_IDS.update).loadState?.(request, patch({ enabled: false }))
    ).resolves.toMatchObject({ version: 3 });
    expect(validateDestination).not.toHaveBeenCalled();
    await expect(
      operation(WEBHOOK_OPERATION_IDS.update).loadState?.(request, patch({ categories: null }))
    ).rejects.toMatchObject({ statusCode: 422 });
  });
});

describe('what an approver is shown of a webhook operation (#537)', () => {
  const render = (id: string, body: unknown, state?: AdminWebhookSubscription) => {
    const entry = operation(id);
    if (entry.render === undefined) throw new Error(`${id} renders nothing`);
    return entry.render({
      operationId: id,
      method: 'POST',
      params: { realmId: REALM, subscriptionId: SUBSCRIPTION },
      query: {},
      body,
      ...(state === undefined ? {} : { state }),
    });
  };

  it('shows a create whole: the URL as it is stored, the categories, the types and whether it is enabled', () => {
    const shown = render(WEBHOOK_OPERATION_IDS.create, {
      url: 'https://HOOKS.example.com/qauth',
      categories: ['user'],
      eventTypes: [USER_REGISTERED],
    });
    expect(shown.title).toBe('Add a webhook subscription');
    expect(shown.fields?.slice(1)).toEqual([
      { label: 'url', value: URL_A },
      { label: 'description', value: '(none)' },
      { label: 'categories', value: 'user' },
      { label: 'event types', value: USER_REGISTERED },
      { label: 'enabled', value: 'yes' },
    ]);
  });

  it('shows an update as each member it changes, beside the value it replaces', () => {
    const shown = render(
      WEBHOOK_OPERATION_IDS.update,
      { url: 'https://other.example.com/hook', enabled: false, eventTypes: 'all' },
      subscription()
    );
    expect(shown.fields).toEqual([
      { label: 'url before', value: URL_A },
      { label: 'url', value: 'https://other.example.com/hook' },
      { label: 'event types before', value: USER_REGISTERED },
      { label: 'event types', value: 'every type of the categories' },
      { label: 'enabled', value: 'no', before: 'yes' },
    ]);
    expect(() => render(WEBHOOK_OPERATION_IDS.update, {})).toThrow(/filed against/);
  });

  it('shows a deletion, a rotation and a test by the subscription they act on', () => {
    expect(render(WEBHOOK_OPERATION_IDS.delete, null, subscription()).fields?.slice(0, 2)).toEqual([
      { label: 'subscription', value: SUBSCRIPTION },
      { label: 'url', value: URL_A },
    ]);
    const rotation = render(WEBHOOK_OPERATION_IDS.rotateSecret, { overlapSeconds: 0 });
    expect(rotation.fields?.[0]).toEqual({ label: 'subscription', value: SUBSCRIPTION });
    expect(rotation.fields?.[1]?.value).toContain('the old secret stops signing');
    expect(render(WEBHOOK_OPERATION_IDS.rotateSecret, null).fields?.[1]?.value).toContain(
      '86400 seconds'
    );
    expect(render(WEBHOOK_OPERATION_IDS.test, null).fields?.[1]?.value).toContain(
      'for this subscription and no other'
    );
  });

  it('splits a long URL and a long list of types over lines, each whole and marked as its part', () => {
    const long = `https://hooks.example.com/${'a'.repeat(1500)}`;
    const lines = urlLines('url', long);
    expect(lines.map((line) => line.label)).toEqual(['url, part 1 of 2', 'url, part 2 of 2']);
    expect(lines.map((line) => line.value).join('')).toBe(long);
    const types = EVENT_TYPES.map((definition) => definition.type).filter(
      (type) => type !== webhookTest.type
    );
    const fields = settingsLines({
      url: URL_A,
      description: null,
      eventTypes: types,
      categories: ['user', 'admin'],
      enabled: true,
    });
    const typeLines = fields.filter((field) => field.label.startsWith('event types'));
    expect(typeLines.length).toBeGreaterThan(1);
    expect(typeLines.every((field) => fitsApprovalLine(field.value))).toBe(true);
    expect(
      typeLines
        .map((field) => field.value)
        .join(', ')
        .split(', ')
    ).toEqual(types);
    // A whole update stays well inside the fifty lines an approval shows.
    const before = {
      url: long,
      description: null,
      eventTypes: types,
      categories: ['user'],
      enabled: true,
    };
    const after = { ...before, url: `${long}b`, eventTypes: 'all' as const, enabled: false };
    expect(changeLines(before, after).length).toBeLessThan(50);
  });
});

describe('the webhook routes in the admin OpenAPI document (#537)', () => {
  it("pass the API conventions against the server's own registry", async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { adminOpenapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { webhookRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      await app.register(swagger, adminOpenapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(webhookRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths)).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/webhooks',
        '/admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}',
        '/admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}/rotate-secret',
        '/admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}/test',
      ]);
      const one = document.paths['/admin/v1-rc.0/realms/{realmId}/webhooks/{subscriptionId}'];
      expect(one['patch']).toMatchObject({
        operationId: 'webhooks.update',
        'x-qauth-class': 'security',
        'x-qauth-effects': ['token-content'],
      });
      // Only the create and the rotation answer a secret.
      const answers = JSON.stringify(document.paths);
      expect(answers.match(/AdminWebhookSubscriptionWithSecret/g)?.length).toBe(2);
      expect(JSON.stringify(one['get']['responses'])).not.toContain('WithSecret');
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(7);
    } finally {
      await app.close();
    }
  });

  it('skips a test registry without its operations', async () => {
    const { webhookRoutes } = await import('./routes');
    const get = vi.fn();
    const fastify = {
      withTypeProvider: () => ({ get, post: get, patch: get, delete: get }),
      adminApi: { registry: { get: () => undefined } },
    };
    await webhookRoutes(fastify as never, {});
    expect(get).not.toHaveBeenCalled();
    const partial = {
      ...fastify,
      adminApi: {
        registry: {
          get: (id: string) => (id === WEBHOOK_OPERATION_IDS.list ? operation(id) : undefined),
        },
      },
    };
    await expect(webhookRoutes(partial as never, {})).rejects.toThrow(/only some/);
  });
});
