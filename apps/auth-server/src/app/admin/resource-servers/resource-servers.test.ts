import { NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { classifyRequest, OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { RESERVED_OPERATIONS } from '../../helpers/admin-operations-reserved';
import { BUILT_IN_ROLES } from '../../helpers/admin-roles';
import type { AdminRateLimitCheck } from '../pipeline';
import {
  ANY_CLIENT_LINE,
  resourceServerChangeLines,
  resourceServerCreateLines,
  UPDATE_HEADER_LINES,
} from './approval-lines';
import {
  applyResourceServerPatch,
  assertResourceServerUpdate,
  RESOURCE_SERVER_OPERATION_IDS,
  resourceServerPatchProblems,
} from './operations';
import { clientsDirection, previewResourceServerPatch, scopesDirection } from './preview';
import {
  type AdminResourceServer,
  adminResourceServerOf,
  adminResourceServerSchema,
  adminResourceServerVersion,
  type ProtectedResourceRecord,
} from './representation';
import { resourceServerCreateBodySchema, resourceServerPatchBodySchema } from './routes';

/**
 * The resource server operations of the admin API (#1087), without a
 * listener: their classification and permissions, the representation, the
 * patch and its refusals, what an approver is shown (every value whole, or
 * the change is refused), the preview, and the routes in the admin document.
 * The routes behind the pipeline, their approvals and their writes are
 * exercised against real containers in
 * `admin-resource-servers.integration.test.ts`.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
const SERVER = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e81';
const RESOURCE = 'https://notes.example.com/mcp';

const NOTES_READ = {
  scope: 'notes:read',
  text: { en: 'Read your notes', de: 'Deine Notizen lesen' },
  sensitive: false,
};
const NOTES_DELETE = {
  scope: 'notes:delete',
  text: { en: 'Delete your notes' },
  sensitive: true,
};

/** A stored protected resource, as the repository returns it. */
function row(overrides: Partial<ProtectedResourceRecord> = {}): ProtectedResourceRecord {
  return {
    id: SERVER,
    realmId: REALM,
    resource: RESOURCE,
    scopes: [NOTES_READ, NOTES_DELETE],
    anyClient: false,
    clientIds: ['notes-app', 'https://agent.example.com/client.json'],
    version: 3,
    createdAt: Date.UTC(2026, 10, 1),
    updatedAt: Date.UTC(2026, 10, 2),
    ...overrides,
  };
}

const server = (overrides: Partial<ProtectedResourceRecord> = {}): AdminResourceServer =>
  adminResourceServerOf(row(overrides));

const patch = (body: unknown) => ({
  method: 'PATCH',
  params: { realmId: REALM, resourceServerId: SERVER },
  query: {},
  body,
});

const operation = (id: string) => {
  const found = OPERATION_REGISTRY.get(id);
  if (found === undefined) throw new Error(`${id} is not registered`);
  return found;
};

/** A request behind the pipeline whose repository answers `found`. */
function pipelineRequest(found: ProtectedResourceRecord | undefined) {
  const findById = vi.fn(async () => found);
  const request = {
    adminPipeline: { authority: { targetRealm: { id: REALM } }, transaction: 'tx' },
    server: { repositories: { protectedResources: { findById } } },
  } as unknown as FastifyRequest;
  return { request, findById };
}

describe('the resource server operations in the registry (#1087)', () => {
  it('reads with resourceServers.read, and writes as security operations with token-content', () => {
    const shape = Object.values(RESOURCE_SERVER_OPERATION_IDS).map((id) => {
      const entry = operation(id);
      return [entry.id, entry.class, entry.effects, entry.permissions];
    });
    expect(shape).toEqual([
      ['resourceServers.list', 'read', [], ['resourceServers.read']],
      ['resourceServers.get', 'read', [], ['resourceServers.read']],
      ['resourceServers.create', 'security', ['token-content'], ['resourceServers.security']],
      ['resourceServers.update', 'security', ['token-content'], ['resourceServers.security']],
      ['resourceServers.preview', 'read', [], ['resourceServers.read']],
      ['resourceServers.delete', 'security', ['token-content'], ['resourceServers.security']],
    ]);
    expect(OPERATION_REGISTRY.permissions.get('resourceServers.read')?.class).toBe('read');
    expect(OPERATION_REGISTRY.permissions.get('resourceServers.security')?.class).toBe('security');
  });

  it('takes the reserved ids, none classifying: every request needs its declaration', () => {
    for (const id of [
      'resourceServers.create',
      'resourceServers.update',
      'resourceServers.delete',
    ]) {
      const entry = RESERVED_OPERATIONS.find((candidate) => candidate.id === id);
      expect(entry, id).toMatchObject({ effects: ['token-content'] });
      expect(entry?.requestDependent, id).toBeUndefined();
      expect(entry?.source, id).toContain('#1087');
    }
    const classifying = Object.values(RESOURCE_SERVER_OPERATION_IDS).filter(
      (id) => operation(id).classify !== undefined
    );
    expect(classifying).toEqual([]);
  });

  it('gives the permissions to the built-in roles that hold the client ones', () => {
    for (const role of Object.values(BUILT_IN_ROLES)) {
      const held = new Set(role.permissionIds);
      expect(held.has('resourceServers.read'), role.name).toBe(held.has('clients.read'));
      expect(held.has('resourceServers.security'), role.name).toBe(held.has('clients.security'));
    }
  });

  it('classifies an update as a security change on every request, a narrowing too, bound to the version', () => {
    const state = server();
    for (const body of [{}, { scopes: [NOTES_READ] }, { clients: ['notes-app'] }]) {
      const result = classifyRequest(
        OPERATION_REGISTRY,
        operation(RESOURCE_SERVER_OPERATION_IDS.update),
        patch(body),
        state,
        adminResourceServerVersion(state)
      );
      expect(result, JSON.stringify(body)).toMatchObject({
        class: 'security',
        effects: ['token-content'],
        permissions: ['resourceServers.security'],
        stateVersion: '3',
        failedClosed: null,
      });
    }
  });
});

describe('the resource server representation (#1087)', () => {
  it('shows the indicator, each scope whole, who may ask, the version and the times', () => {
    const shown = server();
    expect(shown).toEqual({
      id: SERVER,
      resource: RESOURCE,
      scopes: [NOTES_READ, NOTES_DELETE],
      clients: ['notes-app', 'https://agent.example.com/client.json'],
      version: 3,
      createdAt: '2026-11-01T00:00:00.000Z',
      updatedAt: '2026-11-02T00:00:00.000Z',
    });
    expect(adminResourceServerSchema.parse(shown)).toEqual(shown);
    expect(server({ anyClient: true, clientIds: [] }).clients).toBe('any_client');
  });

  it('copies the row, so a change of the representation never reaches it', () => {
    const stored = row();
    const shown = adminResourceServerOf(stored);
    (shown.scopes[0].text as Record<string, string>)['en'] = 'Changed';
    (shown.clients as string[]).push('other');
    expect(stored.scopes[0].text['en']).toBe('Read your notes');
    expect(stored.clientIds).toHaveLength(2);
  });

  it('is versioned by the row version, which is its ETag', () => {
    expect(adminResourceServerVersion(server())).toBe('3');
    expect(adminResourceServerVersion(server({ version: 4 }))).toBe('4');
  });
});

describe('a merge patch of a resource server (#1087)', () => {
  it('replaces the scopes and the clients whole, and keeps what it leaves out', () => {
    const state = server();
    expect(
      applyResourceServerPatch(state, { scopes: [{ ...NOTES_READ, sensitive: undefined }] })
    ).toEqual({
      scopes: [{ ...NOTES_READ, sensitive: false }],
      clients: state.clients,
    });
    expect(applyResourceServerPatch(state, { clients: 'any_client' })).toEqual({
      scopes: state.scopes,
      clients: 'any_client',
    });
    expect(applyResourceServerPatch(state, {})).toEqual({
      scopes: state.scopes,
      clients: state.clients,
    });
  });

  it('refuses a change of the indicator and a null scopes or clients, with 422', () => {
    const state = server();
    expect(
      resourceServerPatchProblems(state, {
        resource: 'https://other.example.com/mcp',
        scopes: null,
        clients: null,
      }).map(({ pointer }) => pointer)
    ).toEqual(['/resource', '/scopes', '/clients']);
    expect(resourceServerPatchProblems(state, { resource: null })).toMatchObject([
      { pointer: '/resource' },
    ]);
    // Named as it is stored, the indicator is no change.
    expect(resourceServerPatchProblems(state, { resource: RESOURCE })).toEqual([]);
    expect(() => assertResourceServerUpdate(state, { resource: 'https://x.example/' })).toThrow(
      expect.objectContaining({ statusCode: 422 })
    );
  });

  it('changes neither the state nor the body', () => {
    const state = server();
    const body = { scopes: [NOTES_READ], clients: ['notes-app'] };
    const before = structuredClone({ state, body });
    const settings = applyResourceServerPatch(state, body);
    (settings.scopes[0].text as Record<string, string>)['en'] = 'Changed';
    expect({ state, body }).toEqual(before);
  });

  it('takes the shared rules: a QAuth scope, a scope without English and an empty client list are refused', () => {
    expect(resourceServerPatchBodySchema.safeParse({ scopes: [NOTES_READ] }).success).toBe(true);
    for (const body of [
      { scopes: [{ scope: 'openid', text: { en: 'Sign you in' } }] },
      { scopes: [{ scope: 'notes:read', text: { de: 'Lesen' } }] },
      { clients: [] },
      { name: 'unknown member' },
    ]) {
      expect(resourceServerPatchBodySchema.safeParse(body).success, JSON.stringify(body)).toBe(
        false
      );
    }
  });
});

describe('the state of a resource server operation (#1087)', () => {
  it('is 404 for a resource server the realm does not have, one of another realm included', async () => {
    const { request, findById } = pipelineRequest(undefined);
    for (const id of [RESOURCE_SERVER_OPERATION_IDS.update, RESOURCE_SERVER_OPERATION_IDS.delete]) {
      await expect(operation(id).loadState?.(request, patch({}))).rejects.toBeInstanceOf(
        NotFoundError
      );
    }
    // Keyed by the realm of the path, in the handler's transaction.
    expect(findById).toHaveBeenCalledWith(REALM, SERVER, 'tx');
    await expect(
      operation(RESOURCE_SERVER_OPERATION_IDS.delete).loadState?.(request, {
        ...patch({}),
        params: { realmId: REALM, resourceServerId: 'notes' },
      })
    ).rejects.toBeInstanceOf(NotFoundError);
  });

  it('refuses an update that changes the indicator before it is filed, and reads a deletion as it stands', async () => {
    const { request } = pipelineRequest(row());
    await expect(
      operation(RESOURCE_SERVER_OPERATION_IDS.update).loadState?.(
        request,
        patch({ resource: 'https://other.example.com/mcp' })
      )
    ).rejects.toMatchObject({ statusCode: 422 });
    await expect(
      operation(RESOURCE_SERVER_OPERATION_IDS.delete).loadState?.(request, {
        ...patch(null),
        method: 'DELETE',
      })
    ).resolves.toMatchObject({ resource: RESOURCE, version: 3 });
    expect(
      operation(RESOURCE_SERVER_OPERATION_IDS.delete).stateVersion?.(server({ version: 7 }))
    ).toBe('7');
  });
});

describe('what an approver is shown of a resource server operation (#1087)', () => {
  const render = (id: string, body: unknown, state?: AdminResourceServer) => {
    const entry = operation(id);
    if (entry.render === undefined) throw new Error(`${id} renders nothing`);
    return entry.render({
      operationId: id,
      method: 'POST',
      params: { realmId: REALM, resourceServerId: SERVER },
      query: {},
      body,
      ...(state === undefined ? {} : { state }),
    });
  };

  it('shows a registration whole: each scope with its flag, every locale’s text, every client', () => {
    const shown = render(RESOURCE_SERVER_OPERATION_IDS.create, {
      resource: RESOURCE,
      scopes: [NOTES_READ, NOTES_DELETE],
      clients: ['notes-app', 'https://agent.example.com/client.json'],
    });
    expect(shown.title).toBe('Register a resource server');
    expect(shown.fields?.slice(1)).toEqual([
      { label: 'resource', value: RESOURCE },
      { label: 'scope', value: 'notes:read' },
      { label: 'consent text (en)', value: 'notes:read — Read your notes' },
      { label: 'consent text (de)', value: 'notes:read — Deine Notizen lesen' },
      { label: 'scope, sensitive', value: 'notes:delete' },
      { label: 'consent text (en)', value: 'notes:delete — Delete your notes' },
      { label: 'client', value: 'notes-app' },
      { label: 'client', value: 'https://agent.example.com/client.json' },
    ]);
    const open = render(RESOURCE_SERVER_OPERATION_IDS.create, {
      resource: RESOURCE,
      scopes: [NOTES_READ],
      clients: 'any_client',
    });
    expect(open.fields?.at(-1)).toEqual({ label: 'clients', value: ANY_CLIENT_LINE });
  });

  it('shows an update as each scope and client it removes and adds, and each text and flag beside the one it replaces', () => {
    const shown = render(
      RESOURCE_SERVER_OPERATION_IDS.update,
      {
        scopes: [
          {
            ...NOTES_READ,
            text: { en: 'Read all your notes', fr: 'Lire vos notes' },
            sensitive: true,
          },
          { scope: 'notes:write', text: { en: 'Write your notes' } },
        ],
        clients: ['notes-app', 'reports'],
      },
      server()
    );
    expect(shown.fields).toEqual([
      { label: 'resource', value: RESOURCE },
      { label: 'scope removed', value: 'notes:delete' },
      { label: 'sensitive', before: 'notes:read: no', value: 'notes:read: yes' },
      { label: 'consent text removed (de)', value: 'notes:read — Deine Notizen lesen' },
      {
        label: 'consent text (en)',
        before: 'notes:read — Read your notes',
        value: 'notes:read — Read all your notes',
      },
      { label: 'consent text added (fr)', value: 'notes:read — Lire vos notes' },
      { label: 'scope added', value: 'notes:write' },
      { label: 'consent text (en)', value: 'notes:write — Write your notes' },
      { label: 'client removed', value: 'https://agent.example.com/client.json' },
      { label: 'client added', value: 'reports' },
    ]);
    // Opened to every client, and closed again to a list.
    expect(
      render(RESOURCE_SERVER_OPERATION_IDS.update, { clients: 'any_client' }, server()).fields
    ).toEqual([
      { label: 'resource', value: RESOURCE },
      { label: 'clients', before: 'only the clients listed', value: ANY_CLIENT_LINE },
    ]);
    expect(
      render(
        RESOURCE_SERVER_OPERATION_IDS.update,
        { clients: ['notes-app'] },
        server({ anyClient: true, clientIds: [] })
      ).fields?.slice(1)
    ).toEqual([
      { label: 'clients', before: ANY_CLIENT_LINE, value: 'only the clients listed below' },
      { label: 'client listed', value: 'notes-app' },
    ]);
  });

  it('shows a deletion as the resource server stood, and refuses an update or a deletion without it', () => {
    const shown = render(RESOURCE_SERVER_OPERATION_IDS.delete, null, server());
    expect(shown.title).toBe('Delete a resource server');
    expect(shown.fields?.slice(0, 3)).toEqual([
      { label: 'resource', value: RESOURCE },
      { label: 'scopes', value: 'notes:read notes:delete' },
      { label: 'clients', value: 'notes-app https://agent.example.com/client.json' },
    ]);
    expect(shown.fields?.at(-1)?.label).toBe('effect');
    for (const id of [RESOURCE_SERVER_OPERATION_IDS.update, RESOURCE_SERVER_OPERATION_IDS.delete]) {
      expect(() => render(id, {}), id).toThrow();
    }
  });

  it('refuses a change an approver could not be shown whole, with 422', () => {
    const state = server();
    // A consent text the display would cut: each combining mark may be escaped.
    const cut = { scope: 'notes:read', text: { en: `e${'́'.repeat(200)}` } };
    expect(() => assertResourceServerUpdate(state, { scopes: [cut] })).toThrow(
      expect.objectContaining({ statusCode: 422 })
    );
    // More lines than one approval holds.
    const many = Array.from({ length: 30 }, (_, index) => ({
      scope: `notes:${index}`,
      text: { en: `Scope ${index}` },
    }));
    const settings = applyResourceServerPatch(state, { scopes: many });
    expect(resourceServerChangeLines(state, settings, UPDATE_HEADER_LINES).problems).toMatchObject([
      { pointer: '' },
    ]);
    expect(() => assertResourceServerUpdate(state, { scopes: many })).toThrow(
      expect.objectContaining({ statusCode: 422 })
    );
    // A text in another script is shown as long as it is.
    const japanese = { scope: 'notes:read', text: { en: 'Read', ja: 'あ'.repeat(280) } };
    expect(() => assertResourceServerUpdate(state, { scopes: [japanese] })).not.toThrow();
  });

  it('refuses a registration an approver could not be shown whole, and splits only the indicator', () => {
    const base = { resource: RESOURCE, scopes: [NOTES_READ], clients: 'any_client' };
    expect(resourceServerCreateBodySchema.safeParse(base).success).toBe(true);
    const many = Array.from({ length: 50 }, (_, index) => `client-${index}`);
    expect(resourceServerCreateBodySchema.safeParse({ ...base, clients: many }).success).toBe(
      false
    );
    expect(
      resourceServerCreateBodySchema.safeParse({
        ...base,
        scopes: [{ scope: 'notes:read', text: { en: `e${'́'.repeat(200)}` } }],
      }).success
    ).toBe(false);
    // A long indicator is shown in parts, each marked, and never refused for it.
    const long = `https://notes.example.com/${'a'.repeat(1500)}`;
    expect(resourceServerCreateBodySchema.safeParse({ ...base, resource: long }).success).toBe(
      true
    );
    const lines = resourceServerCreateLines({ ...base, resource: long }, 1);
    expect(lines.problems).toEqual([]);
    expect(lines.fields.slice(0, 2).map((field) => field.label)).toEqual([
      'resource, part 1 of 2',
      'resource, part 2 of 2',
    ]);
    expect(
      lines.fields
        .slice(0, 2)
        .map((field) => field.value)
        .join('')
    ).toBe(long);
  });

  it('takes the shared rules for a registration: a QAuth API audience or a fragment is refused', () => {
    const base = { scopes: [NOTES_READ], clients: 'any_client' };
    for (const resource of [
      'urn:qauth:aud:admin:v1-rc.0',
      'https://notes.example.com/#mcp',
      'notes',
    ]) {
      expect(
        resourceServerCreateBodySchema.safeParse({ ...base, resource }).success,
        resource
      ).toBe(false);
    }
    expect(
      resourceServerCreateBodySchema.safeParse({ ...base, resource: RESOURCE, version: 1 }).success
    ).toBe(false);
  });
});

describe('the preview of a resource server update (#1087)', () => {
  it('lists the scopes and the clients it changes, each with its direction, all needing approval', () => {
    const state = server();
    const preview = previewResourceServerPatch(
      OPERATION_REGISTRY,
      { realmId: REALM, resourceServerId: SERVER },
      { scopes: [NOTES_READ], clients: 'any_client' },
      state
    );
    expect(preview.classification).toMatchObject({
      class: 'security',
      effects: ['token-content'],
      failedClosed: null,
      stateVersion: '3',
    });
    expect(
      preview.changes.map(({ path, direction, classification }) => [
        path,
        direction,
        classification.class,
      ])
    ).toEqual([
      ['scopes', 'tightening', 'security'],
      ['clients', 'loosening', 'security'],
    ]);
    expect(
      previewResourceServerPatch(
        OPERATION_REGISTRY,
        { realmId: REALM, resourceServerId: SERVER },
        { resource: RESOURCE },
        state
      ).changes
    ).toEqual([]);
  });

  it('loosens with a scope added, a flag cleared or a text changed, and tightens only by taking away', () => {
    expect(scopesDirection([NOTES_READ], [NOTES_READ, NOTES_DELETE])).toBe('loosening');
    expect(scopesDirection([NOTES_DELETE], [{ ...NOTES_DELETE, sensitive: false }])).toBe(
      'loosening'
    );
    expect(scopesDirection([NOTES_READ], [{ ...NOTES_READ, text: { en: 'Other' } }])).toBe(
      'loosening'
    );
    expect(scopesDirection([NOTES_READ, NOTES_DELETE], [NOTES_DELETE])).toBe('tightening');
    expect(scopesDirection([NOTES_READ], [{ ...NOTES_READ, sensitive: true }])).toBe('tightening');
    expect(scopesDirection([NOTES_READ, NOTES_DELETE], [NOTES_DELETE, NOTES_READ])).toBe('neutral');
    expect(clientsDirection('any_client', ['a'])).toBe('tightening');
    expect(clientsDirection(['a'], 'any_client')).toBe('loosening');
    expect(clientsDirection(['a'], ['a', 'b'])).toBe('loosening');
    expect(clientsDirection(['a', 'b'], ['b'])).toBe('tightening');
    expect(clientsDirection(['a', 'b'], ['b', 'a'])).toBe('neutral');
  });
});

describe('the resource server routes in the admin OpenAPI document (#1087)', () => {
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
    const { resourceServerRoutes } = await import('./routes');

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
          await scope.register(resourceServerRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths)).toEqual([
        '/admin/v1-rc.0/realms/{realmId}/resource-servers',
        '/admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}',
        '/admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}/preview',
      ]);
      const one =
        document.paths['/admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}'];
      expect(one['patch']).toMatchObject({
        operationId: 'resourceServers.update',
        'x-qauth-class': 'security',
        'x-qauth-effects': ['token-content'],
      });
      expect(JSON.stringify(one['patch']['requestBody'])).toContain('AdminResourceServerPatch');
      expect(JSON.stringify(one['get']['responses'])).toContain('AdminResourceServer');
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(6);
    } finally {
      await app.close();
    }
  });

  it('skips a test registry without its operations', async () => {
    const { resourceServerRoutes } = await import('./routes');
    const get = vi.fn();
    const fastify = {
      withTypeProvider: () => ({ get, post: get, patch: get, delete: get }),
      adminApi: { registry: { get: () => undefined } },
    };
    await resourceServerRoutes(fastify as never, {});
    expect(get).not.toHaveBeenCalled();
    const partial = {
      ...fastify,
      adminApi: {
        registry: {
          get: (id: string) =>
            id === RESOURCE_SERVER_OPERATION_IDS.list ? operation(id) : undefined,
        },
      },
    };
    await expect(resourceServerRoutes(partial as never, {})).rejects.toThrow(/only some/);
  });
});
