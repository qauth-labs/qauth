import { randomUUID } from 'node:crypto';

import { createTestSigner } from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import { BadRequestError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  type AdminOperation,
  createOperationRegistry,
  defineOperation,
  OPERATION_REGISTRY,
} from '../../helpers/admin-operations';
import { authMethodPluginSecretCipher } from '../../helpers/auth-method-plugins';
import { renderOperation } from '../approvals/display';
import type { AdminOperationRoute } from '../pipeline';
import { pluginSealScope, pluginSecretMember } from '../plugins/routes';
import { SECRET_OPERATION_IDS } from './operations';
import { secretRoutes } from './routes';
import {
  openRequestSealedValue,
  openSealedValue,
  type SealBinding,
  sealBindingOf,
  sealedValueContext,
  sealValue,
} from './sealed-values';
import {
  isSecretMember,
  isSecretMemberPattern,
  memberPointer,
  memberTokens,
  sealedMembersOf,
  secretMemberMatches,
} from './secret-members';

/**
 * Sealing a security operation's secret (#984), without a listener: the
 * member grammar, the binding of a sealed value to its operation, member,
 * resource and realm over a real in-memory signer, the seal route's own
 * checks, and the
 * approval display's refusal of a renderer that shows a sealed value. The
 * boot check of a declared member's schema is in `../pipeline.test.ts`; the
 * routes behind the pipeline run against real containers in
 * `auth-method-plugins-admin.integration.test.ts`.
 */

const SIGNER = createTestSigner();
const REALM = randomUUID();
const OTHER_REALM = randomUUID();
const SECRET = 'a-guessable-secret';

/** Another security operation that declares the same member as `plugins.update`. */
const OTHER = defineOperation({
  id: 'fixtureCredentials.update',
  class: 'security',
  effects: ['credential-path'],
  permissions: ['realms.policies.security'],
  description: 'A security operation that sets a secret (fixture).',
  render: () => ({ title: 'Set the credential' }),
  secretMembers: ['/secrets/*', '/password'],
});

const PLUGINS_UPDATE = OPERATION_REGISTRY.get('plugins.update') as AdminOperation;
const SEAL = OPERATION_REGISTRY.get(SECRET_OPERATION_IDS.seal) as AdminOperation;
const REGISTRY = createOperationRegistry([SEAL, PLUGINS_UPDATE, OTHER], { reserved: [] });
const MEMBER = '/secrets/clientSecret';

/** The plugin installed under `corp`, as a configure's route binds a value sealed for it. */
const CORP = { id: 'corp', package: '@example/corp', type: 'corp_sso' };
/** Plugin names the tests take away from {@link INSTALLED}. */
const INSTALLED_GONE = new Set<string>();
const INSTALLED = {
  find: (name: string) => (name === CORP.id && !INSTALLED_GONE.has(name) ? CORP : undefined),
};
/** The route of `plugins.update`, as the pipeline records it: its params and its sealScope. */
const CONFIGURE_ROUTE: AdminOperationRoute = {
  method: 'POST',
  url: '/admin/v1-rc.0/realms/:realmId/plugins/:plugin/config',
  params: z.object({ realmId: z.uuid(), plugin: z.enum([CORP.id]) }),
  sealScope: (params) => pluginSealScope(INSTALLED, params),
};
/** What a configure of `corp` in {@link REALM} binds a sealed value to. */
const BINDING: SealBinding = {
  params: { realmId: REALM, plugin: CORP.id },
  scope: JSON.stringify([CORP.package, CORP.type]),
};

beforeAll(async () => {
  await SIGNER.addRealm({ issuer: 'https://alpha.example.com', id: REALM });
  await SIGNER.addRealm({ issuer: 'https://beta.example.com', id: OTHER_REALM });
});

const signer = { signer: SIGNER.signer };

describe('secret members (#984)', () => {
  it('reads a member as an RFC 6901 pointer, and writes one back', () => {
    expect(memberTokens('/secrets/clientSecret')).toEqual(['secrets', 'clientSecret']);
    expect(memberTokens('/a~1b/c~0d')).toEqual(['a/b', 'c~d']);
    expect(memberPointer(['a/b', 'c~d'])).toBe('/a~1b/c~0d');
    expect(pluginSecretMember('mtls.key')).toBe('/secrets/mtls.key');
    for (const pointer of ['', 'secrets', '/', '/a//b', '/a~2', '/a\u0007', 42, undefined]) {
      expect(memberTokens(pointer), String(pointer)).toBeUndefined();
    }
  });

  it('matches a concrete member against a declared one, `*` standing for any one token', () => {
    expect(secretMemberMatches('/secrets/*', '/secrets/clientSecret')).toBe(true);
    expect(secretMemberMatches('/password', '/password')).toBe(true);
    expect(secretMemberMatches('/secrets/*', '/secrets')).toBe(false);
    expect(secretMemberMatches('/secrets/*', '/secrets/a/b')).toBe(false);
    expect(secretMemberMatches('/password', '/passwords')).toBe(false);
    // A concrete member names one member: `*` is no member a value is sealed for.
    expect(secretMemberMatches('/secrets/*', '/secrets/*')).toBe(false);
    expect(isSecretMember('/secrets/*')).toBe(false);
    expect(isSecretMemberPattern('/secrets/*')).toBe(true);
  });

  it('finds every sealed value a parsed body holds at its declared members', () => {
    const body = {
      password: { sealed: 'v1.k.i.one' },
      secrets: { a: { sealed: 'v1.k.i.two' }, b: null, 'c/d': { sealed: 'v1.k.i.three' } },
      note: { sealed: 'v1.k.i.undeclared' },
    };
    expect(sealedMembersOf(body, ['/secrets/*', '/password', '/missing'])).toEqual([
      { member: '/secrets/a', sealed: 'v1.k.i.two' },
      { member: '/secrets/c~1d', sealed: 'v1.k.i.three' },
      { member: '/password', sealed: 'v1.k.i.one' },
    ]);
    expect(sealedMembersOf(null, ['/password'])).toEqual([]);
  });
});

describe('a sealed value (#984)', () => {
  it('opens for the operation, the member and the realm it was sealed for', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    expect(sealed).toMatch(/^v1\./);
    expect(sealed).not.toContain(SECRET);
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, sealed)
    ).resolves.toBe(SECRET);
  });

  // Acceptance criterion: a sealed value made for another operation, member or
  // realm is refused; and one made for another resource the request acts on.
  it.each([
    ['another operation', OTHER, MEMBER, BINDING, REALM],
    ['another member', PLUGINS_UPDATE, '/secrets/otherSecret', BINDING, REALM],
    ['another realm', PLUGINS_UPDATE, MEMBER, BINDING, OTHER_REALM],
    [
      'another plugin',
      PLUGINS_UPDATE,
      MEMBER,
      { ...BINDING, params: { ...BINDING.params, plugin: 'partner' } },
      REALM,
    ],
    [
      'another package installed under the plugin',
      PLUGINS_UPDATE,
      MEMBER,
      { ...BINDING, scope: JSON.stringify(['@example/other', CORP.type]) },
      REALM,
    ],
    [
      'a route that binds nothing beside the parameters',
      PLUGINS_UPDATE,
      MEMBER,
      { ...BINDING, scope: null },
      REALM,
    ],
  ] as const)('is refused with 400 for %s', async (_case, operation, member, binding, realmId) => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    const opened = openSealedValue(
      signer,
      realmId,
      operation,
      member,
      binding,
      sealed,
      'the member'
    );
    await expect(opened).rejects.toBeInstanceOf(BadRequestError);
    await expect(opened).rejects.toThrow(
      'The value for the member was not sealed for it, for this operation, in this realm'
    );
  });

  it('is refused once changed', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    // A character inside the ciphertext, which carries six bits of it.
    const at = sealed.length - 8;
    const changed = `${sealed.slice(0, at)}${sealed[at] === 'A' ? 'B' : 'A'}${sealed.slice(at + 1)}`;
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, changed)
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('never opens as a stored plugin secret, nor a stored plugin secret as a sealed value', async () => {
    const plugin = { id: 'corp', package: '@example/corp', type: 'corp_sso' };
    const cipher = authMethodPluginSecretCipher(signer);
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    await expect(cipher.open(REALM, plugin, 'clientSecret', sealed)).rejects.toThrow();
    const stored = await cipher.seal(REALM, plugin, 'clientSecret', SECRET);
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, stored)
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('is sealed and opened as the signer caller admin, under its own context', async () => {
    const context = sealedValueContext('plugins.update', MEMBER, BINDING);
    expect(context).toMatch(/^admin-sealed-value:plugins\.update:[A-Za-z0-9_-]{43}$/);
    // The realm's parameter is the signer's to bind, and the order of the others is not read.
    expect(
      sealedValueContext('plugins.update', MEMBER, { ...BINDING, params: { plugin: 'corp' } })
    ).toBe(context);
    expect(
      sealedValueContext('plugins.update', MEMBER, {
        scope: null,
        params: { b: '2', a: '1' },
      })
    ).toBe(
      sealedValueContext('plugins.update', MEMBER, { scope: null, params: { a: '1', b: '2' } })
    );
    // A long member and parameters still fit the signer's context.
    const long = sealedValueContext('plugins.update', `/secrets/${'x'.repeat(700)}`, {
      params: { plugin: 'y'.repeat(1024) },
      scope: 'z'.repeat(4096),
    });
    expect(long.length).toBe(context.length);
    const sealed = await SIGNER.signer.encrypt('admin', {
      realmId: REALM,
      plaintext: Buffer.from(SECRET, 'utf8'),
      context,
    });
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, sealed)
    ).resolves.toBe(SECRET);
    // The admin caller opens nothing else.
    await expect(
      SIGNER.signer.encrypt('admin', {
        realmId: REALM,
        plaintext: Buffer.from(SECRET, 'utf8'),
        context: 'auth-method-plugin:corp:@example/corp:corp_sso:clientSecret',
      })
    ).rejects.toThrow();
  });

  it('is never sealed or opened for a member its operation does not declare', async () => {
    await expect(
      sealValue(signer, REALM, PLUGINS_UPDATE, '/config/issuer', BINDING, SECRET)
    ).rejects.toThrow(/declares no secret member \/config\/issuer/);
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    await expect(openSealedValue(signer, REALM, SEAL, MEMBER, BINDING, sealed)).rejects.toThrow(
      /secrets.seal declares no secret member/
    );
  });
});

describe('the binding of a sealed value (#984)', () => {
  it("reads the route's scope from the parsed path parameters", async () => {
    await expect(sealBindingOf(CONFIGURE_ROUTE, BINDING.params)).resolves.toEqual(BINDING);
    await expect(sealBindingOf({}, { realmId: REALM })).resolves.toEqual({
      params: { realmId: REALM },
      scope: null,
    });
  });

  it('binds nothing a route says names nothing it acts on', async () => {
    await expect(
      sealBindingOf(CONFIGURE_ROUTE, { realmId: REALM, plugin: 'partner' })
    ).resolves.toBeUndefined();
    await expect(sealBindingOf({ sealScope: () => 42 as never }, {})).rejects.toThrow(TypeError);
  });

  it("binds a configure's value to the package and the type installed under the plugin (#949)", () => {
    expect(pluginSealScope(INSTALLED, { plugin: CORP.id })).toBe('["@example/corp","corp_sso"]');
    const swapped = { find: () => ({ ...CORP, package: '@example/other' }) };
    expect(pluginSealScope(swapped, { plugin: CORP.id })).not.toBe(
      pluginSealScope(INSTALLED, { plugin: CORP.id })
    );
    expect(pluginSealScope(INSTALLED, { plugin: 'partner' })).toBeUndefined();
    expect(pluginSealScope(INSTALLED, {})).toBeUndefined();
  });
});

describe("a handler's sealed value (#984)", () => {
  /** A request of `operationId` on `realmId`, as the admin pipeline hands one to its handler. */
  const requestOf = (
    operationId: string,
    realmId: string,
    params: Record<string, unknown> = { realmId, plugin: CORP.id }
  ) =>
    ({
      adminOperation: { operationId },
      adminPipeline: { authority: { targetRealm: { id: realmId } } },
      params,
      server: {
        adminApi: { registry: REGISTRY, routeOf: () => CONFIGURE_ROUTE },
        signer: SIGNER.signer,
      },
    }) as unknown as FastifyRequest;

  // Acceptance criterion: a handler opens a sealed value only for its own
  // operation, member and realm.
  it('opens a value only for the operation the request was classified as, and its realm', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    await expect(
      openRequestSealedValue(requestOf('plugins.update', REALM), MEMBER, sealed)
    ).resolves.toBe(SECRET);
    await expect(
      openRequestSealedValue(requestOf(OTHER.id, REALM), MEMBER, sealed)
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      openRequestSealedValue(requestOf('plugins.update', OTHER_REALM), MEMBER, sealed)
    ).rejects.toBeInstanceOf(BadRequestError);
    await expect(
      openRequestSealedValue(requestOf('plugins.update', REALM), '/secrets/other', sealed)
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('opens a value only for the path parameters of the request, and what its route binds', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, SECRET);
    // Another plugin of the same realm: its route's scope names nothing installed.
    await expect(
      openRequestSealedValue(
        requestOf('plugins.update', REALM, { realmId: REALM, plugin: 'partner' }),
        MEMBER,
        sealed
      )
    ).rejects.toBeInstanceOf(BadRequestError);
    // The same plugin, once another package is installed under it.
    const swapped = {
      ...requestOf('plugins.update', REALM),
      server: {
        adminApi: {
          registry: REGISTRY,
          routeOf: () => ({
            ...CONFIGURE_ROUTE,
            sealScope: (params: Readonly<Record<string, unknown>>) =>
              pluginSealScope({ find: () => ({ ...CORP, package: '@example/other' }) }, params),
          }),
        },
        signer: SIGNER.signer,
      },
    } as unknown as FastifyRequest;
    await expect(openRequestSealedValue(swapped, MEMBER, sealed)).rejects.toBeInstanceOf(
      BadRequestError
    );
  });

  it('refuses to open anything for an operation with no route on the listener', async () => {
    const request = {
      ...requestOf('plugins.update', REALM),
      server: { adminApi: { registry: REGISTRY, routeOf: () => undefined }, signer: SIGNER.signer },
    } as unknown as FastifyRequest;
    await expect(openRequestSealedValue(request, MEMBER, 'v1.a.b.c')).rejects.toThrow(
      /has no route on this listener/
    );
  });

  it('refuses to open anything for a request that was never classified', async () => {
    const request = {
      adminOperation: undefined,
      server: { adminApi: { registry: REGISTRY }, signer: SIGNER.signer },
    } as unknown as FastifyRequest;
    await expect(openRequestSealedValue(request, MEMBER, 'v1.a.b.c')).rejects.toThrow(
      /no admin operation classification/
    );
  });
});

describe('the seal route (#984)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  /** The seal route on a bare instance, with the realm the pipeline would resolve. */
  async function boot(): Promise<FastifyInstance> {
    const instance = Fastify({ logger: false });
    app = instance;
    instance.setValidatorCompiler(validatorCompiler);
    instance.setSerializerCompiler(serializerCompiler);
    instance.decorate('signer', SIGNER.signer);
    instance.decorate('adminApi', {
      registry: REGISTRY,
      routeOf: (operationId: string) =>
        operationId === PLUGINS_UPDATE.id ? CONFIGURE_ROUTE : undefined,
    });
    instance.decorateRequest('adminPipeline', null);
    instance.addHook('onRequest', async (request) => {
      request.adminPipeline = {
        authority: { targetRealm: { id: REALM } },
      } as unknown as typeof request.adminPipeline;
    });
    await instance.register(secretRoutes);
    await instance.ready();
    return instance;
  }

  const url = `/admin/v1-rc.0/realms/${REALM}/secrets/seal`;

  it('answers the value sealed for the operation and member, in the realm of the path', async () => {
    const response = await (
      await boot()
    ).inject({
      method: 'POST',
      url,
      payload: {
        operation: 'plugins.update',
        member: MEMBER,
        params: { plugin: 'corp' },
        value: SECRET,
      },
    });
    expect(response.statusCode, response.body).toBe(200);
    const answer = response.json<{ operation: string; member: string; sealed: string }>();
    expect(answer).toEqual({
      operation: 'plugins.update',
      member: MEMBER,
      sealed: expect.stringMatching(/^v1\./),
    });
    expect(response.body).not.toContain(SECRET);
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, answer.sealed)
    ).resolves.toBe(SECRET);
  });

  it.each([
    ['an operation the registry does not hold', { operation: 'widgets.update', member: MEMBER }],
    ['an operation that declares no secret member', { operation: 'secrets.seal', member: MEMBER }],
    ['an operation with no route on the listener', { operation: OTHER.id, member: '/password' }],
    [
      'a member the operation does not declare',
      { operation: 'plugins.update', member: '/config/x' },
    ],
    ['every member at once', { operation: 'plugins.update', member: '/secrets/*' }],
    [
      'no path parameters, where the route has one',
      { operation: 'plugins.update', member: MEMBER, params: undefined },
    ],
    [
      'path parameters its route does not parse',
      { operation: 'plugins.update', member: MEMBER, params: { plugin: 'Not A Plugin' } },
    ],
  ])('refuses %s with 400, echoing nothing', async (_case, target) => {
    const response = await (
      await boot()
    ).inject({
      method: 'POST',
      url,
      payload: { params: { plugin: 'corp' }, ...target, value: SECRET },
    });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain(SECRET);
    expect(response.body).not.toContain(target.member);
    expect(response.body).not.toContain('Not A Plugin');
  });

  it('refuses with 400 a value for parameters its route binds nothing to', async () => {
    const instance = await boot();
    // `corp` parses, but the route's scope finds no plugin once it is gone.
    INSTALLED_GONE.add(CORP.id);
    try {
      const response = await instance.inject({
        method: 'POST',
        url,
        payload: {
          operation: 'plugins.update',
          member: MEMBER,
          params: { plugin: 'corp' },
          value: SECRET,
        },
      });
      expect(response.statusCode).toBe(400);
    } finally {
      INSTALLED_GONE.delete(CORP.id);
    }
  });

  it('seals for the realm of its own path, whatever params say of the realm', async () => {
    const response = await (
      await boot()
    ).inject({
      method: 'POST',
      url,
      payload: {
        operation: 'plugins.update',
        member: MEMBER,
        params: { plugin: 'corp', realmId: OTHER_REALM },
        value: SECRET,
      },
    });
    expect(response.statusCode, response.body).toBe(200);
    const { sealed } = response.json<{ sealed: string }>();
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, BINDING, sealed)
    ).resolves.toBe(SECRET);
  });

  it.each([
    ['an empty value', { operation: 'plugins.update', member: MEMBER, value: '' }],
    ['a value too long', { operation: 'plugins.update', member: MEMBER, value: 'x'.repeat(8193) }],
    [
      'a member other than the three',
      { operation: 'plugins.update', member: MEMBER, value: SECRET, realm: 'x' },
    ],
    ['a malformed operation id', { operation: 'Plugins Update', member: MEMBER, value: SECRET }],
  ])('refuses %s', async (_case, payload) => {
    const response = await (await boot()).inject({ method: 'POST', url, payload });
    expect(response.statusCode).toBe(400);
  });

  it('serves nothing on a registry without secrets.seal', async () => {
    const instance = Fastify({ logger: false });
    app = instance;
    instance.decorate('adminApi', {
      registry: createOperationRegistry([OTHER], { reserved: [] }),
      routeOf: () => undefined,
    });
    await instance.register(secretRoutes);
    await instance.ready();
    expect(instance.printRoutes()).toBe('(empty tree)');
  });
});

describe('what an approver is shown of a secret member (#984)', () => {
  const sealed = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHRjaXBoZXJ0ZXh0';
  const request = (operationId: string) => ({
    operationId,
    request: {
      method: 'POST',
      params: { realmId: REALM },
      query: {},
      body: { password: { sealed } },
    },
    reason: null,
  });

  it('files a renderer that names the secret member only', () => {
    const named = createOperationRegistry(
      [
        defineOperation({
          ...OTHER,
          render: () => ({
            title: 'Set the password',
            fields: [{ label: 'password', value: 'set (not shown)' }],
          }),
        }),
      ],
      { reserved: [] }
    );
    expect(renderOperation(request(OTHER.id), named).fields).toEqual([
      { label: 'password', value: 'set (not shown)' },
    ]);
  });

  it.each([
    ['whole', sealed],
    ['capped', `${sealed.slice(0, 44)}…`],
    ['the end of its ciphertext', `…${sealed.slice(-24)}`],
    ['the start of its ciphertext alone', sealed.slice(sealed.lastIndexOf('.') + 1).slice(0, 24)],
  ])('refuses a renderer that shows its sealed value, %s', (_case, shown) => {
    const showing = createOperationRegistry(
      [
        defineOperation({
          ...OTHER,
          render: () => ({
            title: 'Set the password',
            fields: [{ label: 'password', value: shown }],
          }),
        }),
      ],
      { reserved: [] }
    );
    expect(() => renderOperation(request(OTHER.id), showing)).toThrow(
      /shows the sealed value of a secret member/
    );
  });
});

describe('the seal route in the admin OpenAPI document (#984)', () => {
  it("passes the API conventions against the server's own registry", async () => {
    const [{ default: swagger }, { adminOpenapiOptions }, pipeline, { checkApiConventions }] =
      await Promise.all([
        import('@fastify/swagger'),
        import('../openapi-options'),
        import('../pipeline'),
        import('../../api-conventions/openapi-conventions'),
      ]);
    const instance = Fastify({ logger: false });
    try {
      instance.setValidatorCompiler(validatorCompiler);
      instance.setSerializerCompiler(serializerCompiler);
      await instance.register(swagger, adminOpenapiOptions);
      const uncounted = async () => ({ isAllowed: true, key: 'uncounted' });
      await instance.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted as never,
        callsBySubject: uncounted as never,
        routes: async (scope) => {
          await scope.register(secretRoutes);
        },
      });
      await instance.ready();

      const document = instance.swagger() as { paths: Record<string, unknown> };
      expect(Object.keys(document.paths)).toEqual(['/admin/v1-rc.0/realms/{realmId}/secrets/seal']);
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(1);
    } finally {
      await instance.close();
    }
  });
});
