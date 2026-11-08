import { randomUUID } from 'node:crypto';

import { createTestSigner } from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import { BadRequestError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import {
  type AdminOperation,
  createOperationRegistry,
  defineOperation,
  OPERATION_REGISTRY,
} from '../../helpers/admin-operations';
import { authMethodPluginSecretCipher } from '../../helpers/auth-method-plugins';
import { renderOperation } from '../approvals/display';
import { pluginSecretMember } from '../plugins/routes';
import { SECRET_OPERATION_IDS } from './operations';
import { secretRoutes } from './routes';
import {
  openRequestSealedValue,
  openSealedValue,
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
 * member grammar, the binding of a sealed value to its operation, member and
 * realm over a real in-memory signer, the seal route's own checks, and the
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
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
    expect(sealed).toMatch(/^v1\./);
    expect(sealed).not.toContain(SECRET);
    await expect(openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, sealed)).resolves.toBe(
      SECRET
    );
  });

  // Acceptance criterion: a sealed value made for another operation, member or
  // realm is refused.
  it.each([
    ['another operation', OTHER, MEMBER, REALM],
    ['another member', PLUGINS_UPDATE, '/secrets/otherSecret', REALM],
    ['another realm', PLUGINS_UPDATE, MEMBER, OTHER_REALM],
  ] as const)('is refused with 400 for %s', async (_case, operation, member, realmId) => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
    const opened = openSealedValue(signer, realmId, operation, member, sealed, 'the member');
    await expect(opened).rejects.toBeInstanceOf(BadRequestError);
    await expect(opened).rejects.toThrow(
      'The value for the member was not sealed for it, for this operation, in this realm'
    );
  });

  it('is refused once changed', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
    // A character inside the ciphertext, which carries six bits of it.
    const at = sealed.length - 8;
    const changed = `${sealed.slice(0, at)}${sealed[at] === 'A' ? 'B' : 'A'}${sealed.slice(at + 1)}`;
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, changed)
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('never opens as a stored plugin secret, nor a stored plugin secret as a sealed value', async () => {
    const plugin = { id: 'corp', package: '@example/corp', type: 'corp_sso' };
    const cipher = authMethodPluginSecretCipher(signer);
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
    await expect(cipher.open(REALM, plugin, 'clientSecret', sealed)).rejects.toThrow();
    const stored = await cipher.seal(REALM, plugin, 'clientSecret', SECRET);
    await expect(
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, stored)
    ).rejects.toBeInstanceOf(BadRequestError);
  });

  it('is sealed and opened as the signer caller admin, under its own context', async () => {
    expect(sealedValueContext('plugins.update', MEMBER)).toBe(
      'admin-sealed-value:plugins.update:/secrets/clientSecret'
    );
    const sealed = await SIGNER.signer.encrypt('admin', {
      realmId: REALM,
      plaintext: Buffer.from(SECRET, 'utf8'),
      context: sealedValueContext('plugins.update', MEMBER),
    });
    await expect(openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, sealed)).resolves.toBe(
      SECRET
    );
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
      sealValue(signer, REALM, PLUGINS_UPDATE, '/config/issuer', SECRET)
    ).rejects.toThrow(/declares no secret member \/config\/issuer/);
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
    await expect(openSealedValue(signer, REALM, SEAL, MEMBER, sealed)).rejects.toThrow(
      /secrets.seal declares no secret member/
    );
  });
});

describe("a handler's sealed value (#984)", () => {
  /** A request of `operationId` on `realmId`, as the admin pipeline hands one to its handler. */
  const requestOf = (operationId: string, realmId: string) =>
    ({
      adminOperation: { operationId },
      adminPipeline: { authority: { targetRealm: { id: realmId } } },
      server: { adminApi: { registry: REGISTRY }, signer: SIGNER.signer },
    }) as unknown as FastifyRequest;

  // Acceptance criterion: a handler opens a sealed value only for its own
  // operation, member and realm.
  it('opens a value only for the operation the request was classified as, and its realm', async () => {
    const sealed = await sealValue(signer, REALM, PLUGINS_UPDATE, MEMBER, SECRET);
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
    instance.decorate('adminApi', { registry: REGISTRY, routeOf: () => undefined });
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
      payload: { operation: 'plugins.update', member: MEMBER, value: SECRET },
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
      openSealedValue(signer, REALM, PLUGINS_UPDATE, MEMBER, answer.sealed)
    ).resolves.toBe(SECRET);
  });

  it.each([
    ['an operation the registry does not hold', { operation: 'widgets.update', member: MEMBER }],
    ['an operation that declares no secret member', { operation: 'secrets.seal', member: MEMBER }],
    [
      'a member the operation does not declare',
      { operation: 'plugins.update', member: '/config/x' },
    ],
    ['every member at once', { operation: 'plugins.update', member: '/secrets/*' }],
  ])('refuses %s with 400, echoing neither', async (_case, target) => {
    const response = await (
      await boot()
    ).inject({ method: 'POST', url, payload: { ...target, value: SECRET } });
    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain(SECRET);
    expect(response.body).not.toContain(target.member);
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
  const sealed = 'v1.kid-1.aXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHRjaXBoZXJ0ZXh0';
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
