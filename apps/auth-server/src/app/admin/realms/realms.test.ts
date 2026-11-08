import {
  defaultsFromEnv,
  REALM_POLICY_SCHEMA_VERSION,
  toRealmPoliciesRepresentation,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { MAX_FAILED_LOGIN_LOCKOUT_SECONDS } from '@qauth-labs/server-config';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { classifyRequest, OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { ADMIN_SCOPES } from '../../helpers/admin-scopes';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import type { AdminRateLimitCheck } from '../pipeline';
import {
  classifyPolicyPatch,
  REALM_OPERATION_IDS,
  REALM_POLICY_SECRET_MEMBERS,
  type RealmPolicyState,
} from './operations';
import { auditedChange, policyPatchBodySchema, realmResource, realmSchema } from './routes';

/**
 * The realm operations of the admin API (#517), without a listener: their
 * entries in the registry, how a policy patch is classified field by field on
 * the merged document, what an approver is shown, the body a patch may send,
 * the representation and the audit record. The routes behind the pipeline are
 * exercised against real containers in `admin-realms.integration.test.ts`.
 */

const REALM = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';
/** A value as secrets.seal answers one. */
const SEALED = 'v1.kid-1.aXZhaXZhaXZhaXZh.Y2lwaGVydGV4dGNpcGhlcnRleHQ';
/** A secret's value, which nothing here may repeat. */
const SMTP_PASSWORD = 'smtp-password-never-shown';

type Document = Record<string, Record<string, unknown>>;

/** The policies of an empty environment, edited, as `loadState` reads them. */
function stateOf(edit: (document: Document) => void = () => undefined, setSecrets: string[] = []) {
  const document = structuredClone(defaultsFromEnv({})) as unknown as Document;
  edit(document);
  return {
    version: 4,
    policies: toRealmPoliciesRepresentation(document, setSecrets),
  } as RealmPolicyState;
}

const patchOf = (body: unknown) => ({
  method: 'PATCH',
  params: { realmId: REALM },
  query: {},
  body,
});

const operation = () => {
  const found = OPERATION_REGISTRY.get(REALM_OPERATION_IDS.updatePolicies);
  if (found === undefined) throw new Error('realms.policies.update is not registered');
  return found;
};

/** Every patch reads the realm it answers (realms.read), whatever it changes. */
const WRITE = {
  class: 'write',
  effects: [],
  permissions: ['realms.read', 'realms.policies.write'],
};
const SECURITY_PERMISSIONS = ['realms.read', 'realms.policies.security'];

describe('the realm operations in the registry (#517)', () => {
  it('reads with realms.read, and patches the policies as a security operation that may need either permission', () => {
    const get = OPERATION_REGISTRY.get(REALM_OPERATION_IDS.get);
    expect([get?.id, get?.class, get?.effects, get?.permissions]).toEqual([
      'realms.get',
      'read',
      [],
      ['realms.read'],
    ]);
    const update = operation();
    expect(update.id).toBe('realms.policies.update');
    expect(update.class).toBe('security');
    expect(update.permissions).toEqual([
      'realms.policies.write',
      'realms.policies.security',
      'realms.read',
    ]);
    expect(update.effects).toEqual(
      expect.arrayContaining(['credential-path', 'token-content', 'posture-loosening'])
    );
    expect(update.secretMembers).toEqual(['/mail/smtp/password', '/mail/resend/apiKey']);
    expect(REALM_POLICY_SECRET_MEMBERS).toEqual(update.secretMembers);

    const classes = ['realms.read', 'realms.policies.write', 'realms.policies.security'].map(
      (id) => OPERATION_REGISTRY.permissions.get(id)?.class
    );
    expect(classes).toEqual(['read', 'write', 'security']);
    expect(ADMIN_SCOPES.security).toBe('qauth:admin:security');
  });
});

describe('the classification of a policy patch (#517)', () => {
  const classify = (body: unknown, state: RealmPolicyState = stateOf()) =>
    classifyPolicyPatch(patchOf(body), state);

  it('makes a change that tightens a loosening-annotated field a write', () => {
    // The defaults: 900 s access tokens, password score 2.
    expect(classify({ tokens: { accessTokenLifespanSeconds: 300 } })).toEqual(WRITE);
    expect(classify({ password: { minScore: 3 } })).toEqual(WRITE);
  });

  it('makes a loosening a security change, with the effects of the field', () => {
    expect(classify({ password: { minScore: 1 } })).toEqual({
      class: 'security',
      effects: ['credential-path'],
      permissions: SECURITY_PERMISSIONS,
    });
    expect(classify({ tokens: { accessTokenLifespanSeconds: 3600 } })).toMatchObject({
      class: 'security',
      effects: ['posture-loosening'],
      permissions: SECURITY_PERMISSIONS,
    });
  });

  it('needs both permissions, once, for a patch of a write field and a security field', () => {
    const classification = classify({
      tokens: { accessTokenLifespanSeconds: 300 },
      password: { minScore: 1 },
    });
    expect(classification.class).toBe('security');
    expect(classification.effects).toEqual(['credential-path']);
    expect([...classification.permissions].sort()).toEqual([
      'realms.policies.security',
      'realms.policies.write',
      'realms.read',
    ]);
  });

  // The review of #890: null gives a field its default, judged on the merged
  // document, so a null that loosens is a security change.
  it('judges null by the default it gives the field', () => {
    const allowlist = stateOf((document) => {
      document['registration'] = {
        ...document['registration'],
        cimd: {
          ...(document['registration']['cimd'] as Record<string, unknown>),
          trustPolicy: 'allowlist',
          trustedDomains: ['clients.example'],
        },
      };
    });
    expect(classify({ registration: { cimd: { trustPolicy: null } } }, allowlist)).toMatchObject({
      class: 'security',
      effects: ['token-content'],
    });
    // A field already at its default does not move.
    expect(classify({ password: { minScore: null } })).toEqual(WRITE);
  });

  it('makes a patch that changes nothing a write', () => {
    expect(classify({})).toEqual(WRITE);
    expect(classify({ password: { minScore: 2 } })).toEqual(WRITE);
    // The representation's flag is taken back and sets nothing.
    expect(classify({ mail: { smtp: { passwordSet: true } } })).toEqual(WRITE);
  });

  it('makes every secret member a security change, whatever it does', () => {
    const set = stateOf(undefined, ['mail.smtp.password']);
    for (const [body, state] of [
      [{ mail: { smtp: { password: { sealed: SEALED } } } }, stateOf()],
      [{ mail: { smtp: { password: { sealed: SEALED } } } }, set],
      [{ mail: { smtp: { password: null } } }, set],
      // Clearing a secret that holds nothing is still a change of a secret.
      [{ mail: { smtp: { password: null } } }, stateOf()],
    ] as const) {
      expect(classify(body, state), JSON.stringify(body)).toEqual({
        class: 'security',
        effects: ['credential-path'],
        permissions: SECURITY_PERMISSIONS,
      });
    }
  });

  it('fails closed to the declaration on a member the policies do not have', () => {
    const update = operation();
    for (const body of [{ tokens: { lifetime: 1 } }, { sessions: { idleSeconds: 60 } }]) {
      const classification = classifyRequest(
        OPERATION_REGISTRY,
        update,
        patchOf(body),
        stateOf(),
        '4'
      );
      expect(classification.failedClosed, JSON.stringify(body)).not.toBeNull();
      expect(classification.class).toBe('security');
      expect([...classification.permissions].sort()).toEqual([
        'realms.policies.security',
        'realms.policies.write',
        'realms.read',
      ]);
    }
  });

  it('classifies through the registry as it does alone, bound to the state version', () => {
    const classification = classifyRequest(
      OPERATION_REGISTRY,
      operation(),
      patchOf({ password: { minScore: 3 } }),
      stateOf(),
      '4'
    );
    expect(classification).toMatchObject({
      class: 'write',
      effects: [],
      failedClosed: null,
      stateVersion: '4',
    });
    expect([...classification.permissions].sort()).toEqual([...WRITE.permissions].sort());
  });
});

describe('the state a policy patch is checked against (#517)', () => {
  /** A request behind the pipeline, for `realms.policies.update`'s `loadState`. */
  function requestFor(state: RealmPolicyState, secretStore: unknown = null, transaction?: unknown) {
    const document = structuredClone(defaultsFromEnv({}));
    return {
      adminPipeline: { authority: { targetRealm: { id: REALM } }, transaction },
      server: {
        realmSecretStore: secretStore,
        policyStore: {
          get: vi.fn(async () => ({
            realmId: REALM,
            version: state.version,
            hasPolicies: true,
            schemaVersion: REALM_POLICY_SCHEMA_VERSION,
            policies: document,
          })),
          representation: vi.fn(async () => ({
            realmId: REALM,
            version: state.version,
            schemaVersion: REALM_POLICY_SCHEMA_VERSION,
            policies: state.policies,
          })),
        },
      },
    } as unknown as FastifyRequest;
  }

  const load = (body: unknown, secretStore: unknown = null) => {
    const state = stateOf();
    const loadState = operation().loadState;
    if (loadState === undefined) throw new Error('realms.policies.update reads no state');
    return loadState(requestFor(state, secretStore), patchOf(body));
  };

  const refusal = async (promise: Promise<unknown>) => {
    const error = await promise.then(
      () => undefined,
      (caught: unknown) => caught
    );
    expect(error).toBeInstanceOf(UnprocessableContentError);
    return (error as UnprocessableContentError).fields;
  };

  it('reads the policies the patch is classified against', async () => {
    await expect(load({ password: { minScore: 3 } })).resolves.toEqual(
      expect.objectContaining({ version: 4 })
    );
  });

  // From the reviews of #887 and #517: inside a handler, as when
  // approvals.create files a patch, the read holds no second connection
  // beside the handler's transaction.
  it("reads in the handler's transaction when it runs inside one", async () => {
    const tx = { id: 'handler-tx' };
    const loadState = operation().loadState;
    if (loadState === undefined) throw new Error('realms.policies.update reads no state');
    const outside = requestFor(stateOf());
    await loadState(outside, patchOf({}));
    expect(outside.server.policyStore.get).toHaveBeenCalledWith(REALM, undefined);

    const inside = requestFor(stateOf(), { isSet: vi.fn(async () => false) }, tx);
    await loadState(inside, patchOf({}));
    expect(inside.server.policyStore.representation).toHaveBeenCalledWith(REALM, tx);
  });

  // d-1102-02: a lockout or window longer than a day is refused, by field.
  it('refuses a brute-force lockout or window above a day with 422, naming the field', async () => {
    expect(MAX_FAILED_LOGIN_LOCKOUT_SECONDS).toBe(86_400);
    const fields = await refusal(
      load({ bruteForce: { lockoutSeconds: 86_401, windowSeconds: 172_800 } })
    );
    expect(fields.map((field) => field.pointer).sort()).toEqual([
      '/bruteForce/lockoutSeconds',
      '/bruteForce/windowSeconds',
    ]);
    await expect(load({ bruteForce: { lockoutSeconds: 86_400 } })).resolves.toBeDefined();
  });

  it('refuses a value of the wrong type with 422, naming the field', async () => {
    const fields = await refusal(load({ password: { minScore: 'high' } }));
    expect(fields.map((field) => field.pointer)).toEqual(['/password/minScore']);
  });

  it('refuses a secret on a server without a secret store, naming the member and never a value', async () => {
    const fields = await refusal(load({ mail: { smtp: { password: { sealed: SEALED } } } }));
    expect(fields.map((field) => field.pointer)).toEqual(['/mail/smtp/password']);
    expect(JSON.stringify(fields)).not.toContain(SEALED);
    const secretStore = { isSet: vi.fn(async () => false) };
    await expect(
      load({ mail: { smtp: { password: { sealed: SEALED } } } }, secretStore)
    ).resolves.toBeDefined();
  });
});

describe('what an approver is shown of a policy patch (#517)', () => {
  const render = (body: unknown, state?: RealmPolicyState) => {
    const { render: renderer } = operation();
    if (renderer === undefined) throw new Error('realms.policies.update has no renderer');
    return renderer({
      operationId: REALM_OPERATION_IDS.updatePolicies,
      method: 'PATCH',
      params: { realmId: REALM },
      query: {},
      body,
      state,
    });
  };

  it('shows each changed field beside the value it replaces, and the version it replaces', () => {
    const rendered = render(
      { password: { minScore: 1 }, tokens: { accessTokenLifespanSeconds: 900 } },
      stateOf()
    );
    expect(rendered.title).toBe('Change one realm policy');
    expect(rendered.fields).toEqual([
      { label: 'replaces the policies of version', value: '4' },
      { label: 'password.minScore', before: '2', value: '1' },
    ]);
  });

  it('shows a secret only as whether it is set, never a value or its sealed form', () => {
    const set = stateOf(undefined, ['mail.smtp.password']);
    const rendered = render({ mail: { smtp: { password: { sealed: SEALED } } } }, set);
    expect(rendered.fields).toContainEqual({
      label: 'mail.smtp.password',
      before: 'set (not shown)',
      value: 'set to a new sealed value (not shown)',
    });
    expect(JSON.stringify(rendered)).not.toContain(SEALED);
    expect(render({ mail: { smtp: { password: null } } }, stateOf()).fields).toContainEqual({
      label: 'mail.smtp.password',
      before: 'not set',
      value: 'cleared',
    });
  });

  it('refuses to render without the policies the approval was filed against', () => {
    expect(() => render({ password: { minScore: 1 } })).toThrow(/filed against/);
  });
});

describe('the body of a policy patch (#517)', () => {
  const schema = policyPatchBodySchema();

  it('takes any field of the policy groups, a sealed secret, null and the flags of the representation', () => {
    for (const body of [
      {},
      { password: { minScore: 1 } },
      { password: { minScore: null }, tokens: { accessTokenLifespanSeconds: 'later checked' } },
      { mail: { smtp: { password: { sealed: SEALED } } } },
      { mail: { smtp: { password: null, passwordSet: true } } },
      { mail: { resend: { apiKey: { sealed: SEALED } } } },
    ]) {
      expect(schema.safeParse(body).success, JSON.stringify(body)).toBe(true);
    }
  });

  it('refuses a member the policies do not have, null on a group and a secret that is not sealed', () => {
    for (const body of [
      { sessions: {} },
      { tokens: { lifetime: 1 } },
      { mail: null },
      { registration: null },
      { registration: { cimd: null } },
      { mail: { smtp: { password: SMTP_PASSWORD } } },
      { mail: { smtp: { password: { sealed: SEALED, value: SMTP_PASSWORD } } } },
      { mail: { smtp: { passwordSet: 'yes' } } },
      [],
    ]) {
      expect(schema.safeParse(body).success, JSON.stringify(body)).toBe(false);
    }
  });
});

describe('the realm representation (#517)', () => {
  const ROW = {
    id: REALM,
    name: 'example',
    enabled: true,
    isOperator: false,
    sandboxOfRealmId: null,
    createdAt: new Date('2026-11-01T10:00:00.000Z'),
    updatedAt: new Date('2026-11-02T10:00:00.000Z'),
  };

  /** A request in an admin handler, over a realm whose SMTP password is set. */
  function handlerRequest() {
    const document = structuredClone(defaultsFromEnv({})) as unknown as Document;
    return {
      adminPipeline: { transaction: { id: 'tx' } },
      server: {
        repositories: {
          realms: { findById: vi.fn(async () => ROW), findSandboxOf: vi.fn(async () => undefined) },
        },
        realmSecretStore: { isSet: vi.fn(async () => true) },
        policyStore: {
          representation: vi.fn(async () => ({
            realmId: REALM,
            version: 9,
            schemaVersion: REALM_POLICY_SCHEMA_VERSION,
            policies: toRealmPoliciesRepresentation(document, ['mail.smtp.password']),
          })),
        },
      },
    } as unknown as FastifyRequest;
  }

  // Acceptance criterion: the representation never contains a secret's value.
  it('shows a set secret as <name>Set, and its ETag is the policy version', async () => {
    const { etag, body } = await realmResource(handlerRequest(), REALM);
    expect(etag).toBe('"9"');
    expect(body).toMatchObject({
      id: REALM,
      name: 'example',
      enabled: true,
      operator: false,
      createdAt: '2026-11-01T10:00:00.000Z',
      updatedAt: '2026-11-02T10:00:00.000Z',
      sandboxOf: null,
      sandbox: null,
      policySchemaVersion: REALM_POLICY_SCHEMA_VERSION,
    });
    const smtp = (body.policies as { mail: { smtp: Record<string, unknown> } }).mail.smtp;
    expect(smtp['passwordSet']).toBe(true);
    expect(smtp).not.toHaveProperty('password');
    expect(realmSchema.safeParse(body).success).toBe(true);
  });

  it('never serializes a secret value, should one reach the representation', () => {
    const representation = toRealmPoliciesRepresentation(
      structuredClone(defaultsFromEnv({})) as unknown as Document,
      ['mail.smtp.password']
    ) as unknown as Record<string, Record<string, Record<string, unknown>>>;
    const leaked = structuredClone(representation);
    leaked['mail']['smtp']['password'] = SMTP_PASSWORD;
    const parsed = realmSchema.safeParse({
      id: REALM,
      name: 'example',
      enabled: true,
      operator: false,
      createdAt: '2026-11-01T10:00:00.000Z',
      updatedAt: '2026-11-02T10:00:00.000Z',
      sandboxOf: null,
      sandbox: null,
      policySchemaVersion: REALM_POLICY_SCHEMA_VERSION,
      policies: leaked,
    });
    // Stripped, or refused: either way the value is never sent.
    expect(parsed.success ? JSON.stringify(parsed.data) : '').not.toContain(SMTP_PASSWORD);
  });
});

describe('the audit record of a policy change (#517)', () => {
  it('holds the changed fields before and after, each secret as whether it is set, annotated', () => {
    const recorded = auditedChange({
      realmId: REALM,
      version: 4,
      before: {} as never,
      after: {} as never,
      diff: {
        changes: [
          {
            path: 'password.minScore',
            before: 2,
            after: 1,
            class: 'security',
            effects: ['credential-path'],
            secret: false,
          },
          {
            path: 'mail.smtp.password',
            before: false,
            after: true,
            class: 'security',
            effects: ['credential-path'],
            secret: true,
          },
        ],
      } as never,
    });
    expect(recorded).toEqual({
      change: {
        before: {
          policiesVersion: 4,
          policies: { password: { minScore: 2 }, mail: { smtp: { password: false } } },
        },
        after: {
          policiesVersion: 5,
          policies: { password: { minScore: 1 }, mail: { smtp: { password: true } } },
        },
      },
      annotations: { 'policies.mail.smtp.password': 'secret' },
    });
  });
});

describe('the realm routes in the admin OpenAPI document (#517)', () => {
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
    const { realmRoutes } = await import('./routes');

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
          await scope.register(realmRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths).sort()).toEqual([
        '/admin/v1-rc.0/realms/{realmId}',
        '/admin/v1-rc.0/realms/{realmId}/policies',
      ]);
      const get = document.paths['/admin/v1-rc.0/realms/{realmId}']['get'];
      expect(get).toMatchObject({
        operationId: 'realms.get',
        'x-qauth-class': 'read',
        'x-qauth-permission': 'realms.read',
      });
      const patch = document.paths['/admin/v1-rc.0/realms/{realmId}/policies']['patch'];
      expect(patch).toMatchObject({
        operationId: 'realms.policies.update',
        'x-qauth-class': 'security',
        'x-qauth-permission': ['realms.policies.write', 'realms.policies.security', 'realms.read'],
        'x-qauth-effects': expect.arrayContaining(['credential-path']),
      });
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(2);
    } finally {
      await app.close();
    }
  });
});
