import { SECURITY_EFFECTS, type SecurityEffect } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  ADMIN_OPERATIONS,
  type AdminOperationDefinition,
  type Classification,
  classifyByField,
  type ClassifyInput,
  classifyRequest,
  createOperationRegistry,
  defineOperation,
  mergeClassifications,
  OPERATION_REGISTRY,
  OperationDefinitionError,
  operationSchemaExtensions,
  UnknownFieldError,
} from './admin-operations';
import { RESERVED_OPERATIONS, type ReservedOperation } from './admin-operations-reserved';
import {
  createPermissionRegistry,
  definePermission,
  PERMISSION_REGISTRY,
} from './admin-permissions';

/**
 * The admin operation registry (#508): the static rule, the permission and
 * reserved-id checks at registration, and the request-dependent
 * classification that fails closed.
 */

const NO_RESERVATIONS: readonly ReservedOperation[] = [];

const readOperation = (overrides: Partial<AdminOperationDefinition> = {}) =>
  ({
    id: 'widgets.get',
    class: 'read',
    effects: [],
    permissions: ['realms.read'],
    description: 'Read a widget.',
    ...overrides,
  }) as AdminOperationDefinition;

const WRITE: Classification = {
  class: 'write',
  effects: [],
  permissions: ['realms.policies.write'],
};
const SECURITY: Classification = {
  class: 'security',
  effects: ['credential-path'],
  permissions: ['realms.policies.security'],
};

/** A policy-patch-like operation: write or security by field. */
function patchOperation(classify: AdminOperationDefinition['classify']) {
  return defineOperation({
    id: 'widgets.policies.update',
    class: 'security',
    effects: ['credential-path', 'posture-loosening'],
    permissions: ['realms.policies.write', 'realms.policies.security'],
    description: 'Change widget policies.',
    classify,
  });
}

const registry = (
  operations: readonly AdminOperationDefinition[],
  reserved: readonly ReservedOperation[] = NO_RESERVATIONS
) => createOperationRegistry(operations, { reserved });

const input = (body: unknown = {}): ClassifyInput => ({
  method: 'PATCH',
  params: { realmId: '018f0000-0000-7000-8000-000000000000' },
  query: {},
  body,
});

describe('defineOperation: the static rule (#508)', () => {
  it('accepts a read, a write and a security operation', () => {
    expect(defineOperation(readOperation()).class).toBe('read');
    expect(
      defineOperation(
        readOperation({
          id: 'widgets.update',
          class: 'write',
          permissions: ['realms.policies.write'],
        })
      ).class
    ).toBe('write');
    expect(
      defineOperation(
        readOperation({
          id: 'widgets.rotate',
          class: 'security',
          effects: ['key-custody'],
          permissions: ['realms.policies.security'],
        })
      ).effects
    ).toEqual(['key-custody']);
  });

  // Acceptance criterion: an operation with class write and a non-empty
  // effects list fails registration.
  it('refuses a write operation with an effect', () => {
    const definition = readOperation({
      id: 'widgets.update',
      class: 'write',
      effects: ['token-content'],
      permissions: ['realms.policies.write'],
    });
    expect(() => defineOperation(definition)).toThrow(OperationDefinitionError);
    expect(() => defineOperation(definition)).toThrow(/is a security operation, not write/);
    expect(() => registry([definition])).toThrow(OperationDefinitionError);
  });

  it('refuses a read operation with an effect', () => {
    expect(() => defineOperation(readOperation({ effects: ['import'] }))).toThrow(
      /is a security operation, not read/
    );
  });

  // Acceptance criterion: an operation with class security and no effect
  // fails registration.
  it('refuses a security operation with no effect', () => {
    const definition = readOperation({
      id: 'widgets.rotate',
      class: 'security',
      effects: [],
      permissions: ['realms.policies.security'],
    });
    expect(() => defineOperation(definition)).toThrow(/names the effects that make it one/);
    expect(() => registry([definition])).toThrow(OperationDefinitionError);
  });

  it('refuses an unknown effect, a repeated effect and an effect list that is not a list', () => {
    const security = { class: 'security' as const, permissions: ['realms.policies.security'] };
    expect(() =>
      defineOperation(
        readOperation({ ...security, effects: ['credential-paths' as SecurityEffect] })
      )
    ).toThrow(/is not an effect tag/);
    expect(() =>
      defineOperation(readOperation({ ...security, effects: ['Key-Custody' as SecurityEffect] }))
    ).toThrow(/is not an effect tag/);
    expect(() =>
      defineOperation(readOperation({ ...security, effects: ['import', 'import'] }))
    ).toThrow(/listed twice/);
    expect(() =>
      defineOperation(
        readOperation({ ...security, effects: 'import' as unknown as SecurityEffect[] })
      )
    ).toThrow(/a list of effect tags/);
  });

  // Fail closed at registration: a misspelt member (`effect` for `effects`)
  // would otherwise leave the operation with no effect and the class write.
  it('refuses an unknown member', () => {
    expect(() =>
      defineOperation({
        ...readOperation({
          id: 'widgets.update',
          class: 'write',
          permissions: ['realms.policies.write'],
        }),
        effect: ['token-content'],
      } as AdminOperationDefinition)
    ).toThrow(/unknown member effect/);
    expect(() =>
      defineOperation({ ...readOperation(), [Symbol('x')]: true } as AdminOperationDefinition)
    ).toThrow(/unknown member/);
  });

  it.each([
    ['an id that is not <resource>.<verb>', { id: 'getWidget' }, /an id is <resource>.<verb>/],
    ['an unknown class', { class: 'admin' }, /the class must be one of/],
    ['no permission', { permissions: [] }, /non-empty list of permission ids/],
    ['a malformed permission', { permissions: ['qauth:admin:read'] }, /list of permission ids/],
    ['a repeated permission', { permissions: ['realms.read', 'realms.read'] }, /listed twice/],
    ['an empty description', { description: '' }, /one line/],
    ['a two-line description', { description: 'Read.\nA widget.' }, /one line/],
    ['a classify that is not a function', { classify: 'read' }, /classify is a function/],
  ])('refuses %s', (_label, overrides, message) => {
    expect(() =>
      defineOperation(readOperation(overrides as Partial<AdminOperationDefinition>))
    ).toThrow(message);
  });

  // A request whose classification fails closed gets the declaration, so the
  // declaration of an operation with classify is the security case.
  it('refuses classify on an operation that does not declare the security case', () => {
    expect(() =>
      defineOperation(
        readOperation({
          id: 'widgets.update',
          class: 'write',
          permissions: ['realms.policies.write'],
          classify: () => WRITE,
        })
      )
    ).toThrow(/declares the strictest case, class security/);
  });

  it('refuses loadState without classify', () => {
    expect(() => defineOperation(readOperation({ loadState: async () => ({}) }))).toThrow(
      /loadState is read only by classify/
    );
  });

  // What is checked is what is stored: a getter could answer the checks one
  // way and the stored copy another.
  it('refuses an accessor member, and stores the values it checked', () => {
    let reads = 0;
    const shifty = Object.defineProperty(
      {
        ...readOperation({
          id: 'realms.delete',
          effects: ['realm-lifecycle'],
          permissions: ['realms.policies.security'],
        }),
      },
      'class',
      { get: () => (++reads > 5 ? 'write' : 'security'), enumerable: true }
    ) as AdminOperationDefinition;
    expect(() => defineOperation(shifty)).toThrow(/class is a value, not an accessor/);
    expect(() => createOperationRegistry([shifty])).toThrow(/class is a value, not an accessor/);
  });

  it('refuses a permission list with a hole', () => {
    // eslint-disable-next-line no-sparse-arrays
    const permissions = ['realms.read', , 'realms.export'] as string[];
    expect(() => defineOperation(readOperation({ permissions }))).toThrow(
      /non-empty list of permission ids/
    );
  });

  it('freezes the operation and its lists', () => {
    const operation = defineOperation(readOperation());
    expect(Object.isFrozen(operation)).toBe(true);
    expect(Object.isFrozen(operation.effects)).toBe(true);
    expect(Object.isFrozen(operation.permissions)).toBe(true);
  });
});

describe('createOperationRegistry (#508)', () => {
  it('looks operations up by exact id', () => {
    const operations = registry([readOperation(), readOperation({ id: 'widgets.list' })]);
    expect(operations.all.map((operation) => operation.id)).toEqual([
      'widgets.get',
      'widgets.list',
    ]);
    expect(operations.get('widgets.get')?.id).toBe('widgets.get');
    expect(operations.get('Widgets.get')).toBeUndefined();
    expect(operations.get('toString')).toBeUndefined();
  });

  it('refuses an id defined twice, or twice in different case', () => {
    expect(() => registry([readOperation(), readOperation()])).toThrow(/defined twice/);
    expect(() =>
      registry([readOperation({ id: 'widgets.getOne' }), readOperation({ id: 'widgets.getone' })])
    ).toThrow(/differ only in case/);
  });

  it('refuses a permission the catalog cannot grant: unknown or retired', () => {
    expect(() => registry([readOperation({ permissions: ['widgets.read'] })])).toThrow(
      /not a grantable permission/
    );
    const permissions = createPermissionRegistry([
      ...PERMISSION_REGISTRY.all,
      definePermission({
        id: 'widgets.read',
        class: 'read',
        resource: 'widgets',
        description: 'Read the widgets.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    expect(() =>
      createOperationRegistry([readOperation({ permissions: ['widgets.read'] })], {
        permissions,
        reserved: NO_RESERVATIONS,
      })
    ).toThrow(/not a grantable permission/);
  });

  // The class is the strictest class among the permissions: otherwise a
  // security operation would be reachable with `qauth:admin:write`, or a
  // write operation would hide a security permission.
  it('refuses a class that is not the strictest class among its permissions', () => {
    expect(() =>
      registry([
        readOperation({
          id: 'widgets.rotate',
          class: 'security',
          effects: ['key-custody'],
          permissions: ['realms.policies.write'],
        }),
      ])
    ).toThrow(/the strictest class among its permissions is write/);
    expect(() =>
      registry([
        readOperation({
          id: 'widgets.update',
          class: 'write',
          permissions: ['realms.policies.write', 'approvals.approve'],
        }),
      ])
    ).toThrow(/the strictest class among its permissions is security/);
    expect(() =>
      registry([readOperation({ permissions: ['realms.read', 'realms.policies.write'] })])
    ).toThrow(/the strictest class among its permissions is write/);
  });

  describe('the reserved table', () => {
    const reserved: readonly ReservedOperation[] = [
      {
        id: 'widgets.rotate',
        effects: ['key-custody', 'token-content'],
        source: 'a test',
        description: 'Rotate a widget.',
      },
    ];
    const rotate = (overrides: Partial<AdminOperationDefinition>) =>
      readOperation({
        id: 'widgets.rotate',
        class: 'security',
        effects: ['key-custody', 'token-content'],
        permissions: ['realms.policies.security'],
        ...overrides,
      });

    it('accepts a reserved id registered with its effects, or more', () => {
      expect(registry([rotate({})], reserved).get('widgets.rotate')).toBeDefined();
      expect(
        registry([rotate({ effects: ['token-content', 'key-custody', 'import'] })], reserved).get(
          'widgets.rotate'
        )
      ).toBeDefined();
    });

    // Acceptance criterion: registering a reserved id with a weaker effect fails.
    it('refuses a reserved id registered with a weaker effect', () => {
      expect(() => registry([rotate({ effects: ['key-custody'] })], reserved)).toThrow(
        /reserved as a security operation with the effects key-custody, token-content \(a test\)/
      );
      expect(() => registry([rotate({ effects: ['import'] })], reserved)).toThrow(
        OperationDefinitionError
      );
      expect(() =>
        registry(
          [rotate({ class: 'write', effects: [], permissions: ['realms.policies.write'] })],
          reserved
        )
      ).toThrow(/it is registered as write with no effect/);
      expect(() =>
        registry([rotate({ class: 'read', effects: [], permissions: ['realms.read'] })], reserved)
      ).toThrow(/it is registered as read with no effect/);
    });

    // A classify could otherwise answer `write` for every request of an
    // operation reserved as a security operation.
    it('refuses classify on a reserved id unless its entry says the request decides', () => {
      const lowering = rotate({
        permissions: ['realms.policies.write', 'realms.policies.security'],
        classify: () => WRITE,
      });
      expect(() => registry([lowering], reserved)).toThrow(
        /reserved as a security operation on every request \(a test\); it may not classify/
      );
      expect(
        registry([lowering], [{ ...reserved[0], requestDependent: true }]).get('widgets.rotate')
      ).toBeDefined();
    });

    // Ids that differ only in case are one id everywhere else in the registry.
    it('refuses a case variant of a reserved id', () => {
      expect(() =>
        registry(
          [
            readOperation({
              id: 'widgets.rotatE',
              class: 'write',
              permissions: ['realms.policies.write'],
            }),
          ],
          reserved
        )
      ).toThrow(/differs only in case from the reserved id "widgets.rotate"/);
      // A realistic slip against the server table.
      expect(() =>
        createOperationRegistry([
          readOperation({
            id: 'upstreamproviders.create',
            class: 'write',
            permissions: ['realms.policies.write'],
          }),
        ])
      ).toThrow(/differs only in case from the reserved id "upstreamProviders.create"/);
    });

    it('applies the server table by default', () => {
      expect(() =>
        createOperationRegistry([
          readOperation({
            id: 'realms.policies.update',
            class: 'write',
            permissions: ['realms.policies.write'],
          }),
        ])
      ).toThrow(/realms.policies.update" is reserved as a security operation/);
      expect(() =>
        createOperationRegistry(
          [patchOperation(() => WRITE) as AdminOperationDefinition].map((operation) => ({
            ...operation,
            id: 'realms.policies.update',
          }))
        )
      ).toThrow(/credential-path, token-content, posture-loosening, administration/);
    });

    it('refuses a malformed table', () => {
      const entry = reserved[0];
      for (const table of [
        [entry, { ...entry, id: 'Widgets.rotate' }],
        [{ ...entry, id: 'rotate' }],
        [{ ...entry, effects: [] }],
        [{ ...entry, effects: ['rotation' as SecurityEffect] }],
        [{ ...entry, effects: ['import', 'import'] as SecurityEffect[] }],
        [{ ...entry, source: '' }],
        [{ ...entry, requestDepedent: true } as ReservedOperation],
        [{ ...entry, requestDependent: false } as unknown as ReservedOperation],
      ]) {
        expect(() => registry([], table)).toThrow(OperationDefinitionError);
      }
    });
  });
});

describe('the server registry and reserved table (#508)', () => {
  it('builds from the server definitions', () => {
    expect(OPERATION_REGISTRY.all).toEqual(ADMIN_OPERATIONS);
    expect(OPERATION_REGISTRY.permissions).toBe(PERMISSION_REGISTRY);
    expect(OPERATION_REGISTRY.reserved).toEqual(RESERVED_OPERATIONS);
  });

  it('lets only request-dependent reserved operations classify', () => {
    expect(
      RESERVED_OPERATIONS.filter((entry) => entry.requestDependent).map((entry) => entry.id)
    ).toEqual(['realms.policies.update', 'clients.update', 'realms.imports.apply']);
    const policies = defineOperation({
      id: 'realms.policies.update',
      class: 'security',
      effects: ['credential-path', 'token-content', 'posture-loosening', 'administration'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      description: "Change a realm's policies.",
      classify: () => WRITE,
    });
    expect(createOperationRegistry([policies]).get('realms.policies.update')).toBeDefined();
    expect(() =>
      createOperationRegistry([
        defineOperation({
          id: 'keys.rotate',
          class: 'security',
          effects: ['key-custody'],
          permissions: ['realms.policies.write', 'realms.policies.security'],
          description: 'Rotate a key.',
          classify: () => WRITE,
        }),
      ])
    ).toThrow(/keys.rotate" is reserved as a security operation on every request/);
  });

  it('reserves at least one operation id for every effect', () => {
    const covered = new Set(RESERVED_OPERATIONS.flatMap((entry) => entry.effects));
    expect(SECURITY_EFFECTS.filter((effect) => !covered.has(effect))).toEqual([]);
  });

  it('reserves no id of an operation the API conventions treat as a read', () => {
    for (const entry of RESERVED_OPERATIONS) {
      expect(entry.id, entry.id).not.toMatch(/\.(get|list)$/);
    }
  });

  // Acceptance criterion: a reserved id, once registered, carries its
  // declared effect. The registry refuses one that does not; this walks the
  // server's own registry, so a later definition is checked here too.
  it('registers every reserved id it holds as a security operation with its reserved effects', () => {
    for (const entry of RESERVED_OPERATIONS) {
      const operation = OPERATION_REGISTRY.get(entry.id);
      if (operation === undefined) continue;
      expect(operation.class, entry.id).toBe('security');
      expect(operation.effects, entry.id).toEqual(expect.arrayContaining([...entry.effects]));
    }
  });

  it('keeps every registered operation within the static rule', () => {
    for (const operation of OPERATION_REGISTRY.all) {
      expect(operation.class === 'security', operation.id).toBe(operation.effects.length > 0);
    }
  });
});

describe('classifyRequest (#508)', () => {
  it('gives an operation without classify its declaration', () => {
    const operation = defineOperation(readOperation());
    const classification = classifyRequest(registry([operation]), operation, input());
    expect(classification).toEqual({
      operationId: 'widgets.get',
      class: 'read',
      effects: [],
      permissions: ['realms.read'],
      failedClosed: null,
    });
    expect(Object.isFrozen(classification)).toBe(true);
  });

  it('keeps a well-formed classification within the declaration, in canonical order', () => {
    const operation = patchOperation(() => ({
      class: 'security',
      effects: ['posture-loosening', 'credential-path', 'posture-loosening'],
      permissions: ['realms.policies.security', 'realms.policies.write'],
    }));
    const classification = classifyRequest(registry([operation]), operation, input());
    expect(classification).toEqual({
      operationId: 'widgets.policies.update',
      class: 'security',
      effects: ['credential-path', 'posture-loosening'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      failedClosed: null,
    });
    expect(Object.isFrozen(classification.effects)).toBe(true);
    expect(Object.isFrozen(classification.permissions)).toBe(true);
  });

  it('lets a request need less than the declaration: a write-only patch', () => {
    const operation = patchOperation(() => WRITE);
    expect(classifyRequest(registry([operation]), operation, input())).toMatchObject({
      ...WRITE,
      failedClosed: null,
    });
  });

  const DECLARATION = {
    class: 'security',
    effects: ['credential-path', 'posture-loosening'],
    permissions: ['realms.policies.write', 'realms.policies.security'],
  };

  // Acceptance criterion: a classify that throws yields security.
  it('fails closed to the security declaration when classify throws', () => {
    const operation = patchOperation(() => {
      throw new Error('no rule');
    });
    expect(classifyRequest(registry([operation]), operation, input())).toEqual({
      operationId: 'widgets.policies.update',
      ...DECLARATION,
      failedClosed: 'threw',
    });
    const throwsValue = patchOperation(() => {
      throw 'not an error';
    });
    expect(classifyRequest(registry([throwsValue]), throwsValue, input())).toMatchObject({
      class: 'security',
      failedClosed: 'threw',
    });
  });

  it.each([
    ['an unknown member', { ...WRITE, approved: true }, 'unknown-field'],
    ['a symbol member', { ...WRITE, [Symbol('x')]: 1 }, 'unknown-field'],
    ['an unknown effect', { ...SECURITY, effects: ['credentials'] }, 'unknown-effect'],
    ['an effect that is not a string', { ...SECURITY, effects: [1] }, 'unknown-effect'],
    ['an unknown class', { ...WRITE, class: 'none' }, 'unknown-class'],
    ['an unknown permission', { ...WRITE, permissions: ['widgets.write'] }, 'unknown-permission'],
    [
      'a permission the operation does not declare',
      { ...WRITE, class: 'read', permissions: ['realms.read'] },
      'exceeds-declaration',
    ],
    [
      'an effect the operation does not declare',
      { ...SECURITY, effects: ['import'] },
      'exceeds-declaration',
    ],
    [
      'a write class with a security permission',
      { ...WRITE, permissions: ['realms.policies.write', 'realms.policies.security'] },
      'inconsistent',
    ],
    ['a write class with an effect', { ...WRITE, effects: ['credential-path'] }, 'inconsistent'],
    ['a security class with no effect', { ...SECURITY, effects: [] }, 'inconsistent'],
    [
      'a security class with only a write permission',
      { ...SECURITY, permissions: ['realms.policies.write'] },
      'inconsistent',
    ],
    ['no permission', { ...WRITE, permissions: [] }, 'malformed'],
    ['no class', { effects: [], permissions: ['realms.policies.write'] }, 'malformed'],
    ['effects that are not a list', { ...WRITE, effects: 'none' }, 'malformed'],
    ['null', null, 'malformed'],
    ['a list', [WRITE], 'malformed'],
    ['a string', 'write', 'malformed'],
    ['undefined', undefined, 'malformed'],
  ])('fails closed on %s', (_label, result, reason) => {
    const operation = patchOperation(() => result as Classification);
    expect(classifyRequest(registry([operation]), operation, input())).toEqual({
      operationId: 'widgets.policies.update',
      ...DECLARATION,
      failedClosed: reason,
    });
  });

  it('fails closed on a result that is not a plain object', () => {
    class Result {
      class = 'write';
      effects = [];
      permissions = ['realms.policies.write'];
    }
    const instance = patchOperation(() => new Result() as Classification);
    expect(classifyRequest(registry([instance]), instance, input()).failedClosed).toBe('malformed');

    const accessor = patchOperation(
      () =>
        Object.defineProperty({ effects: [], permissions: ['realms.policies.write'] }, 'class', {
          get: () => 'write',
          enumerable: true,
        }) as unknown as Classification
    );
    expect(classifyRequest(registry([accessor]), accessor, input()).failedClosed).toBe('malformed');

    const proxy = patchOperation(
      () =>
        new Proxy({} as Classification, {
          ownKeys: () => {
            throw new Error('trap');
          },
        })
    );
    expect(classifyRequest(registry([proxy]), proxy, input()).failedClosed).toBe('malformed');
  });

  it('fails closed, without throwing, when classify throws a value whose members throw', () => {
    const operation = patchOperation(() => {
      throw new Proxy(
        {},
        {
          get: () => {
            throw new Error('trap');
          },
        }
      );
    });
    expect(classifyRequest(registry([operation]), operation, input()).failedClosed).toBe('threw');
  });

  it('fails closed on a classify that returns a promise, without an unhandled rejection', async () => {
    const operation = patchOperation(
      () => Promise.reject(new Error('later')) as unknown as Classification
    );
    expect(classifyRequest(registry([operation]), operation, input()).failedClosed).toBe(
      'not-synchronous'
    );
    const resolved = patchOperation(() => Promise.resolve(WRITE) as unknown as Classification);
    expect(classifyRequest(registry([resolved]), resolved, input()).failedClosed).toBe(
      'not-synchronous'
    );
    await new Promise((resolve) => setImmediate(resolve));
  });

  it('runs classify on frozen copies, so it cannot change the request or the state', () => {
    const body = { password: { minScore: 1 } };
    const state = { password: { minScore: 3 } };
    let seen: { body: unknown; state: unknown } | undefined;
    const reader = patchOperation((request, currentState) => {
      seen = { body: request.body, state: currentState };
      return WRITE;
    });
    classifyRequest(registry([reader]), reader, input(body), state);
    expect(seen?.body).toEqual(body);
    expect(seen?.body).not.toBe(body);
    expect(seen?.state).toEqual(state);
    expect(seen?.state).not.toBe(state);

    const writer = patchOperation((request) => {
      (request.body as typeof body).password.minScore = 4;
      return WRITE;
    });
    expect(classifyRequest(registry([writer]), writer, input(body), state)).toMatchObject({
      class: 'security',
      failedClosed: 'threw',
    });
    expect(body.password.minScore).toBe(1);
  });

  it('fails closed when the state cannot be copied', () => {
    const operation = patchOperation(() => WRITE);
    expect(
      classifyRequest(registry([operation]), operation, input(), { load: () => undefined })
        .failedClosed
    ).toBe('uncloneable-input');
  });

  it('copies a binary body without failing', () => {
    const operation = patchOperation((request) =>
      request.body instanceof Uint8Array ? WRITE : SECURITY
    );
    expect(
      classifyRequest(registry([operation]), operation, input(Buffer.from('realm file')))
    ).toMatchObject({ class: 'write', failedClosed: null });
  });
});

describe('classifyByField (#508)', () => {
  type State = { minScore: number };
  const leafPaths = (request: ClassifyInput): string[] => {
    const paths: string[] = [];
    const walk = (value: unknown, prefix: string) => {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        for (const [key, child] of Object.entries(value))
          walk(child, prefix ? `${prefix}.${key}` : key);
      } else {
        paths.push(prefix);
      }
    };
    walk(request.body, '');
    return paths;
  };
  const operation = patchOperation(
    classifyByField<State>({
      changedFields: leafPaths,
      fields: {
        'tokens.accessTokenLifespanSeconds': WRITE,
        // Security only when the change loosens the policy.
        'password.minScore': (request, state) =>
          (request.body as { password: { minScore: number } }).password.minScore < state.minScore
            ? SECURITY
            : WRITE,
        'posture.maxEnvironmentLaxity': {
          class: 'security',
          effects: ['posture-loosening'],
          permissions: ['realms.policies.security'],
        },
      },
      unchanged: WRITE,
    }) as AdminOperationDefinition['classify']
  );
  const operations = registry([operation]);
  const classify = (body: unknown) =>
    classifyRequest(operations, operation, input(body), { minScore: 2 });

  it('classifies each known field, and merges a mixed change', () => {
    expect(classify({ tokens: { accessTokenLifespanSeconds: 600 } })).toMatchObject({
      ...WRITE,
      failedClosed: null,
    });
    expect(classify({ password: { minScore: 3 } })).toMatchObject({ ...WRITE, failedClosed: null });
    expect(classify({ password: { minScore: 1 } })).toMatchObject({
      ...SECURITY,
      failedClosed: null,
    });
    expect(
      classify({ tokens: { accessTokenLifespanSeconds: 600 }, password: { minScore: 1 } })
    ).toMatchObject({
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      failedClosed: null,
    });
    expect(classify({})).toMatchObject({ ...WRITE, failedClosed: null });
  });

  // Fail closed: an unknown field counts as security, never as write.
  it.each([
    [{ tokens: { idTokenLifespanSeconds: 1 } }],
    [{ password: { minScore: 3 }, brandColour: 'red' }],
    [JSON.parse('{"__proto__": {"x": 1}}')],
    [{ constructor: 1 }],
    [{ toString: 1 }],
    [{ hasOwnProperty: 1 }],
  ])('fails closed on an unknown field: %j', (body) => {
    expect(classify(body)).toMatchObject({
      class: 'security',
      effects: ['credential-path', 'posture-loosening'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      failedClosed: 'unknown-field',
    });
  });

  it('fails closed on a field rule that names an unknown effect', () => {
    const broken = patchOperation(
      classifyByField({
        changedFields: () => ['mail.provider'],
        fields: {
          'mail.provider': {
            ...SECURITY,
            effects: ['mail' as SecurityEffect],
          },
        },
        unchanged: WRITE,
      })
    );
    expect(classifyRequest(registry([broken]), broken, input()).failedClosed).toBe(
      'unknown-effect'
    );
  });

  it('recognizes an UnknownFieldError of any copy of the module', () => {
    const foreign = Object.assign(new Error('x'), {
      [Symbol.for('qauth.adminOperations.unknownField')]: true,
    });
    const operation2 = patchOperation(() => {
      throw foreign;
    });
    expect(classifyRequest(registry([operation2]), operation2, input()).failedClosed).toBe(
      'unknown-field'
    );
    expect(new UnknownFieldError('a.b').field).toBe('a.b');
  });
});

describe('mergeClassifications (#508)', () => {
  it('takes the strictest class and every effect and permission', () => {
    expect(mergeClassifications([WRITE, SECURITY, WRITE])).toEqual({
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
    });
    expect(mergeClassifications([])).toEqual({ class: 'read', effects: [], permissions: [] });
  });
});

describe('operationSchemaExtensions (#508)', () => {
  it('gives a read operation its id, class and permission', () => {
    expect(operationSchemaExtensions(defineOperation(readOperation()))).toEqual({
      operationId: 'widgets.get',
      'x-qauth-class': 'read',
      'x-qauth-permission': 'realms.read',
    });
  });

  it('gives a security operation its effects and the two-admin marker, and a permission list', () => {
    expect(operationSchemaExtensions(patchOperation(() => WRITE))).toEqual({
      operationId: 'widgets.policies.update',
      'x-qauth-class': 'security',
      'x-qauth-permission': ['realms.policies.write', 'realms.policies.security'],
      'x-qauth-effects': ['credential-path', 'posture-loosening'],
      'x-qauth-two-admin': 'recommended',
    });
  });
});
