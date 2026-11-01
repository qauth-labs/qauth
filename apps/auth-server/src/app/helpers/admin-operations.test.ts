import { createHash } from 'node:crypto';

import { SECURITY_EFFECTS, type SecurityEffect } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  ADMIN_OPERATIONS,
  type AdminOperationDefinition,
  bodyDigestOf,
  type Classification,
  classifyByField,
  type ClassifyInput,
  classifyRequest,
  createOperationRegistry,
  defineOperation,
  ifMatchAllows,
  mergeClassifications,
  mergePatchLeafPaths,
  OPERATION_REGISTRY,
  OperationDefinitionError,
  operationSchemaExtensions,
  operationStateVersion,
  UnknownFieldError,
} from './admin-operations';
import {
  RESERVED_OPERATIONS,
  type ReservedOperation,
  type ReservedVector,
} from './admin-operations-reserved';
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

/** A security case of a request-dependent test entry. */
const KEYS_CASE: ReservedVector = {
  name: 'replaces the keys',
  request: { method: 'PATCH', params: {}, query: {}, body: { keys: [] } },
  state: {},
  effects: ['key-custody'],
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
    expect(() =>
      defineOperation(readOperation({ loadState: async () => ({}), stateVersion: () => 'v1' }))
    ).toThrow(/loadState is read only by classify/);
  });

  // M1: the classification holds for the state it was made against only.
  it('requires stateVersion with loadState, and only with it', () => {
    const classified = {
      class: 'security' as const,
      effects: ['credential-path' as const],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      classify: () => WRITE,
    };
    expect(() =>
      defineOperation(readOperation({ ...classified, loadState: async () => ({}) }))
    ).toThrow(/names the version of the state it read \(stateVersion\)/);
    expect(() =>
      defineOperation(readOperation({ ...classified, stateVersion: () => 'v1' }))
    ).toThrow(/stateVersion is read only with loadState/);
    expect(() =>
      defineOperation(
        readOperation({
          ...classified,
          loadState: async () => ({}),
          stateVersion: 'v1' as unknown as () => string,
        })
      )
    ).toThrow(/stateVersion is a function/);
    expect(
      defineOperation(
        readOperation({ ...classified, loadState: async () => ({}), stateVersion: () => 'v1' })
      ).stateVersion
    ).toBeTypeOf('function');
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
      const meeting = rotate({
        permissions: ['realms.policies.write', 'realms.policies.security'],
        classify: (request) =>
          (request.body as { keys?: unknown }).keys === undefined
            ? WRITE
            : {
                class: 'security',
                effects: ['key-custody'],
                permissions: ['realms.policies.security'],
              },
      });
      expect(
        registry([meeting], [{ ...reserved[0], requestDependent: true, vectors: [KEYS_CASE] }]).get(
          'widgets.rotate'
        )
      ).toBeDefined();
    });

    // M2: a request-dependent reservation keeps its security cases.
    it('refuses a classify that gives a reserved case less than it needs', () => {
      const table = [{ ...reserved[0], requestDependent: true as const, vectors: [KEYS_CASE] }];
      const answering = (classification: Classification) =>
        rotate({
          permissions: ['realms.policies.write', 'realms.policies.security'],
          classify: () => classification,
        });
      expect(() => registry([answering(WRITE)], table)).toThrow(
        /classify gives the reserved case "replaces the keys" write with no effect, but it needs at least security with key-custody \(a test\)/
      );
      expect(() =>
        registry(
          [
            answering({
              class: 'security',
              effects: ['token-content'],
              permissions: ['realms.policies.security'],
            }),
          ],
          table
        )
      ).toThrow(/gives the reserved case "replaces the keys" security with token-content/);
      // A case classify fails closed on tests nothing: it is in another shape.
      expect(() =>
        registry(
          [
            rotate({
              permissions: ['realms.policies.write', 'realms.policies.security'],
              classify: () => {
                throw new UnknownFieldError('/keys');
              },
            }),
          ],
          table
        )
      ).toThrow(/classify fails closed \(unknown-field\) on the reserved case "replaces the keys"/);
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
        // A request-dependent entry lists cases; no other entry does.
        [{ ...entry, requestDependent: true } as ReservedOperation],
        [{ ...entry, requestDependent: true, vectors: [] } as ReservedOperation],
        [{ ...entry, vectors: [KEYS_CASE] }],
        [
          {
            ...entry,
            requestDependent: true,
            vectors: [{ ...KEYS_CASE, effects: ['import'] }],
          } as ReservedOperation,
        ],
        [
          {
            ...entry,
            requestDependent: true,
            vectors: [{ ...KEYS_CASE, effects: [] }],
          } as ReservedOperation,
        ],
        [
          {
            ...entry,
            requestDependent: true,
            vectors: [KEYS_CASE, KEYS_CASE],
          } as ReservedOperation,
        ],
        [
          {
            ...entry,
            requestDependent: true,
            vectors: [{ ...KEYS_CASE, extra: 1 } as ReservedVector],
          } as ReservedOperation,
        ],
      ]) {
        expect(() => registry([], table)).toThrow(OperationDefinitionError);
      }
    });
  });
});

describe('the server registry and reserved table (#508)', () => {
  it('builds from the server definitions and the approval operations (#512)', () => {
    expect(OPERATION_REGISTRY.all.map((operation) => operation.id)).toEqual([
      ...ADMIN_OPERATIONS.map((operation) => operation.id),
      'approvals.create',
      'approvals.get',
      'approvals.cancel',
    ]);
    expect(OPERATION_REGISTRY.permissions).toBe(PERMISSION_REGISTRY);
    expect(OPERATION_REGISTRY.reserved).toEqual(RESERVED_OPERATIONS);
  });

  it('lets only request-dependent reserved operations classify', () => {
    expect(
      RESERVED_OPERATIONS.filter((entry) => entry.requestDependent).map((entry) => entry.id)
    ).toEqual(['realms.policies.update', 'clients.update', 'realms.imports.apply']);
    // M2: answering `write` for every request no longer takes the entry.
    const policies = defineOperation({
      id: 'realms.policies.update',
      class: 'security',
      effects: ['credential-path', 'token-content', 'posture-loosening', 'administration'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      description: "Change a realm's policies.",
      classify: () => WRITE,
    });
    expect(() => createOperationRegistry([policies])).toThrow(
      /classify gives the reserved case "lowers the password minimum length" write with no effect/
    );
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
      stateVersion: null,
      bodyDigest: null,
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
      stateVersion: null,
      bodyDigest: null,
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
      stateVersion: null,
      bodyDigest: null,
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
      stateVersion: null,
      bodyDigest: null,
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

/** A security classification with `effects`, needing the security permission. */
const securityWith = (...effects: SecurityEffect[]): Classification => ({
  class: 'security',
  effects,
  permissions: ['realms.policies.security'],
});

/** The member of a merge-patch body at a top-level or two-level JSON Pointer. */
function at(value: unknown, path: string): unknown {
  return path
    .split('/')
    .slice(1)
    .reduce<unknown>(
      (node, key) =>
        typeof node === 'object' && node !== null
          ? (node as Record<string, unknown>)[key]
          : undefined,
      value
    );
}

/** A number that grows, or a cap removed, loosens. */
const lengthening =
  (path: string) =>
  (request: ClassifyInput, state: unknown): Classification => {
    const next = at(request.body, path);
    const current = at(state, path);
    return next === null || (typeof next === 'number' && next > (current as number))
      ? securityWith('posture-loosening')
      : WRITE;
  };

/** A retention that shrinks, or is switched off, loosens. */
const shortening =
  (path: string) =>
  (request: ClassifyInput, state: unknown): Classification => {
    const next = at(request.body, path);
    const current = at(state, path);
    return next === null || (typeof next === 'number' && next < (current as number))
      ? securityWith('posture-loosening')
      : WRITE;
  };

/** A field that is a security change unless it keeps or tightens `safe`. */
const unless =
  (path: string, safe: (value: unknown, current: unknown) => boolean, effect: SecurityEffect) =>
  (request: ClassifyInput, state: unknown): Classification =>
    safe(at(request.body, path), at(state, path)) ? WRITE : securityWith(effect);

const REQUEST_DEPENDENT_PERMISSIONS = ['realms.policies.write', 'realms.policies.security'];

/** A correct classify for each request-dependent reserved entry, as its issue would write it. */
const CORRECT_CLASSIFY: Record<string, AdminOperationDefinition['classify']> = {
  'realms.policies.update': classifyByField<unknown>({
    changedFields: (request) => mergePatchLeafPaths(request.body),
    fields: {
      '/passwordPolicy/minLength': unless(
        '/passwordPolicy/minLength',
        (next, current) => typeof next === 'number' && next >= (current as number),
        'credential-path'
      ),
      '/bruteForce/enabled': unless(
        '/bruteForce/enabled',
        (next) => next === true,
        'credential-path'
      ),
      '/maxEnvironmentLaxity': unless(
        '/maxEnvironmentLaxity',
        (next) => next === 'production',
        'posture-loosening'
      ),
      '/accessTokenLifespan': lengthening('/accessTokenLifespan'),
      '/refreshTokenLifespan': lengthening('/refreshTokenLifespan'),
      '/ssoMaxLifespan': lengthening('/ssoMaxLifespan'),
      '/ssoIdleTimeout': lengthening('/ssoIdleTimeout'),
      '/keyRotationIntervalDays': lengthening('/keyRotationIntervalDays'),
      '/adminEventRetentionDays': shortening('/adminEventRetentionDays'),
      '/userEventRetentionDays': shortening('/userEventRetentionDays'),
    },
    unchanged: WRITE,
  }),
  'clients.update': classifyByField<unknown>({
    changedFields: (request) => mergePatchLeafPaths(request.body),
    fields: {
      '/redirectUris': unless(
        '/redirectUris',
        (next, current) =>
          Array.isArray(next) && next.every((uri) => (current as unknown[]).includes(uri)),
        'token-content'
      ),
      '/tokenEndpointAuthMethod': securityWith('token-content'),
      '/jwks': securityWith('token-content'),
      '/jwks/keys': securityWith('token-content'),
      '/jwksUri': securityWith('token-content'),
      '/requirePkce': unless('/requirePkce', (next) => next === true, 'posture-loosening'),
      '/dpopBoundAccessTokens': unless(
        '/dpopBoundAccessTokens',
        (next) => next === true,
        'posture-loosening'
      ),
      '/firstParty': unless('/firstParty', (next) => next === false, 'token-content'),
      '/verifiedDomain': securityWith('token-content'),
      // #891: a list that keeps or narrows the scopes a token naming no user
      // may carry is an ordinary write; lifting it (NULL) or adding a scope is not.
      '/clientCredentialsScopes': unless(
        '/clientCredentialsScopes',
        (next, current) =>
          Array.isArray(next) &&
          (current === null ||
            current === undefined ||
            (Array.isArray(current) && next.every((scope) => current.includes(scope)))),
        'token-content'
      ),
      '/environment': unless('/environment', (next) => next === 'production', 'posture-loosening'),
    },
    unchanged: WRITE,
  }),
  // An import is a security operation as soon as its file differs from the
  // realm in anything but the display name.
  'realms.imports.apply': (request, state) => {
    const content = (value: unknown) =>
      JSON.stringify({ ...(value as Record<string, unknown>), displayName: undefined });
    return content(request.body) === content(state) ? WRITE : securityWith('import');
  },
};

/** The request-dependent entry `id` registered with `classify`. */
function requestDependentOperation(id: string, classify: AdminOperationDefinition['classify']) {
  const entry = RESERVED_OPERATIONS.find((candidate) => candidate.id === id) as ReservedOperation;
  return defineOperation({
    id,
    class: 'security',
    effects: entry.effects,
    permissions: REQUEST_DEPENDENT_PERMISSIONS,
    description: entry.description,
    classify,
  });
}

describe('the reserved security cases (#508)', () => {
  const requestDependent = RESERVED_OPERATIONS.filter((entry) => entry.requestDependent);

  it('gives every request-dependent entry cases, and a correct classify meets them', () => {
    expect(Object.keys(CORRECT_CLASSIFY).sort()).toEqual(
      requestDependent.map((entry) => entry.id).sort()
    );
    for (const entry of requestDependent) {
      expect(entry.vectors?.length ?? 0, entry.id).toBeGreaterThan(0);
      const operation = requestDependentOperation(entry.id, CORRECT_CLASSIFY[entry.id]);
      expect(createOperationRegistry([operation]).get(entry.id), entry.id).toBeDefined();
    }
  });

  it('refuses a classify that answers write for every request, on every entry', () => {
    for (const entry of requestDependent) {
      expect(
        () => createOperationRegistry([requestDependentOperation(entry.id, () => WRITE)]),
        entry.id
      ).toThrow(/classify gives the reserved case ".+" write with no effect/);
    }
  });

  it('covers the client cases the security review named', () => {
    const names = RESERVED_OPERATIONS.find((entry) => entry.id === 'clients.update')?.vectors?.map(
      (vector) => vector.name
    );
    expect(names).toEqual(
      expect.arrayContaining([
        'adds a redirect URI',
        'sets the token endpoint authentication method to none',
        'replaces the JWKS',
        'moves the keys to a JWKS URI',
        'switches PKCE off',
        'switches DPoP binding off',
        'makes the client first-party',
        'sets the verified domain',
        'changes the verified domain',
      ])
    );
  });

  // ADR-019 Decision 7, by effect: lengthening a lifetime or the rotation
  // interval, or shortening or switching off retention, loosens the posture;
  // the opposite direction is a write.
  it('counts lifetimes, the rotation interval and retention by direction', () => {
    const policies = requestDependentOperation(
      'realms.policies.update',
      CORRECT_CLASSIFY['realms.policies.update']
    );
    const entry = RESERVED_OPERATIONS.find(
      (candidate) => candidate.id === 'realms.policies.update'
    );
    const state = entry?.vectors?.[0].state;
    const classOf = (body: Record<string, unknown>) =>
      classifyRequest(
        { permissions: PERMISSION_REGISTRY },
        policies,
        { method: 'PATCH', params: {}, query: {}, body },
        state
      ).class;
    expect(classOf({ accessTokenLifespan: 3600 })).toBe('security');
    expect(classOf({ accessTokenLifespan: 300 })).toBe('write');
    expect(classOf({ keyRotationIntervalDays: 30 })).toBe('write');
    expect(classOf({ adminEventRetentionDays: 730 })).toBe('write');
    expect(classOf({ adminEventRetentionDays: null })).toBe('security');
    expect(entry?.description).toMatch(/lengthening a lifetime or the rotation interval/);
  });

  // M3: the operations the security review found missing.
  it('reserves roles, groups, admin-set credentials and client secret rotation', () => {
    const effectsOf = (id: string) => RESERVED_OPERATIONS.find((entry) => entry.id === id)?.effects;
    for (const id of [
      'roles.create',
      'roles.update',
      'roles.delete',
      'groups.create',
      'groups.update',
      'groups.delete',
      'groups.roles.assign',
      'groups.roles.remove',
      'clients.secret.rotate',
      'clients.registrationToken.rotate',
    ]) {
      expect(effectsOf(id), id).toEqual(['token-content']);
    }
    for (const id of ['users.password.set', 'users.passkeys.create', 'users.credentials.create']) {
      expect(effectsOf(id), id).toEqual(['credential-path']);
    }
  });
});

describe('mergePatchLeafPaths (#508)', () => {
  it('walks the body, with arrays, null and empty objects as changed fields', () => {
    expect(
      mergePatchLeafPaths({
        passwordPolicy: { minLength: 8, forbidden: ['password'] },
        ssoMaxLifespan: null,
        bruteForce: {},
        'a/b~c': 1,
      })
    ).toEqual([
      '/a~1b~0c',
      '/bruteForce',
      '/passwordPolicy/forbidden',
      '/passwordPolicy/minLength',
      '/ssoMaxLifespan',
    ]);
  });

  it('gives the whole resource for a body that is not an object, and nothing for none', () => {
    expect(mergePatchLeafPaths(null)).toEqual(['']);
    expect(mergePatchLeafPaths([1])).toEqual(['']);
    expect(mergePatchLeafPaths('x')).toEqual(['']);
    expect(mergePatchLeafPaths(undefined)).toEqual([]);
    expect(mergePatchLeafPaths({})).toEqual([]);
  });

  it('reports a field the classifier has no rule for, which then fails closed', () => {
    const operation = patchOperation(
      classifyByField({
        changedFields: (request) => mergePatchLeafPaths(request.body),
        fields: { '/lifespan': WRITE },
        unchanged: WRITE,
      })
    );
    const classify = (body: unknown) =>
      classifyRequest(
        { permissions: PERMISSION_REGISTRY },
        operation as never,
        { method: 'PATCH', params: {}, query: {}, body },
        undefined
      );
    expect(classify({ lifespan: 1 }).failedClosed).toBeNull();
    expect(classify({ lifespan: 1, password: { minLength: 1 } }).failedClosed).toBe(
      'unknown-field'
    );
  });
});

describe('the state version and If-Match (#508)', () => {
  const versioned = (stateVersion: (state: unknown) => unknown) =>
    defineOperation({
      id: 'widgets.policies.update',
      class: 'security',
      effects: ['credential-path'],
      permissions: ['realms.policies.write', 'realms.policies.security'],
      description: 'Change widget policies.',
      classify: () => WRITE,
      loadState: async () => ({ version: 7 }),
      stateVersion: stateVersion as (state: unknown) => string,
    });

  it('reads an entity-tag opaque value, and refuses anything else', () => {
    expect(operationStateVersion(versioned(() => 'r7') as never, {})).toBe('r7');
    for (const bad of ['', 'has space', 'has"quote', 'x'.repeat(257), 7, undefined]) {
      expect(() => operationStateVersion(versioned(() => bad) as never, {})).toThrow(
        /not an entity-tag's opaque value/
      );
    }
    expect(() => operationStateVersion(readOperation() as never, {})).toThrow(
      /names no stateVersion/
    );
  });

  it('puts the version on the classification, including one that failed closed', () => {
    const operation = versioned(() => 'r7');
    const input = { method: 'PATCH', params: {}, query: {}, body: {} };
    const permissions = { permissions: PERMISSION_REGISTRY };
    expect(classifyRequest(permissions, operation as never, input, {}, 'r7').stateVersion).toBe(
      'r7'
    );
    const throwing = defineOperation({
      ...operation,
      classify: () => {
        throw new Error('broken');
      },
    });
    const failed = classifyRequest(permissions, throwing as never, input, {}, 'r7');
    expect([failed.failedClosed, failed.stateVersion]).toEqual(['threw', 'r7']);
    expect(classifyRequest(permissions, readOperation() as never, input).stateVersion).toBeNull();
  });

  it.each([
    [undefined, true],
    ['*', true],
    ['"r7"', true],
    ['"r6", "r7"', true],
    ['"r6",, "r7"', true],
    ['W/"r7"', false],
    ['"r6"', false],
    ['r7', false],
    ['"r7" "r6"', false],
    ['', false],
    [',', false],
    ['"r7",', true],
    ['"r6", W/"r7"', false],
    ['"r,7"', false],
    ['"r7', false],
  ])('If-Match %j allows version r7: %s', (field, allowed) => {
    expect(ifMatchAllows(field, 'r7')).toBe(allowed);
  });

  it('parses a long run of whitespace and commas in linear time', () => {
    const field = `${' ,\t'.repeat(100_000)}"r6"`;
    const started = performance.now();
    expect(ifMatchAllows(field, 'r7')).toBe(false);
    expect(performance.now() - started).toBeLessThan(1000);
  });
});

describe('bodyDigestOf (#508)', () => {
  const digest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('base64url');

  it('digests a binary body, whatever view holds it', () => {
    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    expect(bodyDigestOf(Buffer.from(bytes))).toBe(digest(bytes));
    expect(bodyDigestOf(bytes.buffer)).toBe(digest(bytes));
    // A view of part of a larger buffer digests its own bytes only.
    expect(bodyDigestOf(new DataView(bytes.buffer, 1, 3))).toBe(digest(bytes.subarray(1, 4)));
  });

  it('gives null for any other body', () => {
    expect(bodyDigestOf({ a: 1 })).toBeNull();
    expect(bodyDigestOf('text')).toBeNull();
    expect(bodyDigestOf(undefined)).toBeNull();
  });

  it('puts the digest of a binary body on the classification', () => {
    const body = Buffer.from('realm file');
    const classification = classifyRequest(
      { permissions: PERMISSION_REGISTRY },
      readOperation() as never,
      { method: 'POST', params: {}, query: {}, body }
    );
    expect(classification.bodyDigest).toBe(digest(body));
  });
});
