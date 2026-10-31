import { SECURITY_EFFECTS } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  type AdminOperation,
  classifyRequest,
  createAdminOperationRegistry,
  defineOperation,
  OPERATION_REGISTRY,
  OperationDefinitionError,
} from '../../helpers/admin-operations';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { approvalOperationDefinitions, isApprovalEngineOperation } from './operations';

/**
 * THE APPROVAL ENGINE'S OPERATIONS (#512): filing and withdrawing an approval
 * take the classification of the operation it is for, reading one needs
 * `approvals.read`, and only the engine's own two pass the approval gate.
 */

const ROTATE = defineOperation({
  id: 'fixtureKeys.rotate',
  class: 'security',
  effects: ['key-custody'],
  permissions: ['realms.policies.security'],
  description: 'A security operation (fixture).',
  render: () => ({ title: 'Rotate the key' }),
});
const READ = defineOperation({
  id: 'realms.get',
  class: 'read',
  effects: [],
  permissions: ['realms.read'],
  description: 'Read a realm (fixture).',
});

const REGISTRY = createAdminOperationRegistry([ROTATE, READ] as AdminOperation[], {
  reserved: [],
});

const operation = (id: string) => {
  const found = REGISTRY.get(id);
  if (found === undefined) throw new Error(`no ${id}`);
  return found;
};

const filing = (body: unknown) =>
  classifyRequest(REGISTRY, operation('approvals.create'), {
    method: 'POST',
    params: {},
    query: {},
    body,
  });

describe('the approval operations (#512)', () => {
  it('are in every registry built for the admin listener, the server one included', () => {
    for (const registry of [REGISTRY, OPERATION_REGISTRY]) {
      expect(registry.get('approvals.create')?.class).toBe('security');
      expect(registry.get('approvals.get')).toMatchObject({
        class: 'read',
        permissions: ['approvals.read'],
      });
      expect(registry.get('approvals.cancel')?.class).toBe('security');
    }
  });

  it('file an approval with the classification of the operation it is for', () => {
    expect(filing({ operation: ROTATE.id })).toMatchObject({
      class: 'security',
      effects: ['key-custody'],
      permissions: ['realms.policies.security'],
      failedClosed: null,
    });
  });

  it('fail closed, to every effect and permission, for an operation that needs no approval', () => {
    const everything = {
      class: 'security',
      effects: [...SECURITY_EFFECTS],
      permissions: PERMISSION_REGISTRY.active.map((permission) => permission.id),
    };
    for (const body of [
      { operation: 'realms.get' },
      { operation: 'nothing.here' },
      { operation: 'approvals.create' },
      { operation: 'approvals.cancel' },
      {},
      null,
    ]) {
      expect(filing(body), JSON.stringify(body)).toMatchObject({
        ...everything,
        failedClosed: 'threw',
      });
    }
  });

  it('withdraw an approval with the classification of the operation it names', () => {
    const cancel = operation('approvals.cancel');
    expect(cancel.loadState).toBeTypeOf('function');
    expect(
      classifyRequest(
        REGISTRY,
        cancel,
        { method: 'POST', params: {}, query: {}, body: undefined },
        { operationId: ROTATE.id, version: 'pending.0' },
        'pending.0'
      )
    ).toMatchObject({ class: 'security', effects: ['key-custody'], stateVersion: 'pending.0' });
  });

  it('pass the approval gate by their id and their own classify, nothing else', () => {
    expect(isApprovalEngineOperation(operation('approvals.create'))).toBe(true);
    expect(isApprovalEngineOperation(operation('approvals.cancel'))).toBe(true);
    expect(isApprovalEngineOperation(operation('approvals.get'))).toBe(false);
    expect(isApprovalEngineOperation(ROTATE)).toBe(false);
    // Another operation that borrows the engine's classify is not the engine.
    const borrowed = { ...operation('approvals.create'), id: 'fixtureKeys.rotate' };
    expect(isApprovalEngineOperation(borrowed as AdminOperation)).toBe(false);
    // An operation under the engine's id with a classify of its own is not either.
    const impostor = approvalOperationDefinitions(PERMISSION_REGISTRY, () => undefined)[0];
    expect(
      isApprovalEngineOperation({
        ...impostor,
        classify: () => ({ class: 'read', effects: [], permissions: ['realms.read'] }),
      } as AdminOperation)
    ).toBe(false);
  });
});

describe('the render member of an operation (#512)', () => {
  it('is a function, on a security operation only', () => {
    expect(() => defineOperation({ ...READ, render: () => ({ title: 'Read' }) } as never)).toThrow(
      /only a security operation renders/
    );
    expect(() => defineOperation({ ...ROTATE, render: 'Rotate' } as never)).toThrow(
      OperationDefinitionError
    );
  });
});
