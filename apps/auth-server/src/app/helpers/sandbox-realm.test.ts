import { BadRequestError, SandboxPairingError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { SandboxCeilingError } from './api-request-errors';
import { updateRealmPolicies } from './realm-policy-update';
import type { RealmRow } from './request-realm';
import {
  createSandboxRealm,
  SANDBOX_POLICY_PATCH,
  sandboxPairingOf,
  type SandboxRealmDependencies,
  type SandboxRealmTransaction,
} from './sandbox-realm';

/**
 * The paired sandbox realm's helpers (#554), over stubs: what
 * `createSandboxRealm` asks of each dependency, in which transaction and in
 * which order, and how the policy update answers a sandbox's development
 * ceiling. The database rules are proven in the container suites
 * (`sandbox-realm.integration.test.ts`, and `realm-sandbox.integration.test.ts`
 * in `@qauth-labs/infra-db`).
 */

const LIVE_ID = '0190a000-0000-7000-8000-00000000000a';
const SANDBOX_ID = '0190a000-0000-7000-8000-00000000000b';
const TX = { marker: 'the transaction' } as unknown as SandboxRealmTransaction;

function sandboxRow(overrides: Partial<RealmRow> = {}): RealmRow {
  return {
    id: SANDBOX_ID,
    name: 'live-sandbox',
    issuer: 'https://sandbox.example.com',
    sandboxOfRealmId: LIVE_ID,
    maxEnvironmentLaxity: 'staging',
    policiesVersion: 1,
    ...overrides,
  } as RealmRow;
}

function stubs(overrides: Partial<Record<'create' | 'update' | 'keys', unknown>> = {}) {
  const calls: string[] = [];
  const deps = {
    db: {
      transaction: vi.fn(async (work: (tx: SandboxRealmTransaction) => Promise<unknown>) => {
        calls.push('transaction');
        return work(TX);
      }),
    },
    realms: {
      lockProvisioning: vi.fn(async () => {
        calls.push('lockProvisioning');
      }),
      createSandboxWithPrimaryHost: vi.fn(async () => {
        calls.push('createSandboxWithPrimaryHost');
        if (overrides.create instanceof Error) throw overrides.create;
        return { realm: sandboxRow(), host: { host: 'sandbox.example.com', kind: 'primary' } };
      }),
      findById: vi.fn(async () => {
        calls.push('findById');
        return sandboxRow({ policiesVersion: 2 });
      }),
    },
    policies: {
      update: vi.fn(async () => {
        calls.push('policies.update');
        return { version: 2, policies: { mail: { provider: 'mock' } } };
      }),
    },
    provisionKeys: vi.fn(async () => {
      calls.push('provisionKeys');
      if (overrides.keys instanceof Error) throw overrides.keys;
    }),
  };
  return { deps: deps as unknown as SandboxRealmDependencies, raw: deps, calls };
}

describe('createSandboxRealm', () => {
  it('creates the paired realm, sets the test mail transport and gives it keys, in one transaction', async () => {
    const { deps, raw, calls } = stubs();

    const created = await createSandboxRealm(deps, LIVE_ID, {
      name: 'live-sandbox',
      issuer: 'https://sandbox.example.com',
    });

    expect(calls).toEqual([
      'transaction',
      'lockProvisioning',
      'createSandboxWithPrimaryHost',
      'policies.update',
      'provisionKeys',
      'findById',
    ]);
    expect(raw.realms.lockProvisioning).toHaveBeenCalledWith(TX);
    expect(raw.realms.createSandboxWithPrimaryHost).toHaveBeenCalledWith(
      LIVE_ID,
      { name: 'live-sandbox', issuer: 'https://sandbox.example.com', enabled: true },
      'sandbox.example.com',
      TX
    );
    expect(raw.policies.update).toHaveBeenCalledWith(SANDBOX_ID, SANDBOX_POLICY_PATCH, {
      expectedVersion: 1,
      tx: TX,
    });
    expect(raw.provisionKeys).toHaveBeenCalledWith(expect.objectContaining({ id: SANDBOX_ID }), TX);
    expect(created).toMatchObject({
      realm: { id: SANDBOX_ID, policiesVersion: 2 },
      host: 'sandbox.example.com',
      policies: { version: 2 },
    });
  });

  it('copies nothing from the live realm: the patch names the mail transport alone', () => {
    expect(SANDBOX_POLICY_PATCH).toEqual({ mail: { provider: 'mock' } });
  });

  it('takes the primary host from the issuer, its port included for the repository to drop', async () => {
    const { deps, raw } = stubs();

    await createSandboxRealm(deps, LIVE_ID, {
      name: 'live-sandbox',
      issuer: 'https://Sandbox.Example.com:8443',
    });

    expect(raw.realms.createSandboxWithPrimaryHost).toHaveBeenCalledWith(
      LIVE_ID,
      expect.anything(),
      'sandbox.example.com:8443',
      TX
    );
  });

  it('refuses an issuer that is not a URL before it opens a transaction', async () => {
    const { deps, calls } = stubs();

    await expect(
      createSandboxRealm(deps, LIVE_ID, { name: 'live-sandbox', issuer: 'not a url' })
    ).rejects.toBeInstanceOf(BadRequestError);
    expect(calls).toEqual([]);
  });

  it('passes a refused pairing through, and stops before the policies and keys', async () => {
    const { deps, calls } = stubs({ create: new SandboxPairingError('one_sandbox') });

    await expect(
      createSandboxRealm(deps, LIVE_ID, {
        name: 'live-sandbox',
        issuer: 'https://sandbox.example.com',
      })
    ).rejects.toMatchObject({ rule: 'one_sandbox' });
    expect(calls).not.toContain('policies.update');
    expect(calls).not.toContain('provisionKeys');
  });

  it('fails whole when the keys cannot be created', async () => {
    const { deps } = stubs({ keys: new Error('KEK unavailable') });

    await expect(
      createSandboxRealm(deps, LIVE_ID, {
        name: 'live-sandbox',
        issuer: 'https://sandbox.example.com',
      })
    ).rejects.toThrow('KEK unavailable');
  });
});

describe('sandboxPairingOf', () => {
  it("shows a sandbox's live realm without a query, and a live realm's sandbox", async () => {
    const realms = { findSandboxOf: vi.fn(async () => sandboxRow()) };

    expect(await sandboxPairingOf(realms, { id: SANDBOX_ID, sandboxOfRealmId: LIVE_ID })).toEqual({
      sandboxOf: LIVE_ID,
      sandbox: null,
    });
    expect(realms.findSandboxOf).not.toHaveBeenCalled();

    expect(await sandboxPairingOf(realms, { id: LIVE_ID, sandboxOfRealmId: null })).toEqual({
      sandboxOf: null,
      sandbox: SANDBOX_ID,
    });
    expect(realms.findSandboxOf).toHaveBeenCalledWith(LIVE_ID, undefined);
  });

  it('shows null for both on a realm that is not paired', async () => {
    const realms = { findSandboxOf: vi.fn(async () => undefined) };

    expect(await sandboxPairingOf(realms, { id: LIVE_ID, sandboxOfRealmId: null })).toEqual({
      sandboxOf: null,
      sandbox: null,
    });
  });
});

describe("updateRealmPolicies and a sandbox's ceiling", () => {
  function storeThrowing(error: Error) {
    return {
      update: vi.fn(async () => {
        throw error;
      }),
    } as unknown as FastifyInstance['policyStore'];
  }

  it('answers the database refusing a development ceiling with 422 sandbox_ceiling', async () => {
    const policyStore = storeThrowing(new SandboxPairingError('ceiling'));

    const refused = updateRealmPolicies(
      { policyStore },
      SANDBOX_ID,
      { posture: { maxEnvironmentLaxity: 'development' } },
      { expectedVersion: 1 }
    );

    await expect(refused).rejects.toBeInstanceOf(SandboxCeilingError);
    await expect(refused).rejects.toMatchObject({
      statusCode: 422,
      code: 'SANDBOX_CEILING',
      fields: [{ pointer: '/posture/maxEnvironmentLaxity', message: expect.any(String) }],
    });
  });

  it('passes every other sandbox rule through as it is', async () => {
    const error = new SandboxPairingError('permanent');

    await expect(
      updateRealmPolicies(
        { policyStore: storeThrowing(error) },
        SANDBOX_ID,
        {},
        {
          expectedVersion: 1,
        }
      )
    ).rejects.toBe(error);
  });
});
