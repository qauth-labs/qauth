import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { RESERVED_OPERATIONS } from './admin-operations-reserved';
import {
  parseServiceAccountsArguments,
  runServiceAccountsCommand,
  SERVICE_ACCOUNT_OPERATIONS,
  type ServiceAccountsCommand,
  ServiceAccountsUsageError,
} from './service-accounts-command';

/**
 * The host's `service-accounts` command (#522): its arguments, refused
 * before anything connects, and what each command writes, over fake
 * repositories.
 */

const OPERATOR = '01900000-0000-7000-8000-00000000000a';
const TENANT = '01900000-0000-7000-8000-00000000000b';
const KEY = { kty: 'EC', crv: 'P-256', x: 'x-coordinate', y: 'y-coordinate' };
const TX = { tx: true };

const noFile = () => {
  throw new Error('no such file');
};

describe('parseServiceAccountsArguments', () => {
  it('reads a creation with its keys by URL and its grants, in either flag form', () => {
    expect(
      parseServiceAccountsArguments(
        [
          'create',
          '--name',
          'ci-realm-import',
          '--client-id=ci-realm-import',
          '--jwks-uri',
          'https://ci.example.com/jwks.json',
          '--grant',
          'security-admin@*',
          '--grant=viewer@tenant',
        ],
        noFile
      )
    ).toEqual({
      kind: 'create',
      name: 'ci-realm-import',
      clientId: 'ci-realm-import',
      jwksUri: 'https://ci.example.com/jwks.json',
      grants: [
        { role: 'security-admin', realm: null },
        { role: 'viewer', realm: 'tenant' },
      ],
    });
  });

  // #1090: a relying party's service account deletes one realm's accounts.
  it('reads an account-closer grant on one realm', () => {
    expect(
      parseServiceAccountsArguments(
        [
          'create',
          '--name=notes-account-closing',
          '--client-id=notes-account-closing',
          '--jwks-uri=https://notes.example/jwks.json',
          '--grant=account-closer@customers',
        ],
        noFile
      )
    ).toMatchObject({ grants: [{ role: 'account-closer', realm: 'customers' }] });
  });

  it('reads an inline key set from the file --jwks names', () => {
    const read = vi.fn(() => JSON.stringify({ keys: [KEY] }));
    expect(
      parseServiceAccountsArguments(
        ['create', '--name=ci', '--client-id=ci', '--jwks=/etc/qauth/ci.jwks.json'],
        read
      )
    ).toEqual({ kind: 'create', name: 'ci', clientId: 'ci', jwks: { keys: [KEY] }, grants: [] });
    expect(read).toHaveBeenCalledWith('/etc/qauth/ci.jwks.json');
  });

  it('reads disable, enable, list and help', () => {
    expect(parseServiceAccountsArguments(['disable', '--name', 'ci'], noFile)).toEqual({
      kind: 'disable',
      name: 'ci',
    });
    expect(parseServiceAccountsArguments(['enable', '--name=ci'], noFile)).toEqual({
      kind: 'enable',
      name: 'ci',
    });
    expect(parseServiceAccountsArguments(['list'], noFile)).toEqual({ kind: 'list' });
    for (const argv of [[], ['--help'], ['help']]) {
      expect(parseServiceAccountsArguments(argv, noFile)).toBe('help');
    }
  });

  it.each([
    [['remove', '--name=ci']],
    [['create', '--client-id=ci', '--jwks-uri=https://ci.example.com/jwks.json']],
    [['create', '--name=ci', '--jwks-uri=https://ci.example.com/jwks.json']],
    // Exactly one source of keys, never a secret.
    [['create', '--name=ci', '--client-id=ci']],
    [['create', '--name=ci', '--client-id=ci', '--jwks=a', '--jwks-uri=https://x.example/j']],
    [['create', '--name=ci', '--client-id=ci', '--client-secret=s3cr3t']],
    [['create', '--name=ci', '--name=other', '--client-id=ci', '--jwks-uri=https://x.example/j']],
    [
      [
        'create',
        '--name=ci',
        '--client-id=ci',
        '--jwks-uri=https://x.example/j',
        '--grant=owner@*',
      ],
    ],
    [['create', '--name=ci', '--client-id=ci', '--jwks-uri=https://x.example/j', '--grant=viewer']],
    // The unattended deletion is granted on one realm, never on every realm (#1090).
    [
      [
        'create',
        '--name=rp',
        '--client-id=rp',
        '--jwks-uri=https://x.example/j',
        '--grant=account-closer@*',
      ],
    ],
    [['disable']],
    [['disable', '--name']],
  ])('refuses %j before anything connects', (argv) => {
    expect(() => parseServiceAccountsArguments(argv, noFile)).toThrow(ServiceAccountsUsageError);
  });

  it('refuses a --jwks file that is not a JWK Set', () => {
    for (const text of ['not json', '{"kty":"EC"}', '[]']) {
      expect(() =>
        parseServiceAccountsArguments(
          ['create', '--name=ci', '--client-id=ci', '--jwks=/k.json'],
          () => text
        )
      ).toThrow(ServiceAccountsUsageError);
    }
  });
});

/** A server whose operator realm is {@link OPERATOR}, with a realm named `tenant`. */
function server(options: { operator?: boolean; createError?: Error; enabled?: boolean } = {}) {
  const appendAdminAudit = vi.fn(async () => ({}));
  const createAccount = vi.fn(async (input: { name: string; clientId: string }) => {
    if (options.createError) throw options.createError;
    return {
      serviceAccount: { id: 'sa-1', name: input.name, enabled: true },
      userId: 'robot-user',
      client: { id: 'client-row-1', clientId: input.clientId },
    };
  });
  const createGrant = vi.fn(async (grant: { targetRealmId: string | null }) => ({
    id: `grant-${grant.targetRealmId ?? 'all'}`,
  }));
  const setEnabled = vi.fn(async () => ({}));
  const fastify = {
    db: { transaction: vi.fn(async (work: (tx: unknown) => unknown) => work(TX)) },
    repositories: {
      realms: {
        findOperator: vi.fn(async () =>
          options.operator === false ? undefined : { id: OPERATOR, isOperator: true }
        ),
        findByName: vi.fn(async (name: string) =>
          name === 'tenant' ? { id: TENANT, name } : undefined
        ),
      },
      serviceAccounts: {
        create: createAccount,
        findByName: vi.fn(async (_realmId: string, name: string) =>
          name === 'ci'
            ? { id: 'sa-1', name: 'ci', enabled: options.enabled ?? true, userId: 'robot-user' }
            : undefined
        ),
        setEnabled,
        list: vi.fn(async () => [{ id: 'sa-1', name: 'ci', enabled: true, userId: 'robot-user' }]),
      },
      adminGrants: { create: createGrant },
      adminAuditLog: { appendAdminAudit },
    },
  };
  return {
    fastify: fastify as unknown as Pick<FastifyInstance, 'db' | 'repositories'>,
    appendAdminAudit,
    createAccount,
    createGrant,
    setEnabled,
  };
}

function run(
  fastify: Pick<FastifyInstance, 'db' | 'repositories'>,
  command: ServiceAccountsCommand,
  reservedClientIds: readonly string[] = ['portal-system']
) {
  const out: string[] = [];
  const err: string[] = [];
  const done = runServiceAccountsCommand(command, {
    fastify,
    operatingSystemUser: 'operator',
    reservedClientIds,
    out: (line) => out.push(line),
    err: (line) => err.push(line),
  });
  return { done, out, err };
}

const CREATE = {
  kind: 'create',
  name: 'ci',
  clientId: 'ci',
  jwksUri: 'https://ci.example.com/jwks.json',
  grants: [
    { role: 'security-admin', realm: null },
    { role: 'viewer', realm: 'tenant' },
  ],
} as const satisfies ServiceAccountsCommand;

describe('runServiceAccountsCommand', () => {
  it('creates the account in the operator realm, grants it, and records it in one transaction', async () => {
    const { fastify, createAccount, createGrant, appendAdminAudit } = server();
    const { done, out } = run(fastify, CREATE);
    await expect(done).resolves.toBe(0);

    expect(createAccount).toHaveBeenCalledWith(
      {
        realmId: OPERATOR,
        name: 'ci',
        clientId: 'ci',
        jwksUri: 'https://ci.example.com/jwks.json',
        createdBy: null,
        // The deployment's SYSTEM_CLIENT_ID, which the repository refuses
        // beside the default one (#522).
        reservedClientIds: ['portal-system'],
      },
      TX
    );
    // The grants attach to the account's user row.
    expect(createGrant.mock.calls).toEqual([
      [
        {
          userId: 'robot-user',
          role: { kind: 'built-in', name: 'security-admin' },
          targetRealmId: null,
          createdBy: null,
        },
        TX,
      ],
      [
        {
          userId: 'robot-user',
          role: { kind: 'built-in', name: 'viewer' },
          targetRealmId: TENANT,
          createdBy: null,
        },
        TX,
      ],
    ]);
    expect(appendAdminAudit).toHaveBeenCalledWith(
      TX,
      expect.objectContaining({
        realmId: OPERATOR,
        actorKind: 'host_operator',
        actorId: 'operator',
        actorRealmId: null,
        operationId: 'serviceAccounts.create',
        operationClass: 'security',
        effects: ['administration'],
        outcome: 'succeeded',
        diff: {
          change: {
            before: null,
            after: expect.objectContaining({ name: 'ci', userId: 'robot-user', clientId: 'ci' }),
          },
          annotations: {},
        },
      })
    );
    expect(out.join('\n')).toContain('Created the service account "ci"');
    // Nothing secret is printed: there is no secret.
    expect(out.join('\n')).not.toMatch(/secret/i);
  });

  it('refuses, and writes nothing, without an operator realm or for an unknown realm', async () => {
    const none = server({ operator: false });
    const missing = run(none.fastify, CREATE);
    await expect(missing.done).resolves.toBe(1);
    expect(missing.err.join('\n')).toContain('no operator realm');
    expect(none.createAccount).not.toHaveBeenCalled();

    const unknown = server();
    const refused = run(unknown.fastify, {
      ...CREATE,
      grants: [{ role: 'viewer', realm: 'nowhere' }],
    });
    await expect(refused.done).resolves.toBe(1);
    expect(refused.err.join('\n')).toContain('no such realm');
    expect(unknown.appendAdminAudit).not.toHaveBeenCalled();
  });

  it('answers a name or client id already taken, and a refused key set, with 1', async () => {
    for (const createError of [
      new UniqueConstraintError('service_accounts_realm_name_unique'),
      new BadRequestError('a key carries private material'),
    ]) {
      const { fastify, appendAdminAudit } = server({ createError });
      const { done, err } = run(fastify, CREATE);
      await expect(done).resolves.toBe(1);
      expect(err.join('\n')).toContain('Nothing was changed');
      expect(appendAdminAudit).not.toHaveBeenCalled();
    }
  });

  /** The audit row a switch of the service account `ci` writes, by the operator. */
  const switchRow = (operationId: string, diff: unknown) => ({
    realmId: OPERATOR,
    actorKind: 'host_operator',
    actorId: 'operator',
    actorRealmId: null,
    actChain: null,
    operationId,
    operationClass: 'security',
    effects: ['administration'],
    outcome: 'succeeded',
    diff,
    approvals: [],
    requestDigest: null,
    traceId: null,
  });
  const state = (enabled: boolean) => ({ id: 'sa-1', name: 'ci', userId: 'robot-user', enabled });

  it('disables a service account by name, and records it in the same transaction', async () => {
    const { fastify, setEnabled, appendAdminAudit } = server();
    const disabled = run(fastify, { kind: 'disable', name: 'ci' });
    await expect(disabled.done).resolves.toBe(0);
    expect(setEnabled).toHaveBeenCalledWith(OPERATOR, 'sa-1', false, TX);
    expect(disabled.out.join('\n')).toContain('gets no token');
    expect(appendAdminAudit.mock.calls).toEqual([
      [
        TX,
        switchRow('serviceAccounts.disable', {
          change: { before: state(true), after: state(false) },
          annotations: {},
        }),
      ],
    ]);
  });

  it('enables a disabled service account, and records it', async () => {
    const { fastify, setEnabled, appendAdminAudit } = server({ enabled: false });
    const enabled = run(fastify, { kind: 'enable', name: 'ci' });
    await expect(enabled.done).resolves.toBe(0);
    expect(setEnabled).toHaveBeenCalledWith(OPERATOR, 'sa-1', true, TX);
    expect(enabled.out.join('\n')).toContain('is enabled');
    expect(appendAdminAudit.mock.calls).toEqual([
      [
        TX,
        switchRow('serviceAccounts.enable', {
          change: { before: state(false), after: state(true) },
          annotations: {},
        }),
      ],
    ]);
  });

  it('records a run that finds the service account switched already, with no change', async () => {
    const { fastify, setEnabled, appendAdminAudit } = server();
    const already = run(fastify, { kind: 'enable', name: 'ci' });
    await expect(already.done).resolves.toBe(0);
    expect(already.out.join('\n')).toContain('nothing changed');
    expect(setEnabled).not.toHaveBeenCalled();
    expect(appendAdminAudit.mock.calls).toEqual([[TX, switchRow('serviceAccounts.enable', null)]]);
  });

  it('refuses an unknown service account, and records nothing', async () => {
    const { fastify, setEnabled, appendAdminAudit } = server();
    const unknown = run(fastify, { kind: 'disable', name: 'other' });
    await expect(unknown.done).resolves.toBe(1);
    expect(unknown.err.join('\n')).toContain('no service account "other"');
    expect(setEnabled).not.toHaveBeenCalled();
    expect(appendAdminAudit).not.toHaveBeenCalled();
  });

  // #522: the ids the host writes are the admin API's, reserved as security
  // operations that change who administers.
  it('names only operations the admin operation registry reserves, with the administration effect', () => {
    for (const id of Object.values(SERVICE_ACCOUNT_OPERATIONS)) {
      const reserved = RESERVED_OPERATIONS.find((operation) => operation.id === id);
      expect(reserved, id).toBeDefined();
      expect(reserved?.effects, id).toContain('administration');
    }
  });

  it('lists the operator realm’s service accounts', async () => {
    const { fastify } = server();
    const listed = run(fastify, { kind: 'list' });
    await expect(listed.done).resolves.toBe(0);
    expect(listed.out).toEqual(['ci\tenabled\tuser robot-user']);
  });
});
