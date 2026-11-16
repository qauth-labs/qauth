import type { JWTPayload } from '@qauth-labs/fastify-plugin-jwt';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import errorHandler from '../plugins/error-handler';
import { checkAdminActChain, listAdminAccess, registerAdminActChainAudit } from './admin-access';
import { isAdminActChain } from './admin-act-chain';

const REALM = { id: '0192a000-0000-7000-8000-0000000000aa', isOperator: false, enabled: true };
const OPERATOR = {
  id: '0192a000-0000-7000-8000-0000000000ff',
  issuer: 'https://operator.example.test',
  isOperator: true,
  enabled: true,
};
const USER_ID = '0192a000-0000-7000-8000-000000000011';
const ADMIN_ID = '0192a000-0000-7000-8000-000000000022';
const APPROVAL_ID = '0192a000-0000-7000-8000-000000000033';
const SESSION_ID = '0192a000-0000-7000-8000-000000000044';
const JTI = '0192a000-0000-7000-8000-000000000055';
const CLIENT_ID = 'admin-console';
const NOW = Date.now();

const ACT = { sub: ADMIN_ID, iss: OPERATOR.issuer, client_id: CLIENT_ID };

const SESSION = {
  id: SESSION_ID,
  realmId: REALM.id,
  userId: USER_ID,
  adminRealmId: OPERATOR.id,
  adminUserId: ADMIN_ID,
  adminClientId: CLIENT_ID,
  approvalId: APPROVAL_ID,
  operationId: 'users.actChainTokens.create',
  permissionIds: ['users.security'],
  tokenJti: JTI,
  scopes: ['qauth:account:read'],
  createdAt: NOW - 1_000,
  expiresAt: NOW + 599_000,
};

/** A live grant of a built-in role to the admin, on `targetRealmId` (`null`: every realm). */
function grant(builtInRole: string, targetRealmId: string | null = REALM.id) {
  return {
    grant: { id: 'grant-1', builtInRole, roleId: null, targetRealmId },
    role: null,
  };
}

const findLive = vi.fn(async (..._args: unknown[]) => SESSION as typeof SESSION | undefined);
const findRealm = vi.fn(async (id: string) => (id === OPERATOR.id ? OPERATOR : undefined));
const findUser = vi.fn(async (_realmId: string, id: string) =>
  id === ADMIN_ID
    ? { id, realmId: OPERATOR.id, enabled: true, notValidBefore: null }
    : (undefined as never)
);
const listLive = vi.fn(async (..._args: unknown[]) => [grant('security-admin')]);
const appendAdminAudit = vi.fn(async (..._args: unknown[]) => ({ seq: 1 }));
const listForUser = vi.fn(async (..._args: unknown[]) => [SESSION]);

let app: FastifyInstance;

/** The claims of the admin's act-chain token, as the family guard verified them. */
function claims(overrides: Partial<JWTPayload> = {}): JWTPayload {
  return {
    sub: USER_ID,
    clientId: CLIENT_ID,
    jti: JTI,
    act: ACT,
    aud: 'urn:qauth:aud:account:v1-rc.0',
    ...overrides,
  } as JWTPayload;
}

/** An app with an audited scope and one outside it, each with a probe route. */
async function boot(): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  instance.decorate('repositories', {
    adminActSessions: { findLive, listForUser },
    realms: { findById: findRealm },
    users: { findById: findUser },
    adminGrants: { listLive },
    adminAuditLog: { appendAdminAudit },
  } as never);
  instance.decorate('db', {
    transaction: async (run: (tx: unknown) => Promise<unknown>) => run({ the: 'audit tx' }),
  } as never);
  instance.decorateRequest('realm', null);
  instance.decorateRequest('jwtPayload', undefined);
  await instance.register(errorHandler);
  const probe = async (request: FastifyRequest) => {
    const token = JSON.parse(String(request.headers['x-claims'])) as JWTPayload;
    request.jwtPayload = token;
    request.realm = REALM as never;
    await checkAdminActChain(request, token, {
      operationId: 'account.sessions.list',
      operationClass: 'read',
    });
  };
  await instance.register(async (scope) => {
    registerAdminActChainAudit(scope);
    scope.get('/audited', { preHandler: probe }, async (request, reply) => {
      const status = Number(request.headers['x-status'] ?? 200);
      if (status !== 200) return reply.code(status).send({ status });
      return { ok: true };
    });
  });
  instance.get('/unaudited', { preHandler: probe }, async () => ({ ok: true }));
  await instance.ready();
  return instance;
}

function call(path: string, token: JWTPayload, status?: number) {
  return app.inject({
    method: 'GET',
    url: path,
    headers: {
      // The probe reads its claims below; the header makes the refusal a token's.
      authorization: 'DPoP act-chain-token',
      'x-claims': JSON.stringify(token),
      ...(status === undefined ? {} : { 'x-status': String(status) }),
    },
  });
}

beforeEach(async () => {
  for (const mock of [findLive, findRealm, findUser, listLive, appendAdminAudit, listForUser]) {
    mock.mockClear();
  }
  app = await boot();
});

afterEach(async () => {
  await app.close();
});

describe('isAdminActChain (#523)', () => {
  it("tells an admin's act chain from an agent's", () => {
    expect(isAdminActChain(ACT)).toBe(true);
    expect(isAdminActChain({ sub: 'agent', act: { sub: ADMIN_ID, iss: OPERATOR.issuer } })).toBe(
      true
    );
    expect(isAdminActChain({ sub: 'agent' })).toBe(false);
    expect(isAdminActChain({ sub: 'agent', act: { sub: 'earlier-agent' } })).toBe(false);
    expect(isAdminActChain(undefined)).toBe(false);
    expect(isAdminActChain(null)).toBe(false);
  });
});

describe("checkAdminActChain: an admin's act-chain token on the account API (#523)", () => {
  it('admits a live token and writes the audit row of the call, with the full act chain', async () => {
    const response = await call('/audited', claims());
    expect(response.statusCode).toBe(200);
    expect(findLive).toHaveBeenCalledWith(REALM.id, JTI, expect.any(Number));
    expect(listLive).toHaveBeenCalledWith(OPERATOR.id, ADMIN_ID);
    expect(appendAdminAudit).toHaveBeenCalledTimes(1);
    expect(appendAdminAudit.mock.calls[0][0]).toEqual({ the: 'audit tx' });
    expect(appendAdminAudit.mock.calls[0][1]).toEqual({
      realmId: REALM.id,
      actorKind: 'human_admin',
      actorId: ADMIN_ID,
      actorRealmId: OPERATOR.id,
      actChain: { sub: USER_ID, act: ACT },
      operationId: 'account.sessions.list',
      operationClass: 'read',
      effects: [],
      outcome: 'succeeded',
      diff: null,
      approvals: [],
      requestDigest: null,
      traceId: expect.any(String),
    });
  });

  it('records a refused and a failed call with their outcome', async () => {
    expect((await call('/audited', claims(), 404)).statusCode).toBe(404);
    expect((await call('/audited', claims(), 503)).statusCode).toBe(503);
    expect(
      appendAdminAudit.mock.calls.map((args) => (args[1] as { outcome: string }).outcome)
    ).toEqual(['denied', 'failed']);
  });

  it('withholds the answer of a call whose audit row cannot be written', async () => {
    appendAdminAudit.mockRejectedValueOnce(new Error('the database is gone'));
    const response = await call('/audited', claims());
    expect(response.statusCode).toBe(503);
    expect(response.body).not.toContain('"ok"');
    expect(response.headers['retry-after']).toBe('5');
    // Once: the answer that replaced it is not audited again.
    expect(appendAdminAudit).toHaveBeenCalledTimes(1);
  });

  it('refuses it on a route that no audit hook covers', async () => {
    const response = await call('/unaudited', claims());
    expect(response.statusCode).toBe(403);
    expect(findLive).not.toHaveBeenCalled();
  });

  it.each([
    [
      'its row is gone, expired or its approval no longer consumed',
      () => findLive.mockResolvedValueOnce(undefined),
    ],
    [
      "the admin's grant no longer holds the permission",
      () => listLive.mockResolvedValueOnce([grant('editor')]),
    ],
    ['the admin holds no grant any more', () => listLive.mockResolvedValueOnce([])],
    [
      "the admin's grant is on another realm",
      () =>
        listLive.mockResolvedValueOnce([
          grant('security-admin', '0192a000-0000-7000-8000-0000000000bb'),
        ]),
    ],
    [
      "the admin's account is disabled",
      () =>
        findUser.mockResolvedValueOnce({
          id: ADMIN_ID,
          realmId: OPERATOR.id,
          enabled: false,
          notValidBefore: null,
        }),
    ],
    [
      "the admin's realm is disabled",
      () => findRealm.mockResolvedValueOnce({ ...OPERATOR, enabled: false }),
    ],
  ])('refuses it with 401 when %s, and audits nothing', async (_case, arrange) => {
    arrange();
    const response = await call('/audited', claims());
    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toContain('error="invalid_token"');
    expect(appendAdminAudit).not.toHaveBeenCalled();
  });

  it('admits a grant on every realm of an operator-realm admin', async () => {
    listLive.mockResolvedValueOnce([grant('security-admin', null)]);
    expect((await call('/audited', claims())).statusCode).toBe(200);
  });

  it.each([
    ['another user', { sub: '0192a000-0000-7000-8000-000000000099' }],
    ['another admin', { act: { ...ACT, sub: '0192a000-0000-7000-8000-000000000098' } }],
    ['another client', { clientId: 'other-client', act: { ...ACT, client_id: 'other-client' } }],
    ['another issuer', { act: { ...ACT, iss: 'https://elsewhere.example.test' } }],
    ['a nested actor', { act: { ...ACT, act: { sub: 'agent' } } }],
    ['no token id', { jti: undefined }],
  ])('refuses a token that names %s than its row', async (_case, overrides) => {
    const response = await call('/audited', claims(overrides as Partial<JWTPayload>));
    expect(response.statusCode).toBe(401);
    expect(appendAdminAudit).not.toHaveBeenCalled();
  });

  it("leaves an agent's token and a token with no act chain to the operation's rules", async () => {
    expect((await call('/unaudited', claims({ act: { sub: 'agent' } }))).statusCode).toBe(200);
    expect((await call('/audited', claims({ act: undefined }))).statusCode).toBe(200);
    expect(findLive).not.toHaveBeenCalled();
    expect(appendAdminAudit).not.toHaveBeenCalled();
  });
});

describe('listAdminAccess (#523)', () => {
  it('lists who acted for the user, when and on which approval', async () => {
    expect(await listAdminAccess(app, REALM.id, USER_ID)).toEqual([
      {
        id: SESSION_ID,
        adminId: ADMIN_ID,
        adminRealmId: OPERATOR.id,
        approvalId: APPROVAL_ID,
        operationId: 'users.actChainTokens.create',
        scopes: ['qauth:account:read'],
        actedAt: SESSION.createdAt,
        expiresAt: SESSION.expiresAt,
      },
    ]);
    expect(listForUser).toHaveBeenCalledWith(REALM.id, USER_ID, {});
  });
});
