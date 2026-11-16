import { generateKeyPairSync } from 'node:crypto';

import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import {
  ACT_CHAIN_TOKEN_AUDIENCE,
  ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS as SIGNER_MAX_LIFETIME_SECONDS,
  ACT_CHAIN_TOKEN_SCOPES,
  actChainTokenClaimsProblem,
} from '@qauth-labs/fastify-plugin-signer';
import { createTestSigner } from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import { ForbiddenError, NotFoundError } from '@qauth-labs/shared-errors';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import { API_FAMILY_AUDIENCES, API_FAMILY_SCOPES } from '../api-conventions/families';
import { ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS, mintActChainToken } from './act-chain-tokens';
import {
  type AuthorizedOperation,
  AuthorizedOperationRefusedError,
  issueAuthorizedOperation,
  retireAuthorizedOperation,
} from './authorized-operation';
import type { AdminCaller, AdminPipelineState, AdminTransaction } from './pipeline';

const REALM = {
  id: '0192a000-0000-7000-8000-0000000000aa',
  issuer: 'https://acme.example.test',
  isOperator: false,
};
const OPERATOR = {
  id: '0192a000-0000-7000-8000-0000000000ff',
  issuer: 'https://operator.example.test',
  isOperator: true,
};
const USER_ID = '0192a000-0000-7000-8000-000000000011';
const ADMIN_ID = '0192a000-0000-7000-8000-000000000022';
const APPROVAL_ID = '0192a000-0000-7000-8000-000000000033';
const SESSION_ID = '0192a000-0000-7000-8000-000000000044';
const CLIENT_ID = 'admin-console';
const JKT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

const findUser = vi.fn(async (_realmId: string, id: string, _tx?: unknown) =>
  id === USER_ID ? { id, realmId: REALM.id, enabled: true, notValidBefore: null } : undefined
);
const createSession = vi.fn(async (_tx: unknown, session: Record<string, unknown>) => ({
  ...session,
  id: SESSION_ID,
}));

let app: FastifyInstance;

beforeEach(async () => {
  findUser.mockClear();
  createSession.mockClear();
  const signer = createTestSigner();
  for (const realm of [REALM, OPERATOR]) {
    const pem = generateKeyPairSync('ed25519')
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();
    await signer.addRealm({ id: realm.id, issuer: realm.issuer, ed25519PrivateKey: pem });
  }
  app = Fastify({ logger: false });
  app.decorate('repositories', {
    users: { findById: findUser },
    adminActSessions: { create: createSession },
  } as never);
  await app.register(jwtPlugin, {
    signer: signer.signer,
    requestRealm: () => ({ id: REALM.id, issuer: REALM.issuer }) as never,
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
  });
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

/** An approved call of an `issue-for-other` operation, inside its handler. */
function approvedCall(
  options: {
    readonly body?: unknown;
    readonly params?: Record<string, unknown>;
    readonly caller?: Partial<AdminCaller>;
    readonly effects?: readonly ('issue-for-other' | 'key-custody')[];
  } = {}
) {
  const transaction = { the: 'operation transaction' } as unknown as AdminTransaction;
  const state: AdminPipelineState = { handlerStarted: true, committed: false, transaction };
  const request = { server: app, adminPipeline: state } as unknown as FastifyRequest;
  const caller = {
    allowed: true,
    issuerRealm: OPERATOR,
    operator: true,
    targetRealm: REALM,
    userId: ADMIN_ID,
    kind: 'human',
    serviceAccount: null,
    permissions: new Set(['users.security']),
    rolePermissions: new Set(['users.security']),
    grantIds: ['grant-1'],
    ...options.caller,
  } as unknown as AdminCaller;
  const operation = issueAuthorizedOperation({
    request,
    transaction,
    caller,
    operationId: 'fixtureUsers.actChainTokens.create',
    effects: options.effects ?? ['issue-for-other'],
    permissions: ['users.security'],
    approvalId: APPROVAL_ID,
    adminToken: { issuer: OPERATOR.issuer, clientId: CLIENT_ID, jkt: JKT },
    params: options.params ?? { realmId: REALM.id, userId: USER_ID },
    body: options.body ?? {},
  });
  return { operation, state, transaction };
}

describe('mintActChainToken (#523)', () => {
  it('mints a token whose sub is the user and whose act is the admin, for the account API, bound, short-lived, with no sign-in time', async () => {
    const { operation, state, transaction } = approvedCall();
    const minted = await mintActChainToken(operation, { userId: USER_ID });

    const claims = decodeJwt(minted.accessToken);
    expect(decodeProtectedHeader(minted.accessToken).typ).toBe('at+jwt');
    expect(claims).toMatchObject({
      iss: REALM.issuer,
      sub: USER_ID,
      aud: API_FAMILY_AUDIENCES.account,
      act: { sub: ADMIN_ID, iss: OPERATOR.issuer, client_id: CLIENT_ID },
      client_id: CLIENT_ID,
      cnf: { jkt: JKT },
      scope: 'qauth:account:read',
      token_use: 'access',
    });
    expect(claims).not.toHaveProperty('auth_time');
    expect(claims).not.toHaveProperty('amr');
    expect(claims).not.toHaveProperty('sid');
    expect((claims.exp as number) - (claims.iat as number)).toBe(600);
    expect(minted).toMatchObject({
      tokenType: 'DPoP',
      expiresIn: 600,
      scope: 'qauth:account:read',
      sessionId: SESSION_ID,
      expiresAt: (claims.exp as number) * 1000,
    });
    // What the signer holds the admin role to: the token fits it.
    const { iss: _iss, ...signed } = claims;
    expect(actChainTokenClaimsProblem(signed, claims.iat as number)).toBeUndefined();

    // Its row, in the operation's transaction, with the token's own times.
    expect(createSession).toHaveBeenCalledTimes(1);
    expect(createSession.mock.calls[0][0]).toBe(transaction);
    expect(createSession.mock.calls[0][1]).toEqual({
      realmId: REALM.id,
      userId: USER_ID,
      adminRealmId: OPERATOR.id,
      adminUserId: ADMIN_ID,
      adminClientId: CLIENT_ID,
      approvalId: APPROVAL_ID,
      operationId: 'fixtureUsers.actChainTokens.create',
      permissionIds: ['users.security'],
      tokenJti: claims.jti,
      scopes: ['qauth:account:read'],
      createdAt: (claims.iat as number) * 1000,
      expiresAt: (claims.exp as number) * 1000,
    });
    expect(findUser).toHaveBeenCalledWith(REALM.id, USER_ID, transaction);
    // The operation's change, for its audit row.
    expect(state.change?.change.after).toMatchObject({ id: SESSION_ID, userId: USER_ID });
  });

  it('lives at most ten minutes', async () => {
    const short = await mintActChainToken(approvedCall().operation, {
      userId: USER_ID,
      lifetimeSeconds: 120,
    });
    const claims = decodeJwt(short.accessToken);
    expect((claims.exp as number) - (claims.iat as number)).toBe(120);
    for (const lifetimeSeconds of [601, 0, -1, 1.5, Number.NaN]) {
      await expect(
        mintActChainToken(approvedCall().operation, { userId: USER_ID, lifetimeSeconds })
      ).rejects.toThrow(RangeError);
    }
    expect(ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS).toBe(600);
  });

  it('reads the account unless the approval names more, and carries account scopes only', async () => {
    const write = API_FAMILY_SCOPES.account.write;
    await expect(
      mintActChainToken(approvedCall().operation, {
        userId: USER_ID,
        scopes: [API_FAMILY_SCOPES.account.read, write],
      })
    ).rejects.toThrow(ForbiddenError);

    const approved = await mintActChainToken(
      approvedCall({ body: { scopes: [write] } }).operation,
      {
        userId: USER_ID,
        scopes: [API_FAMILY_SCOPES.account.read, write],
      }
    );
    expect(decodeJwt(approved.accessToken).scope).toBe(`qauth:account:read ${write}`);

    for (const scopes of [['openid'], [], ['qauth:account:read', 'qauth:account:read']]) {
      await expect(
        mintActChainToken(approvedCall({ body: { scopes } }).operation, { userId: USER_ID, scopes })
      ).rejects.toThrow(RangeError);
    }
    expect(createSession).toHaveBeenCalledTimes(1);
  });

  it('acts only for the user the approved request names, an active user of the realm', async () => {
    await expect(
      mintActChainToken(approvedCall().operation, {
        userId: '0192a000-0000-7000-8000-000000000099',
      })
    ).rejects.toThrow(/the user the approved request names/);
    const absent = '0192a000-0000-7000-8000-000000000098';
    await expect(
      mintActChainToken(approvedCall({ params: { realmId: REALM.id, userId: absent } }).operation, {
        userId: absent,
      })
    ).rejects.toThrow(NotFoundError);
    findUser.mockResolvedValueOnce({
      id: USER_ID,
      realmId: REALM.id,
      enabled: false,
      notValidBefore: null,
    });
    await expect(mintActChainToken(approvedCall().operation, { userId: USER_ID })).rejects.toThrow(
      NotFoundError
    );
    expect(createSession).not.toHaveBeenCalled();
  });

  it('is refused to a service account', async () => {
    const { operation } = approvedCall({
      caller: { kind: 'service_account', serviceAccount: { clientId: 'ci' } as never },
    });
    await expect(mintActChainToken(operation, { userId: USER_ID })).rejects.toThrow(ForbiddenError);
  });

  it('needs the capability of an approved issue-for-other operation, once, while its handler runs', async () => {
    const forged = { ...approvedCall().operation } as AuthorizedOperation;
    await expect(mintActChainToken(forged, { userId: USER_ID })).rejects.toThrow(
      AuthorizedOperationRefusedError
    );

    const { operation } = approvedCall();
    await mintActChainToken(operation, { userId: USER_ID });
    await expect(mintActChainToken(operation, { userId: USER_ID })).rejects.toThrow(
      /its one write/
    );

    const retired = approvedCall().operation;
    retireAuthorizedOperation(retired);
    await expect(mintActChainToken(retired, { userId: USER_ID })).rejects.toThrow(
      /while its handler runs/
    );

    const otherEffect = approvedCall({ effects: ['key-custody'] }).operation;
    await expect(mintActChainToken(otherEffect, { userId: USER_ID })).rejects.toThrow(
      AuthorizedOperationRefusedError
    );
    expect(createSession).toHaveBeenCalledTimes(1);
  });

  it('takes the capability as its first argument (type test)', () => {
    const literal = { operationId: 'x', effects: [], permissions: [], approvalId: 'a' };
    const typeOnly = async () => {
      // @ts-expect-error An object literal is no capability: its brand cannot be named.
      await mintActChainToken(literal, { userId: USER_ID });
      // @ts-expect-error The capability comes first, and is required.
      await mintActChainToken({ userId: USER_ID });
    };
    expect(typeof typeOnly).toBe('function');
  });

  it("keeps the account API's audience, scopes and lifetime equal to the signer's profile", () => {
    expect(ACT_CHAIN_TOKEN_AUDIENCE).toBe(API_FAMILY_AUDIENCES.account);
    expect([...ACT_CHAIN_TOKEN_SCOPES].sort()).toEqual(
      Object.values(API_FAMILY_SCOPES.account).sort()
    );
    expect(SIGNER_MAX_LIFETIME_SECONDS).toBe(ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS);
  });
});
