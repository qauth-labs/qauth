import { createTestEgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  type LocalHttpsFixture,
  startLocalHttpsFixture,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { type CryptoKey, exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  dpopProof,
  type DpopTestKey,
  dpopTestKey,
  rememberTokenKey,
} from '../testing/admin-dpop';
import type { TestApprovalFactor } from '../testing/approval-factor';
import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  decodeJwtClaims,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { ageAdminAccount } from '../testing/two-admin';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';

/**
 * THE CI TOKEN EXCHANGE (#526, ADR-019 Decision 7), against a real Postgres
 * and Redis, the token endpoint, the admin listener and a local HTTPS issuer:
 *
 * - a CI job's workload token, from an issuer and subject the operator
 *   realm's `admin.workloadIssuers` lists, is exchanged (RFC 8693) for a
 *   DPoP-bound admin token of the service account the entry names, which the
 *   admin API takes;
 * - a disabled service account gets no token;
 * - the exchange without a DPoP proof is refused, and spends nothing;
 * - a security operation filed with an exchanged token waits for a human
 *   admin's approval (API-09).
 *
 * The issuer is a local HTTPS fixture serving a discovery document and a JWK
 * Set, reached through the test-only egress client. Locally the suite skips
 * when no Docker daemon is reachable; on CI it fails (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const TOKEN_REQUEST_FAILED = 'urn:qauth:event:token.request_failed:v1-rc.0';
const SA_NAME = 'ci-realm-import';
const SA_CLIENT_ID = 'ci-realm-import';
const WORKLOAD_AUDIENCE = 'qauth-admin';
const WORKLOAD_SUBJECT = 'repo:acme/infra:ref:refs/heads/main';

let infra: E2eInfrastructure | undefined;
let jwt: PemKeyPair | undefined;
let fixture: LocalHttpsFixture | undefined;
let dockerUp = false;
/** The CI issuer's signing key: its JWK Set, which the fixture serves, holds the public half. */
let issuerKey: { privateKey: CryptoKey; jwk: JWK };

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
  jwt = await generateJwtPem();
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  issuerKey = { privateKey, jwk: { ...(await exportJWK(publicKey)), kid: 'ci-2026' } };
  const served = await startLocalHttpsFixture();
  const origin = served.origin;
  served.handler = (req, _body, res) => {
    const document =
      req.url === '/.well-known/openid-configuration'
        ? { issuer: origin, jwks_uri: `${origin}/jwks` }
        : req.url === '/jwks'
          ? { keys: [issuerKey.jwk] }
          : undefined;
    res.writeHead(document === undefined ? 404 : 200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(document ?? {}));
  };
  fixture = served;
}, 240_000);

afterAll(async () => {
  await fixture?.close();
  await infra?.teardown();
});

describe('the CI token exchange for the admin API (#526, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      // The server's own operation registry and admin routes; the issuer's
      // documents through the client that reaches the local fixture.
      { adminListener: async () => ({}), egressClientFactory: createTestEgressClient }
    );
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !booted) {
      ctx.skip();
      return;
    }
    await resetE2eState(booted.app);
    // Imported once the boot reset the modules, as the engine is.
    const { createTestApprovalFactor } = await import('../testing/approval-factor');
    test = createTestApprovalFactor();
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  function admin(): FastifyInstance {
    if (!booted?.admin) throw new Error('admin listener not booted');
    return booted.admin;
  }

  function issuer(): string {
    if (!fixture) throw new Error('no issuer fixture');
    return fixture.origin;
  }

  /** The default realm, which is the operator realm of a one-realm deployment. */
  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer || !realm.isOperator) throw new Error('operator realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /**
   * A service account with `role` on the operator realm, as the host's
   * command creates one. Its client's key is never used: the CI job holds no
   * credential of its own.
   */
  async function serviceAccount(role: 'viewer' | 'security-admin' = 'security-admin') {
    const realm = await operatorRealm();
    const { publicKey } = await generateKeyPair('ES256', { extractable: true });
    const created = await app().repositories.serviceAccounts.create({
      realmId: realm.id,
      name: SA_NAME,
      clientId: SA_CLIENT_ID,
      jwks: { keys: [{ ...(await exportJWK(publicKey)), kid: 'unused' }] },
      createdBy: null,
    });
    await app().repositories.adminGrants.create({
      userId: created.userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realm.id,
      createdBy: null,
    });
    return created;
  }

  /** Trust the fixture's tokens for the subjects under `repo:acme/infra:`, as `SA_NAME`. */
  async function trustTheIssuer(): Promise<void> {
    const { id } = await operatorRealm();
    const current = await app().policyStore.get(id);
    if (current === undefined) throw new Error('no policies for the operator realm');
    await app().policyStore.update(
      id,
      {
        admin: {
          workloadIssuers: [
            {
              issuer: issuer(),
              audience: WORKLOAD_AUDIENCE,
              subject: 'repo:acme/infra:*',
              serviceAccount: SA_NAME,
            },
          ],
        },
      },
      { expectedVersion: current.version }
    );
    app().realmHostCache.clear();
  }

  /** A workload token of the fixture issuer, as a CI platform signs one. */
  async function workloadToken(claims: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: issuer(),
      sub: WORKLOAD_SUBJECT,
      aud: WORKLOAD_AUDIENCE,
      iat: now,
      nbf: now - 5,
      exp: now + 300,
      jti: crypto.randomUUID(),
      repository: 'acme/infra',
      ref: 'refs/heads/main',
      ...claims,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT', kid: 'ci-2026' })
      .sign(issuerKey.privateKey);
  }

  /** The CI job's exchange: its workload token, with a DPoP proof of `key` when given. */
  async function exchange(
    token: string,
    key: DpopTestKey | undefined,
    scope = 'qauth:admin:read qauth:admin:security'
  ): Promise<LightMyRequestResponse> {
    const proof =
      key === undefined
        ? undefined
        : await dpopProof(key, {
            method: 'POST',
            url: `${(await operatorRealm()).issuer}/oauth/token`,
          });
    return app().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        ...(proof === undefined ? {} : { dpop: proof }),
      },
      payload: new URLSearchParams({
        grant_type: TOKEN_EXCHANGE,
        subject_token: token,
        subject_token_type: JWT_TYPE,
        resource: ADMIN,
        scope,
      }).toString(),
    });
  }

  async function send(
    method: 'GET' | 'POST',
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    return admin().inject({
      method,
      url,
      headers: { ...(await adminCallHeaders(token, method, url)), ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  async function failureReasons(): Promise<unknown[]> {
    const { rows } = await app().dbPool.query<{ data: Record<string, unknown> }>(
      'SELECT data FROM events WHERE type = $1 ORDER BY seq',
      [TOKEN_REQUEST_FAILED]
    );
    return rows.map((row) => row.data['reason']);
  }

  // Acceptance criterion: a workload token from an allowlisted issuer and
  // subject is exchanged for a DPoP-bound admin token.
  it("exchanges a trusted workload token for the service account's DPoP-bound admin token", async () => {
    const { userId } = await serviceAccount('viewer');
    await trustTheIssuer();
    const realm = await operatorRealm();
    const key = await dpopTestKey();

    const issued = await exchange(await workloadToken(), key, 'qauth:admin:read');
    expect(issued.statusCode, issued.body).toBe(200);
    const body = issued.json<Record<string, unknown>>();
    expect(body).toMatchObject({
      token_type: 'DPoP',
      issued_token_type: ACCESS_TOKEN_TYPE,
      scope: 'qauth:admin:read',
    });
    expect(body).not.toHaveProperty('refresh_token');
    const claims = decodeJwtClaims(body['access_token'] as string);
    expect(claims).toMatchObject({
      sub: userId,
      client_id: SA_CLIENT_ID,
      aud: ADMIN,
      scope: 'qauth:admin:read',
      cnf: { jkt: key.thumbprint },
    });
    // The admin token policy: short-lived, at most 900 seconds.
    expect(body['expires_in']).toBeLessThanOrEqual(900);
    expect((claims['exp'] as number) - (claims['iat'] as number)).toBe(body['expires_in']);
    // The issuer's documents were fetched from the fixture.
    expect(fixture?.requests.map((request) => request.url)).toEqual(
      expect.arrayContaining(['/.well-known/openid-configuration', '/jwks'])
    );

    const token = body['access_token'] as string;
    rememberTokenKey(token, key);
    const read = await send('GET', `/admin/v1-rc.0/realms/${realm.id}`, token);
    expect(read.statusCode, read.body).toBe(200);

    // A workload token is exchanged once.
    const workload = await workloadToken();
    expect((await exchange(workload, await dpopTestKey())).statusCode).toBe(200);
    const replayed = await exchange(workload, await dpopTestKey());
    expect(replayed.statusCode).toBe(400);
    expect(replayed.json()).toMatchObject({ error: 'invalid_request' });
    expect(await failureReasons()).toEqual(['workload_replayed']);
  });

  // Acceptance criterion: a disabled service account gets no token.
  it('gives a disabled service account no token', async () => {
    const created = await serviceAccount();
    await trustTheIssuer();
    // As the host's `service-accounts disable` command does: the service
    // account and its account, in one transaction.
    const { id: realmId } = await operatorRealm();
    await app().repositories.serviceAccounts.setEnabled(realmId, created.serviceAccount.id, false);

    const refused = await exchange(await workloadToken(), await dpopTestKey());
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toMatchObject({ error: 'invalid_request' });
    expect(refused.json()).not.toHaveProperty('access_token');
    expect(await failureReasons()).toEqual(['workload_service_account_disabled']);
  });

  // Acceptance criterion: the exchange without a DPoP proof is refused.
  it('refuses the exchange without a DPoP proof, and the token stays unspent', async () => {
    await serviceAccount();
    await trustTheIssuer();
    const workload = await workloadToken();

    const unbound = await exchange(workload, undefined);
    expect(unbound.statusCode).toBe(400);
    expect(unbound.json()).toMatchObject({ error: 'invalid_dpop_proof' });
    expect(await failureReasons()).toEqual(['dpop_missing_proof']);

    // Refused before it was read, the workload token is still good once.
    const bound = await exchange(workload, await dpopTestKey());
    expect(bound.statusCode, bound.body).toBe(200);
  });

  // Acceptance criterion: a security operation filed with an exchanged token
  // waits for a human approval.
  it('files a security operation that waits for a human approval', async () => {
    const realm = await operatorRealm();
    const { userId: robot } = await serviceAccount();
    await trustTheIssuer();
    const key = await dpopTestKey();
    const issued = await exchange(await workloadToken(), key);
    expect(issued.statusCode, issued.body).toBe(200);
    const token = issued.json<{ access_token: string }>().access_token;
    rememberTokenKey(token, key);

    // A person's account whose address is not confirmed: confirming it is a
    // security operation.
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email: 'imported-by-ci@example.com', password: E2E_PASSWORD },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      realm.id,
      'password',
      'imported-by-ci@example.com'
    );
    if (!credential) throw new Error('registration left no password credential');
    const target = credential.userId;
    const verificationUrl = `/admin/v1-rc.0/realms/${realm.id}/users/${target}/verification`;
    const verify = (headers: Record<string, string> = {}) =>
      send('POST', verificationUrl, token, {}, { 'if-match': '*', ...headers });

    // A human admin who may approve it: without one, the operation and its
    // filing answer 409 approval_unavailable, as a service account never
    // approves its own request.
    const approverId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId: approverId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    await ageAdminAccount(app().dbPool, approverId);

    const unapproved = await verify();
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const filed = await send('POST', `/admin/v1-rc.0/realms/${realm.id}/approvals`, token, {
      operation: 'users.verify',
      params: { userId: target },
      body: {},
      reason: 'The CI import confirmed the owner out of band.',
    });
    expect(filed.statusCode, filed.body).toBe(201);
    const approval = filed.json<{ id: string; status: string; requester: unknown }>();
    expect(approval).toMatchObject({
      status: 'pending',
      requester: { kind: 'service_account', realmId: realm.id, accountId: robot },
    });

    // Pending, it runs nothing, and the service account cannot approve it.
    const early = await verify({ 'qauth-approval': approval.id });
    expect(early.statusCode).toBe(403);
    const engine = await import('./admin/approvals/engine');
    await expect(
      engine.startApproval(app(), test.factor, {
        realmId: realm.id,
        approvalId: approval.id,
        approver: { realmId: realm.id, accountId: robot },
        sessionIssuedAtMs: Date.now(),
      })
    ).rejects.toMatchObject({ statusCode: 404 });

    // A human admin approves it; then it runs.
    const decision = {
      realmId: realm.id,
      approvalId: approval.id,
      approver: { realmId: realm.id, accountId: approverId },
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    const approved = await engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, decision.approver),
    });
    expect(approved.status).toBe('approved');

    const done = await verify({ 'qauth-approval': approval.id });
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json()).toMatchObject({ userId: target, verifiedBy: robot });
  });
});
