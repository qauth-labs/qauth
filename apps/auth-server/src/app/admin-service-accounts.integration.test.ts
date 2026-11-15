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
  signBoundAccessToken,
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
 * SERVICE ACCOUNTS FOR THE ADMIN API (#522, ADR-019 Decision 7), against a
 * real Postgres and Redis, the token endpoint and the admin listener:
 *
 * - a service account gets an admin token through `client_credentials` with
 *   `private_key_jwt` and a DPoP proof, whose `sub` is its user id, and the
 *   admin API takes it;
 * - a client that authenticates with `client_secret_basic` gets no admin
 *   audience, and a developer API key calls nothing on the admin API;
 * - a security operation it files needs a human's approval, runs only once
 *   given, and the audit rows name the actor kind `service_account`;
 * - a disabled service account gets no token, and its token makes no admin
 *   call.
 *
 * The service account is created with the repository, as the host's
 * `service-accounts` command creates it. Locally the suite skips when no
 * Docker daemon is reachable; on CI it fails (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const TOKEN_REQUEST_FAILED = 'urn:qauth:event:token.request_failed:v1-rc.0';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const SA_CLIENT_ID = 'ci-realm-import';

let infra: E2eInfrastructure | undefined;
let jwt: PemKeyPair | undefined;
let dockerUp = false;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  infra = await startE2eInfrastructure();
  jwt = await generateJwtPem();
}, 240_000);

afterAll(async () => {
  await infra?.teardown();
});

interface AuditRow {
  actor_kind: string;
  actor_id: string;
  actor_realm_id: string | null;
  operation_id: string;
  outcome: string;
}

describe('service accounts for the admin API (#522, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;
  /** The service account's key pair: its client's `jwks` holds the public half. */
  let clientKey: { privateKey: CryptoKey; jwk: JWK };

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      // The server's own operation registry and admin routes.
      { adminListener: async () => ({}) }
    );
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    clientKey = { privateKey, jwk: { ...(await exportJWK(publicKey)), kid: 'ci-1' } };
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

  /** The default realm, which is the operator realm of a one-realm deployment. */
  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer || !realm.isOperator) throw new Error('operator realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A service account with `role` on the operator realm, as the host's command creates one. */
  async function serviceAccount(
    role: 'viewer' | 'security-admin' = 'security-admin',
    name = 'ci-realm-import',
    clientId = SA_CLIENT_ID
  ) {
    const realm = await operatorRealm();
    const created = await app().repositories.serviceAccounts.create({
      realmId: realm.id,
      name,
      clientId,
      jwks: { keys: [clientKey.jwk as Record<string, unknown>] },
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

  /** A `private_key_jwt` assertion of the service account's client, for the realm's issuer. */
  async function assertion(clientId = SA_CLIENT_ID): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'ci-1' })
      .setIssuer(clientId)
      .setSubject(clientId)
      .setAudience((await operatorRealm()).issuer)
      .setJti(crypto.randomUUID())
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(clientKey.privateKey);
  }

  /** A token request, with a DPoP proof of `key` for the token endpoint when given. */
  async function tokenRequest(
    form: Record<string, string>,
    key?: DpopTestKey,
    headers: Record<string, string> = {}
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
        ...headers,
      },
      payload: new URLSearchParams(form).toString(),
    });
  }

  /** The service account's token request: `client_credentials`, `private_key_jwt`. */
  async function serviceAccountToken(key: DpopTestKey | undefined, scope: string) {
    return tokenRequest(
      {
        grant_type: 'client_credentials',
        client_id: SA_CLIENT_ID,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: await assertion(),
        scope,
        resource: ADMIN,
      },
      key
    );
  }

  /** An admin token of the service account, its DPoP key remembered for the calls. */
  async function adminTokenOf(scope = 'qauth:admin:read qauth:admin:security'): Promise<string> {
    const key = await dpopTestKey();
    const issued = await serviceAccountToken(key, scope);
    expect(issued.statusCode, issued.body).toBe(200);
    const token = issued.json<{ access_token: string }>().access_token;
    rememberTokenKey(token, key);
    return token;
  }

  async function send(
    method: 'GET' | 'POST' | 'DELETE',
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

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT actor_kind::text AS actor_kind, actor_id, actor_realm_id, operation_id, outcome::text AS outcome
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  /** A password account registered through the real route, its address unconfirmed. */
  async function unconfirmedAccount(email: string): Promise<string> {
    const registered = await app().inject({
      method: 'POST',
      url: '/auth/register',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(registered.statusCode, registered.body).toBe(202);
    const { id } = await operatorRealm();
    const credential = await app().repositories.userCredentials.findByRealmProviderSub(
      id,
      'password',
      email
    );
    if (!credential) throw new Error(`registration of ${email} left no password credential`);
    return credential.userId;
  }

  /** A person's admin account with security-admin on the operator realm, old enough to approve. */
  async function humanApprover(): Promise<{ realmId: string; accountId: string }> {
    const realm = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    // The two-admin rule: an approver held its right, and was made, before
    // the 7 days the request looks back on (#521).
    await ageAdminAccount(app().dbPool, userId);
    return { realmId: realm.id, accountId: userId };
  }

  // Acceptance criteria: a service account gets an admin token with
  // private_key_jwt and DPoP; its `sub` is the service account's user id.
  it('gets an admin token with private_key_jwt and a DPoP proof, which the admin API takes', async () => {
    const { userId } = await serviceAccount('viewer');
    const realm = await operatorRealm();
    const key = await dpopTestKey();

    const issued = await serviceAccountToken(key, 'qauth:admin:read');
    expect(issued.statusCode, issued.body).toBe(200);
    const body = issued.json<Record<string, unknown>>();
    expect(body).toMatchObject({ token_type: 'DPoP', scope: 'qauth:admin:read' });
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

    const token = body['access_token'] as string;
    rememberTokenKey(token, key);
    const read = await send('GET', `/admin/v1-rc.0/realms/${realm.id}`, token);
    expect(read.statusCode, read.body).toBe(200);
    expect(await auditRows(realm.id)).toEqual([
      {
        actor_kind: 'service_account',
        actor_id: userId,
        actor_realm_id: realm.id,
        operation_id: 'realms.get',
        outcome: 'succeeded',
      },
    ]);

    // Without a DPoP proof there is no admin token at all.
    const unbound = await serviceAccountToken(undefined, 'qauth:admin:read');
    expect(unbound.statusCode).toBe(400);
    expect(unbound.json()).toMatchObject({ error: 'invalid_dpop_proof' });
  });

  // Acceptance criterion: a client using client_secret_basic cannot get the
  // admin audience.
  it('gives a client that authenticates with client_secret_basic no admin audience', async () => {
    const realm = await operatorRealm();
    const secret = 'a-long-shared-secret-of-the-machine-client';
    const client = await app().repositories.oauthClients.create({
      realmId: realm.id,
      clientId: 'basic-machine',
      clientSecretHash: await app().passwordHasher.hashPassword(secret),
      tokenEndpointAuthMethod: 'client_secret_basic',
      name: 'Basic machine client',
      redirectUris: [],
      scopes: ['qauth:admin:read'],
      grantTypes: ['client_credentials'],
      audience: [ADMIN],
      enabled: true,
      requirePkce: true,
      provisionedByOperator: true,
    });
    const basic = `Basic ${Buffer.from(`basic-machine:${secret}`).toString('base64')}`;
    const ask = async () =>
      tokenRequest(
        { grant_type: 'client_credentials', scope: 'qauth:admin:read', resource: ADMIN },
        await dpopTestKey(),
        { authorization: basic }
      );

    const refused = await ask();
    expect(refused.statusCode).toBe(400);
    expect(refused.json()).toMatchObject({ error: 'invalid_target' });
    expect(await failureReasons()).toEqual(['admin_audience_requires_private_key_jwt']);

    // Bound to a service account by hand, it is still no service account's
    // client that may act: it gets no token at all.
    const realmUser = await app().dbPool.query<{ id: string }>(
      'INSERT INTO users (realm_id, is_service_account) VALUES ($1, true) RETURNING id',
      [realm.id]
    );
    await app().dbPool.query(
      `INSERT INTO service_accounts (realm_id, name, user_id, client_id) VALUES ($1, 'rewritten', $2, $3)`,
      [realm.id, realmUser.rows[0].id, client.id]
    );
    const asServiceAccount = await ask();
    expect(asServiceAccount.statusCode).toBe(401);
    expect(asServiceAccount.json()).toMatchObject({ error: 'invalid_client' });
    expect((await failureReasons()).at(-1)).toBe('service_account_client_not_private_key_jwt');
  });

  // Acceptance criterion: a developer API key cannot call the admin API.
  it('lets no developer API key call the admin API, nor one of a service account’s client', async () => {
    const realm = await operatorRealm();
    // A development client, in a realm whose ceiling lets it hold a key, so
    // that the key itself is valid.
    await app().dbPool.query(
      `UPDATE realms SET max_environment_laxity = 'development' WHERE id = $1`,
      [realm.id]
    );
    const devClient = await app().repositories.oauthClients.create({
      realmId: realm.id,
      clientId: 'dev-app',
      clientSecretHash: 'unused',
      name: 'Development app',
      redirectUris: [],
      scopes: ['read:notes'],
      grantTypes: ['client_credentials'],
      audience: null,
      enabled: true,
      environment: 'development',
    });
    const { authenticateApiKey, generateApiKey } = await import('./helpers/api-key');
    const keyFor = async (clientRowId: string) => {
      const generated = await generateApiKey(app());
      await app().repositories.apiKeys.create({
        realmId: realm.id,
        clientId: clientRowId,
        developerId: null,
        name: 'laptop',
        keyHash: generated.keyHash,
        prefix: generated.prefix,
        last4: generated.last4,
      });
      return generated.key;
    };
    const key = await keyFor(devClient.id);
    const realmRow = await app().repositories.realms.findById(realm.id);
    if (!realmRow) throw new Error('realm missing');
    await expect(authenticateApiKey(app(), realmRow, key)).resolves.not.toBeNull();

    const url = `/admin/v1-rc.0/realms/${realm.id}`;
    for (const authorization of [`Bearer ${key}`, `DPoP ${key}`, key]) {
      const response = await admin().inject({ method: 'GET', url, headers: { authorization } });
      expect(response.statusCode, authorization).toBe(401);
    }
    const byHeader = await admin().inject({ method: 'GET', url, headers: { 'x-api-key': key } });
    expect(byHeader.statusCode).toBe(401);
    expect(await auditRows(realm.id)).toEqual([]);

    // A key of a client that may get the admin audience authenticates
    // nothing, whenever it was written.
    const { client } = await serviceAccount();
    // In development, as the key's own client is: only the admin rule refuses it.
    await app().dbPool.query(`UPDATE oauth_clients SET environment = 'development' WHERE id = $1`, [
      client.id,
    ]);
    await expect(authenticateApiKey(app(), realmRow, await keyFor(client.id))).resolves.toBeNull();
  });

  // Acceptance criteria: a service account that files a security operation
  // gets approval_required, and the operation runs only after a human
  // approves; the audit rows name the actor kind `service_account`.
  it('files a security operation that runs only after a human approves it', async () => {
    const realm = await operatorRealm();
    const { userId: robot } = await serviceAccount();
    const approver = await humanApprover();
    const token = await adminTokenOf();
    const target = await unconfirmedAccount('verified-by-a-robot@example.com');
    const verificationUrl = `/admin/v1-rc.0/realms/${realm.id}/users/${target}/verification`;
    const verify = (headers: Record<string, string> = {}) =>
      send('POST', verificationUrl, token, {}, { 'if-match': '*', ...headers });

    const unapproved = await verify();
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const filed = await send('POST', `/admin/v1-rc.0/realms/${realm.id}/approvals`, token, {
      operation: 'users.verify',
      params: { userId: target },
      body: {},
      reason: 'The nightly import confirmed the owner out of band.',
    });
    expect(filed.statusCode, filed.body).toBe(201);
    const approval = filed.json<{
      id: string;
      status: string;
      requester: Record<string, unknown>;
      approvalsRequired: number;
    }>();
    // Every approval of its request comes from a human: none is its own.
    expect(approval).toMatchObject({
      status: 'pending',
      requester: { kind: 'service_account', realmId: realm.id, accountId: robot },
      approvalsRequired: 1,
    });
    // It reads its own approval.
    const read = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${approval.id}`,
      token
    );
    expect(read.statusCode, read.body).toBe(200);

    // Pending, the approval runs nothing.
    const early = await verify({ 'qauth-approval': approval.id });
    expect(early.statusCode).toBe(403);
    expect(early.json()).toMatchObject({ code: 'approval_required' });

    // The service account cannot approve its own request.
    const engine = await import('./admin/approvals/engine');
    await expect(
      engine.startApproval(app(), test.factor, {
        realmId: realm.id,
        approvalId: approval.id,
        approver: { realmId: realm.id, accountId: robot },
        sessionIssuedAtMs: Date.now(),
      })
    ).rejects.toMatchObject({ statusCode: 404 });

    // A human approves it with the factor.
    const decision = {
      realmId: realm.id,
      approvalId: approval.id,
      approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    const approved = await engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, approver),
    });
    expect(approved.status).toBe('approved');

    const done = await verify({ 'qauth-approval': approval.id });
    expect(done.statusCode, done.body).toBe(200);
    expect(done.json()).toMatchObject({ userId: target, verifiedBy: robot });

    // The event names the service account as the client acting for itself.
    const { rows: events } = await app().dbPool.query<{ actor_type: string; actor_id: string }>(
      `SELECT actor_type, actor_id FROM events WHERE type = 'urn:qauth:event:user.verified:v1-rc.0'`
    );
    expect(events).toEqual([{ actor_type: 'client', actor_id: SA_CLIENT_ID }]);

    // Acceptance criterion: the audit rows name the actor kind of a service
    // account, and the approval a human's.
    expect(await auditRows(realm.id)).toEqual([
      {
        actor_kind: 'service_account',
        actor_id: robot,
        actor_realm_id: realm.id,
        operation_id: 'users.verify',
        outcome: 'denied',
      },
      {
        actor_kind: 'service_account',
        actor_id: robot,
        actor_realm_id: realm.id,
        operation_id: 'approvals.create',
        outcome: 'succeeded',
      },
      {
        actor_kind: 'service_account',
        actor_id: robot,
        actor_realm_id: realm.id,
        operation_id: 'approvals.get',
        outcome: 'succeeded',
      },
      {
        actor_kind: 'service_account',
        actor_id: robot,
        actor_realm_id: realm.id,
        operation_id: 'users.verify',
        outcome: 'denied',
      },
      {
        actor_kind: 'human_admin',
        actor_id: approver.accountId,
        actor_realm_id: realm.id,
        operation_id: 'approvals.approve',
        outcome: 'succeeded',
      },
      {
        actor_kind: 'service_account',
        actor_id: robot,
        actor_realm_id: realm.id,
        operation_id: 'users.verify',
        outcome: 'succeeded',
      },
    ]);
  });

  it('files nothing a human cannot approve: another service account never counts as an approver', async () => {
    const realm = await operatorRealm();
    await serviceAccount();
    // Another service account with security-admin on the realm, old enough
    // to approve were it a person's: it never counts all the same (the
    // two-admin rule's rule 1), so no one could approve.
    const { userId: other } = await serviceAccount('security-admin', 'other-robot', 'other-robot');
    await ageAdminAccount(app().dbPool, other);
    const token = await adminTokenOf();
    const target = await unconfirmedAccount('nobody-to-approve@example.com');

    const filed = await send('POST', `/admin/v1-rc.0/realms/${realm.id}/approvals`, token, {
      operation: 'users.verify',
      params: { userId: target },
      body: {},
    });
    expect(filed.statusCode).toBe(409);
    expect(filed.json()).toMatchObject({ code: 'approval_unavailable' });
  });

  // Acceptance criterion: a disabled service account gets no token.
  it('gives a disabled service account no token, and takes the admin API from the token it holds', async () => {
    const realm = await operatorRealm();
    const { serviceAccount: account } = await serviceAccount('viewer');
    const token = await adminTokenOf('qauth:admin:read');
    const url = `/admin/v1-rc.0/realms/${realm.id}`;
    expect((await send('GET', url, token)).statusCode).toBe(200);

    await app().repositories.serviceAccounts.setEnabled(realm.id, account.id, false);

    const refused = await serviceAccountToken(await dpopTestKey(), 'qauth:admin:read');
    expect(refused.statusCode).toBe(401);
    expect(refused.json()).toMatchObject({ error: 'invalid_client' });
    expect(await failureReasons()).toEqual(['service_account_disabled']);
    expect((await send('GET', url, token)).statusCode).toBe(401);

    // Enabled again: the token it held before stays refused, since the
    // disable ended what its account was issued (users.not_valid_before).
    await app().repositories.serviceAccounts.setEnabled(realm.id, account.id, true);
    expect((await send('GET', url, token)).statusCode).toBe(401);
    // A token's `iat` is in whole seconds: one minted in the second of the
    // disable would count as issued before it.
    await nextSecondAfterDisable(account.userId);
    const again = await adminTokenOf('qauth:admin:read');
    expect((await send('GET', url, again)).statusCode).toBe(200);
  });

  /** Wait until a token minted now has an `iat` at or after the account's `not_valid_before`. */
  async function nextSecondAfterDisable(userId: string): Promise<void> {
    const { rows } = await app().dbPool.query<{ not_valid_before: string | null }>(
      'SELECT not_valid_before FROM users WHERE id = $1',
      [userId]
    );
    const notValidBefore = Number(rows[0]?.not_valid_before ?? 0);
    expect(notValidBefore).toBeGreaterThan(0);
    const from = Math.ceil(notValidBefore / 1000) * 1000;
    while (Date.now() < from) await new Promise((resolve) => setTimeout(resolve, 50));
  }

  // #522: a service account's client is not deleted while the service account
  // binds it, and an account whose binding is gone is never a person's.
  it("refuses to delete a service account's client, and refuses a token whose binding is gone", async () => {
    const realm = await operatorRealm();
    const { client, userId: robot } = await serviceAccount('viewer');
    const token = await adminTokenOf('qauth:admin:read');
    const url = `/admin/v1-rc.0/realms/${realm.id}`;
    expect((await send('GET', url, token)).statusCode).toBe(200);

    // A human admin who may delete clients.
    const humanId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId: humanId,
      role: { kind: 'built-in', name: 'security-admin' },
      targetRealmId: realm.id,
      createdBy: null,
    });
    const human = await signBoundAccessToken(app(), realm, {
      sub: humanId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope: 'qauth:admin:read qauth:admin:write qauth:admin:security',
    });
    const clientUrl = `/admin/v1-rc.0/realms/${realm.id}/clients/${client.id}`;
    const read = await send('GET', clientUrl, human);
    expect(read.statusCode, read.body).toBe(200);
    const etag = read.headers['etag'] as string;
    const refused = await send('DELETE', clientUrl, human, undefined, { 'if-match': etag });
    expect(refused.statusCode, refused.body).toBe(409);
    expect(refused.json()).toMatchObject({ code: 'conflict' });
    // The database refuses it too, whoever deletes it.
    await expect(
      app().dbPool.query('DELETE FROM oauth_clients WHERE id = $1', [client.id])
    ).rejects.toMatchObject({ code: '23503' });

    // The binding gone by hand: the account is still a service account's,
    // so its live token makes no admin call, as a person's or otherwise.
    await app().dbPool.query('DELETE FROM service_accounts WHERE user_id = $1', [robot]);
    expect((await send('GET', url, token)).statusCode).toBe(401);
  });
});
