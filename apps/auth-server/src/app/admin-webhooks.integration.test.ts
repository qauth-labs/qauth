import { createHmac, randomUUID } from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import type { TestApprovalFactor } from '../testing/approval-factor';
import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * THE WEBHOOK SUBSCRIPTION OPERATIONS OF THE ADMIN API (#537, ADR-019
 * Decisions 7 to 9), against a real Postgres and Redis: a subscription's
 * signing secret answered once, by its creation and by a rotation, and never
 * by a read, a list or an audit row; an http URL, one with a user name or
 * password and one of a private address refused at creation; a rotation whose
 * two secrets both sign until its overlap ends; the read scope listing but not
 * creating; a subscription of another realm out of reach; and every change
 * applied only once approved, each with its audit row and diff.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const MERGE_PATCH = 'application/merge-patch+json';
const USER_REGISTERED = 'urn:qauth:event:user.registered:v1-rc.0';
const WEBHOOK_TEST = 'urn:qauth:event:webhook.test:v1-rc.0';
/** A public address: the egress client admits it with no allowlist and no lookup. */
const PUBLIC_URL = 'https://93.184.215.14/hooks/qauth';

/** What the signer is asked to sign, as a delivery would ask it. */
const MESSAGE = { id: 'msg_2Z7xYq', timestamp: 1_790_000_000, body: '{"type":"webhook.test"}' };

/** The Standard Webhooks signature `secret` gives {@link MESSAGE}, as `v1,<base64>`. */
function signatureBy(secret: string): string {
  expect(secret).toMatch(/^whsec_[A-Za-z0-9+/]+={0,2}$/);
  const key = Buffer.from(secret.slice('whsec_'.length), 'base64');
  expect(key).toHaveLength(32);
  const mac = createHmac('sha256', key)
    .update(`${MESSAGE.id}.${MESSAGE.timestamp}.${MESSAGE.body}`)
    .digest('base64');
  return `v1,${mac}`;
}

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

interface SubscriptionBody {
  id: string;
  url: string;
  description: string | null;
  eventTypes: 'all' | string[];
  categories: string[];
  enabled: boolean;
  disabledReason: string | null;
  previousSecretExpiresAt: string | null;
  version: number;
  secret?: string;
}

interface AuditRow {
  operation_id: string;
  operation_class: string;
  outcome: string;
  masked_diff: unknown;
}

describe('the admin webhook subscription operations (#537, real containers)', () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...ADMIN_LISTENER_ENVIRONMENT },
      // The server's own operation registry and admin routes.
      { adminListener: async () => ({}) }
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

  async function defaultRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A second realm, which the admins of the default realm hold nothing on. */
  async function otherRealm(): Promise<string> {
    const host = `other-${randomUUID().slice(0, 8)}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name: `other-${randomUUID()}`, issuer: `https://${host}`, enabled: true },
      host
    );
    return realm.id;
  }

  type Admin = Awaited<ReturnType<typeof adminWith>>;

  /** An admin of the default realm with `role` on it: its token and its account as an approver. */
  async function adminWith(role: 'viewer' | 'editor' | 'security-admin', scope = ALL_ADMIN_SCOPES) {
    const realm = await defaultRealm();
    const userId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realm.id,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), realm, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
    return { userId, token, approver: { realmId: realm.id, accountId: userId } };
  }

  const subscriptionsPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}/webhooks`;
  const subscriptionPath = (realmId: string, id: string) => `${subscriptionsPath(realmId)}/${id}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
  async function send(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    token: string,
    payload?: unknown,
    headers: Record<string, string> = {}
  ): Promise<LightMyRequestResponse> {
    const path = url.split('?')[0];
    return admin().inject({
      method,
      url,
      headers: { ...(await adminCallHeaders(token, method, path)), ...headers },
      ...(payload === undefined ? {} : { payload: payload as Record<string, unknown> }),
    });
  }

  /** File an approval for `operation` and approve it with the test factor. */
  async function fileAndApprove(
    realmId: string,
    requester: Admin,
    operation: string,
    params: Record<string, string>,
    body?: unknown
  ): Promise<string> {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation,
        params,
        ...(body === undefined ? {} : { body }),
        reason: 'The operator asked for it in ticket OPS-537.',
      }
    );
    expect(filed.statusCode, filed.body).toBe(201);
    const approvalId = filed.json<{ id: string }>().id;

    const engine = await import('./admin/approvals/engine');
    const decision = {
      realmId,
      approvalId,
      approver: requester.approver,
      sessionIssuedAtMs: Date.now(),
    };
    const { challenge } = await engine.startApproval(app(), test.factor, decision);
    await engine.completeApproval(app(), test.factor, {
      ...decision,
      response: test.answer(challenge, requester.approver),
    });
    return approvalId;
  }

  /** Create a subscription through the admin API, approved: its answer, the secret with it. */
  async function created(
    realmId: string,
    by: Admin,
    body: Record<string, unknown> = { url: PUBLIC_URL, categories: ['user'] }
  ): Promise<SubscriptionBody & { secret: string }> {
    const approvalId = await fileAndApprove(realmId, by, 'webhooks.create', {}, body);
    const response = await send('POST', subscriptionsPath(realmId), by.token, body, {
      'qauth-approval': approvalId,
    });
    expect(response.statusCode, response.body).toBe(201);
    const answered = response.json<SubscriptionBody>();
    if (answered.secret === undefined) throw new Error('webhooks.create answered no secret');
    return { ...answered, secret: answered.secret };
  }

  /** A subscription of `realmId` stored as the admin API stores one, with its secret in the signer. */
  async function storedSubscription(realmId: string) {
    const secrets = app().webhookSecrets;
    if (secrets === null) throw new Error('the boot holds no webhook secrets');
    const id = randomUUID();
    const row = await app().db.transaction(async (tx) => {
      const { kid } = await secrets.create({ realmId, subscriptionId: id, tx });
      return app().repositories.webhookSubscriptions.create(
        realmId,
        {
          id,
          url: PUBLIC_URL,
          description: null,
          eventTypes: null,
          categories: ['user'],
          enabled: true,
          disabledReason: null,
          secretRef: kid,
          createdBy: null,
        },
        tx
      );
    });
    return row;
  }

  /** The signatures the signer gives {@link MESSAGE} for the subscription, sorted. */
  async function signatures(realmId: string, subscriptionId: string): Promise<string[]> {
    const header = await app().signer.signWebhook('local', {
      realmId,
      subscriptionId,
      ...MESSAGE,
    });
    return header.split(' ').sort();
  }

  /** The stored keys of the subscription, as `status` by `kid`. */
  async function keyStatuses(realmId: string, subscriptionId: string) {
    const { rows } = await app().dbPool.query<{ kid: string; status: string }>(
      `SELECT kid, status FROM realm_keys
        WHERE realm_id = $1 AND scope_id = $2 AND purpose = 'webhook_signing'`,
      [realmId, subscriptionId]
    );
    return Object.fromEntries(rows.map((row) => [row.kid, row.status]));
  }

  async function auditRows(realmId: string, operationId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, operation_class, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 AND operation_id = $2 ORDER BY seq`,
      [realmId, operationId]
    );
    return rows;
  }

  /** The subscription's ETag, as webhooks.get answers it. */
  async function etagOf(realmId: string, id: string, by: Admin): Promise<string> {
    const read = await send('GET', subscriptionPath(realmId, id), by.token);
    expect(read.statusCode, read.body).toBe(200);
    const etag = read.headers['etag'];
    if (typeof etag !== 'string') throw new Error('webhooks.get answered no ETag');
    return etag;
  }

  it('answers the secret once, at creation, and never in a read, a list or the audit diff', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const body = {
      url: PUBLIC_URL,
      description: 'CRM sync',
      categories: ['user'],
      eventTypes: [USER_REGISTERED],
    };

    const unapproved = await send('POST', subscriptionsPath(realm.id), securityAdmin.token, body);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const approvalId = await fileAndApprove(realm.id, securityAdmin, 'webhooks.create', {}, body);
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${approvalId}`,
      securityAdmin.token
    );
    expect(shown.statusCode, shown.body).toBe(200);
    for (const value of [PUBLIC_URL, 'CRM sync', USER_REGISTERED]) {
      expect(shown.body).toContain(value);
    }

    const response = await send('POST', subscriptionsPath(realm.id), securityAdmin.token, body, {
      'qauth-approval': approvalId,
    });
    expect(response.statusCode, response.body).toBe(201);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers['etag']).toBe('"1"');
    const subscription = response.json<SubscriptionBody>();
    expect(subscription).toMatchObject({
      url: PUBLIC_URL,
      description: 'CRM sync',
      categories: ['user'],
      eventTypes: [USER_REGISTERED],
      enabled: true,
      disabledReason: null,
      previousSecretExpiresAt: null,
      version: 1,
    });
    expect(response.headers['location']).toBe(subscriptionPath(realm.id, subscription.id));
    // A UUIDv7, reserved in the transaction of the creation.
    expect(subscription.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
    const secret = subscription.secret;
    if (secret === undefined) throw new Error('webhooks.create answered no secret');
    // The secret is the one the signer signs with.
    expect(await signatures(realm.id, subscription.id)).toEqual([signatureBy(secret)]);
    const secretBytes = secret.slice('whsec_'.length);

    const viewer = await adminWith('viewer', 'qauth:admin:read');
    const read = await send('GET', subscriptionPath(realm.id, subscription.id), viewer.token);
    expect(read.statusCode, read.body).toBe(200);
    expect(read.json()).not.toHaveProperty('secret');
    const listed = await send('GET', `${subscriptionsPath(realm.id)}?limit=100`, viewer.token);
    expect(listed.statusCode, listed.body).toBe(200);
    expect(listed.json<{ items: SubscriptionBody[] }>().items.map((item) => item.id)).toEqual([
      subscription.id,
    ]);
    for (const answer of [read, listed]) {
      expect(answer.body).not.toContain(secretBytes);
      expect(answer.body).not.toContain('whsec_');
    }

    // The refused call is audited as denied; the applied one with its diff,
    // the secret masked.
    const rows = await auditRows(realm.id, 'webhooks.create');
    expect(rows.map((row) => row.outcome)).toEqual(['denied', 'succeeded']);
    const applied = rows.at(-1);
    expect(applied).toMatchObject({ operation_class: 'security' });
    expect(applied?.masked_diff).toMatchObject({
      before: null,
      after: { id: subscription.id, url: PUBLIC_URL, secret: '***' },
    });
    const { rows: everywhere } = await app().dbPool.query<{ hits: string }>(
      `SELECT (
          (SELECT count(*) FROM admin_audit_log WHERE masked_diff::text LIKE '%' || $1 || '%')
        + (SELECT count(*) FROM events WHERE data::text LIKE '%' || $1 || '%')
        + (SELECT count(*) FROM webhook_subscriptions WHERE row_to_json(webhook_subscriptions)::text LIKE '%' || $1 || '%')
        + (SELECT count(*) FROM realm_keys WHERE row_to_json(realm_keys)::text LIKE '%' || $1 || '%')
       )::text AS hits`,
      [secretBytes]
    );
    expect(everywhere[0]?.hits).toBe('0');
  });

  it('refuses an http URL, one with a user name or password and one of a private address at creation, with what is wrong', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const webhookKeys = async () => {
      const { rows } = await app().dbPool.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM realm_keys WHERE purpose = 'webhook_signing'`
      );
      return rows[0]?.count;
    };
    const keysBefore = await webhookKeys();

    // Refused by the body schema, before an approval is asked for.
    for (const [url, message] of [
      ['http://93.184.215.14/hooks/qauth', 'url must be an https URL'],
      ['https://user:pass@93.184.215.14/hooks/qauth', 'url must not carry a user name or password'],
    ] as const) {
      const refused = await send('POST', subscriptionsPath(realm.id), securityAdmin.token, {
        url,
        categories: ['user'],
      });
      expect(refused.statusCode, url).toBe(400);
      expect(refused.body, url).toContain(message);
    }

    // A private address passes the schema; the egress client refuses it, with
    // the deployment allowlist naming none, before anything is stored.
    for (const url of ['https://10.0.0.5/hook', 'https://127.0.0.1:8443/hook']) {
      const body = { url, categories: ['user'] };
      const approvalId = await fileAndApprove(realm.id, securityAdmin, 'webhooks.create', {}, body);
      const refused = await send('POST', subscriptionsPath(realm.id), securityAdmin.token, body, {
        'qauth-approval': approvalId,
      });
      expect(refused.statusCode, refused.body).toBe(422);
      expect(refused.json()).toMatchObject({
        code: 'unprocessable_content',
        errors: [expect.objectContaining({ pointer: '/url' })],
      });
      expect(refused.body).toContain('public addresses');
    }

    const listed = await send('GET', subscriptionsPath(realm.id), securityAdmin.token);
    expect(listed.json<{ items: unknown[] }>().items).toEqual([]);
    // No secret was made for a refused subscription.
    expect(await webhookKeys()).toBe(keysBefore);
  });

  it('signs with both secrets after a rotation until its overlap ends, then with the new one alone', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const first = await created(realm.id, securityAdmin);
    const params = { subscriptionId: first.id };
    const body = { overlapSeconds: 3600 };
    const rotatePath = `${subscriptionPath(realm.id, first.id)}/rotate-secret`;

    const unapproved = await send('POST', rotatePath, securityAdmin.token, body);
    expect(unapproved.statusCode).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    const approvalId = await fileAndApprove(
      realm.id,
      securityAdmin,
      'webhooks.rotateSecret',
      params,
      body
    );
    const before = Date.now();
    const response = await send('POST', rotatePath, securityAdmin.token, body, {
      'qauth-approval': approvalId,
    });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    const rotated = response.json<SubscriptionBody>();
    expect(rotated.version).toBe(2);
    expect(rotated.secret).toMatch(/^whsec_/);
    expect(rotated.secret).not.toBe(first.secret);
    const expiresAt = Date.parse(rotated.previousSecretExpiresAt ?? '');
    expect(expiresAt).toBeGreaterThanOrEqual(before + 3_600_000 - 1000);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 3_600_000 + 1000);

    // Both secrets sign each message until the overlap ends.
    expect(await signatures(realm.id, first.id)).toEqual(
      [signatureBy(first.secret), signatureBy(rotated.secret ?? '')].sort()
    );
    const read = await send('GET', subscriptionPath(realm.id, first.id), securityAdmin.token);
    expect(read.json()).toMatchObject({ previousSecretExpiresAt: rotated.previousSecretExpiresAt });
    expect(read.json()).not.toHaveProperty('secret');
    const rows = await auditRows(realm.id, 'webhooks.rotateSecret');
    expect(rows.map((row) => row.outcome)).toEqual(['denied', 'succeeded']);
    expect(rows.at(-1)?.masked_diff).toMatchObject({ after: { secret: '***', version: 2 } });
    for (const secret of [first.secret, rotated.secret ?? '']) {
      expect(JSON.stringify(rows.at(-1)?.masked_diff)).not.toContain(secret.slice(6));
    }

    // The signer-role job ends the overlap once its time has come, and not before.
    const { createWebhookSecretOverlapJob } = await import('./jobs/webhook-secret-overlap');
    const job = createWebhookSecretOverlapJob({
      secrets: app().webhookSecrets,
      subscriptions: app().repositories.webhookSubscriptions,
      transaction: (work) => app().db.transaction(work),
    });
    const log = app().log;
    const signal = new AbortController().signal;
    await job.run({ signal, now: () => expiresAt - 1, log });
    expect(Object.values(await keyStatuses(realm.id, first.id)).sort()).toEqual(['active', 'next']);
    await job.run({ signal, now: () => expiresAt + 1, log });
    expect(Object.values(await keyStatuses(realm.id, first.id)).sort()).toEqual([
      'active',
      'retired',
    ]);
    const ended = await app().repositories.webhookSubscriptions.findById(realm.id, first.id);
    expect(ended).toMatchObject({ previousSecretExpiresAt: null, version: 2 });
  });

  it('lets a token with only qauth:admin:read list and read, and not create', async () => {
    const realm = await defaultRealm();
    const stored = await storedSubscription(realm.id);
    // A security admin's role holds every permission; its token's scopes stop short.
    for (const scope of ['qauth:admin:read', 'qauth:admin:read qauth:admin:write']) {
      const reader = await adminWith('security-admin', scope);
      const listed = await send('GET', subscriptionsPath(realm.id), reader.token);
      expect(listed.statusCode, listed.body).toBe(200);
      expect(listed.headers['cache-control']).toBe('no-store');
      expect(listed.json<{ items: SubscriptionBody[] }>().items.map((item) => item.id)).toEqual([
        stored.id,
      ]);
      expect(
        (await send('GET', subscriptionPath(realm.id, stored.id), reader.token)).statusCode
      ).toBe(200);

      const refused = [
        await send('POST', subscriptionsPath(realm.id), reader.token, {
          url: PUBLIC_URL,
          categories: ['user'],
        }),
        await send(
          'PATCH',
          subscriptionPath(realm.id, stored.id),
          reader.token,
          JSON.stringify({ enabled: false }),
          { 'content-type': MERGE_PATCH, 'if-match': '"1"' }
        ),
        await send(
          'POST',
          `${subscriptionPath(realm.id, stored.id)}/rotate-secret`,
          reader.token,
          {}
        ),
        await send('POST', `${subscriptionPath(realm.id, stored.id)}/test`, reader.token, {}),
        await send('DELETE', subscriptionPath(realm.id, stored.id), reader.token, undefined, {
          'if-match': '"1"',
        }),
      ];
      for (const response of refused) {
        expect(response.statusCode, response.body).toBe(403);
        expect(response.headers['www-authenticate']).toContain('error="insufficient_scope"');
        expect(response.headers['www-authenticate']).toContain('qauth:admin:security');
      }
    }
    const listed = await send(
      'GET',
      subscriptionsPath(realm.id),
      (await adminWith('security-admin')).token
    );
    expect(listed.json<{ items: unknown[] }>().items).toHaveLength(1);
    expect(
      (await app().repositories.webhookSubscriptions.findById(realm.id, stored.id))?.version
    ).toBe(1);
  });

  it("never lets a realm's admin read or change another realm's subscription", async () => {
    const realm = await defaultRealm();
    const elsewhereRealm = await otherRealm();
    const elsewhere = await storedSubscription(elsewhereRealm);
    const own = await storedSubscription(realm.id);
    const securityAdmin = await adminWith('security-admin');

    // Under its own realm's path, the other realm's subscription does not exist.
    const ownPath = subscriptionPath(realm.id, elsewhere.id);
    const listed = await send(
      'GET',
      `${subscriptionsPath(realm.id)}?limit=100`,
      securityAdmin.token
    );
    expect(listed.json<{ items: SubscriptionBody[] }>().items.map((item) => item.id)).toEqual([
      own.id,
    ]);
    const underOwn = [
      await send('GET', ownPath, securityAdmin.token),
      await send('PATCH', ownPath, securityAdmin.token, JSON.stringify({ enabled: false }), {
        'content-type': MERGE_PATCH,
        'if-match': '"1"',
      }),
      await send('DELETE', ownPath, securityAdmin.token, undefined, { 'if-match': '"1"' }),
    ];
    expect(underOwn.map((response) => response.statusCode)).toEqual([404, 404, 404]);
    // Neither can a change be filed against it.
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/approvals`,
      securityAdmin.token,
      {
        operation: 'webhooks.update',
        params: { subscriptionId: elsewhere.id },
        body: { enabled: false },
        reason: 'The operator asked for it in ticket OPS-537.',
      }
    );
    expect(filed.statusCode, filed.body).toBe(404);
    // A rotation and a test, approved under its own realm, find nothing either.
    for (const [operation, suffix] of [
      ['webhooks.rotateSecret', 'rotate-secret'],
      ['webhooks.test', 'test'],
    ] as const) {
      const approvalId = await fileAndApprove(
        realm.id,
        securityAdmin,
        operation,
        { subscriptionId: elsewhere.id },
        {}
      );
      const response = await send(
        'POST',
        `${ownPath}/${suffix}`,
        securityAdmin.token,
        {},
        {
          'qauth-approval': approvalId,
        }
      );
      expect(response.statusCode, `${operation}: ${response.body}`).toBe(404);
    }

    // Under the other realm's path, the admin holds no grant: every route is 404.
    const otherPath = subscriptionPath(elsewhereRealm, elsewhere.id);
    const underOther = [
      await send('GET', subscriptionsPath(elsewhereRealm), securityAdmin.token),
      await send('GET', otherPath, securityAdmin.token),
      await send('PATCH', otherPath, securityAdmin.token, JSON.stringify({ enabled: false }), {
        'content-type': MERGE_PATCH,
        'if-match': '"1"',
      }),
      await send('POST', `${otherPath}/rotate-secret`, securityAdmin.token, {}),
      await send('POST', `${otherPath}/test`, securityAdmin.token, {}),
      await send('DELETE', otherPath, securityAdmin.token, undefined, { 'if-match': '"1"' }),
    ];
    expect(underOther.map((response) => response.statusCode)).toEqual([
      404, 404, 404, 404, 404, 404,
    ]);

    const untouched = await app().repositories.webhookSubscriptions.findById(
      elsewhereRealm,
      elsewhere.id
    );
    expect(untouched).toMatchObject({ version: 1, enabled: true });
    expect(Object.values(await keyStatuses(elsewhereRealm, elsewhere.id))).toEqual(['active']);
  });

  it('queues a test event for the subscription alone, then updates and deletes it, each once approved and audited with its diff', async () => {
    const realm = await defaultRealm();
    const securityAdmin = await adminWith('security-admin');
    const subscription = await created(realm.id, securityAdmin);
    const bystander = await created(realm.id, securityAdmin, {
      url: 'https://93.184.215.15/hooks/other',
      categories: ['user'],
    });
    const path = subscriptionPath(realm.id, subscription.id);
    const params = { subscriptionId: subscription.id };

    // The test event: queued for this subscription and no other.
    const testApproval = await fileAndApprove(realm.id, securityAdmin, 'webhooks.test', params, {});
    const tested = await send(
      'POST',
      `${path}/test`,
      securityAdmin.token,
      {},
      {
        'qauth-approval': testApproval,
      }
    );
    expect(tested.statusCode, tested.body).toBe(202);
    const { eventId } = tested.json<{ eventId: string }>();
    const { rows: events } = await app().dbPool.query<{
      type: string;
      subject_type: string;
      subject_id: string;
    }>(`SELECT type, subject_type, subject_id FROM events WHERE id = $1`, [eventId]);
    expect(events).toEqual([
      { type: WEBHOOK_TEST, subject_type: 'webhook_subscription', subject_id: subscription.id },
    ]);
    const { rows: deliveries } = await app().dbPool.query<{
      destination_kind: string;
      destination_id: string;
      status: string;
    }>(
      `SELECT destination_kind, destination_id, status FROM event_deliveries WHERE event_id = $1`,
      [eventId]
    );
    expect(deliveries).toEqual([
      { destination_kind: 'webhook', destination_id: subscription.id, status: 'pending' },
    ]);
    expect(deliveries.map((row) => row.destination_id)).not.toContain(bystander.id);

    // An update that would move it to a private address is refused at filing.
    const moved = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realm.id}/approvals`,
      securityAdmin.token,
      {
        operation: 'webhooks.update',
        params,
        body: { url: 'https://192.168.1.10/hook' },
        reason: 'The operator asked for it in ticket OPS-537.',
      }
    );
    expect(moved.statusCode, moved.body).toBe(422);
    expect(moved.json()).toMatchObject({
      errors: [expect.objectContaining({ pointer: '/url' })],
    });

    // An update: disabled, renamed, against the version its If-Match names.
    const etag = await etagOf(realm.id, subscription.id, securityAdmin);
    const change = { description: 'Paused for the CRM migration', enabled: false };
    const unapproved = await send('PATCH', path, securityAdmin.token, JSON.stringify(change), {
      'content-type': MERGE_PATCH,
      'if-match': etag,
    });
    expect(unapproved.statusCode).toBe(403);
    const noVersion = await send('PATCH', path, securityAdmin.token, JSON.stringify(change), {
      'content-type': MERGE_PATCH,
    });
    expect(noVersion.statusCode).toBe(428);
    const updateApproval = await fileAndApprove(
      realm.id,
      securityAdmin,
      'webhooks.update',
      params,
      change
    );
    const updated = await send('PATCH', path, securityAdmin.token, JSON.stringify(change), {
      'content-type': MERGE_PATCH,
      'if-match': etag,
      'qauth-approval': updateApproval,
    });
    expect(updated.statusCode, updated.body).toBe(200);
    expect(updated.headers['etag']).toBe('"2"');
    expect(updated.json()).toMatchObject({
      description: 'Paused for the CRM migration',
      enabled: false,
      disabledReason: 'disabled_by_admin',
      version: 2,
    });
    expect(updated.json()).not.toHaveProperty('secret');

    // A disabled subscription receives no test event.
    const pausedTest = await fileAndApprove(realm.id, securityAdmin, 'webhooks.test', params, {});
    const refusedTest = await send(
      'POST',
      `${path}/test`,
      securityAdmin.token,
      {},
      {
        'qauth-approval': pausedTest,
      }
    );
    expect(refusedTest.statusCode, refusedTest.body).toBe(409);

    // A deletion: the subscription and its secrets go.
    const deleteApproval = await fileAndApprove(realm.id, securityAdmin, 'webhooks.delete', params);
    const deleted = await send('DELETE', path, securityAdmin.token, undefined, {
      'if-match': '"2"',
      'qauth-approval': deleteApproval,
    });
    expect(deleted.statusCode, deleted.body).toBe(204);
    expect((await send('GET', path, securityAdmin.token)).statusCode).toBe(404);
    expect(await keyStatuses(realm.id, subscription.id)).toEqual({});
    expect(
      await app().repositories.webhookSubscriptions.findById(realm.id, bystander.id)
    ).toMatchObject({ version: 1 });

    // Each change has its audit row, with its diff.
    const applied = async (operationId: string) =>
      (await auditRows(realm.id, operationId)).filter((row) => row.outcome === 'succeeded');
    expect((await applied('webhooks.create')).map((row) => row.masked_diff)).toEqual([
      expect.objectContaining({ before: null, after: expect.objectContaining({ secret: '***' }) }),
      expect.objectContaining({ before: null, after: expect.objectContaining({ secret: '***' }) }),
    ]);
    expect((await applied('webhooks.test')).map((row) => row.masked_diff)).toEqual([
      expect.objectContaining({
        before: null,
        after: { subscription: subscription.id, event: eventId },
      }),
    ]);
    expect((await applied('webhooks.update')).map((row) => row.masked_diff)).toEqual([
      expect.objectContaining({
        before: expect.objectContaining({ description: null, enabled: true, version: 1 }),
        after: expect.objectContaining({
          description: 'Paused for the CRM migration',
          enabled: false,
          version: 2,
        }),
      }),
    ]);
    expect((await applied('webhooks.delete')).map((row) => row.masked_diff)).toEqual([
      expect.objectContaining({
        before: expect.objectContaining({ id: subscription.id, version: 2 }),
        after: null,
      }),
    ]);
    for (const operationId of ['webhooks.test', 'webhooks.update', 'webhooks.delete']) {
      const rows = await auditRows(realm.id, operationId);
      expect(
        rows.every((row) => row.operation_class === 'security'),
        operationId
      ).toBe(true);
    }
  });
});
