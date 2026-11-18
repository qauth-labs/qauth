import { randomUUID } from 'node:crypto';

import { REALM_POLICY_REGISTRY } from '@qauth-labs/fastify-plugin-realm-policy';
import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  provisionRealmKeys,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';

/**
 * THE DRY RUN OF A REALM-FILE IMPORT (#518, ADR-019 Decisions 7 and 11),
 * against a real Postgres and Redis: `POST /admin/v1-rc.0/realms/{realmId}/imports`
 * with `mode: "dry-run"` answers the import plan of a realm file, needs no
 * more than `qauth:admin:read`, and writes nothing but the audit row every
 * admin call leaves.
 *
 * The suite boots the real app with the admin listener and the server's own
 * operation registry, as `admin-realm-policy-preview.integration.test.ts`
 * does; each test acts on a realm of its own.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;

/** A client secret hash the tests store: it must never come back. */
const SECRET_HASH = `$argon2id$v=19$m=19456,t=2,p=1$${'c2FsdC1vZi10aGUtdGVzdA'}$never-planned-${randomUUID()}`;

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

type Document = Record<string, Record<string, unknown>>;

interface PlanBody {
  realmId: string;
  baseVersion: number;
  prune: boolean;
  digest: string;
  class: 'write' | 'security';
  effects: string[];
  permissions: string[];
  scopes: string[];
  approvalRequired: boolean;
  secretsToSet: string[];
  warnings: string[];
  changes: {
    section: string;
    key: string | null;
    path: string;
    op: 'create' | 'update' | 'delete';
    before: unknown;
    after: unknown;
    direction: 'tightening' | 'loosening' | 'neutral';
    class: 'write' | 'security';
    effects: string[];
    permissions: string[];
    needsSecret: boolean;
  }[];
}

interface AuditRow {
  operation_id: string;
  operation_class: string;
  effects: string[];
  outcome: string;
  masked_diff: unknown;
}

describe('the dry run of a realm-file import (#518, real containers)', () => {
  let booted: BootedAuthServer | undefined;

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
  });

  function app(): FastifyInstance {
    if (!booted) throw new Error('server not booted');
    return booted.app;
  }

  function admin(): FastifyInstance {
    if (!booted?.admin) throw new Error('admin listener not booted');
    return booted.admin;
  }

  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A realm of the test's own, with its keys. */
  async function tenant(name: string): Promise<{ id: string }> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return { id: realm.id };
  }

  /** An operator-realm viewer of `realmId` whose token holds only `qauth:admin:read`. */
  async function viewerOf(realmId: string): Promise<string> {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: 'viewer' },
      targetRealmId: realmId,
      createdBy: null,
    });
    return signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope: 'qauth:admin:read',
    });
  }

  /** A client of `realmId` as the seed manifest or the admin API stores it. */
  async function operatorClient(realmId: string, overrides: Record<string, unknown> = {}) {
    return app().repositories.oauthClients.create({
      realmId,
      clientId: 'portal',
      clientSecretHash: SECRET_HASH,
      name: 'Portal',
      redirectUris: ['https://portal.example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      scopes: ['openid', 'profile'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      provisionedByOperator: true,
      ...overrides,
    } as Parameters<FastifyInstance['repositories']['oauthClients']['create']>[0]);
  }

  const importsPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}/imports`;

  /** The dry run of `body`, with `token` under the `DPoP` scheme (#520). */
  async function plan(
    realmId: string,
    token: string,
    body: unknown
  ): Promise<LightMyRequestResponse> {
    const url = importsPath(realmId);
    return admin().inject({
      method: 'POST',
      url,
      headers: {
        ...(await adminCallHeaders(token, 'POST', url)),
        'content-type': 'application/json',
      },
      payload: JSON.stringify(body),
    });
  }

  /**
   * The realm's policies as `realms.get` answers them to `token`, as a realm
   * file's `policies`: the stored document, without the representation's
   * `<name>Set` flags, edited.
   */
  async function policiesOf(
    realmId: string,
    token: string,
    edit: (document: Document) => void = () => undefined
  ): Promise<Document> {
    const url = `/admin/v1-rc.0/realms/${realmId}`;
    const response = await admin().inject({
      method: 'GET',
      url,
      headers: await adminCallHeaders(token, 'GET', url),
    });
    expect(response.statusCode, response.body).toBe(200);
    const document = REALM_POLICY_REGISTRY.parse(
      response.json<{ policies: unknown }>().policies,
      'input'
    ) as unknown as Document;
    edit(document);
    return document;
  }

  /** Mail sent through an smtp server, as a file selects it: everything but the password. */
  const smtp = (realmId: string, token: string) =>
    policiesOf(realmId, token, (document) => {
      document['mail']['provider'] = 'smtp';
      document['mail']['fromAddress'] = 'no-reply@example.com';
      document['mail']['smtp'] = {
        ...(document['mail']['smtp'] as object),
        host: 'smtp.example.com',
        port: 587,
        user: 'mailer',
      };
    });

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, operation_class, effects, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  /** The text of every row of `table` that belongs to the realm. */
  async function rowsText(table: string, realmId: string): Promise<string> {
    const { rows } = await app().dbPool.query<{ row: string }>(
      `SELECT t::text AS row FROM ${table} t WHERE t.realm_id = $1 ORDER BY t::text`,
      [realmId]
    );
    return rows.map((row) => row.row).join('\n');
  }

  /** What an import would change of the realm: its row, its clients, approvals, events and secrets. */
  async function stored(realmId: string) {
    const { rows } = await app().dbPool.query<{ row: string }>(
      'SELECT r::text AS row FROM realms r WHERE r.id = $1',
      [realmId]
    );
    return {
      realm: rows.map((row) => row.row).join('\n'),
      clients: await rowsText('oauth_clients', realmId),
      approvals: await rowsText('admin_approvals', realmId),
      events: await rowsText('events', realmId),
      secrets: await rowsText('realm_secrets', realmId),
    };
  }

  // Acceptance criterion of #518: the secrets a file's choices need.
  it('names mail.smtp.password when the file selects smtp and no password is stored', async () => {
    const realm = await tenant('alpha');
    const token = await viewerOf(realm.id);

    const response = await plan(realm.id, token, {
      mode: 'dry-run',
      file: { realm: 'alpha', policies: await smtp(realm.id, token) },
    });
    expect(response.statusCode, response.body).toBe(200);
    const body = response.json<PlanBody>();
    expect(body.secretsToSet).toEqual(['mail.smtp.password']);
    // The harness's realms send mail with the mock transport: the file moves
    // them to smtp, which is the change that needs the password.
    const provider = body.changes.find((change) => change.path === 'mail.provider');
    expect(provider).toMatchObject({ before: 'mock', after: 'smtp', needsSecret: true });
    expect(response.body).not.toContain(SECRET_HASH);
  });

  // Acceptance criterion of #518: the dry run is a read.
  it('works with only qauth:admin:read and changes nothing', async () => {
    const realm = await tenant('beta');
    await operatorClient(realm.id);
    const token = await viewerOf(realm.id);
    const file = {
      realm: 'beta',
      policies: await policiesOf(realm.id, token, (document) => {
        document['password']['minScore'] = (document['password']['minScore'] as number) - 1;
      }),
      clients: [
        {
          client_id: 'portal',
          name: 'Customer portal',
          grant_types: ['authorization_code', 'refresh_token'],
          scopes: ['openid', 'profile', 'email'],
          redirect_uris: ['https://portal.example.com/callback'],
        },
        {
          client_id: 'reports',
          name: 'Reports',
          grant_types: ['client_credentials'],
          token_endpoint_auth_method: 'private_key_jwt',
          jwks_uri: 'https://reports.example.com/jwks.json',
        },
      ],
    };
    const before = await stored(realm.id);
    const auditBefore = (await auditRows(realm.id)).length;

    const response = await plan(realm.id, token, { mode: 'dry-run', file });
    expect(response.statusCode, response.body).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    const body = response.json<PlanBody>();
    expect(body).toMatchObject({
      realmId: realm.id,
      prune: false,
      class: 'security',
      approvalRequired: true,
      warnings: [],
    });
    expect(body.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const clientChanges = body.changes
      .filter((change) => change.section === 'clients')
      .map(({ key, path, op, direction, class: changeClass }) => ({
        key,
        path,
        op,
        direction,
        class: changeClass,
      }));
    expect(clientChanges).toEqual([
      { key: 'portal', path: 'name', op: 'update', direction: 'neutral', class: 'write' },
      { key: 'portal', path: 'scopes', op: 'update', direction: 'loosening', class: 'security' },
      { key: 'reports', path: '', op: 'create', direction: 'loosening', class: 'security' },
    ]);
    expect(body.changes.find((change) => change.path === 'password.minScore')).toMatchObject({
      direction: 'loosening',
      class: 'security',
    });
    expect(response.body).not.toContain(SECRET_HASH);

    // The same file, planned again, gives the same digest; nothing was applied.
    const again = await plan(realm.id, token, { mode: 'dry-run', file });
    expect(again.json<PlanBody>().digest).toBe(body.digest);
    expect(await stored(realm.id)).toEqual(before);
    expect((await auditRows(realm.id)).slice(auditBefore)).toEqual(
      [1, 2].map(() => ({
        operation_id: 'realms.imports.plan',
        operation_class: 'read',
        effects: [],
        outcome: 'succeeded',
        masked_diff: null,
      }))
    );
  });

  it('deletes a client the file leaves out only when the import prunes', async () => {
    const realm = await tenant('gamma');
    await operatorClient(realm.id);
    const token = await viewerOf(realm.id);
    const file = { realm: 'gamma', clients: [] };

    const kept = await plan(realm.id, token, { mode: 'dry-run', file });
    expect(kept.statusCode, kept.body).toBe(200);
    expect(kept.json<PlanBody>().changes).toEqual([]);

    const pruned = await plan(realm.id, token, { mode: 'dry-run', file, prune: true });
    expect(pruned.statusCode, pruned.body).toBe(200);
    expect(pruned.json<PlanBody>().changes.map(({ key, op }) => ({ key, op }))).toEqual([
      { key: 'portal', op: 'delete' },
    ]);
    expect(pruned.json<PlanBody>().digest).not.toBe(kept.json<PlanBody>().digest);
  });

  it('refuses another mode, a file the format refuses, and a client no realm file manages', async () => {
    const realm = await tenant('delta');
    // A developer is an account of the realm.
    const developerId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await operatorClient(realm.id, {
      clientId: 'owned',
      provisionedByOperator: false,
      developerId,
    });
    const token = await viewerOf(realm.id);
    const before = await stored(realm.id);

    const apply = await plan(realm.id, token, { mode: 'apply', file: { realm: 'delta' } });
    expect(apply.statusCode, apply.body).toBe(400);

    const invalid = await plan(realm.id, token, {
      mode: 'dry-run',
      file: { realm: 'delta', clients: [{ client_id: 'x', name: 'X', grant_types: ['password'] }] },
    });
    expect(invalid.statusCode, invalid.body).toBe(422);
    expect(JSON.stringify(invalid.json())).toContain('/file/clients/0/grant_types');

    const owned = await plan(realm.id, token, {
      mode: 'dry-run',
      file: {
        realm: 'delta',
        clients: [{ client_id: 'owned', name: 'Owned', grant_types: ['client_credentials'] }],
      },
    });
    expect(owned.statusCode, owned.body).toBe(422);
    expect(JSON.stringify(owned.json())).toContain('/file/clients/0/client_id');

    const unplanned = await plan(realm.id, token, {
      mode: 'dry-run',
      file: {
        realm: 'delta',
        system_client: { redirect_uris: ['https://portal.example.com/callback'] },
      },
    });
    expect(unplanned.statusCode, unplanned.body).toBe(422);

    expect(await stored(realm.id)).toEqual(before);
  });
});
