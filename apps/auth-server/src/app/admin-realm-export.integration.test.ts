import { randomUUID } from 'node:crypto';

import { parseRealmFile, safeParseRealmFile } from '@qauth-labs/realm-file';
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
 * THE EXPORT OF A REALM AS A REALM FILE (#530, ADR-018 §5, ADR-019 Decision
 * 11), against a real Postgres and Redis: `GET /admin/v1-rc.0/realms/{realmId}/realm-file`
 * answers the realm's configuration as a realm file, byte for byte the same
 * for the same state, holding no secret, with only the clients the operator
 * manages; a token with `qauth:admin:read` alone exports, one for another
 * realm gets 404, and each export leaves one audit row. The file imports
 * back into the realm with no change.
 *
 * The suite boots the real app with the admin listener and the server's own
 * operation registry, as `admin-realm-import-plan.integration.test.ts`
 * does; each test acts on a realm of its own.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;

/** A client secret hash the tests store: it must never come back. */
const SECRET_HASH = `$argon2id$v=19$m=19456,t=2,p=1$${'c2FsdC1vZi10aGUtdGVzdA'}$never-exported-${randomUUID()}`;

/** The SMTP password a test sets on its realm: it must never come back. */
const SMTP_PASSWORD = `smtp-password-${randomUUID()}`;

/** A public Ed25519 key, as a private_key_jwt client registers it. */
const PUBLIC_JWK = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
  kid: 'reports-1',
};

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
  operation_id: string;
  operation_class: string;
  effects: string[];
  outcome: string;
  masked_diff: unknown;
}

type ExportedFile = {
  format: string;
  realm: string;
  policies: Record<string, Record<string, unknown>>;
  clients: Record<string, unknown>[];
};

describe('the export of a realm as a realm file (#530, real containers)', () => {
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
      grantTypes: ['refresh_token', 'authorization_code'],
      responseTypes: ['code'],
      scopes: ['profile', 'openid'],
      tokenEndpointAuthMethod: 'client_secret_basic',
      provisionedByOperator: true,
      ...overrides,
    } as Parameters<FastifyInstance['repositories']['oauthClients']['create']>[0]);
  }

  /** A client that authenticates with its public key; its stored hash is never shown either. */
  const reportsClient = (realmId: string) =>
    operatorClient(realmId, {
      clientId: 'reports',
      name: 'Reports',
      redirectUris: [],
      grantTypes: ['client_credentials'],
      responseTypes: [],
      scopes: ['reports:read'],
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: { keys: [PUBLIC_JWK] },
      environment: 'staging',
    });

  const exportPath = (realmId: string) => `/admin/v1-rc.0/realms/${realmId}/realm-file`;

  /** The export of `realmId`, with `token` under the `DPoP` scheme (#520). */
  async function exportRealm(realmId: string, token: string): Promise<LightMyRequestResponse> {
    const url = exportPath(realmId);
    return admin().inject({
      method: 'GET',
      url,
      headers: await adminCallHeaders(token, 'GET', url),
    });
  }

  async function auditRows(realmId: string): Promise<AuditRow[]> {
    const { rows } = await app().dbPool.query<AuditRow>(
      `SELECT operation_id, operation_class, effects, outcome, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 ORDER BY seq`,
      [realmId]
    );
    return rows;
  }

  const EXPORT_AUDIT_ROW: AuditRow = {
    operation_id: 'realms.export',
    operation_class: 'read',
    effects: [],
    outcome: 'succeeded',
    masked_diff: null,
  };

  // Acceptance criteria of #530: the same bytes twice, a valid file, a read
  // token is enough, one audit row per export.
  it('exports the same state as the same bytes, a valid file, with qauth:admin:read alone', async () => {
    const realm = await tenant('alpha');
    await operatorClient(realm.id);
    await reportsClient(realm.id);
    const token = await viewerOf(realm.id);
    const auditBefore = (await auditRows(realm.id)).length;

    const first = await exportRealm(realm.id, token);
    expect(first.statusCode, first.body).toBe(200);
    expect(first.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(first.headers['content-disposition']).toBe('attachment; filename="alpha.realm.json"');
    expect(first.headers['cache-control']).toBe('no-store');
    // One export, one audit row, recording a read and no change.
    expect((await auditRows(realm.id)).slice(auditBefore)).toEqual([EXPORT_AUDIT_ROW]);

    const second = await exportRealm(realm.id, token);
    expect(second.statusCode, second.body).toBe(200);
    expect(second.rawPayload.equals(first.rawPayload)).toBe(true);
    expect((await auditRows(realm.id)).slice(auditBefore)).toEqual([
      EXPORT_AUDIT_ROW,
      EXPORT_AUDIT_ROW,
    ]);

    const parsed = safeParseRealmFile(JSON.parse(first.body));
    expect(parsed.success, JSON.stringify(parsed)).toBe(true);
    const file = first.json<ExportedFile>();
    expect(Object.keys(file)).toEqual(['format', 'realm', 'policies', 'clients']);
    expect(file).toMatchObject({ format: 'urn:qauth:realm-file:v1-rc.0', realm: 'alpha' });
    expect(file.clients.map((entry) => entry['client_id'])).toEqual(['portal', 'reports']);
    expect(file.clients[0]).toMatchObject({
      grant_types: ['authorization_code', 'refresh_token'],
      scopes: ['openid', 'profile'],
      token_endpoint_auth_method: 'client_secret_basic',
    });
    // The public key set stays, and so does the environment the client runs in.
    expect(file.clients[1]).toMatchObject({ jwks: { keys: [PUBLIC_JWK] }, environment: 'staging' });
    expect(first.body).not.toContain(SECRET_HASH);
    expect(first.body).not.toMatch(/client_secret"|secret_hash|clientSecretHash/);
  });

  // Acceptance criterion of #530: no secret value.
  it('exports a realm whose SMTP password is set without any secret value', async () => {
    const realm = await tenant('beta');
    const current = await app().policyStore.get(realm.id);
    await app().policyStore.update(
      realm.id,
      {
        mail: {
          provider: 'smtp',
          smtp: {
            host: 'smtp.example.com',
            port: 587,
            secure: false,
            user: 'mailer-beta',
            password: SMTP_PASSWORD,
          },
        },
      },
      { expectedVersion: current?.version ?? 0 }
    );
    expect(await app().realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(true);
    const token = await viewerOf(realm.id);

    const response = await exportRealm(realm.id, token);
    expect(response.statusCode, response.body).toBe(200);
    expect(response.body).not.toContain(SMTP_PASSWORD);
    expect(response.body).not.toMatch(/passwordSet|apiKey/);
    const smtp = response.json<ExportedFile>().policies['mail']['smtp'] as Record<string, unknown>;
    expect(smtp).toMatchObject({ host: 'smtp.example.com', port: 587, user: 'mailer-beta' });
    expect(Object.keys(smtp)).not.toContain('password');
    expect(response.json<ExportedFile>().policies['mail']['provider']).toBe('smtp');
    const rows = await auditRows(realm.id);
    expect(JSON.stringify(rows)).not.toContain(SMTP_PASSWORD);
  });

  // Acceptance criterion of #530: only the clients the operator manages.
  it('leaves out clients a developer owns and clients that registered themselves', async () => {
    const realm = await tenant('gamma');
    await operatorClient(realm.id);
    const developerId = (
      await app().repositories.users.create({ realmId: realm.id }, testPrimaryCredential())
    ).id;
    await operatorClient(realm.id, {
      clientId: 'owned',
      name: 'Owned',
      provisionedByOperator: false,
      developerId,
    });
    await operatorClient(realm.id, {
      clientId: 'registered',
      name: 'Registered',
      provisionedByOperator: false,
      dynamicRegisteredAt: Date.now(),
    });
    const token = await viewerOf(realm.id);

    const response = await exportRealm(realm.id, token);
    expect(response.statusCode, response.body).toBe(200);
    const file = response.json<ExportedFile>();
    expect(file.clients.map((entry) => entry['client_id'])).toEqual(['portal']);
    expect(response.body).not.toMatch(/"owned"|"registered"|developer_id|dynamic_registered_at/);
  });

  // Acceptance criterion of #530: another realm's token gets 404.
  it("answers 404 to a token for another realm, and shows nothing of the realm's file", async () => {
    const realm = await tenant('delta');
    const other = await tenant('epsilon');
    await operatorClient(realm.id);
    const otherToken = await viewerOf(other.id);

    const response = await exportRealm(realm.id, otherToken);
    expect(response.statusCode, response.body).toBe(404);
    expect(response.headers['content-disposition']).toBeUndefined();
    expect(response.body).not.toContain('portal');
  });

  it('imports back into the realm with no change, prune included', async () => {
    const realm = await tenant('zeta');
    await operatorClient(realm.id);
    await reportsClient(realm.id);
    const current = await app().policyStore.get(realm.id);
    await app().policyStore.update(
      realm.id,
      { password: { minScore: 4 }, tokens: { accessTokenLifespanSeconds: 600 } },
      { expectedVersion: current?.version ?? 0 }
    );
    const token = await viewerOf(realm.id);

    const exported = await exportRealm(realm.id, token);
    expect(exported.statusCode, exported.body).toBe(200);
    const file = parseRealmFile(JSON.parse(exported.body));
    expect(file.policies?.['password']).toMatchObject({ minScore: 4 });

    const url = `/admin/v1-rc.0/realms/${realm.id}/imports`;
    const plan = await admin().inject({
      method: 'POST',
      url,
      headers: {
        ...(await adminCallHeaders(token, 'POST', url)),
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ mode: 'dry-run', prune: true, file: JSON.parse(exported.body) }),
    });
    expect(plan.statusCode, plan.body).toBe(200);
    expect(plan.json<{ changes: unknown[]; secretsToSet: string[] }>()).toMatchObject({
      changes: [],
      secretsToSet: [],
    });
  });
});
