import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE FIRST-PARTY PROFILE IS OPERATOR-SET, AND THE PROVISIONED SYSTEM CLIENT
 * STILL ISSUES MANAGEMENT TOKENS (ADR-017 Decision 2 and phase F0, #631).
 *
 * - Dynamic registration and the developer API write no first-party profile,
 *   policy or reason, whatever the request says, and the database refuses one
 *   on the rows they create.
 * - The operator provisions the system client through the seed manifest's
 *   `system_client` section (the script itself, run as an operator runs it):
 *   it becomes a `private_key_jwt` client with the `web_redirect` profile and
 *   the portal's callback, in place, and the portal's management tokens from
 *   it, minted before or after, still pass `assertManagementToken`.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const DB_LIB = path.resolve(process.cwd(), 'libs/infra/db');
const TSX_CLI = createRequire(path.join(DB_LIB, 'package.json')).resolve('tsx/cli');

const PORTAL_CALLBACK = 'https://portal.example.com/auth/callback';
const PORTAL_JWKS = {
  keys: [{ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }],
};

/** What a request might try to set: every spelling of the three fields. */
const FLAGGING_MEMBERS = {
  firstPartyProfile: 'web_redirect',
  firstPartyPolicy: { flows: ['login', 'register'], pkce_required: false },
  firstPartyReason: 'trust me',
  first_party_profile: 'native_backend',
  first_party_policy: { flows: ['login'] },
  first_party_reason: 'trust me',
};

interface FirstPartyRow {
  first_party_profile: string | null;
  first_party_policy: unknown;
  first_party_reason: string | null;
}

describe('first-party profile write paths and the provisioned system client (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let booted: BootedAuthServer | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    booted = await bootAuthServer({
      ...baseEnvironment(infra, jwt),
      // Several accounts register and sign in from one address.
      REGISTRATION_RATE_LIMIT: '100',
      LOGIN_RATE_LIMIT: '100',
    });
  }, 240_000);

  afterAll(async () => {
    await booted?.close();
    await infra?.teardown();
    delete process.env['REGISTRATION_RATE_LIMIT'];
    delete process.env['LOGIN_RATE_LIMIT'];
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

  async function firstPartyColumns(clientId: string): Promise<FirstPartyRow | undefined> {
    const { rows } = await app().dbPool.query<FirstPartyRow>(
      `SELECT first_party_profile, first_party_policy, first_party_reason
         FROM oauth_clients WHERE client_id = $1`,
      [clientId]
    );
    return rows[0];
  }

  /** Try to flag a client by hand, as if a write path had let a profile through. */
  async function flagByHand(clientId: string): Promise<{ code?: string; constraint?: string }> {
    return app()
      .dbPool.query(
        `UPDATE oauth_clients
            SET first_party_profile = 'web_redirect', first_party_reason = 'Ours.',
                token_endpoint_auth_method = 'private_key_jwt'
          WHERE client_id = $1`,
        [clientId]
      )
      .then(
        () => ({}),
        (error: { code?: string; constraint?: string }) => error
      );
  }

  /** The developer-portal token `/auth/login` gives a new, verified account. */
  async function managementToken(email: string): Promise<string> {
    await registerPasswordAccount(app(), email);
    return signIn(email);
  }

  async function signIn(email: string): Promise<string> {
    const login = await app().inject({
      method: 'POST',
      url: '/auth/login',
      payload: { email, password: E2E_PASSWORD },
    });
    expect(login.statusCode, login.body).toBe(200);
    return login.json<{ access_token: string }>().access_token;
  }

  function listClients(token: string) {
    return app().inject({
      method: 'GET',
      url: '/api/clients',
      headers: { authorization: `Bearer ${token}` },
    });
  }

  /** Run the seed script as an operator runs it, against the suite's database. */
  async function runSeed(
    manifest: Record<string, unknown>
  ): Promise<{ code: number | null; stdout: string; stderr: string }> {
    if (!infra) throw new Error('infrastructure not started');
    const dir = mkdtempSync(path.join(tmpdir(), 'qauth-seed-'));
    const file = path.join(dir, 'manifest.json');
    writeFileSync(file, JSON.stringify(manifest));
    try {
      const child = spawn(
        process.execPath,
        [TSX_CLI, 'src/scripts/seed-oauth-clients.ts', `--manifest=${file}`],
        {
          cwd: DB_LIB,
          env: {
            PATH: process.env['PATH'] ?? '',
            DATABASE_URL: infra.postgres.connectionString,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
      child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString('utf8')));
      const code = await new Promise<number | null>((resolve, reject) => {
        child.on('error', reject);
        child.on('close', resolve);
      });
      return { code, stdout, stderr };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('dynamic registration writes no first-party profile, and the database refuses one on its row', async () => {
    const registered = await app().inject({
      method: 'POST',
      url: '/oauth/register',
      payload: {
        client_name: 'Claims to be ours',
        redirect_uris: ['https://app.example.com/callback'],
        ...FLAGGING_MEMBERS,
      },
    });
    expect(registered.statusCode, registered.body).toBe(201);
    const clientId = registered.json<{ client_id: string }>().client_id;

    expect(await firstPartyColumns(clientId)).toEqual({
      first_party_profile: null,
      first_party_policy: null,
      first_party_reason: null,
    });
    expect(await flagByHand(clientId)).toMatchObject({
      code: '23514',
      constraint: 'oauth_clients_first_party_operator_only',
    });
  });

  it('the developer API cannot set the fields, on create or on update', async () => {
    const token = await managementToken('developer@example.test');

    const created = await app().inject({
      method: 'POST',
      url: '/api/clients',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        name: 'Ours, honestly',
        redirectUris: ['https://app.example.com/callback'],
        ...FLAGGING_MEMBERS,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    const { id, clientId } = created.json<{ id: string; clientId: string }>();
    const unflagged = {
      first_party_profile: null,
      first_party_policy: null,
      first_party_reason: null,
    };
    expect(await firstPartyColumns(clientId)).toEqual(unflagged);

    const renamed = await app().inject({
      method: 'PATCH',
      url: `/api/clients/${id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: { name: 'Renamed', ...FLAGGING_MEMBERS },
    });
    expect(renamed.statusCode, renamed.body).toBe(200);
    expect(await firstPartyColumns(clientId)).toEqual(unflagged);

    // A body with nothing the API may write is no update at all.
    const onlyFlags = await app().inject({
      method: 'PATCH',
      url: `/api/clients/${id}`,
      headers: { authorization: `Bearer ${token}` },
      payload: FLAGGING_MEMBERS,
    });
    expect(onlyFlags.statusCode, onlyFlags.body).toBe(400);
    expect(await firstPartyColumns(clientId)).toEqual(unflagged);

    // And the database refuses a profile on a developer's row, whatever path
    // tried to write it.
    expect(await flagByHand(clientId)).toMatchObject({
      code: '23514',
      constraint: 'oauth_clients_first_party_operator_only',
    });
  });

  it('a sign-in before provisioning creates a placeholder that holds no secret and no profile', async () => {
    await managementToken('early@example.test');

    const { rows } = await app().dbPool.query<{
      token_endpoint_auth_method: string;
      jwks: unknown;
      jwks_uri: string | null;
      first_party_profile: string | null;
      redirect_uris: string[];
    }>(
      `SELECT token_endpoint_auth_method, jwks, jwks_uri, first_party_profile, redirect_uris
         FROM oauth_clients WHERE client_id = 'system'`
    );
    expect(rows).toEqual([
      {
        token_endpoint_auth_method: 'private_key_jwt',
        jwks: null,
        jwks_uri: null,
        first_party_profile: null,
        redirect_uris: [],
      },
    ]);
  });

  it('after provisioning, the system client is private_key_jwt and web_redirect, and its management tokens pass', async () => {
    // A token minted before provisioning, under the placeholder row.
    const before = await managementToken('portal-user@example.test');
    const {
      rows: [placeholder],
    } = await app().dbPool.query<{ id: string }>(
      `SELECT id FROM oauth_clients WHERE client_id = 'system'`
    );

    const seeded = await runSeed({
      realm: E2E_REALM_NAME,
      system_client: { redirect_uris: [PORTAL_CALLBACK], jwks: PORTAL_JWKS },
    });
    expect(seeded.code, `${seeded.stdout}\n${seeded.stderr}`).toBe(0);
    expect(seeded.stdout).toContain(
      `Re-provisioned the system client "system" in realm "${E2E_REALM_NAME}"`
    );

    const { rows } = await app().dbPool.query<{
      id: string;
      token_endpoint_auth_method: string;
      first_party_profile: string | null;
      first_party_policy: unknown;
      redirect_uris: string[];
      grant_types: string[];
      jwks: unknown;
    }>(
      `SELECT id, token_endpoint_auth_method, first_party_profile, first_party_policy,
              redirect_uris, grant_types, jwks
         FROM oauth_clients WHERE client_id = 'system'`
    );
    expect(rows).toEqual([
      {
        id: placeholder.id,
        token_endpoint_auth_method: 'private_key_jwt',
        first_party_profile: 'web_redirect',
        first_party_policy: null,
        redirect_uris: [PORTAL_CALLBACK],
        grant_types: ['authorization_code', 'refresh_token'],
        jwks: PORTAL_JWKS,
      },
    ]);

    // assertManagementToken pins the same row: the token minted before
    // provisioning and one minted after both reach the management API.
    const beforeList = await listClients(before);
    expect(beforeList.statusCode, beforeList.body).toBe(200);
    const after = await signIn('portal-user@example.test');
    const afterList = await listClients(after);
    expect(afterList.statusCode, afterList.body).toBe(200);

    // The change is recorded, by the operator's tool.
    const { rows: recorded } = await app().dbPool.query<{ actor_type: string; data: unknown }>(
      `SELECT actor_type, data FROM events
        WHERE type = 'urn:qauth:event:client.first_party_changed:v1-rc.0'`
    );
    expect(recorded).toEqual([
      {
        actor_type: 'operator_cli',
        data: expect.objectContaining({ from: null, to: 'web_redirect', revokedTokenCount: 0 }),
      },
    ]);
  }, 120_000);

  it('a system client provisioned before any sign-in issues management tokens too', async () => {
    const seeded = await runSeed({
      realm: E2E_REALM_NAME,
      system_client: { redirect_uris: [PORTAL_CALLBACK], jwks: PORTAL_JWKS },
    });
    expect(seeded.code, `${seeded.stdout}\n${seeded.stderr}`).toBe(0);
    expect(seeded.stdout).toContain(
      `Provisioned the system client "system" in realm "${E2E_REALM_NAME}"`
    );

    const token = await managementToken('first-user@example.test');
    const listed = await listClients(token);
    expect(listed.statusCode, listed.body).toBe(200);

    const { rows } = await app().dbPool.query<{ count: string; profile: string }>(
      `SELECT count(*) OVER () AS count, first_party_profile AS profile
         FROM oauth_clients WHERE client_id = 'system'`
    );
    expect(rows).toEqual([{ count: '1', profile: 'web_redirect' }]);
  }, 120_000);
});
