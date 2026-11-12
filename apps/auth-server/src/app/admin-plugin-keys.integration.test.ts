import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  verify,
} from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ADMIN_LISTENER_ENVIRONMENT,
  adminCallHeaders,
  signBoundAccessToken,
} from '../testing/admin-dpop';
import type { TestApprovalFactor } from '../testing/approval-factor';
import { fixturePluginImporter } from '../testing/auth-method-plugins';
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
import {
  SIGNED_SECRET_PRESET_ID,
  SIGNED_SECRET_PRESET_ISSUER,
  SIGNED_SECRET_PRESET_PACKAGE,
  SIGNED_SECRET_PRESET_TYPE,
  signedSecretPresetPackage,
} from '../testing/signed-secret-preset';
import { API_FAMILY_AUDIENCES } from './api-conventions/families';
import { ADMIN_SCOPE_LIST } from './helpers/admin-scopes';

/**
 * A PROVIDER-ISSUED CLIENT-ASSERTION KEY THROUGH THE ADMIN API (#1073,
 * ADR-019 Decisions 9 and 12), against a real Postgres and Redis.
 *
 * The suite boots the real app with the admin listener and one preset plugin
 * whose client authenticates with a client secret the signer role signs, as
 * Sign in with Apple's does: a Services ID as its client id and a Team ID as
 * the signed secret's issuer. An operator configures and enables it, imports
 * the provider's ES256 key under the provider's key id
 * (`plugins.keys.import`), and switches to a second one
 * (`plugins.keys.activate`). The signer then signs the plugin's client
 * assertions with the imported key, reading the client from the realm's
 * stored record of the plugin.
 *
 * Every line the server logs is kept, at `debug`, so the suite can check
 * that none holds the private key, as no response, audit row or event does.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ADMIN = API_FAMILY_AUDIENCES.admin;
const ALL_ADMIN_SCOPES = ADMIN_SCOPE_LIST.join(' ');
const PLUGIN = SIGNED_SECRET_PRESET_ID;
const SERVICES_ID = 'com.example.signin';
const TEAM_ID = 'TEAM123456';

/** A private key as Apple issues one: P-256, PKCS#8 PEM. */
function ecKey(): { pem: string; publicKey: KeyObject } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  return { pem, publicKey: createPublicKey(createPrivateKey(pem)) };
}

/** The base64 body of a PEM: what would show if any part of the key leaked. */
function pemBody(pem: string): string[] {
  return pem
    .split('\n')
    .filter((line) => line.length > 0 && !line.startsWith('-----'))
    .map((line) => line.slice(0, 40));
}

/** The header and payload of a compact JWS, and whether `publicKey` verifies it. */
function readAssertion(jws: string, publicKey: KeyObject) {
  const [header, payload, signature] = jws.split('.');
  return {
    header: JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >,
    payload: JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >,
    verifiedBy: (key: KeyObject) =>
      verify(
        'sha256',
        Buffer.from(`${header}.${payload}`),
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signature, 'base64url')
      ),
    verified: verify(
      'sha256',
      Buffer.from(`${header}.${payload}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url')
    ),
  };
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

describe("a provider plugin's client-assertion key through the admin API (#1073, real containers)", () => {
  let booted: BootedAuthServer | undefined;
  let test: TestApprovalFactor;
  const logLines: string[] = [];

  beforeAll(async () => {
    if (!dockerUp || !infra || !jwt) return;
    booted = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        ...ADMIN_LISTENER_ENVIRONMENT,
        AUTH_METHOD_PLUGINS: SIGNED_SECRET_PRESET_PACKAGE,
      },
      {
        // The server's own operation registry and admin routes.
        adminListener: async () => ({}),
        authMethodPlugins: {
          importPackage: fixturePluginImporter({
            [SIGNED_SECRET_PRESET_PACKAGE]: signedSecretPresetPackage(),
          }),
          firstParty: [SIGNED_SECRET_PRESET_PACKAGE],
        },
        logStream: { write: (line: string) => logLines.push(line) },
        logLevel: 'debug',
      }
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

  async function operatorRealm(): Promise<{ id: string; issuer: string }> {
    const realm = await app().repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm?.issuer) throw new Error('default realm missing');
    return { id: realm.id, issuer: realm.issuer };
  }

  /** A realm of the test's own, with its keys. */
  async function ownRealm(name: string): Promise<{ id: string }> {
    const host = `${name}.example.com`;
    const { realm } = await app().repositories.realms.createWithPrimaryHost(
      { name, issuer: `https://${host}`, enabled: true },
      host
    );
    await provisionRealmKeys(app(), name);
    return { id: realm.id };
  }

  /** An operator-realm admin of `realmId` with `role` and `scope`: its token and its account as an approver. */
  async function adminOf(
    realmId: string,
    role: 'editor' | 'security-admin' = 'security-admin',
    scope = ALL_ADMIN_SCOPES
  ) {
    const operator = await operatorRealm();
    const userId = (
      await app().repositories.users.create({ realmId: operator.id }, testPrimaryCredential())
    ).id;
    await app().repositories.adminGrants.create({
      userId,
      role: { kind: 'built-in', name: role },
      targetRealmId: realmId,
      createdBy: null,
    });
    const token = await signBoundAccessToken(app(), operator, {
      sub: userId,
      clientId: 'admin-console',
      aud: ADMIN,
      scope,
    });
    return { token, approver: { realmId: operator.id, accountId: userId } };
  }

  type Requester = Awaited<ReturnType<typeof adminOf>>;

  const pluginPath = (realmId: string, suffix: string) =>
    `/admin/v1-rc.0/realms/${realmId}/plugins/${PLUGIN}${suffix}`;

  /** A call with `token` under the `DPoP` scheme and a fresh proof of its key (#520). */
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

  type Operation =
    | 'plugins.update'
    | 'plugins.enable'
    | 'plugins.keys.import'
    | 'plugins.keys.activate';

  /** File an approval for one request of a plugin operation and approve it with the test factor. */
  async function fileAndApprove(
    realmId: string,
    requester: Requester,
    operation: Operation,
    body: unknown
  ): Promise<string> {
    const filed = await send(
      'POST',
      `/admin/v1-rc.0/realms/${realmId}/approvals`,
      requester.token,
      {
        operation,
        params: { plugin: PLUGIN },
        body,
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

  /** Send an approved plugin operation and answer its response, whatever its status. */
  async function sendApproved(
    realmId: string,
    requester: Requester,
    operation: Operation,
    suffix: string,
    body: unknown
  ): Promise<{ response: LightMyRequestResponse; approvalId: string }> {
    const approvalId = await fileAndApprove(realmId, requester, operation, body);
    const response = await send('POST', pluginPath(realmId, suffix), requester.token, body, {
      'qauth-approval': approvalId,
    });
    return { response, approvalId };
  }

  /** Configure the preset as an Apple-like client and enable it in the realm. */
  async function configured(realmId: string, requester: Requester): Promise<void> {
    const configure = await sendApproved(realmId, requester, 'plugins.update', '/config', {
      version: 0,
      config: { servicesId: SERVICES_ID, teamId: TEAM_ID },
    });
    expect(configure.response.statusCode, configure.response.body).toBe(200);
    const enable = await sendApproved(realmId, requester, 'plugins.enable', '/enable', {
      version: 1,
    });
    expect(enable.response.statusCode, enable.response.body).toBe(200);
  }

  /** Seal `pem` for the import's private key in the realm (`secrets.seal`, #984). */
  async function seal(
    realmId: string,
    token: string,
    pem: string
  ): Promise<LightMyRequestResponse> {
    return send('POST', `/admin/v1-rc.0/realms/${realmId}/secrets/seal`, token, {
      operation: 'plugins.keys.import',
      member: '/privateKey',
      params: { plugin: PLUGIN },
      value: pem,
    });
  }

  /** Import `pem` under `kid`, sealed and approved. */
  async function importKey(realmId: string, requester: Requester, kid: string, pem: string) {
    const sealed = await seal(realmId, requester.token, pem);
    expect(sealed.statusCode, sealed.body).toBe(200);
    const body = { kid, privateKey: { sealed: sealed.json<{ sealed: string }>().sealed } };
    const approved = await sendApproved(realmId, requester, 'plugins.keys.import', '/keys', body);
    return { ...approved, sealed, body };
  }

  /** A client assertion the signer signs for the preset in the realm, as the plugin's token request asks. */
  async function signAssertion(realmId: string): Promise<string> {
    return app().signer.signClientAssertion('api', {
      realmId,
      providerId: SIGNED_SECRET_PRESET_TYPE,
      audience: SIGNED_SECRET_PRESET_ISSUER,
      algorithm: 'ES256',
      claims: { exp: Math.floor(Date.now() / 1000) + 300, jti: `jti-${Date.now()}` },
    });
  }

  async function assertionKeys(realmId: string) {
    const { rows } = await app().dbPool.query<{ kid: string; status: string; algorithm: string }>(
      `SELECT kid, status, algorithm FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'upstream_client_assertion' AND scope_id = $2
        ORDER BY created_at, kid`,
      [realmId, SIGNED_SECRET_PRESET_TYPE]
    );
    return rows;
  }

  // Acceptance criteria: an imported ES256 key signs a client assertion
  // that verifies with its public key, with the provider's kid, iss the
  // assertion issuer and sub the client id; and no response, event, log
  // line or diff carries the private key.
  it('signs with the imported key as the provider names it, and never shows the key', async () => {
    const realm = await ownRealm('keys-import');
    const requester = await adminOf(realm.id);
    await configured(realm.id, requester);
    // The client record the signer reads, stored beside the configuration.
    expect(await app().repositories.realmAuthMethodPlugins.find(realm.id, PLUGIN)).toMatchObject({
      enabled: true,
      assertionClientId: SERVICES_ID,
      assertionIssuer: TEAM_ID,
      assertionAlgorithm: 'ES256',
    });

    const key = ecKey();
    const imported = await importKey(realm.id, requester, 'APPLEKEY01', key.pem);
    expect(imported.response.statusCode, imported.response.body).toBe(200);
    expect(imported.response.json()).toEqual({
      kid: 'APPLEKEY01',
      algorithm: 'ES256',
      status: 'active',
    });
    expect(await assertionKeys(realm.id)).toEqual([
      { kid: 'APPLEKEY01', status: 'active', algorithm: 'ES256' },
    ]);

    const assertion = readAssertion(await signAssertion(realm.id), key.publicKey);
    expect(assertion.verified).toBe(true);
    expect(assertion.header).toMatchObject({ alg: 'ES256', kid: 'APPLEKEY01' });
    expect(assertion.payload).toMatchObject({
      iss: TEAM_ID,
      sub: SERVICES_ID,
      aud: SIGNED_SECRET_PRESET_ISSUER,
    });

    // What the approver was shown: the key id, never the key.
    const shown = await send(
      'GET',
      `/admin/v1-rc.0/realms/${realm.id}/approvals/${imported.approvalId}`,
      requester.token
    );
    expect(shown.statusCode, shown.body).toBe(200);
    expect(shown.body).toContain('APPLEKEY01');
    expect(shown.body).toContain('a sealed value (not shown)');

    const { rows: audit } = await app().dbPool.query<{ text: string }>(
      `SELECT row_to_json(a)::text AS text FROM admin_audit_log a
        WHERE realm_id = $1 AND operation_id = 'plugins.keys.import'`,
      [realm.id]
    );
    expect(audit).toHaveLength(1);
    expect(audit[0].text).toContain('APPLEKEY01');
    // Every event of the realm, whatever records the change.
    const { rows: events } = await app().dbPool.query<{ text: string }>(
      `SELECT row_to_json(e)::text AS text FROM events e WHERE realm_id = $1`,
      [realm.id]
    );
    const { rows: approvals } = await app().dbPool.query<{ text: string }>(
      `SELECT row_to_json(a)::text AS text FROM admin_approvals a WHERE id = $1`,
      [imported.approvalId]
    );
    expect(approvals).toHaveLength(1);

    const seen = [
      imported.sealed.body,
      imported.response.body,
      shown.body,
      ...audit.map((row) => row.text),
      ...events.map((row) => row.text),
      ...approvals.map((row) => row.text),
      ...logLines,
    ].join('\n');
    for (const fragment of pemBody(key.pem)) expect(seen).not.toContain(fragment);
    expect(seen).not.toContain('PRIVATE KEY');
  });

  // Acceptance criterion: the import is refused without step-up, for
  // qauth:admin:write, and for a key of the wrong algorithm.
  it('refuses the import without an approval, for the write scope and for a key of another algorithm', async () => {
    const realm = await ownRealm('keys-refused');
    const requester = await adminOf(realm.id);
    const editor = await adminOf(realm.id, 'editor', 'qauth:admin:read qauth:admin:write');

    // Before the plugin is configured, there is no algorithm to import for.
    const early = await importKey(realm.id, requester, 'APPLEKEY01', ecKey().pem);
    expect(early.response.statusCode, early.response.body).toBe(409);
    await configured(realm.id, requester);

    const key = ecKey();
    const sealed = await seal(realm.id, requester.token, key.pem);
    expect(sealed.statusCode, sealed.body).toBe(200);
    const body = {
      kid: 'APPLEKEY01',
      privateKey: { sealed: sealed.json<{ sealed: string }>().sealed },
    };

    // The write scope reaches no security operation.
    const byEditor = await send('POST', pluginPath(realm.id, '/keys'), editor.token, body);
    expect(byEditor.statusCode, byEditor.body).toBe(403);
    expect(byEditor.json()).toMatchObject({ code: 'forbidden' });

    // Without an approval (the step-up) the operation does not run.
    const unapproved = await send('POST', pluginPath(realm.id, '/keys'), requester.token, body);
    expect(unapproved.statusCode, unapproved.body).toBe(403);
    expect(unapproved.json()).toMatchObject({ code: 'approval_required' });

    // A key of another algorithm than the configuration's ES256.
    const { privateKey: rsa } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPem = rsa.export({ format: 'pem', type: 'pkcs8' }).toString();
    const wrong = await importKey(realm.id, requester, 'APPLEKEY02', rsaPem);
    expect(wrong.response.statusCode, wrong.response.body).toBe(400);
    expect(wrong.response.json()).toMatchObject({ code: 'bad_request' });
    for (const fragment of pemBody(rsaPem)) expect(wrong.response.body).not.toContain(fragment);

    expect(await assertionKeys(realm.id)).toEqual([]);
    for (const response of [byEditor, unapproved]) {
      for (const fragment of pemBody(key.pem)) expect(response.body).not.toContain(fragment);
    }
  });

  // Acceptance criterion: after a second import and a switch, the new key
  // signs and the old one does not.
  it('keeps the first key signing while the second waits, and signs with the second after the switch', async () => {
    const realm = await ownRealm('keys-rotation');
    const requester = await adminOf(realm.id);
    await configured(realm.id, requester);

    const first = ecKey();
    const second = ecKey();
    const one = await importKey(realm.id, requester, 'APPLEKEY01', first.pem);
    expect(one.response.json()).toMatchObject({ status: 'active' });
    const two = await importKey(realm.id, requester, 'APPLEKEY02', second.pem);
    expect(two.response.statusCode, two.response.body).toBe(200);
    expect(two.response.json()).toEqual({ kid: 'APPLEKEY02', algorithm: 'ES256', status: 'next' });
    // A third waits for nothing: one next key at a time.
    const three = await importKey(realm.id, requester, 'APPLEKEY03', ecKey().pem);
    expect(three.response.statusCode, three.response.body).toBe(409);

    // The switch waits for the rotation overlap.
    const early = await sendApproved(
      realm.id,
      requester,
      'plugins.keys.activate',
      '/keys/activate',
      {
        kid: 'APPLEKEY02',
      }
    );
    expect(early.response.statusCode, early.response.body).toBe(409);
    expect(await assertionKeys(realm.id)).toEqual([
      { kid: 'APPLEKEY01', status: 'active', algorithm: 'ES256' },
      { kid: 'APPLEKEY02', status: 'next', algorithm: 'ES256' },
    ]);

    // Eight days later, as the overlap counts them.
    const eightDays = 8 * 24 * 60 * 60 * 1000;
    for (const table of ['realm_keys', 'realm_public_keys']) {
      await app().dbPool.query(
        `UPDATE ${table} SET publish_at = publish_at - $3 WHERE realm_id = $1 AND kid = $2`,
        [realm.id, 'APPLEKEY02', eightDays]
      );
    }
    const switched = await sendApproved(
      realm.id,
      requester,
      'plugins.keys.activate',
      '/keys/activate',
      { kid: 'APPLEKEY02' }
    );
    expect(switched.response.statusCode, switched.response.body).toBe(200);
    expect(switched.response.json()).toMatchObject({
      activatedKid: 'APPLEKEY02',
      retiredKid: 'APPLEKEY01',
    });
    expect(await assertionKeys(realm.id)).toEqual([
      { kid: 'APPLEKEY01', status: 'retired', algorithm: 'ES256' },
      { kid: 'APPLEKEY02', status: 'active', algorithm: 'ES256' },
    ]);

    const assertion = readAssertion(await signAssertion(realm.id), second.publicKey);
    expect(assertion.verified).toBe(true);
    expect(assertion.header).toMatchObject({ kid: 'APPLEKEY02' });
    expect(assertion.verifiedBy(first.publicKey)).toBe(false);
  });
});
