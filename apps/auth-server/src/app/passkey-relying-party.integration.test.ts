import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import { resolveRpId } from '@qauth-labs/shared-validation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { storePasskeyEnrolment } from './helpers/passkey-enrolment';
import { defaultRealmPlugin, type DefaultRealmPluginOptions } from './plugins/default-realm';

/**
 * THE PASSKEY RELYING PARTY AGAINST A REAL POSTGRES (ADR-017 Decision 14,
 * ADR-019 Decision 2, issues #467 and #553).
 *
 * What only the database and a booted server can show:
 *
 * - a credential id exists once per realm: a second enrolment of it is
 *   refused, and the refusal leaves nothing behind;
 * - the boot stores `WEBAUTHN_RP_ID` on the realm row while no passkey has
 *   locked it; the realm's first enrolment locks it, concurrent first
 *   enrolments lock it once, and a boot whose `WEBAUTHN_RP_ID` differs from
 *   the lock refuses to start, saying why;
 * - the association files are served only while the RP ID is the realm host.
 *
 * `WEBAUTHN_ENABLED` stays off throughout: it is refused at boot until F2b is
 * complete, and none of the three depends on it.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ISSUER = 'https://auth.example.com';
const REALM_HOST = 'auth.example.com';
const APPLE_APP_ID = 'ABCDE12345.com.example.app';
const FINGERPRINT =
  'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

/** A verified registration as the WebAuthn provider returns it. */
function enrolment(externalSub: string, rpId = REALM_HOST) {
  return {
    externalSub,
    rpId,
    purpose: 'sign-in' as const,
    attestationFormat: 'none',
    credentialData: {
      public_key: 'pQECAyYgASFYIK_voW-Xypst',
      algorithm: -7 as const,
      sign_count: 0,
      transports: ['internal' as const],
      backup_eligible: true,
      backed_up: true,
      aaguid: '00000000-0000-0000-0000-000000000000',
      rp_id: rpId,
      user_handle: 'dXNlci1oYW5kbGU',
      nickname: null,
      created_at: Date.now(),
      last_used_at: null,
      sign_counter_regressed_at: null,
    },
  };
}

describe('the passkey relying party on a real Postgres', () => {
  let infra: E2eInfrastructure | undefined;
  let admin: FastifyInstance | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const nodes: FastifyInstance[] = [];
  const servers: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    admin = Fastify({ logger: false });
    await admin.register(databasePlugin, {
      config: { connectionString: infra.postgres.connectionString },
    });
    await admin.ready();
  }, 240_000);

  afterAll(async () => {
    await admin?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await database().dbPool.query(truncateDomainTablesStatement());
  });

  afterEach(async () => {
    await Promise.all(nodes.splice(0).map((node) => node.close()));
    await Promise.all(servers.splice(0).map((server) => server.close()));
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  /** Boot a node running the default realm's boot step, as `listen()` would. */
  async function bootNode(
    settings: Partial<DefaultRealmPluginOptions> = {}
  ): Promise<FastifyInstance> {
    if (!infra) throw new Error('database not started');
    const app = Fastify({ logger: false });
    nodes.push(app);
    await app.register(databasePlugin, {
      config: { connectionString: infra.postgres.connectionString, pool: { max: 2, min: 0 } },
    });
    await app.register(defaultRealmPlugin, {
      realmName: 'master',
      jwtIssuer: ISSUER,
      endpointHosts: [],
      ...settings,
    });
    await app.ready();
    return app;
  }

  /** Boot the real auth-server with extra environment. */
  async function bootServer(environment: Record<string, string>): Promise<BootedAuthServer> {
    if (!infra || !jwt) throw new Error('database not started');
    const server = await bootAuthServer({ ...baseEnvironment(infra, jwt), ...environment });
    servers.push(server);
    return server;
  }

  async function defaultRealmId(): Promise<string> {
    const realm = await database().repositories.realms.findByName('master');
    if (!realm) throw new Error('no default realm');
    return realm.id;
  }

  async function newUser(realmId: string): Promise<string> {
    const { rows } = await database().dbPool.query<{ id: string }>(
      'INSERT INTO users (realm_id) VALUES ($1) RETURNING id',
      [realmId]
    );
    return rows[0].id;
  }

  async function enrol(realmId: string, userId: string, externalSub: string, rpId = REALM_HOST) {
    const { db, repositories } = database();
    return storePasskeyEnrolment(
      { db, realms: repositories.realms, userCredentials: repositories.userCredentials },
      { realmId, userId, enrolment: enrolment(externalSub, rpId) }
    );
  }

  async function defaultRealm() {
    const realm = await database().repositories.realms.findByName('master');
    if (!realm) throw new Error('no default realm');
    return realm;
  }

  async function passkeyCount(realmId: string): Promise<number> {
    const { rows } = await database().dbPool.query<{ count: string }>(
      `SELECT count(*) FROM user_credentials WHERE realm_id = $1 AND provider_type = 'webauthn'`,
      [realmId]
    );
    return Number(rows[0].count);
  }

  describe('enrolment', () => {
    it('stores the passkey with provider_type webauthn and the credential id, and locks the RP ID', async () => {
      await bootNode();
      const realmId = await defaultRealmId();

      const stored = await enrol(realmId, await newUser(realmId), 'Y3JlZGVudGlhbC0x');

      expect(stored).toMatchObject({
        providerType: 'webauthn',
        externalSub: 'Y3JlZGVudGlhbC0x',
        credentialData: expect.objectContaining({ rp_id: REALM_HOST, sign_count: 0 }),
      });
      const realm = await defaultRealm();
      expect(realm).toMatchObject({ webauthnRpId: null });
      expect(realm.webauthnRpIdLockedAt).toEqual(expect.any(Number));
      expect(resolveRpId(realm)).toBe(REALM_HOST);
    });

    it('locks once when two first enrolments run together, and stores both passkeys', async () => {
      await bootNode();
      const realmId = await defaultRealmId();
      const [ada, grace] = [await newUser(realmId), await newUser(realmId)];

      const results = await Promise.allSettled([
        enrol(realmId, ada, 'Y29uY3VycmVudC1h'),
        enrol(realmId, grace, 'Y29uY3VycmVudC1i'),
      ]);

      expect(results.map((result) => result.status)).toEqual(['fulfilled', 'fulfilled']);
      expect(await passkeyCount(realmId)).toBe(2);
      // The row-level choreography of the race is in infra-db's
      // webauthn-relying-party.integration.test.ts; here, the helper end to end.
      const realm = await defaultRealm();
      expect(realm.webauthnRpIdLockedAt).toEqual(expect.any(Number));
      expect(resolveRpId(realm)).toBe(REALM_HOST);
    });

    it("refuses a first passkey created under another RP ID than the realm's, and leaves the realm unlocked", async () => {
      await bootNode();
      const realmId = await defaultRealmId();

      await expect(
        enrol(realmId, await newUser(realmId), 'b3RoZXItcnBpZA', 'example.com')
      ).rejects.toBeInstanceOf(BadRequestError);
      expect(await passkeyCount(realmId)).toBe(0);
      expect((await defaultRealm()).webauthnRpIdLockedAt).toBeNull();
    });

    it('refuses a duplicate credential id in the realm, for another account too, and leaves nothing behind', async () => {
      await bootNode();
      const realmId = await defaultRealmId();
      const ada = await newUser(realmId);
      const grace = await newUser(realmId);
      await enrol(realmId, ada, 'ZHVwbGljYXRl');

      await expect(enrol(realmId, grace, 'ZHVwbGljYXRl')).rejects.toBeInstanceOf(
        UniqueConstraintError
      );
      await expect(enrol(realmId, ada, 'ZHVwbGljYXRl')).rejects.toBeInstanceOf(
        UniqueConstraintError
      );
      expect(await passkeyCount(realmId)).toBe(1);
    });

    it('refuses a passkey created under another RP ID once the realm is locked', async () => {
      await bootNode();
      const realmId = await defaultRealmId();
      const user = await newUser(realmId);
      await enrol(realmId, user, 'Zmlyc3Q');

      await expect(enrol(realmId, user, 'c2Vjb25k', 'example.com')).rejects.toBeInstanceOf(
        BadRequestError
      );
      expect(await passkeyCount(realmId)).toBe(1);
    });
  });

  describe('the RP ID lock at boot', () => {
    it('stores any valid WEBAUTHN_RP_ID on the realm while it has no passkey', async () => {
      await bootNode();
      await expect(
        bootNode({ passkeys: { rpId: 'example.com', allowParentDomainRpId: true } })
      ).resolves.toBeDefined();
      expect(await defaultRealm()).toMatchObject({
        webauthnRpId: 'example.com',
        webauthnRpIdLockedAt: null,
      });

      await expect(bootNode()).resolves.toBeDefined();
      expect(await defaultRealm()).toMatchObject({ webauthnRpId: null });
    });

    it('locks a parent-domain RP ID at the first enrolment and keeps reporting it', async () => {
      await bootNode({ passkeys: { rpId: 'example.com', allowParentDomainRpId: true } });
      const realmId = await defaultRealmId();

      await enrol(realmId, await newUser(realmId), 'cGFyZW50LWRvbWFpbg', 'example.com');

      const realm = await defaultRealm();
      expect(realm.webauthnRpIdLockedAt).toEqual(expect.any(Number));
      expect(resolveRpId(realm)).toBe('example.com');
      await expect(bootNode()).rejects.toThrow(
        'The default realm "master" has passkeys bound to the RP ID "example.com", but WEBAUTHN_RP_ID gives "auth.example.com".'
      );
      await expect(
        database().dbPool.query(`UPDATE realms SET webauthn_rp_id = NULL WHERE id = $1`, [realmId])
      ).rejects.toMatchObject({ constraint: 'realms_webauthn_rp_id_locked' });
      await expect(
        bootNode({ passkeys: { rpId: 'example.com', allowParentDomainRpId: true } })
      ).resolves.toBeDefined();
    });

    it('refuses to boot when WEBAUTHN_RP_ID changes after the first enrolment, explaining why', async () => {
      await bootNode();
      const realmId = await defaultRealmId();
      await enrol(realmId, await newUser(realmId), 'bG9ja2Vk');

      await expect(
        bootNode({ passkeys: { rpId: 'example.com', allowParentDomainRpId: true } })
      ).rejects.toThrow(
        'The default realm "master" has passkeys bound to the RP ID "auth.example.com", but WEBAUTHN_RP_ID gives "example.com". The RP ID is locked once a realm has a passkey: another one would orphan every passkey enrolled under "auth.example.com". Unset WEBAUTHN_RP_ID, or set it to "auth.example.com".'
      );
      await expect(bootNode()).resolves.toBeDefined();
      await expect(
        bootNode({ passkeys: { rpId: REALM_HOST, allowParentDomainRpId: false } })
      ).resolves.toBeDefined();
    });

    it('refuses to start the real auth-server with a changed WEBAUTHN_RP_ID after the first enrolment', async () => {
      await bootNode();
      const realmId = await defaultRealmId();
      await enrol(realmId, await newUser(realmId), 'YXV0aC1zZXJ2ZXI');

      await expect(
        bootServer({ WEBAUTHN_RP_ID: 'example.com', WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN: 'true' })
      ).rejects.toThrow('has passkeys bound to the RP ID "auth.example.com"');
      await expect(bootServer({})).resolves.toBeDefined();
    });
  });

  describe('the association files', () => {
    const APPS = {
      WEBAUTHN_APPLE_APP_IDS: APPLE_APP_ID,
      WEBAUTHN_ANDROID_APPS: JSON.stringify({ 'com.example.app': [FINGERPRINT] }),
    };

    it('are served while the RP ID is the realm host, as the platforms require', async () => {
      const { app } = await bootServer(APPS);

      const apple = await app.inject({
        method: 'GET',
        url: '/.well-known/apple-app-site-association',
        headers: { host: REALM_HOST },
      });
      expect(apple.statusCode).toBe(200);
      expect(apple.headers['content-type']).toBe('application/json');
      expect(apple.json()).toEqual({ webcredentials: { apps: [APPLE_APP_ID] } });

      const android = await app.inject({
        method: 'GET',
        url: '/.well-known/assetlinks.json',
        headers: { host: REALM_HOST },
      });
      expect(android.statusCode).toBe(200);
      expect(android.headers['content-type']).toBe('application/json');
      expect(android.json()).toEqual([
        {
          relation: ['delegate_permission/common.get_login_creds'],
          target: {
            namespace: 'android_app',
            package_name: 'com.example.app',
            sha256_cert_fingerprints: [FINGERPRINT],
          },
        },
      ]);
    });

    it('are served when WEBAUTHN_RP_ID names the realm host', async () => {
      const { app } = await bootServer({ ...APPS, WEBAUTHN_RP_ID: REALM_HOST });
      const apple = await app.inject({
        method: 'GET',
        url: '/.well-known/apple-app-site-association',
      });
      expect(apple.statusCode).toBe(200);
    });

    it('are not served under a parent-domain RP ID, where they belong on the parent', async () => {
      const { app } = await bootServer({
        ...APPS,
        WEBAUTHN_RP_ID: 'example.com',
        WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN: 'true',
      });

      for (const url of [
        '/.well-known/apple-app-site-association',
        '/.well-known/assetlinks.json',
      ]) {
        const response = await app.inject({ method: 'GET', url, headers: { host: REALM_HOST } });
        expect(response.statusCode).toBe(404);
      }
    });

    it('are not served when the operator listed no app for the platform', async () => {
      const { app } = await bootServer({ WEBAUTHN_APPLE_APP_IDS: APPLE_APP_ID });

      const apple = await app.inject({
        method: 'GET',
        url: '/.well-known/apple-app-site-association',
      });
      const android = await app.inject({ method: 'GET', url: '/.well-known/assetlinks.json' });
      expect(apple.statusCode).toBe(200);
      expect(android.statusCode).toBe(404);
    });
  });
});
