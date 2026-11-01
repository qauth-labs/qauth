import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createTestEgressClient } from '@qauth-labs/fastify-plugin-egress';
import {
  createFixtureNetwork,
  type EgressTransport,
  type FixtureNetwork,
  type FixtureServer,
  type LocalHttpsFixture,
  startLocalHttpsFixture,
} from '@qauth-labs/fastify-plugin-egress/src/testing/egress-fixtures';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootAuthServerOptions,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE DEPLOYMENT EGRESS ALLOWLIST, END TO END (issue #481, ADR-019 Decision 8).
 *
 * The real app boots with Postgres and Redis and reads its allowlist from the
 * file EGRESS_ALLOWLIST_PATH names. The egress client refuses every non-public
 * address, so to put a "private" issuer behind one this suite replaces only
 * its two network edges, as the egress library's own tests do: a DNS table
 * and a dialler that routes the addresses below to local HTTPS servers. Every
 * check between, the address checks and the allowlist included, is the
 * production code. The last block uses the real network edges.
 *
 * Covers the acceptance criteria of #481: an operator-set destination on a
 * private address is reachable when an allowlist entry names its realm and
 * refused for another realm; a client or remote-document destination on the
 * same address is refused even with an entry; a realm admin has no API that
 * edits the list; and a test reaches a localhost fixture only through the
 * test-only client factory.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const network = vi.hoisted(() => ({ current: undefined as EgressTransport | undefined }));

// The production client's network edges: the fixture network while a test
// sets one, the real ones otherwise.
vi.mock('../../../../libs/server/egress/src/lib/transport', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const real = actual['NODE_TRANSPORT'] as EgressTransport;
  const current = (): EgressTransport => network.current ?? real;
  return {
    ...actual,
    NODE_TRANSPORT: {
      resolveHost: (...args: Parameters<EgressTransport['resolveHost']>) =>
        current().resolveHost(...args),
      exchange: (...args: Parameters<EgressTransport['exchange']>) => current().exchange(...args),
    },
  };
});

/** The trusted ID-JAG issuer, on a private address. */
const ISSUER = 'https://idp.egress.test';
const ISSUER_ADDRESS = '10.0.0.7';
/** A key host in the same private range. */
const PRIVATE_KEYS_ADDRESS = '10.0.0.8';
/** A key host on a public address. */
const PUBLIC_KEYS_ADDRESS = '93.184.215.14';

const OTHER_REALM = 'other';
const OTHER_HOST = 'other.example.com';

/** The deployment allowlist: the issuer's range, for the default realm only. */
const ALLOWLIST = { entries: [{ cidr: '10.0.0.0/24', realms: [E2E_REALM_NAME] }] };

const KEY_ID = 'issuer-key-1';

describe('the egress allowlist (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let net: FixtureNetwork | undefined;
  let issuer: FixtureServer;
  let privateKeys: FixtureServer;
  let publicKeys: FixtureServer;
  let issuerJwk: JWK;
  let dir: string;
  let allowlistPath: string;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];
  /** The `jwks_uri` the issuer's discovery document names; set per test. */
  let jwksUri = 'https://public-keys.egress.test/jwks';

  const json =
    (body: unknown): FixtureServer['handler'] =>
    (_req, _body, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    const { publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
    issuerJwk = { ...(await exportJWK(publicKey)), kid: KEY_ID, alg: 'EdDSA', use: 'sig' };
    net = await createFixtureNetwork();
    issuer = await net.serve(ISSUER_ADDRESS, () => undefined);
    privateKeys = await net.serve(PRIVATE_KEYS_ADDRESS, () => undefined);
    publicKeys = await net.serve(PUBLIC_KEYS_ADDRESS, () => undefined);
    dir = mkdtempSync(join(tmpdir(), 'qauth-egress-allowlist-'));
    allowlistPath = join(dir, 'egress-allowlist.json');
  }, 240_000);

  afterAll(async () => {
    await net?.close();
    await infra?.teardown();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  beforeEach((ctx) => {
    if (!dockerUp || !net) {
      ctx.skip();
      return;
    }
    net.dns.clear();
    net.dns.set('idp.egress.test', [ISSUER_ADDRESS]);
    net.dns.set('keys.egress.test', [PRIVATE_KEYS_ADDRESS]);
    net.dns.set('public-keys.egress.test', [PUBLIC_KEYS_ADDRESS]);
    for (const server of [issuer, privateKeys, publicKeys]) server.requests.length = 0;
    issuer.handler = (req, body, res) =>
      req.url === '/.well-known/openid-configuration'
        ? json({ issuer: ISSUER, jwks_uri: jwksUri })(req, body, res)
        : json({ secret: 'internal' })(req, body, res);
    privateKeys.handler = json({ keys: [issuerJwk] });
    publicKeys.handler = json({ keys: [issuerJwk] });
    jwksUri = 'https://public-keys.egress.test/jwks';
    writeFileSync(allowlistPath, JSON.stringify(ALLOWLIST));
    chmodSync(allowlistPath, 0o600);
    network.current = net.transport;
  });

  afterEach(async () => {
    await Promise.all(booted.splice(0).map((server) => server.close()));
  });

  /** Boot the server with the allowlist file and a trusted private issuer, and a second realm. */
  async function boot(options: BootAuthServerOptions = {}): Promise<FastifyInstance> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(
      {
        ...baseEnvironment(infra, jwt),
        EGRESS_ALLOWLIST_PATH: allowlistPath,
        ID_JAG_ENABLED: 'true',
        ID_JAG_TRUSTED_ISSUERS: ISSUER,
      },
      options
    );
    booted.push(server);
    const { app } = server;
    await app.redis.flushdb();
    if ((await app.repositories.realms.findByName(OTHER_REALM)) === undefined) {
      await app.repositories.realms.createWithPrimaryHost(
        { name: OTHER_REALM, issuer: `https://${OTHER_HOST}`, enabled: true },
        OTHER_HOST
      );
    }
    return app;
  }

  /** The default realm's CIMD policy (#534): the seeded defaults, any HTTPS host. */
  async function defaultRealmCimdPolicy(app: FastifyInstance) {
    const { cimdPolicyOf } = await import('./helpers/cimd-policy');
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error(`no realm ${E2E_REALM_NAME}`);
    return cimdPolicyOf(app, realm);
  }

  const get = (
    app: FastifyInstance,
    url: string,
    source: 'operator' | 'admin' | 'client' | 'end_user' | 'remote_document',
    realm: string
  ) => app.egress.request({ method: 'GET', url, purpose: 'test', source, realm });

  describe('an operator-set destination on a private address', () => {
    it('is reachable when an entry names its realm, and refused for another realm', async () => {
      const app = await boot();
      const url = `${ISSUER}/.well-known/openid-configuration`;

      const res = await get(app, url, 'operator', E2E_REALM_NAME);
      expect(res.status).toBe(200);
      expect(JSON.parse(res.body.toString())).toMatchObject({ issuer: ISSUER });

      await expect(get(app, url, 'operator', OTHER_REALM)).rejects.toMatchObject({
        reason: 'address',
        outcome: 'blocked',
      });
      expect(issuer.requests).toHaveLength(1);
    });

    it('is the ID-JAG discovery fetch, which reaches the issuer only for the named realm', async () => {
      const app = await boot();
      // After the boot: the app's own instance of the module, and of `env`.
      const { createIdJagIssuerKeyResolver } = await import('./helpers/id-jag-issuer-keys');
      const request = { issuer: ISSUER, keyId: KEY_ID, algorithm: 'EdDSA' as const };

      await expect(
        createIdJagIssuerKeyResolver(app, E2E_REALM_NAME)(request)
      ).resolves.toMatchObject({ identifier: ISSUER });
      expect(issuer.requests.map(({ url }) => url)).toEqual(['/.well-known/openid-configuration']);
      expect(publicKeys.requests.map(({ url }) => url)).toEqual(['/jwks']);

      // The caches are per issuer; empty them so the other realm has to fetch.
      await app.redis.flushdb();
      await expect(
        createIdJagIssuerKeyResolver(app, OTHER_REALM)(request)
      ).resolves.toBeUndefined();
      expect(issuer.requests).toHaveLength(1);
    });

    it('does not hold the issuer back for the named realm after another realm was refused', async () => {
      const app = await boot();
      const { createIdJagIssuerKeyResolver } = await import('./helpers/id-jag-issuer-keys');
      const request = { issuer: ISSUER, keyId: KEY_ID, algorithm: 'EdDSA' as const };

      await expect(
        createIdJagIssuerKeyResolver(app, OTHER_REALM)(request)
      ).resolves.toBeUndefined();
      expect(issuer.requests).toHaveLength(0);
      // No cache is emptied in between: the refusal left nothing behind.
      await expect(
        createIdJagIssuerKeyResolver(app, E2E_REALM_NAME)(request)
      ).resolves.toMatchObject({ identifier: ISSUER });
      expect(issuer.requests).toHaveLength(1);
    });

    it('stays refused for another realm after the file is changed, since it is read at boot only', async () => {
      const app = await boot();
      writeFileSync(
        allowlistPath,
        JSON.stringify({
          entries: [{ cidr: '10.0.0.0/24', realms: [E2E_REALM_NAME, OTHER_REALM] }],
        })
      );

      await expect(get(app, `${ISSUER}/x`, 'operator', OTHER_REALM)).rejects.toMatchObject({
        reason: 'address',
      });
      expect(issuer.requests).toHaveLength(0);
    });
  });

  describe('a client or remote-document destination on the same private address', () => {
    it.each(['client', 'end_user', 'remote_document'] as const)(
      'is refused as a %s destination, even for the realm the entry names',
      async (source) => {
        const app = await boot();
        await expect(get(app, `${ISSUER}/x`, source, E2E_REALM_NAME)).rejects.toMatchObject({
          reason: 'address',
          outcome: 'blocked',
        });
        expect(issuer.requests).toHaveLength(0);
      }
    );

    it('is refused as the jwks_uri an allowlisted discovery document names', async () => {
      jwksUri = 'https://keys.egress.test/jwks';
      const app = await boot();
      const { createIdJagIssuerKeyResolver } = await import('./helpers/id-jag-issuer-keys');

      await expect(
        createIdJagIssuerKeyResolver(
          app,
          E2E_REALM_NAME
        )({
          issuer: ISSUER,
          keyId: KEY_ID,
          algorithm: 'EdDSA',
        })
      ).resolves.toBeUndefined();
      // Discovery went through for the realm; its jwks_uri, in the same
      // listed range, was never dialled.
      expect(issuer.requests).toHaveLength(1);
      expect(privateKeys.requests).toHaveLength(0);
    });

    it('is refused as a CIMD client_id and as a client jwks_uri', async () => {
      const app = await boot();
      const { fetchAndValidateCimdDocument } = await import('./helpers/cimd');
      const { fetchClientJwkSet } = await import('./helpers/client-jwks');

      await expect(
        fetchAndValidateCimdDocument(
          app,
          `${ISSUER}/client.json`,
          await defaultRealmCimdPolicy(app)
        )
      ).rejects.toMatchObject({ errorDescription: expect.stringContaining('CIMD fetch blocked') });
      await expect(fetchClientJwkSet(app, `${ISSUER}/jwks`)).rejects.toMatchObject({
        errorDescription: expect.stringContaining('client jwks_uri fetch blocked'),
      });
      expect(issuer.requests).toHaveLength(0);
    });
  });

  describe('the list is out of a realm admin reach', () => {
    it('has no route that reads or edits it', async () => {
      const app = await boot();
      // Fastify prints its routes as a tree of path segments: a route whose
      // path names the list in any segment shows that segment.
      const routes = app.printRoutes({ commonPrefix: false });

      expect(routes).toMatch(/token \(POST/);
      expect(routes).toMatch(/clients/);
      expect(routes).not.toMatch(/egress|allowlist/i);
    });

    it('has no path in the published API documents', async () => {
      const { readFileSync } = await import('node:fs');
      for (const file of ['apps/docs-site/public/openapi.json', 'stable-surface/openapi.json']) {
        const document = JSON.parse(readFileSync(join(__dirname, '../../../..', file), 'utf8')) as {
          paths: Record<string, unknown>;
        };
        const paths = Object.keys(document.paths);
        expect(paths.length).toBeGreaterThan(0);
        expect(paths.filter((path) => /egress|allowlist/i.test(path))).toEqual([]);
      }
    });

    it('is not in the database', async () => {
      const app = await boot();
      const { rows } = await app.dbPool.query<{ name: string }>(
        `SELECT table_name AS name FROM information_schema.tables
          WHERE table_schema = 'public' AND table_name ILIKE '%egress%'
         UNION
         SELECT table_name || '.' || column_name FROM information_schema.columns
          WHERE table_schema = 'public' AND column_name ILIKE '%egress%'`
      );
      expect(rows).toEqual([]);
    });
  });

  describe('a localhost fixture', () => {
    let fixture: LocalHttpsFixture;

    beforeEach(async () => {
      // The real network edges from here on.
      network.current = undefined;
      fixture = await startLocalHttpsFixture((req, _body, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            client_id: `${fixture.origin}${req.url ?? ''}`,
            client_name: 'Local fixture client',
            redirect_uris: ['https://app.example.com/callback'],
          })
        );
      });
    });

    afterEach(async () => {
      await fixture.close();
    });

    it('is refused by the production client, also for an operator destination of a listed realm', async () => {
      const app = await boot();
      const { fetchAndValidateCimdDocument } = await import('./helpers/cimd');

      await expect(
        fetchAndValidateCimdDocument(
          app,
          `https://127.0.0.1:${fixture.port}/client.json`,
          await defaultRealmCimdPolicy(app)
        )
      ).rejects.toMatchObject({ errorDescription: expect.stringContaining('CIMD fetch blocked') });
      await expect(
        get(app, `https://127.0.0.1:${fixture.port}/x`, 'operator', E2E_REALM_NAME)
      ).rejects.toMatchObject({ reason: 'address', outcome: 'blocked' });
      expect(fixture.connections).toBe(0);
    });

    it('is reachable through the test-only client factory, by the CIMD fetch', async () => {
      const app = await boot({ egressClientFactory: createTestEgressClient });
      const { fetchAndValidateCimdDocument } = await import('./helpers/cimd');
      const clientId = `${fixture.origin}/client.json`;

      await expect(
        fetchAndValidateCimdDocument(app, clientId, await defaultRealmCimdPolicy(app))
      ).resolves.toMatchObject({
        client_id: clientId,
        client_name: 'Local fixture client',
      });
      expect(fixture.requests.map(({ url }) => url)).toEqual(['/client.json']);
    });
  });
});
