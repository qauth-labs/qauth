import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyPluginAsync } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import {
  createInternalPki,
  eventually,
  fingerprintOf,
  type InternalPki,
  type IssuedCredentials,
  servedFingerprint,
  tlsExchange,
  type TlsFileDirectory,
  writeTlsFiles,
} from '../testing/internal-pki';
import { createInternalClient, type InternalClient, InternalClientError } from './internal/client';
import type { InternalRouteModule } from './internal/route-manifest';

/**
 * THE INTERNAL LISTENER IN THE REAL APP (#496, ADR-019 Decision 8), against
 * a real Postgres and Redis.
 *
 * The suite boots the real app as a split process holding the signer, with
 * the internal listener beside it as `main.ts` builds it (the harness's
 * `internalListener`): its TLS files on disk, mutual TLS on loopback, its
 * peers in INTERNAL_PEER_ROLES. No internal route ships until the signer
 * service (#497), so a fixture module stands in for the manifest's; one of
 * its routes reads the database through the decorators the listener shares
 * with the app. `internal/listener.test.ts` holds the same properties
 * without a database; `internal-listener-boot.integration.test.ts` runs
 * `main.ts` itself.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const SIGNER_SAN = 'spiffe://qauth.test/signer';
const PREFIX = '/internal/fixture/v1-rc.0';

const fixtureRoutes: FastifyPluginAsync = async (scope) => {
  scope.get('/peer', async (request) => ({ peerRole: request.peerRole }));
  scope.get('/realm', async () => {
    const realm = await scope.repositories.realms.findByName(E2E_REALM_NAME);
    return { found: realm !== undefined };
  });
};

const FIXTURE_MODULE: InternalRouteModule = {
  module: 'fixture',
  prefix: PREFIX,
  roles: ['signer'],
  load: async () => ({ default: fixtureRoutes }),
};

describe('the internal listener (#496)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let pki: InternalPki;
  let otherPki: InternalPki;
  let peers: Record<'web' | 'api' | 'delivery' | 'admin' | 'stranger', IssuedCredentials>;
  let tls: TlsFileDirectory;
  let booted: BootedAuthServer | undefined;
  const clients: InternalClient[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    pki = createInternalPki();
    otherPki = createInternalPki('Another CA');
    peers = {
      web: pki.issue({ uris: ['spiffe://qauth.test/web'] }),
      api: pki.issue({ dnsNames: ['api.qauth.internal'] }),
      delivery: pki.issue({ uris: ['spiffe://qauth.test/delivery'] }),
      admin: pki.issue({ dnsNames: ['admin.qauth.internal'] }),
      stranger: pki.issue({ dnsNames: ['stranger.qauth.internal'] }),
    };
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  describe('on a split process holding the signer, with mutual TLS', () => {
    beforeEach(async (ctx) => {
      if (!dockerUp || !infra || !jwt) {
        ctx.skip();
        return;
      }
      tls = writeTlsFiles(
        pki.issue({ dnsNames: ['signer.qauth.internal'], uris: [SIGNER_SAN] }),
        pki.caPem
      );
      booted = await bootAuthServer(
        {
          ...baseEnvironment(infra, jwt),
          SERVICE_ROLES: 'api,signer',
          INTERNAL_TLS_CERT_PATH: tls.files.certPath,
          INTERNAL_TLS_KEY_PATH: tls.files.keyPath,
          INTERNAL_TLS_CA_PATH: tls.files.caPath,
          INTERNAL_PEER_ROLES: JSON.stringify({
            'spiffe://qauth.test/web': 'web',
            'api.qauth.internal': 'api',
            'spiffe://qauth.test/delivery': 'delivery',
            'admin.qauth.internal': 'admin',
          }),
        },
        { internalListener: () => ({ modules: [FIXTURE_MODULE], reloadIntervalMs: 100 }) }
      );
    });

    afterEach(async () => {
      for (const client of clients.splice(0)) client.close();
      await booted?.close();
      booted = undefined;
      tls?.remove();
    });

    /** The listener's address. */
    function target(): { host: string; port: number } {
      const url = new URL(booted?.internalUrl ?? 'https://0.0.0.0:0');
      return { host: url.hostname, port: Number(url.port) };
    }

    function client(
      credentials: IssuedCredentials,
      overrides: Partial<Parameters<typeof createInternalClient>[0]> = {}
    ): InternalClient {
      const made = createInternalClient({
        url: booted?.internalUrl ?? '',
        cert: credentials.cert,
        key: credentials.key,
        ca: pki.caPem,
        expectedServerSan: SIGNER_SAN,
        ...overrides,
      });
      clients.push(made);
      return made;
    }

    it('shares the app database pool, cache and signer, and reads the database through them', async () => {
      expect(booted?.internalUrl).toMatch(/^https:\/\/127\.0\.0\.1:\d+$/);
      expect(booted?.internal?.dbPool).toBe(booted?.app.dbPool);
      expect(booted?.internal?.db).toBe(booted?.app.db);
      expect(booted?.internal?.redis).toBe(booted?.app.redis);
      expect(booted?.internal?.signer).toBe(booted?.app.signer);
      const response = await client(peers.api).request({ method: 'GET', path: `${PREFIX}/realm` });
      expect(response.status).toBe(200);
      expect(JSON.parse(response.body.toString())).toEqual({ found: true });
    });

    it('lets a client with a certificate from the right CA reach an internal route', async () => {
      const response = await client(peers.web).request({ method: 'GET', path: `${PREFIX}/peer` });
      expect(response.status).toBe(200);
    });

    it('fails the handshake of a client with no certificate or one from another CA', async () => {
      expect((await tlsExchange(target(), { ca: pki.caPem }, `${PREFIX}/peer`)).received).toBe('');
      const forged = otherPki.issue({ uris: ['spiffe://qauth.test/web'] });
      expect(
        (
          await tlsExchange(
            target(),
            { ca: pki.caPem, cert: forged.cert, key: forged.key },
            `${PREFIX}/peer`
          )
        ).received
      ).toBe('');
      const refused = await client(forged)
        .request({ method: 'GET', path: `${PREFIX}/peer` })
        .catch((caught: unknown) => caught);
      expect((refused as InternalClientError).code).toBe('unreachable');
    });

    it('answers 403 to a valid certificate whose SAN INTERNAL_PEER_ROLES does not map', async () => {
      const response = await client(peers.stranger).request({
        method: 'GET',
        path: `${PREFIX}/peer`,
      });
      expect(response.status).toBe(403);
      expect(JSON.parse(response.body.toString())).toMatchObject({ code: 'forbidden' });
    });

    it('gives each request the role its certificate maps to', async () => {
      for (const role of ['web', 'api', 'delivery', 'admin'] as const) {
        const response = await client(peers[role]).request({
          method: 'GET',
          path: `${PREFIX}/peer`,
        });
        expect(JSON.parse(response.body.toString()), role).toEqual({ peerRole: role });
      }
    });

    it('serves replaced certificate files with no restart', async () => {
      const rotated = pki.issue({ dnsNames: ['signer.qauth.internal'], uris: [SIGNER_SAN] });
      tls.replace(rotated, pki.caPem);
      await eventually(
        async () =>
          (await servedFingerprint(target(), peers.web, [pki.caPem])) ===
          fingerprintOf(rotated.cert)
      );
      const response = await client(peers.web).request({ method: 'GET', path: `${PREFIX}/peer` });
      expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });
    });

    it('has its client refuse a server whose SAN is not expectedServerSan', async () => {
      const refused = await client(peers.web, { expectedServerSan: 'spiffe://qauth.test/other' })
        .request({ method: 'GET', path: `${PREFIX}/peer` })
        .catch((caught: unknown) => caught);
      expect(refused).toBeInstanceOf(InternalClientError);
      expect((refused as InternalClientError).code).toBe('server_identity');
    });

    it('answers no internal path on the public listener', async () => {
      const response = await booted?.app.inject({ method: 'GET', url: `${PREFIX}/peer` });
      expect(response?.statusCode).toBe(404);
    });

    it('closes with the server', async () => {
      const address = target();
      await booted?.close();
      booted = undefined;
      const { error, received } = await tlsExchange(address, { ca: pki.caPem });
      expect(received).toBe('');
      expect(error?.code).toBe('ECONNREFUSED');
    });
  });

  describe('on a split process holding the signer without mutual TLS', () => {
    it('registers no signer route and refuses to boot, naming each setting', async (ctx) => {
      if (!dockerUp || !infra || !jwt) {
        ctx.skip();
        return;
      }
      // Refused before the app registers anything, the internal modules
      // included: no route of the signer ever exists without mutual TLS.
      await expect(
        bootAuthServer(
          { ...baseEnvironment(infra, jwt), SERVICE_ROLES: 'api,signer' },
          { internalListener: () => ({ modules: [FIXTURE_MODULE] }) }
        )
      ).rejects.toThrow(
        /INTERNAL_TLS_CERT_PATH is required: SERVICE_ROLES=api,signer serves the signer to the other roles on the internal listener, over mutual TLS only while the roles are split, so the signer routes are not registered without it/
      );
    });
  });
});
