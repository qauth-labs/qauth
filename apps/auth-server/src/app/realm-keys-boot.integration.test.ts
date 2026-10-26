import { createPublicKey, generateKeyPairSync } from 'node:crypto';

import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import { createLocalJWKSet, importPKCS8, jwtVerify, SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * THE KEY IMPORT AT FIRST BOOT, THROUGH THE REAL AUTH-SERVER (ADR-019 Decision
 * 9 and its answer on existing issuers, issue #485).
 *
 * Each boot is the whole server under one environment, against one Postgres:
 * the variables of a deployment from before the key store, booted once to
 * import them and again to see the import is not repeated. What only the real
 * server shows: the default realm's step runs first and the key step after it,
 * the JWKS the server publishes names its keys as the store does, and a key
 * variable that cannot be imported stops the boot.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ISSUER = 'https://auth.example.com';
const COOKIE_SECRET = 'an-operator-session-cookie-secret-0123456789';

interface LogLine {
  readonly msg: string;
  readonly variable?: string;
  readonly [field: string]: unknown;
}

interface StoredKey {
  readonly purpose: string;
  readonly algorithm: string;
  readonly kid: string;
}

/** A published JWK's public members, as both the old and the new JWKS carry them. */
function publicMembers(jwk: object): Record<string, unknown> {
  const { kty, crv, x, n, e } = jwk as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries({ kty, crv, x, n, e }).filter(([, value]) => value !== undefined)
  );
}

describe('key import at first boot, through the real auth-server', () => {
  let infra: E2eInfrastructure | undefined;
  let dockerUp = false;
  let jwt: PemKeyPair;
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp || !infra) {
      ctx.skip();
      return;
    }
    // A throwaway server only to reach the database: every test starts empty.
    const server = await boot();
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.close();
  });

  /** The variables of a deployment from before the key store. */
  function oldVariables(): Record<string, string> {
    if (!infra) throw new Error('no infrastructure');
    return {
      ...baseEnvironment(infra, jwt),
      JWT_RS256_PRIVATE_KEY: rsa,
      SESSION_COOKIE_SECRET: COOKIE_SECRET,
    };
  }

  async function boot(
    environment: Record<string, string> = oldVariables(),
    lines: LogLine[] = []
  ): Promise<BootedAuthServer> {
    return bootAuthServer(environment, {
      logStream: { write: (line: string) => lines.push(JSON.parse(line) as LogLine) },
    });
  }

  async function storedKeys(server: BootedAuthServer): Promise<StoredKey[]> {
    const { rows } = await server.app.dbPool.query<StoredKey>(
      `SELECT k.purpose, k.algorithm, k.kid FROM realm_keys k JOIN realms r ON r.id = k.realm_id
        WHERE r.name = 'master' ORDER BY k.purpose, k.algorithm`
    );
    return rows;
  }

  it('stores the keys; the JWKS has the same public keys as before, plus a kid on Ed25519', async () => {
    const server = await boot();
    try {
      const stored = await storedKeys(server);
      expect(stored.map((key) => `${key.purpose}/${key.algorithm}`)).toEqual([
        'cookie_hmac/HS256',
        'data_at_rest/A256GCM',
        'event_signing/EdDSA',
        'token_signing/EdDSA',
        'token_signing/RS256',
      ]);

      const response = await server.app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
      expect(response.statusCode).toBe(200);
      const { keys } = response.json<{ keys: Record<string, unknown>[] }>();
      const edKid = stored.find(
        (key) => key.algorithm === 'EdDSA' && key.purpose === 'token_signing'
      )?.kid;
      const rsaKid = stored.find((key) => key.algorithm === 'RS256')?.kid;
      expect(keys.map(publicMembers)).toEqual([
        publicMembers(createPublicKey(jwt.publicKey).export({ format: 'jwk' })),
        publicMembers(createPublicKey(rsa).export({ format: 'jwk' })),
      ]);
      expect(keys.map((key) => key['kid'])).toEqual([edKid, rsaKid]);
      expect(edKid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    } finally {
      await server.close();
    }
  });

  it('verifies a token signed before the upgrade', async () => {
    // What the server issued before the key store: an EdDSA access token, no kid.
    const token = await new SignJWT({
      sub: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01',
      client_id: 'client-1',
      jti: 'jti-1',
      token_use: 'access',
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setAudience('client-1')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(await importPKCS8(jwt.privateKey, 'EdDSA'));

    const server = await boot();
    try {
      const realm = await server.app.repositories.realms.findByName('master');
      // The token names no `kid`: the realm's EdDSA keys are tried (#491).
      await expect(
        server.app.jwtUtils.verifyAccessToken({ id: realm?.id ?? '', issuer: ISSUER }, token)
      ).resolves.toMatchObject({ clientId: 'client-1' });

      const jwks = (
        await server.app.inject({ method: 'GET', url: '/.well-known/jwks.json' })
      ).json<{
        keys: Parameters<typeof createLocalJWKSet>[0]['keys'];
      }>();
      await expect(
        jwtVerify(token, createLocalJWKSet(jwks), { issuer: ISSUER })
      ).resolves.toBeDefined();

      const stored = await server.app.signer.getVerificationKeys(
        'local',
        realm?.id ?? '',
        'token_signing'
      );
      await expect(
        jwtVerify(token, createLocalJWKSet({ keys: stored.map((key) => key.publicJwk) }), {
          issuer: ISSUER,
        })
      ).resolves.toBeDefined();
    } finally {
      await server.close();
    }
  });

  it('imports nothing on a second boot with the variables still set, and warns once per variable', async () => {
    const first = await boot();
    const before = await storedKeys(first);
    await first.close();

    const lines: LogLine[] = [];
    const second = await boot(oldVariables(), lines);
    try {
      expect(await storedKeys(second)).toEqual(before);
      const warned = lines
        .filter((line) => line.msg.includes("is in the realm's key store"))
        .map((line) => line.variable);
      expect(warned).toEqual([
        'JWT_PRIVATE_KEY',
        'JWT_PUBLIC_KEY',
        'JWT_RS256_PRIVATE_KEY',
        'SESSION_COOKIE_SECRET',
      ]);
      // A 40-character slice of each key, or the whole cookie secret: its slice
      // from character 40 would be only "6789", which a log line's timestamp or
      // pid can hold by chance.
      for (const line of lines) {
        for (const value of [jwt.privateKey, rsa, COOKIE_SECRET]) {
          const fragment = value.length >= 80 ? value.slice(40, 80) : value;
          expect(JSON.stringify(line)).not.toContain(fragment);
        }
      }
    } finally {
      await second.close();
    }
  });

  it('stops the boot when JWT_PUBLIC_KEY is not the public half of JWT_PRIVATE_KEY', async () => {
    const other = await generateJwtPem();

    await expect(
      boot({ ...oldVariables(), JWT_PUBLIC_KEY: other.publicKey })
    ).rejects.toMatchObject({
      name: 'InvalidConfigurationError',
      message: expect.stringContaining('JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY'),
    });
  });

  it('stops the boot with a clear message when the keys must be imported and no KEK is set', async () => {
    const withoutKek = oldVariables();
    delete withoutKek['KEK'];

    await expect(boot(withoutKek)).rejects.toMatchObject({
      name: 'InvalidConfigurationError',
      message: expect.stringContaining('no KEK is set'),
    });
  });
});
