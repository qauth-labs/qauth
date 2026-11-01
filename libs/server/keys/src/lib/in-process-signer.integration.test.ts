/**
 * Real-Postgres integration tests for the in-process signer (issues #464 and
 * #547).
 *
 * Keys are created by the key factory into the migrated `realm_keys` and
 * `realm_public_keys` tables (#461, #463), and the signer reads them back with
 * plain SQL, the shape of the repositories its wiring passes in production.
 * The store records every statement, so a warm-cache signature can be shown
 * to run none.
 *
 * Requires Docker; self-skips without it, like the other container suites.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

import {
  getSignatureBackend,
  importPublicSigningJwk,
  type JwsAlgorithm,
  type SignatureAlgorithm,
  verifyHybrid,
  verifyWithHeader,
} from '@qauth-labs/core-crypto';
import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import { decodeProtectedHeader } from 'jose';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import { createPgKeyStore } from '../testing/pg-key-store';
import { createPgSignerStore, type PgSignerStore } from '../testing/pg-signer-store';
import { createInProcessSigner } from './in-process-signer';
import { createKeyFactory } from './key-factory';
import type { RealmJwks, Signer } from './signer';
import { SignerKeyNotFoundError } from './signer-errors';

const NOW = 1_800_000_000_000;
const HYBRID: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];
const CLAIMS = { sub: 'user-1', aud: 'client-1', iat: NOW / 1000, exp: NOW / 1000 + 300 };

describe('in-process signer integration (real Postgres)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  const kekProvider = localProvider({ KEK: KEK_A });

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer({ schema: 'migrated' });
    pool = new Pool({ connectionString: container.connectionString });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool) {
      testCtx.skip();
      return;
    }
    await pool.query(truncateDomainTablesStatement());
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  async function seedRealm(issuer: string): Promise<string> {
    const { rows } = await db().query<{ id: string }>(
      'INSERT INTO realms (name, issuer) VALUES ($1, $2) RETURNING id',
      [`realm-${Math.random().toString(36).slice(2)}`, issuer]
    );
    return rows[0].id;
  }

  function setup(hybrid = false): {
    signer: Signer;
    store: PgSignerStore;
    provision(realmId: string): Promise<unknown>;
  } {
    const enabled = hybrid ? HYBRID : (['EdDSA'] as const);
    const factory = createKeyFactory({
      store: createPgKeyStore(db()),
      kekProvider,
      enabledSignatureAlgorithms: enabled,
      hybridSigning: hybrid,
      now: () => NOW,
    });
    const store = createPgSignerStore(db());
    const signer = createInProcessSigner({
      store,
      kekProvider,
      enabledSignatureAlgorithms: enabled,
      hybridSigning: hybrid,
      now: () => NOW,
    });
    return { signer, store, provision: (realmId) => factory.provisionRealmKeys(realmId) };
  }

  async function verifyWithJwks(token: string, jwks: RealmJwks, issuer: string) {
    const { kid, alg } = decodeProtectedHeader(token);
    const jwk = jwks.keys.find((key) => key.kid === kid);
    if (jwk === undefined) throw new Error(`no published key for kid ${String(kid)}`);
    return verifyWithHeader(token, await importPublicSigningJwk(jwk, alg as JwsAlgorithm), {
      algorithms: [alg as JwsAlgorithm],
      issuer,
      currentDate: new Date(NOW),
    });
  }

  it('signs for two realms with different keys, each verifying only with its own JWKS', async () => {
    const { signer, provision } = setup();
    const realmA = await seedRealm('https://a.example.test');
    const realmB = await seedRealm('https://b.example.test');
    await provision(realmA);
    await provision(realmB);

    const request = { purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS } as const;
    const tokenA = await signer.signJws('local', { realmId: realmA, ...request });
    const tokenB = await signer.signJws('local', { realmId: realmB, ...request });
    const jwksA = await signer.getJwks('local', realmA);
    const jwksB = await signer.getJwks('local', realmB);

    expect(decodeProtectedHeader(tokenA).kid).not.toBe(decodeProtectedHeader(tokenB).kid);
    expect((await verifyWithJwks(tokenA, jwksA, 'https://a.example.test')).claims['iss']).toBe(
      'https://a.example.test'
    );
    expect((await verifyWithJwks(tokenB, jwksB, 'https://b.example.test')).claims['iss']).toBe(
      'https://b.example.test'
    );
    await expect(verifyWithJwks(tokenA, jwksB, 'https://a.example.test')).rejects.toThrow(
      /no published key/
    );
  });

  it('gives a typed error for a realm with no key and creates no key', async () => {
    const { signer, store } = setup();
    const realmId = await seedRealm('https://empty.example.test');

    const error = await signer
      .signJws('local', { realmId, purpose: 'token_signing', typ: 'at+jwt', claims: CLAIMS })
      .catch((e) => e);

    expect(error).toBeInstanceOf(SignerKeyNotFoundError);
    expect(error).toMatchObject({ realmId, purpose: 'token_signing', algorithm: 'EdDSA' });
    const { rows } = await db().query('SELECT count(*)::int AS n FROM realm_keys');
    expect(rows[0].n).toBe(0);
    expect(store.queries.every((text) => /^\s*SELECT/i.test(text))).toBe(true);
  });

  it('runs no database query to sign with a warm cache', async () => {
    const { signer, store, provision } = setup();
    const realmId = await seedRealm('https://a.example.test');
    await provision(realmId);
    await signer.signJws('local', {
      realmId,
      purpose: 'token_signing',
      typ: 'at+jwt',
      claims: CLAIMS,
    });
    expect(store.queries.length).toBeGreaterThan(0);
    store.queries.length = 0;

    await signer.signJws('local', {
      realmId,
      purpose: 'token_signing',
      typ: 'at+jwt',
      claims: CLAIMS,
    });
    await signer.signJws('local', {
      realmId,
      purpose: 'token_signing',
      typ: 'JWT',
      claims: CLAIMS,
    });

    expect(store.queries).toEqual([]);
  });

  it('signs a hybrid token from the stored pair', async () => {
    const { signer, provision } = setup(true);
    const realmId = await seedRealm('https://a.example.test');
    await provision(realmId);

    const hybrid = await signer.signHybrid('local', { realmId, typ: 'at+jwt', claims: CLAIMS });
    const keys = await signer.getVerificationKeys('local', realmId, 'token_signing');
    const ed = keys.find((key) => key.algorithm === 'EdDSA');
    const mlDsa = keys.find((key) => key.algorithm === 'ML-DSA-65');
    if (ed === undefined || mlDsa === undefined) throw new Error('no pair');
    const backend = getSignatureBackend('ML-DSA-65', HYBRID);

    await expect(
      verifyHybrid(
        hybrid,
        {
          ed: await importPublicSigningJwk(ed.publicJwk, 'EdDSA'),
          mlDsa: (kid) =>
            kid === mlDsa.kid
              ? backend.importKey(
                  (mlDsa.publicJwk as Record<string, unknown>)['pub'] as string,
                  'public'
                )
              : undefined,
        },
        {
          algorithms: ['EdDSA'],
          issuer: 'https://a.example.test',
          currentDate: new Date(NOW),
          enabledSignatureAlgorithms: HYBRID,
          requirePqc: true,
        }
      )
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  describe('scoped keys (#547)', () => {
    const DAY_MS = 86_400_000;

    /** A factory and a signer on one movable clock; the signer reads the store on every call. */
    function rotating() {
      let clock = NOW;
      const factory = createKeyFactory({
        store: createPgKeyStore(db()),
        kekProvider,
        enabledSignatureAlgorithms: ['EdDSA'],
        hybridSigning: false,
        now: () => clock,
      });
      const store = createPgSignerStore(db());
      const signer = createInProcessSigner({
        store,
        kekProvider,
        enabledSignatureAlgorithms: ['EdDSA'],
        hybridSigning: false,
        refreshIntervalMs: 0,
        now: () => clock,
      });
      return {
        factory,
        signer,
        store,
        advance: (ms: number) => {
          clock += ms;
        },
      };
    }

    /** Whether one `v1` signature of `header` verifies with `secret`, as a receiver checks. */
    function verifies(header: string, secret: string, content: string): boolean {
      const expected = createHmac('sha256', Buffer.from(secret.slice('whsec_'.length), 'base64'))
        .update(content)
        .digest();
      return header.split(' ').some((signature) => {
        const actual = Buffer.from(signature.slice('v1,'.length), 'base64');
        return (
          signature.startsWith('v1,') &&
          actual.length === expected.length &&
          timingSafeEqual(actual, expected)
        );
      });
    }

    it('keeps both webhook signatures valid through a rotation until the old secret is retired', async () => {
      const { factory, signer, advance } = rotating();
      const realmId = await seedRealm('https://a.example.test');
      const scope = { realmId, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
      const [old] = await factory.createKey(scope);
      const message = { realmId, subscriptionId: 'sub-1', id: 'evt_1', body: '{"a":1}' };
      const sign = (timestamp: number) => signer.signWebhook('delivery', { ...message, timestamp });
      const content = (timestamp: number) => `evt_1.${timestamp}.{"a":1}`;
      const oldSecret = old.secret as string;

      const before = await sign(1);
      expect(verifies(before, oldSecret, content(1))).toBe(true);

      advance(DAY_MS);
      const [next] = await factory.createKey({ ...scope, status: 'next' });
      const newSecret = next.secret as string;
      // Every message of the overlap carries both signatures, so a receiver
      // verifies with either secret, whenever it switches.
      for (const day of [0, 3, 6]) {
        if (day > 0) advance(3 * DAY_MS);
        const header = await sign(100 + day);
        expect(header.split(' ')).toHaveLength(2);
        expect(verifies(header, oldSecret, content(100 + day))).toBe(true);
        expect(verifies(header, newSecret, content(100 + day))).toBe(true);
        await expect(factory.activateNextKey(scope)).rejects.toMatchObject({
          reason: 'OVERLAP_NOT_ELAPSED',
        });
      }

      advance(DAY_MS);
      await expect(factory.activateNextKey(scope)).resolves.toMatchObject({
        activatedKid: next.kid,
        retiredKid: old.kid,
      });
      const after = await sign(200);

      expect(after.split(' ')).toHaveLength(1);
      expect(verifies(after, newSecret, content(200))).toBe(true);
      expect(verifies(after, oldSecret, content(200))).toBe(false);
      const { rows } = await db().query(
        'SELECT kid, status FROM realm_keys WHERE realm_id = $1 ORDER BY created_at',
        [realmId]
      );
      expect(rows).toEqual([
        { kid: old.kid, status: 'retired' },
        { kid: next.kid, status: 'active' },
      ]);
    });

    it('serves the next client-assertion key before it signs, and the retired one until its window closes', async () => {
      const { factory, signer, store, advance } = rotating();
      const realmId = await seedRealm('https://a.example.test');
      store.upstreamClients.set(`${realmId}/idp-1`, { clientId: 'qauth-at-idp' });
      const scope = { realmId, purpose: 'upstream_client_assertion', scopeId: 'idp-1' } as const;
      const [old] = await factory.createKey(scope);
      advance(DAY_MS);
      const [next] = await factory.createKey({ ...scope, status: 'next' });
      const assertion = () =>
        signer.signClientAssertion('api', {
          realmId,
          providerId: 'idp-1',
          audience: 'https://idp.example.test',
          claims: { jti: `j-${Math.random()}`, exp: NOW / 1000 + 10 * 86_400 * 30 },
        });
      const kids = async () =>
        (await signer.getUpstreamJwks('api', realmId, 'idp-1')).keys.map((key) => key.kid);

      expect(decodeProtectedHeader(await assertion()).kid).toBe(old.kid);
      expect(await kids()).toEqual([old.kid, next.kid]);

      advance(7 * DAY_MS);
      await factory.activateNextKey(scope);
      const token = await assertion();

      expect(decodeProtectedHeader(token)).toMatchObject({
        kid: next.kid,
        typ: 'client-authentication+jwt',
      });
      const jwks = await signer.getUpstreamJwks('api', realmId, 'idp-1');
      const { claims } = await verifyWithJwks(token, jwks, 'qauth-at-idp');
      expect(claims).toMatchObject({ sub: 'qauth-at-idp', aud: 'https://idp.example.test' });
      expect(await kids()).toEqual([old.kid, next.kid]);
      advance(14 * DAY_MS);
      expect(await kids()).toEqual([next.kid]);
      expect((await signer.getJwks('api', realmId)).keys).toEqual([]);
    });

    it('signs nothing more for a subscription once its keys are deleted', async () => {
      const { factory, signer } = rotating();
      const realmId = await seedRealm('https://a.example.test');
      const scope = { realmId, purpose: 'webhook_signing', scopeId: 'sub-1' } as const;
      await factory.createKey(scope);
      const request = { realmId, subscriptionId: 'sub-1', id: 'evt_1', timestamp: 1, body: '' };
      await signer.signWebhook('delivery', request);

      await factory.deleteScopedKeys(scope);

      await expect(signer.signWebhook('delivery', request)).rejects.toBeInstanceOf(
        SignerKeyNotFoundError
      );
      const { rows } = await db().query('SELECT count(*)::int AS n FROM realm_keys');
      expect(rows[0].n).toBe(0);
    });
  });

  it('encrypts with the stored data key and hands out the stored cookie secret', async () => {
    const { signer, provision } = setup();
    const realmId = await seedRealm('https://a.example.test');
    await provision(realmId);

    const ciphertext = await signer.encrypt('local', {
      realmId,
      plaintext: Buffer.from('secret'),
      context: 'table/row',
    });
    const secrets = await signer.getCookieSecrets('local', realmId);
    const { rows } = await db().query<{ kid: string; purpose: string }>(
      `SELECT kid, purpose FROM realm_keys WHERE realm_id = $1 AND purpose IN ('data_at_rest', 'cookie_hmac')`,
      [realmId]
    );

    expect(ciphertext.split('.')[1]).toBe(rows.find((row) => row.purpose === 'data_at_rest')?.kid);
    expect(await signer.decrypt('local', { realmId, ciphertext, context: 'table/row' })).toEqual(
      Buffer.from('secret')
    );
    expect(secrets.current.kid).toBe(rows.find((row) => row.purpose === 'cookie_hmac')?.kid);
    expect(secrets.current.secret).toHaveLength(32);
  });
});
