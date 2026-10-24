/**
 * Real-Postgres integration tests for the realm key tables (issue #461).
 *
 * The rules under test live in the DDL, so only a database can prove them:
 * the partial unique index that allows one active key per realm, purpose,
 * scope and algorithm, the per-realm `kid` uniqueness, the CHECKs, and the
 * split that lets a role read `realm_public_keys` without any access to
 * `realm_keys`. The sibling unit suite pins which columns each repository
 * method reads.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { NewRealmKey, RealmKeysRepository } from '../../types';
import { realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmKeysRepository } from './realm-keys.repository';

const PUBLIC_JWK = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const PUBLISH_AT = 1_800_000_000_000;

describe('realm_keys integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let keys: RealmKeysRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    keys = createRealmKeysRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  async function seedRealm(): Promise<string> {
    if (!ctx) throw new Error('no ctx');
    const [realm] = await ctx.database.db
      .insert(realms)
      .values({ name: `realm-${Math.random().toString(36).slice(2)}` })
      .returning({ id: realms.id });
    return realm.id;
  }

  /**
   * A key row with distinct wrapped bytes and a fresh `kid`. Keeps the types
   * of `overrides`, so a row given `publishAt` can carry a public JWK.
   */
  function keyRow<T extends Partial<NewRealmKey> = Record<never, never>>(
    realmId: string,
    overrides: T = {} as T
  ): NewRealmKey & T {
    return {
      realmId,
      purpose: 'token_signing',
      algorithm: 'EdDSA',
      kid: `kid-${Math.random().toString(36).slice(2)}`,
      status: 'active',
      ciphertext: Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x80]),
      iv: Buffer.alloc(12, 7),
      wrappedDek: Buffer.alloc(40, 9),
      kekRef: '0123456789abcdef',
      aadVersion: 1,
      ...overrides,
    };
  }

  /** The Postgres error behind a rejected promise: `code` and `constraint`. */
  async function pgError(
    promise: Promise<unknown>
  ): Promise<{ code?: string; constraint?: string }> {
    try {
      await promise;
    } catch (error) {
      let current: unknown = error;
      while (current && typeof current === 'object') {
        const candidate = current as { code?: unknown; constraint?: unknown; cause?: unknown };
        if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
          return { code: candidate.code, constraint: candidate.constraint as string | undefined };
        }
        current = candidate.cause;
      }
      throw error;
    }
    throw new Error('expected the statement to fail');
  }

  /** Insert a `realm_keys` row with raw SQL, so the CHECKs are hit directly. */
  function insertKeyRow(
    realmId: string,
    columns: {
      status?: string;
      scopeId?: string | null;
      publishAt?: number | null;
      unpublishAt?: number | null;
      compromisedAt?: number | null;
    }
  ): Promise<unknown> {
    return pool().query(
      `INSERT INTO realm_keys
         (realm_id, purpose, scope_id, algorithm, kid, status, ciphertext, iv, wrapped_dek,
          kek_ref, aad_version, publish_at, unpublish_at, compromised_at)
       VALUES ($1, 'token_signing', $2, 'EdDSA', $3, $4, '\\x00', '\\x00', '\\x00',
          'kek', 1, $5, $6, $7)`,
      [
        realmId,
        columns.scopeId ?? null,
        `kid-${Math.random().toString(36).slice(2)}`,
        columns.status ?? 'retired',
        columns.publishAt ?? null,
        columns.unpublishAt ?? null,
        columns.compromisedAt ?? null,
      ]
    );
  }

  describe('one active key per realm, purpose, scope and algorithm', () => {
    it('refuses a second active key for the same tuple and allows it in another realm', async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      await keys.create({ key: keyRow(realmA) });

      const second = keys.create({ key: keyRow(realmA) });
      await expect(second).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(second).rejects.toMatchObject({ constraint: 'idx_realm_keys_one_active' });

      await expect(keys.create({ key: keyRow(realmB) })).resolves.toMatchObject({
        realmId: realmB,
        status: 'active',
      });
    });

    it('refuses a second active unscoped key: NULL scopes do not slip past the index', async () => {
      const realmId = await seedRealm();
      await keys.create({ key: keyRow(realmId, { scopeId: null }) });

      await expect(keys.create({ key: keyRow(realmId, { scopeId: null }) })).rejects.toMatchObject({
        constraint: 'idx_realm_keys_one_active',
      });
    });

    it('refuses a second active key for the same scope and allows another scope', async () => {
      const realmId = await seedRealm();
      const webhook = { purpose: 'webhook_signing', algorithm: 'HS256' };
      await keys.create({ key: keyRow(realmId, { ...webhook, scopeId: 'subscription-1' }) });

      await expect(
        keys.create({ key: keyRow(realmId, { ...webhook, scopeId: 'subscription-1' }) })
      ).rejects.toMatchObject({ constraint: 'idx_realm_keys_one_active' });
      await expect(
        keys.create({ key: keyRow(realmId, { ...webhook, scopeId: 'subscription-2' }) })
      ).resolves.toMatchObject({ scopeId: 'subscription-2' });
      // A scoped key does not collide with the unscoped one of the same purpose.
      await expect(keys.create({ key: keyRow(realmId, webhook) })).resolves.toMatchObject({
        scopeId: null,
      });
    });

    it('allows both keys of a hybrid pair to be active, and next or retired keys beside them', async () => {
      const realmId = await seedRealm();
      const pairId = '0190a000-0000-7000-8000-00000000babe';
      await keys.create({ key: keyRow(realmId, { algorithm: 'EdDSA', pairId }) });
      await keys.create({ key: keyRow(realmId, { algorithm: 'ML-DSA-65', pairId }) });
      await keys.create({ key: keyRow(realmId, { status: 'next' }) });
      await keys.create({ key: keyRow(realmId, { status: 'next' }) });
      await keys.create({ key: keyRow(realmId, { status: 'retired' }) });

      const active = await keys.listByRealm(realmId, { status: 'active' });
      expect(active.map((key) => key.algorithm).sort()).toEqual(['EdDSA', 'ML-DSA-65']);
      expect(active.every((key) => key.pairId === pairId)).toBe(true);
    });

    it('refuses an empty scope_id, which would collide with the unscoped key', async () => {
      const realmId = await seedRealm();

      await expect(pgError(insertKeyRow(realmId, { scopeId: '' }))).resolves.toEqual({
        code: '23514',
        constraint: 'realm_keys_scope_id_not_empty',
      });
    });
  });

  describe('kid', () => {
    it('is unique within a realm, across purposes and statuses', async () => {
      const realmId = await seedRealm();
      await keys.create({ key: keyRow(realmId, { kid: 'shared-kid' }) });

      const duplicate = keys.create({
        key: keyRow(realmId, { kid: 'shared-kid', purpose: 'event_signing', status: 'next' }),
      });
      await expect(duplicate).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(duplicate).rejects.toMatchObject({
        constraint: 'realm_keys_realm_id_kid_unique',
      });
    });

    it('may repeat in another realm', async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      await keys.create({ key: keyRow(realmA, { kid: 'shared-kid' }) });

      await expect(
        keys.create({ key: keyRow(realmB, { kid: 'shared-kid' }) })
      ).resolves.toMatchObject({ realmId: realmB, kid: 'shared-kid' });
    });
  });

  describe('CHECK rules', () => {
    it('refuses a compromised key without compromised_at', async () => {
      const realmId = await seedRealm();

      await expect(pgError(insertKeyRow(realmId, { status: 'compromised' }))).resolves.toEqual({
        code: '23514',
        constraint: 'realm_keys_compromised_at_matches_status',
      });
    });

    it('refuses compromised_at on a key that is not compromised', async () => {
      const realmId = await seedRealm();

      await expect(
        pgError(insertKeyRow(realmId, { status: 'retired', compromisedAt: PUBLISH_AT }))
      ).resolves.toEqual({
        code: '23514',
        constraint: 'realm_keys_compromised_at_matches_status',
      });
    });

    it('accepts a compromised key with compromised_at', async () => {
      const realmId = await seedRealm();

      await expect(
        insertKeyRow(realmId, { status: 'compromised', compromisedAt: PUBLISH_AT })
      ).resolves.toBeDefined();
    });

    it('refuses an unpublish_at before publish_at on both tables', async () => {
      const realmId = await seedRealm();

      await expect(
        pgError(insertKeyRow(realmId, { publishAt: PUBLISH_AT, unpublishAt: PUBLISH_AT - 1 }))
      ).resolves.toEqual({ code: '23514', constraint: 'realm_keys_unpublish_not_before_publish' });

      const key = await keys.create({ key: keyRow(realmId, { publishAt: PUBLISH_AT }) });
      await expect(
        pgError(
          pool().query(
            `INSERT INTO realm_public_keys
               (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at, unpublish_at)
             VALUES ($1, $2, 'token_signing', 'EdDSA', 'active', $3, $4, $5)`,
            [realmId, key.kid, PUBLIC_JWK, PUBLISH_AT, PUBLISH_AT - 1]
          )
        )
      ).resolves.toEqual({
        code: '23514',
        constraint: 'realm_public_keys_unpublish_not_before_publish',
      });
    });

    it('accepts an unpublish_at equal to publish_at', async () => {
      const realmId = await seedRealm();

      await expect(
        insertKeyRow(realmId, { publishAt: PUBLISH_AT, unpublishAt: PUBLISH_AT })
      ).resolves.toBeDefined();
    });

    it.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'priv'])(
      "refuses a public JWK that carries the private member '%s'",
      async (member) => {
        const realmId = await seedRealm();

        await expect(
          pgError(
            keys.create({
              key: keyRow(realmId, { publishAt: PUBLISH_AT }),
              publicJwk: { ...PUBLIC_JWK, [member]: 'secret' },
            })
          )
        ).resolves.toEqual({
          code: '23514',
          constraint: 'realm_public_keys_public_jwk_no_private_members',
        });
      }
    );
  });

  describe('realm_public_keys', () => {
    it('create writes the public row from the key row', async () => {
      const realmId = await seedRealm();
      const key = await keys.create({
        key: keyRow(realmId, { publishAt: PUBLISH_AT, unpublishAt: PUBLISH_AT + 10 }),
        publicJwk: PUBLIC_JWK,
      });

      const { rows } = await pool().query(`SELECT * FROM realm_public_keys`);
      expect(rows).toEqual([
        {
          realm_id: realmId,
          kid: key.kid,
          purpose: 'token_signing',
          algorithm: 'EdDSA',
          status: 'active',
          public_jwk: PUBLIC_JWK,
          publish_at: String(PUBLISH_AT),
          unpublish_at: String(PUBLISH_AT + 10),
        },
      ]);
    });

    it('create writes no public row for a symmetric key', async () => {
      const realmId = await seedRealm();
      await keys.create({ key: keyRow(realmId, { purpose: 'cookie_hmac', algorithm: 'HS256' }) });

      const { rows } = await pool().query(`SELECT count(*)::int AS n FROM realm_public_keys`);
      expect(rows[0].n).toBe(0);
    });

    it('create stores neither row when the public row is refused', async () => {
      const realmId = await seedRealm();
      const kid = 'rolled-back';

      await expect(
        keys.create({
          key: keyRow(realmId, { kid, publishAt: PUBLISH_AT }),
          publicJwk: { ...PUBLIC_JWK, d: 'secret' },
        })
      ).rejects.toBeDefined();

      await expect(keys.findByKid(realmId, kid)).resolves.toBeUndefined();
    });

    it.each([
      ['an oct key', { kty: 'oct', alg: 'HS256' }],
      ['no kty', { crv: 'Ed25519', x: PUBLIC_JWK.x }],
    ])('refuses a public JWK with %s', async (_label, publicJwk) => {
      const realmId = await seedRealm();

      await expect(
        pgError(keys.create({ key: keyRow(realmId, { publishAt: PUBLISH_AT }), publicJwk }))
      ).resolves.toEqual({ code: '23514', constraint: 'realm_public_keys_public_jwk_asymmetric' });
    });

    it('create inside an outer transaction rolls back only its own rows', async () => {
      if (!ctx) throw new Error('no ctx');
      const realmId = await seedRealm();

      await ctx.database.db.transaction(async (tx) => {
        await expect(
          keys.create(
            {
              key: keyRow(realmId, { kid: 'refused', publishAt: PUBLISH_AT }),
              publicJwk: { ...PUBLIC_JWK, d: 'secret' },
            },
            tx
          )
        ).rejects.toBeDefined();
        // The savepoint rolled back; the outer transaction is still usable.
        await keys.create(
          { key: keyRow(realmId, { kid: 'kept', publishAt: PUBLISH_AT }), publicJwk: PUBLIC_JWK },
          tx
        );
      });

      const { rows } = await pool().query(
        `SELECT k.kid, p.kid AS public_kid
           FROM realm_keys k LEFT JOIN realm_public_keys p USING (realm_id, kid)
          ORDER BY k.kid`
      );
      expect(rows).toEqual([{ kid: 'kept', public_kid: 'kept' }]);
    });
    it('follows a status change on the key row, compromised included', async () => {
      const realmId = await seedRealm();
      const key = await keys.create({
        key: keyRow(realmId, { status: 'next' as const, publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      const publicStatus = async () =>
        (await pool().query(`SELECT status FROM realm_public_keys WHERE kid = $1`, [key.kid]))
          .rows[0].status;

      await pool().query(`UPDATE realm_keys SET status = 'active' WHERE id = $1`, [key.id]);
      expect(await publicStatus()).toBe('active');

      await pool().query(
        `UPDATE realm_keys SET status = 'compromised', compromised_at = $2 WHERE id = $1`,
        [key.id, PUBLISH_AT + 1]
      );
      expect(await publicStatus()).toBe('compromised');
    });

    it('refuses a public row whose status, purpose or algorithm differs from the key row', async () => {
      const realmId = await seedRealm();
      const key = await keys.create({
        key: keyRow(realmId, { publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });

      // Changing the copy alone, e.g. un-compromising a key in the JWKS.
      await expect(
        pgError(
          pool().query(`UPDATE realm_public_keys SET status = 'retired' WHERE kid = $1`, [key.kid])
        )
      ).resolves.toEqual({ code: '23503', constraint: 'realm_public_keys_realm_key_fk' });

      await pool().query(`DELETE FROM realm_public_keys WHERE kid = $1`, [key.kid]);
      for (const mismatch of [
        { purpose: 'token_signing', algorithm: 'EdDSA', status: 'next' },
        { purpose: 'event_signing', algorithm: 'EdDSA', status: 'active' },
        { purpose: 'token_signing', algorithm: 'ES256', status: 'active' },
      ]) {
        await expect(
          pgError(
            pool().query(
              `INSERT INTO realm_public_keys
                 (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)`,
              [
                realmId,
                key.kid,
                mismatch.purpose,
                mismatch.algorithm,
                mismatch.status,
                PUBLIC_JWK,
                PUBLISH_AT,
              ]
            )
          )
        ).resolves.toEqual({ code: '23503', constraint: 'realm_public_keys_realm_key_fk' });
      }
    });

    it('refuses a public row with no key behind it', async () => {
      const realmId = await seedRealm();

      await expect(
        pgError(
          pool().query(
            `INSERT INTO realm_public_keys
               (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at)
             VALUES ($1, 'no-such-key', 'token_signing', 'EdDSA', 'active', $2, $3)`,
            [realmId, PUBLIC_JWK, PUBLISH_AT]
          )
        )
      ).resolves.toEqual({ code: '23503', constraint: 'realm_public_keys_realm_key_fk' });
    });

    it('loses its row with the key row, and both go with the realm', async () => {
      const realmId = await seedRealm();
      const first = await keys.create({
        key: keyRow(realmId, { publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      await keys.create({
        key: keyRow(realmId, { status: 'next' as const, publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });

      await pool().query(`DELETE FROM realm_keys WHERE id = $1`, [first.id]);
      const afterKey = await pool().query(`SELECT kid FROM realm_public_keys`);
      expect(afterKey.rows).toHaveLength(1);

      await pool().query(`DELETE FROM realms WHERE id = $1`, [realmId]);
      const remaining = await pool().query(
        `SELECT (SELECT count(*) FROM realm_keys)::int AS keys,
                (SELECT count(*) FROM realm_public_keys)::int AS public_keys`
      );
      expect(remaining.rows[0]).toEqual({ keys: 0, public_keys: 0 });
    });
  });

  describe('a role granted only SELECT on realm_public_keys', () => {
    const ROLE = 'qauth_public_reader';
    let reader: Pool | undefined;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      // Login roles are cluster-wide and outlive `reset()`; the container is
      // per file, so creating it once here is enough.
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      await pool().query(`GRANT SELECT ON realm_public_keys TO ${ROLE}`);
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      reader = new Pool({ connectionString: url.toString(), max: 1 });
    });

    afterAll(async () => {
      await reader?.end();
    });

    function readerPool(): Pool {
      if (!reader) throw new Error('no reader pool');
      return reader;
    }

    it('can read realm_public_keys and cannot read realm_keys', async () => {
      const realmId = await seedRealm();
      const key = await keys.create({
        key: keyRow(realmId, { publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });

      const { rows } = await readerPool().query(
        `SELECT kid, public_jwk FROM realm_public_keys WHERE realm_id = $1`,
        [realmId]
      );
      expect(rows).toEqual([{ kid: key.kid, public_jwk: PUBLIC_JWK }]);

      // 42501 = insufficient_privilege, for the whole table and for a single
      // harmless-looking column alike.
      await expect(pgError(readerPool().query(`SELECT * FROM realm_keys`))).resolves.toMatchObject({
        code: '42501',
      });
      await expect(
        pgError(readerPool().query(`SELECT kid FROM realm_keys`))
      ).resolves.toMatchObject({ code: '42501' });
    });

    it('cannot write realm_public_keys', async () => {
      const realmId = await seedRealm();
      const key = await keys.create({ key: keyRow(realmId, { publishAt: PUBLISH_AT }) });

      await expect(
        pgError(
          readerPool().query(
            `INSERT INTO realm_public_keys
               (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at)
             VALUES ($1, $2, 'token_signing', 'EdDSA', 'active', $3, $4)`,
            [realmId, key.kid, PUBLIC_JWK, PUBLISH_AT]
          )
        )
      ).resolves.toMatchObject({ code: '42501' });
    });
  });

  describe('repository', () => {
    it('getWrappedForSigner returns the stored bytes unchanged', async () => {
      const realmId = await seedRealm();
      const row = keyRow(realmId);
      await keys.create({ key: row });

      const wrapped = await keys.getWrappedForSigner(realmId, row.kid);

      expect(wrapped?.ciphertext.equals(row.ciphertext)).toBe(true);
      expect(wrapped?.iv.equals(row.iv)).toBe(true);
      expect(wrapped?.wrappedDek.equals(row.wrappedDek)).toBe(true);
      expect(wrapped).toMatchObject({ kekRef: row.kekRef, aadVersion: 1 });
    });

    it("never opens another realm's key by kid", async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      const row = keyRow(realmA);
      await keys.create({ key: row });

      await expect(keys.getWrappedForSigner(realmB, row.kid)).resolves.toBeUndefined();
      await expect(keys.findByKid(realmB, row.kid)).resolves.toBeUndefined();
    });

    it('create, findByKid and listByRealm return no wrapped columns', async () => {
      const realmId = await seedRealm();
      const row = keyRow(realmId);
      const created = await keys.create({ key: row });
      const found = await keys.findByKid(realmId, row.kid);
      const listed = await keys.listByRealm(realmId);

      expect(listed).toHaveLength(1);
      for (const key of [created, found, ...listed]) {
        expect(key).toBeDefined();
        for (const column of ['ciphertext', 'iv', 'wrappedDek']) {
          expect(key).not.toHaveProperty(column);
        }
      }
      expect(found).toEqual(created);
    });

    it('listByRealm narrows by purpose, scope and status, oldest first', async () => {
      const realmId = await seedRealm();
      const otherRealm = await seedRealm();
      const signing = await keys.create({ key: keyRow(realmId) });
      const next = await keys.create({ key: keyRow(realmId, { status: 'next' }) });
      const hmac = await keys.create({
        key: keyRow(realmId, { purpose: 'cookie_hmac', algorithm: 'HS256' }),
      });
      const webhook = await keys.create({
        key: keyRow(realmId, {
          purpose: 'webhook_signing',
          algorithm: 'HS256',
          scopeId: 'subscription-1',
        }),
      });
      await keys.create({ key: keyRow(otherRealm) });

      const kids = async (filter?: Parameters<RealmKeysRepository['listByRealm']>[1]) =>
        (await keys.listByRealm(realmId, filter)).map((key) => key.kid);

      expect(await kids()).toEqual([signing.kid, next.kid, hmac.kid, webhook.kid]);
      expect(await kids({ purpose: 'token_signing' })).toEqual([signing.kid, next.kid]);
      expect(await kids({ purpose: 'token_signing', status: 'next' })).toEqual([next.kid]);
      expect(await kids({ scopeId: 'subscription-1' })).toEqual([webhook.kid]);
      expect(await kids({ scopeId: null })).toEqual([signing.kid, next.kid, hmac.kid]);
    });

    it('listPublicByRealm returns the public rows of one realm, by purpose, publish_at and kid', async () => {
      const realmId = await seedRealm();
      const otherRealm = await seedRealm();
      const event = await keys.create({
        key: keyRow(realmId, { purpose: 'event_signing', publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      const later = await keys.create({
        key: keyRow(realmId, { status: 'next' as const, publishAt: PUBLISH_AT + 1 }),
        publicJwk: PUBLIC_JWK,
      });
      const first = await keys.create({
        key: keyRow(realmId, { publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      await keys.create({ key: keyRow(realmId, { purpose: 'cookie_hmac', algorithm: 'HS256' }) });
      await keys.create({
        key: keyRow(otherRealm, { publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });

      const listed = await keys.listPublicByRealm(realmId);

      expect(listed.map((key) => key.kid)).toEqual([event.kid, first.kid, later.kid]);
      expect(listed[2]).toMatchObject({
        realmId,
        purpose: 'token_signing',
        algorithm: 'EdDSA',
        status: 'next',
        publicJwk: PUBLIC_JWK,
        publishAt: PUBLISH_AT + 1,
        unpublishAt: null,
      });
    });

    it('updateStatus moves a rotation one step and the public row follows', async () => {
      const realmId = await seedRealm();
      const scoped = { purpose: 'upstream_client_assertion', algorithm: 'RS256', scopeId: 'idp-1' };
      const old = await keys.create({
        key: keyRow(realmId, { ...scoped, publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      const next = await keys.create({
        key: keyRow(realmId, { ...scoped, status: 'next' as const, publishAt: PUBLISH_AT }),
        publicJwk: PUBLIC_JWK,
      });
      const switchAt = PUBLISH_AT + 7 * 86_400_000;
      const unpublishAt = switchAt + 14 * 86_400_000;

      // Retire first: the one-active index refuses the other order.
      await expect(
        keys.updateStatus(realmId, next.kid, { status: 'active', activateAt: switchAt })
      ).rejects.toMatchObject({
        cause: { code: '23505', constraint: 'idx_realm_keys_one_active' },
      });
      const retired = await keys.updateStatus(realmId, old.kid, {
        status: 'retired',
        retireAt: switchAt,
        unpublishAt,
      });
      const activated = await keys.updateStatus(realmId, next.kid, {
        status: 'active',
        activateAt: switchAt,
      });

      expect(retired).toMatchObject({ status: 'retired', retireAt: switchAt, unpublishAt });
      expect(retired).not.toHaveProperty('ciphertext');
      expect(activated).toMatchObject({ status: 'active', activateAt: switchAt, retireAt: null });
      const published = await keys.listPublicByRealm(realmId);
      expect(published.find((key) => key.kid === old.kid)).toMatchObject({
        status: 'retired',
        unpublishAt,
      });
      expect(published.find((key) => key.kid === next.kid)).toMatchObject({
        status: 'active',
        unpublishAt: null,
      });
    });

    it('updateStatus leaves a key that is not in the status the step starts from', async () => {
      const realmId = await seedRealm();
      const active = await keys.create({ key: keyRow(realmId) });
      const retired = await keys.create({ key: keyRow(realmId, { status: 'retired' }) });
      const retire = { status: 'retired', retireAt: PUBLISH_AT, unpublishAt: null } as const;

      await expect(
        keys.updateStatus(realmId, active.kid, { status: 'active', activateAt: PUBLISH_AT })
      ).resolves.toBeUndefined();
      await expect(keys.updateStatus(realmId, retired.kid, retire)).resolves.toBeUndefined();
      await expect(
        keys.updateStatus(await seedRealm(), active.kid, retire)
      ).resolves.toBeUndefined();
      expect((await keys.findByKid(realmId, active.kid))?.status).toBe('active');
    });

    it('deleteByScope removes one scope and its public rows, and nothing else', async () => {
      const realmId = await seedRealm();
      const otherRealm = await seedRealm();
      const webhook = { purpose: 'webhook_signing', algorithm: 'HS256' };
      const upstream = { purpose: 'upstream_client_assertion', algorithm: 'RS256' };
      const gone = [
        await keys.create({ key: keyRow(realmId, { ...webhook, scopeId: 'sub-1' }) }),
        await keys.create({
          key: keyRow(realmId, { ...webhook, scopeId: 'sub-1', status: 'next' as const }),
        }),
      ];
      const kept = [
        await keys.create({ key: keyRow(realmId, { ...webhook, scopeId: 'sub-2' }) }),
        await keys.create({
          key: keyRow(realmId, { ...upstream, scopeId: 'sub-1', publishAt: PUBLISH_AT }),
          publicJwk: PUBLIC_JWK,
        }),
        await keys.create({ key: keyRow(realmId) }),
        await keys.create({ key: keyRow(otherRealm, { ...webhook, scopeId: 'sub-1' }) }),
      ];

      const deleted = await keys.deleteByScope(realmId, 'webhook_signing', 'sub-1');

      expect(deleted.sort()).toEqual(gone.map((key) => key.kid).sort());
      expect((await keys.listByRealm(realmId)).map((key) => key.kid).sort()).toEqual(
        kept
          .slice(0, 3)
          .map((key) => key.kid)
          .sort()
      );
      expect(await keys.listByRealm(otherRealm)).toHaveLength(1);
      expect((await keys.listPublicByRealm(realmId)).map((key) => key.kid)).toEqual([kept[1].kid]);

      // The provider's keys go the same way, with their public rows.
      await expect(
        keys.deleteByScope(realmId, 'upstream_client_assertion', 'sub-1')
      ).resolves.toEqual([kept[1].kid]);
      await expect(keys.listPublicByRealm(realmId)).resolves.toEqual([]);
      await expect(keys.deleteByScope(realmId, 'webhook_signing', 'sub-1')).resolves.toEqual([]);
    });
  });
});
