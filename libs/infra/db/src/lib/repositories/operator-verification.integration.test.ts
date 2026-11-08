/**
 * The two functions `users.verify` runs through as the admin role (migration
 * 0070, #1052), against real Postgres: what an account's credentials prove,
 * read without their secrets, and the write of the verification's two
 * columns alone.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { users } from '../schema/core';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository } from './realms.repository';
import { createUserCredentialsRepository } from './user-credentials.repository';
import { createUsersRepository } from './users.repository';

const ADMIN = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e72';

describe("users.verify's functions (real Postgres)", () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
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

  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx.database.db;
  }

  async function seed(realmName: string, enabled = true) {
    const realm = await createRealmsRepository(db()).create({ name: realmName });
    const user = await createUsersRepository(db()).create(
      { realmId: realm.id, enabled },
      {
        providerType: 'password',
        externalSub: `${realmName}@example.com`,
        credentialData: { password_hash: '$argon2id$secret-hash', email_verified: false },
      }
    );
    return { realm, user };
  }

  it("returns the account's credentials in its realm with what each proves, and nothing secret", async () => {
    const { realm, user } = await seed('proofs-1');
    const credentials = createUserCredentialsRepository(db());
    await credentials.create({
      userId: user.id,
      realmId: realm.id,
      providerType: 'webauthn',
      externalSub: 'key-1',
      credentialData: { public_key: 'secret-key', counter: 0, user_verified: true },
    });
    await credentials.create({
      userId: user.id,
      realmId: realm.id,
      providerType: 'oidc_corp',
      externalSub: 'sub-1',
      credentialData: { kind: 'upstream', iss: 'https://idp.example.com', claims: { a: 1 } },
    });

    const rows = await credentials.findProofsByUserId(realm.id, user.id);
    const byType = Object.fromEntries(rows.map((row) => [row.providerType, row]));
    expect(byType['password']).toMatchObject({
      isPrimary: true,
      disabledAt: null,
      identifier: 'proofs-1@example.com',
      proofData: { email_verified: false },
    });
    expect(byType['webauthn']).toMatchObject({
      isPrimary: false,
      identifier: null,
      proofData: { user_verified: true },
    });
    expect(byType['oidc_corp']).toMatchObject({
      identifier: null,
      proofData: { kind: 'upstream' },
    });
    const shown = JSON.stringify(rows);
    expect(shown).not.toContain('secret-hash');
    expect(shown).not.toContain('secret-key');
    expect(shown).not.toContain('claims');

    // Another realm's id finds none of them.
    const other = await createRealmsRepository(db()).create({ name: 'proofs-other' });
    expect(await credentials.findProofsByUserId(other.id, user.id)).toEqual([]);
  });

  it('records the admin as operator:<id> on an enabled account once, and nothing else', async () => {
    const { realm, user } = await seed('record-1');
    const repository = createUsersRepository(db());
    const before = Date.now();
    const recorded = await repository.recordOperatorVerification(realm.id, user.id, ADMIN);
    expect(recorded).toMatchObject({ id: user.id, operatorVerifiedBy: `operator:${ADMIN}` });
    expect(recorded?.operatorVerifiedAt).toBeGreaterThanOrEqual(before);
    const [row] = await db().select().from(users).where(eq(users.id, user.id));
    expect(row).toMatchObject({
      enabled: true,
      operatorVerifiedBy: `operator:${ADMIN}`,
      operatorVerifiedAt: recorded?.operatorVerifiedAt,
      updatedAt: recorded?.operatorVerifiedAt,
    });

    // Already verified, another realm, a disabled account, a malformed id:
    // nothing is written.
    expect(await repository.recordOperatorVerification(realm.id, user.id, ADMIN)).toBeUndefined();
    const other = await createRealmsRepository(db()).create({ name: 'record-other' });
    const elsewhere = await seed('record-2');
    expect(
      await repository.recordOperatorVerification(other.id, elsewhere.user.id, ADMIN)
    ).toBeUndefined();
    const disabled = await seed('record-3', false);
    expect(
      await repository.recordOperatorVerification(disabled.realm.id, disabled.user.id, ADMIN)
    ).toBeUndefined();
    expect(
      await repository.recordOperatorVerification(realm.id, 'not-a-uuid', ADMIN)
    ).toBeUndefined();
    const [untouched] = await db().select().from(users).where(eq(users.id, elsewhere.user.id));
    expect(untouched.operatorVerifiedAt).toBeNull();
  });
});
