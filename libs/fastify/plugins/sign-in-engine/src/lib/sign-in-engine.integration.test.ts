/**
 * The sign-in engine over the auth server's adapters, against the migrated
 * schema in real Postgres (#614): the account directory over the real
 * repositories, Argon2id from the server's hasher.
 *
 * The case the issue names: a disabled user never completes a sign-in and no
 * state changes, the right password included. Every table of the schema is
 * compared before and after, so a write anywhere fails the test. An enabled
 * account completes through the same adapters, so the refusal is the
 * disabled flag's and not a broken setup.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { createHmac } from 'node:crypto';

import {
  createAdminGrantsRepository,
  createDatabase,
  createRealmsRepository,
  createUserCredentialsRepository,
  createUsersRepository,
  type DatabaseInstance,
} from '@qauth-labs/infra-db';
import { buildPasswordCredentialData } from '@qauth-labs/server-federation';
import { createPasswordHasher } from '@qauth-labs/server-password';
import {
  createSignInEngine,
  type RoundContext,
  type SignInAuditRecord,
  type SignInEngine,
  type SignInTransaction,
} from '@qauth-labs/server-sign-in-engine';
import { STEP_URNS } from '@qauth-labs/server-step-grammar';
import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createRepositoryAccountDirectory } from './account-directory';
import { signInAuditEvent } from './audit-events';
import { createArgon2PasswordVerifier } from './password-verifier';

const PASSWORD = 'a long passphrase nobody guesses 2026';

describe('the sign-in engine over the server adapters (real Postgres)', () => {
  let dockerUp = false;
  let container: StartedPostgres | undefined;
  let database: DatabaseInstance | undefined;
  let engine: SignInEngine;
  let realmId: string;
  let disabledUserId: string;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer({ schema: 'migrated' });
    database = createDatabase({ connectionString: container.connectionString });
    const { db } = database;
    const hasher = createPasswordHasher();
    const users = createUsersRepository(db);
    const userCredentials = createUserCredentialsRepository(db);

    const realm = await createRealmsRepository(db).create({ name: 'sign-in-engine' });
    realmId = realm.id;
    const hash = await hasher.hashPassword(PASSWORD);
    const seed = async (identifier: string, enabled: boolean) => {
      const user = await users.create({ realmId, enabled });
      await userCredentials.create({
        userId: user.id,
        realmId,
        providerType: 'password',
        externalSub: identifier,
        credentialData: buildPasswordCredentialData(hash, true),
      });
      return user.id;
    };
    disabledUserId = await seed('disabled@example.com', false);
    await seed('enabled@example.com', true);

    const log = { error: () => undefined };
    engine = createSignInEngine({
      accounts: createRepositoryAccountDirectory(
        { users, userCredentials, adminGrants: createAdminGrantsRepository(db) },
        log
      ),
      passwords: createArgon2PasswordVerifier(hasher, log),
      policy: { read: async () => ({ realm: 'off', client: 'off' }) },
      identifierDigest: async ({ realmId: realm, identifier }) =>
        createHmac('sha256', 'integration-key')
          .update(`${realm}\u0000${identifier}`)
          .digest('base64url'),
      requireVerifiedAccount: true,
    });
  }, 180_000);

  afterAll(async () => {
    await database?.close();
    await container?.stop();
  });

  /** Every row of every table of the schema, in a stable order. */
  async function snapshot(): Promise<Record<string, string[]>> {
    if (database === undefined) throw new Error('no database');
    const { rows: tables } = await database.pool.query<{ name: string }>(
      `SELECT table_name AS name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`
    );
    const result: Record<string, string[]> = {};
    for (const { name } of tables) {
      const { rows } = await database.pool.query(
        `SELECT row_to_json(t)::text AS row FROM "${name}" t`
      );
      result[name] = rows.map((row: { row: string }) => row.row).sort();
    }
    return result;
  }

  function context(records: SignInAuditRecord[], loginHint?: string): RoundContext {
    return {
      realm: { id: realmId },
      client: { id: 'native-app' },
      ...(loginHint === undefined ? {} : { loginHint }),
      audit: async (record) => {
        records.push(record);
      },
    };
  }

  const password = (value: string, loginHint?: string) => ({
    step: STEP_URNS.password,
    fields: { password: value, ...(loginHint === undefined ? {} : { login_hint: loginHint }) },
  });

  it('never completes a disabled user’s sign-in and changes nothing, its right password included', async (testCtx) => {
    if (!dockerUp) {
      testCtx.skip();
      return;
    }
    const before = await snapshot();
    const records: SignInAuditRecord[] = [];

    // Two rounds: the identifier from the request, then the right password.
    const first = await engine.advance(null, null, context(records, 'disabled@example.com'));
    expect(first).toMatchObject({ kind: 'step', offer: { current: { step: 'password' } } });
    const second = await engine.advance(
      first.transaction as SignInTransaction,
      password(PASSWORD),
      context(records, 'disabled@example.com')
    );
    // The one-call path: identifier and password in one round.
    const eager = await engine.advance(
      null,
      password(PASSWORD, 'disabled@example.com'),
      context(records)
    );

    for (const result of [second, eager]) {
      expect(result).toMatchObject({
        kind: 'step',
        offer: { current: { step: 'password', error: 'invalid_credentials' } },
      });
      expect(result.transaction).not.toHaveProperty('subject');
    }
    expect(JSON.stringify(records)).not.toContain(disabledUserId);
    expect(records.filter((record) => record.outcome === 'refused')).toEqual([
      expect.objectContaining({ step: 'password', reason: 'account_disabled' }),
      expect.objectContaining({ step: 'password', reason: 'account_disabled' }),
    ]);
    for (const record of records) expect(() => signInAuditEvent(record)).not.toThrow();

    // No row of any table changed: no session, no code, no token, no user update.
    expect(await snapshot()).toEqual(before);
  });

  it('answers a disabled user exactly as an identifier no account holds', async (testCtx) => {
    if (!dockerUp) {
      testCtx.skip();
      return;
    }
    const answers = [];
    for (const identifier of ['disabled@example.com', 'nobody@example.com']) {
      const result = await engine.advance(null, password(PASSWORD, identifier), context([]));
      answers.push(JSON.stringify({ ...result, transaction: undefined, personal: undefined }));
    }
    expect(answers[0]).toBe(answers[1]);
  });

  it('completes an enabled account’s sign-in through the same adapters, and writes nothing itself', async (testCtx) => {
    if (!dockerUp) {
      testCtx.skip();
      return;
    }
    const before = await snapshot();
    const result = await engine.advance(
      null,
      password(PASSWORD, 'enabled@example.com'),
      context([])
    );
    expect(result).toMatchObject({ kind: 'complete', signIn: { amr: ['pwd'] } });
    // The transport mints the session or the code; the engine writes nothing.
    expect(await snapshot()).toEqual(before);
  });
});
