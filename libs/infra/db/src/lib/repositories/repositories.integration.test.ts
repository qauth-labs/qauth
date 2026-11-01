/**
 * Real-DB repository integration tests (#167).
 *
 * Exercises the security-critical atomics against a throwaway Postgres 18
 * container with the real generated migrations applied — the parts that can
 * NOT be verified by the mocked-repo route tests:
 *
 *   - authorization-code single-use (markUsed CAS — second use fails)
 *   - refresh-token rotation + family-wide revocation on replay (RFC 9700)
 *   - consent revoke = soft-delete (row preserved) + upsertGrant scope union
 *   - realm-scoped unique constraints (users / oauth_clients)
 *
 * Requires Docker. Locally the suite skips when no daemon is reachable; on CI
 * it FAILS instead (see `requireDockerOrSkip`), because this file is the only
 * coverage for the real migrated DDL and a silent skip there would be
 * indistinguishable from a pass.
 *
 * Tagged via the `*.integration.test.ts` suffix so the fast unit run and the
 * coverage gate (vitest.config.ts) exclude it — CI runs it via the dedicated
 * `test-integration` target in the `integration` job of ci.yml.
 */
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { DbClient, RefreshToken, RefreshTokensRepository } from '../../types';
import { oauthClients, oauthConsents, refreshTokens } from '../schema';
import {
  createApiKeysRepository,
  createAuditLogsRepository,
  createAuthorizationCodesRepository,
  createOAuthClientsRepository,
  createOAuthConsentsRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
  createUserCredentialsRepository,
  createUsersRepository,
} from './index';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

describe('repository integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  // Resolved in beforeAll (Docker probe is async — avoids top-level await,
  // which the lib's CommonJS typecheck disallows). When Docker is absent each
  // test self-skips so non-Docker lanes stay green instead of failing.
  let dockerUp = false;

  // Container startup is paid once for the whole suite.
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

  // Non-null accessor: tests only run past the beforeEach guard when ctx is set.
  function db() {
    if (!ctx) throw new Error('integration db not initialised');
    return ctx;
  }

  // --- seed helpers --------------------------------------------------------

  async function seedRealm(name = 'default') {
    const realms = createRealmsRepository(db().database.db);
    return realms.create({ name });
  }

  async function seedUser(realmId: string) {
    const users = createUsersRepository(db().database.db);
    // #230: users is a pure identity anchor — realmId is the only required
    // field; credential data goes through user_credentials (seedCredential).
    return users.create({ realmId });
  }

  async function seedCredential(realmId: string, userId: string, email = 'user@example.com') {
    const credentials = createUserCredentialsRepository(db().database.db);
    return credentials.create({
      userId,
      realmId,
      providerType: 'password',
      externalSub: email.toLowerCase(),
      credentialData: { password_hash: 'argon2-hash', email_verified: true },
    });
  }

  async function seedClient(realmId: string, clientId = 'client-a') {
    const clients = createOAuthClientsRepository(db().database.db);
    return clients.create({
      realmId,
      clientId,
      clientSecretHash: 'secret-hash',
      name: 'Client A',
      redirectUris: ['https://app.example.com/cb'],
      scopes: ['read:foo', 'write:foo'],
      grantTypes: ['authorization_code', 'refresh_token'],
    });
  }

  // --- authorization-code single-use (CAS) ---------------------------------

  describe('authorization codes — single-use markUsed CAS', () => {
    it('marks a code used exactly once; the second use throws NotFoundError', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      const code = await codes.create({
        code: 'auth-code-123',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        scopes: ['read:foo'],
        expiresAt: Date.now() + 60_000,
      });

      const first = await codes.markUsed(code.id);
      expect(first.used).toBe(true);
      expect(first.usedAt).toBeTypeOf('number');

      // Second redemption must fail — the CAS `WHERE used = false` matches no
      // rows, so the repository surfaces NotFoundError.
      await expect(codes.markUsed(code.id)).rejects.toThrow();

      // And findByCode (used=false filter) no longer returns it.
      const after = await codes.findByCode(realm.id, 'auth-code-123');
      expect(after).toBeUndefined();
    });

    it('only one of two concurrent markUsed calls succeeds (race)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      const code = await codes.create({
        code: 'race-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        scopes: ['read:foo'],
        expiresAt: Date.now() + 60_000,
      });

      const results = await Promise.allSettled([codes.markUsed(code.id), codes.markUsed(code.id)]);
      const fulfilled = results.filter((r) => r.status === 'fulfilled');
      const rejected = results.filter((r) => r.status === 'rejected');

      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
    });

    it('does not return expired codes from findByCode', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      await codes.create({
        code: 'expired-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        scopes: ['read:foo'],
        expiresAt: Date.now() - 1_000,
      });

      expect(await codes.findByCode(realm.id, 'expired-code')).toBeUndefined();
    });

    it('invalidateForUser also ends a code that has just expired', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      // A redemption that read the code while it was live goes on to markUsed,
      // which does not look at the expiry again — so the invalidation must
      // not skip the row either.
      const code = await codes.create({
        code: 'just-expired-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        scopes: ['read:foo'],
        expiresAt: Date.now() - 1,
      });

      expect(await codes.invalidateForUser(user.id)).toBe(1);
      await expect(codes.markUsed(code.id)).rejects.toThrow();
    });

    it('invalidateForUserAndClient ends only that user-client pair', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const other = await seedUser(realm.id);
      const clientA = await seedClient(realm.id, 'client-a');
      const clientB = await seedClient(realm.id, 'client-b');
      const codes = createAuthorizationCodesRepository(db().database.db);
      const seedCode = (code: string, userId: string, oauthClientId: string) =>
        codes.create({
          code,
          oauthClientId,
          userId,
          redirectUri: 'https://app.example.com/cb',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'S256',
          scopes: ['read:foo'],
          expiresAt: Date.now() + 60_000,
        });
      await seedCode('pair-code', user.id, clientA.id);
      await seedCode('other-client-code', user.id, clientB.id);
      await seedCode('other-user-code', other.id, clientA.id);

      expect(await codes.invalidateForUserAndClient(user.id, clientA.id)).toBe(1);

      expect(await codes.findByCode(realm.id, 'pair-code')).toBeUndefined();
      expect(await codes.findByCode(realm.id, 'other-client-code')).toBeDefined();
      expect(await codes.findByCode(realm.id, 'other-user-code')).toBeDefined();
    });

    it.each(['logout', 'consent revocation'] as const)(
      '%s started while a redemption is uncommitted still revokes its refresh token (race)',
      async (kind) => {
        const realm = await seedRealm();
        const user = await seedUser(realm.id);
        const client = await seedClient(realm.id);
        const codes = createAuthorizationCodesRepository(db().database.db);
        const tokens = createRefreshTokensRepository(db().database.db);
        const code = await codes.create({
          code: 'in-flight-code',
          oauthClientId: client.id,
          userId: user.id,
          redirectUri: 'https://app.example.com/cb',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'S256',
          scopes: ['read:foo'],
          expiresAt: Date.now() + 60_000,
        });
        const revoke = {
          logout: async () => {
            await codes.invalidateForUser(user.id);
            await tokens.revokeAllForUser(user.id, 'logout');
          },
          'consent revocation': () =>
            db().database.db.transaction(async (tx) => {
              await codes.invalidateForUserAndClient(user.id, client.id, tx);
              await tokens.revokeAllForUserAndClient(user.id, client.id, 'consent_revoked', tx);
            }),
        }[kind];

        // The revocation starts on its own connection after the code is spent
        // and before the refresh token exists — the window the authorization
        // code grant used to leave open. Its code invalidation waits on the
        // row `markUsed` locked, so the sweep runs after the commit.
        let revocation: Promise<unknown> | undefined;
        await db().database.db.transaction(async (tx) => {
          await codes.markUsed(code.id, tx);
          revocation = revoke();
          await new Promise((resolve) => setTimeout(resolve, 200));
          await tokens.create(
            {
              tokenHash: 'v'.repeat(64),
              userId: user.id,
              oauthClientId: client.id,
              familyCreatedAt: Date.now(),
              familySessionExpiresAt: null,
              scopes: ['read:foo'],
              expiresAt: Date.now() + 600_000,
            },
            tx
          );
        });
        await revocation;

        expect(await tokens.findByUserId(user.id)).toHaveLength(0);
      }
    );
  });

  // --- opaque state/nonce are not length-bounded by the DDL (#316) ----------

  describe('authorization codes — long opaque state/nonce (#316)', () => {
    /**
     * `state` and `nonce` are opaque and client-owned: RFC 6749 §4.1.1 and OIDC
     * Core set NO length limit, and the values are round-tripped to the client
     * verbatim. They were `varchar(255)`, so a real client (Cursor's MCP client
     * base64url-encodes ~280 chars of workspace context into `state`) passed
     * both Zod layers and then 500'd here at code-mint with
     * "value too long for type character varying(255)".
     *
     * This is the ONLY place that failure is observable: the auth-server route
     * tests mock the repositories, so they can assert the untruncated value
     * reaches `create()` but never that Postgres accepts it. The columns are
     * now `text`; the DoS bound lives in the app layer
     * (`OAUTH_OPAQUE_PARAM_MAX_LENGTH`).
     */
    const LONG_STATE = Buffer.from(
      JSON.stringify({
        id: 7,
        owner: { workspaceId: '9f2c1ab47de35608b1e4c7a09d5f3e21' },
        attemptId: '3f6c2b18-9d47-4e5a-b0c1-7e2f8a4d9b63',
        surface: 'mcp_process',
        redirect: 'cursor://anysphere.cursor-mcp/oauth/user-qauth/callback',
      })
    ).toString('base64url');

    const LONG_NONCE = 'n'.repeat(300);

    it('stores and returns a ~280-char state and 300-char nonce untruncated', async () => {
      // Fails against varchar(255) with a Postgres 22001 string_data_right_truncation.
      expect(LONG_STATE.length).toBeGreaterThan(255);

      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      const created = await codes.create({
        code: 'long-state-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        state: LONG_STATE,
        nonce: LONG_NONCE,
        scopes: ['read:foo'],
        expiresAt: Date.now() + 60_000,
      });

      // INSERT ... RETURNING reflects what the column actually holds.
      expect(created.state).toBe(LONG_STATE);
      expect(created.nonce).toBe(LONG_NONCE);

      // And a full round-trip through a fresh SELECT — byte for byte, so the
      // client's `state` comes back exactly as it was sent (RFC 6749 §4.1.2).
      const found = await codes.findByCode(realm.id, 'long-state-code');
      expect(found?.state).toBe(LONG_STATE);
      expect(found?.nonce).toBe(LONG_NONCE);
    });

    it('accepts a state at the app-layer DoS bound (2048 chars)', async () => {
      // `text` has no length limit, so the 2048 app-layer cap is the only
      // bound — nothing below it may be rejected by storage.
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);

      const atBound = 'x'.repeat(2048);
      const created = await codes.create({
        code: 'bound-state-code',
        oauthClientId: client.id,
        userId: user.id,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'challenge',
        codeChallengeMethod: 'S256',
        state: atBound,
        expiresAt: Date.now() + 60_000,
      });

      expect(created.state).toHaveLength(2048);
      expect(created.state).toBe(atBound);
    });
  });

  // --- refresh-token rotation + family-wide revocation ----------------------

  describe('refresh tokens — rotation + family-wide revoke on replay', () => {
    async function seedToken(
      userId: string,
      clientId: string,
      tokenHash: string,
      familyId: string,
      overrides: Record<string, unknown> = {}
    ) {
      const tokens = createRefreshTokensRepository(db().database.db);
      return tokens.create({
        tokenHash,
        userId,
        oauthClientId: clientId,
        familyId,
        familyCreatedAt: Date.now(),
        familySessionExpiresAt: null,
        scopes: ['read:foo'],
        expiresAt: Date.now() + 600_000,
        ...overrides,
      });
    }

    it('revokeFamily revokes every active token sharing a family_id and returns the count', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      const familyId = (
        await seedToken(user.id, client.id, 'h'.repeat(64), 'fam-1', {
          familyId: undefined,
        })
      ).familyId;
      // Two more rotations in the same family.
      await seedToken(user.id, client.id, 'i'.repeat(64), familyId);
      await seedToken(user.id, client.id, 'j'.repeat(64), familyId);
      // An unrelated family that must remain untouched.
      const other = await seedToken(user.id, client.id, 'k'.repeat(64), 'fam-2', {
        familyId: undefined,
      });

      const revokedCount = await tokens.revokeFamily(familyId, 'replay_detected');
      expect(revokedCount).toBe(3);

      // All three in the family are revoked with the reason recorded.
      const familyRows = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.familyId, familyId));
      expect(familyRows).toHaveLength(3);
      expect(familyRows.every((r) => r.revoked && r.revokedReason === 'replay_detected')).toBe(
        true
      );

      // The other family is still active.
      const otherRow = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, other.id));
      expect(otherRow[0].revoked).toBe(false);
    });

    it('deleteExpired deletes a family whole once its newest token has expired, and keeps every family with a live token', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const past = Date.now() - 60_000;
      const future = Date.now() + 600_000;
      const family = async (rows: ReadonlyArray<readonly [string, number, boolean]>) => {
        let familyId: string | undefined;
        for (const [tokenHash, expiresAt, revoked] of rows) {
          const row = await seedToken(user.id, client.id, tokenHash, familyId as string, {
            familyId,
            expiresAt,
            revoked,
          });
          familyId = row.familyId;
        }
        return familyId as string;
      };

      // Every token expired: the family goes, rotated ancestor included.
      const ended = await family([
        ['a'.repeat(64), past - 60_000, true],
        ['b'.repeat(64), past, false],
      ]);
      // The newest token is live: its expired, rotated ancestor stays, so a
      // replay of the ancestor is still found revoked and revokes the family.
      const live = await family([
        ['c'.repeat(64), past, true],
        ['d'.repeat(64), future, false],
      ]);
      // A revoked family follows the same rule while its newest row is unexpired.
      const revoked = await family([
        ['e'.repeat(64), past, true],
        ['f'.repeat(64), future, true],
      ]);

      expect(await tokens.deleteExpired()).toBe(2);

      const left = async (familyId: string) =>
        (
          await db()
            .database.db.select({ tokenHash: refreshTokens.tokenHash })
            .from(refreshTokens)
            .where(eq(refreshTokens.familyId, familyId))
        )
          .map((r) => r.tokenHash)
          .sort();
      expect(await left(ended)).toEqual([]);
      expect(await left(live)).toEqual(['c'.repeat(64), 'd'.repeat(64)]);
      expect(await left(revoked)).toEqual(['e'.repeat(64), 'f'.repeat(64)]);
      // The kept ancestor is what replay detection reads.
      expect(
        (await tokens.findByTokenHashIncludingRevoked(realm.id, 'c'.repeat(64)))?.revoked
      ).toBe(true);
    });

    it('revokeFamily preserves the earliest revokedReason (only touches active rows)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      const familyId = (
        await seedToken(user.id, client.id, 'a'.repeat(64), 'fam-x', {
          familyId: undefined,
        })
      ).familyId;
      const rotated = await seedToken(user.id, client.id, 'b'.repeat(64), familyId);

      // The rotated predecessor was already revoked as 'rotated' during normal use.
      await tokens.revoke(rotated.id, 'rotated');

      const count = await tokens.revokeFamily(familyId, 'replay_detected');
      // Only the still-active token is flipped (the already-revoked one is skipped).
      expect(count).toBe(1);

      const rows = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.familyId, familyId));
      const reasons = rows.map((r) => r.revokedReason).sort();
      // The earlier 'rotated' reason is preserved, not overwritten.
      expect(reasons).toEqual(['replay_detected', 'rotated']);
    });

    it('findByTokenHash hides revoked/expired tokens but findByTokenHashIncludingRevoked surfaces them', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      const token = await seedToken(user.id, client.id, 'c'.repeat(64), 'fam-y', {
        familyId: undefined,
      });
      await tokens.revoke(token.id, 'rotated');

      // Liveness-filtered lookup hides it (replay must not pass the happy path)...
      expect(await tokens.findByTokenHash(realm.id, 'c'.repeat(64))).toBeUndefined();
      // ...but the replay-detection lookup still finds the revoked row.
      const replayRow = await tokens.findByTokenHashIncludingRevoked(realm.id, 'c'.repeat(64));
      expect(replayRow?.id).toBe(token.id);
      expect(replayRow?.revoked).toBe(true);
    });

    it('revokeAllForUser revokes only that user’s active tokens (logout-all)', async () => {
      const realm = await seedRealm();
      const userA = await seedUser(realm.id);
      const userB = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      await seedToken(userA.id, client.id, 'd'.repeat(64), 'fam-a', { familyId: undefined });
      await seedToken(userB.id, client.id, 'e'.repeat(64), 'fam-b', { familyId: undefined });

      await tokens.revokeAllForUser(userA.id, 'logout');

      expect(await tokens.findByUserId(userA.id)).toHaveLength(0);
      expect(await tokens.findByUserId(userB.id)).toHaveLength(1);
    });

    it('only one of two concurrent rotation compare-and-sets wins (race)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const token = await seedToken(user.id, client.id, 'r'.repeat(64), 'fam-race', {
        familyId: undefined,
      });

      // Each attempt runs in its own transaction, as rotation does, so the
      // second UPDATE blocks on the first's row lock and then re-evaluates
      // `revoked = false` against the committed row.
      const attempt = () =>
        db().database.db.transaction((tx) => tokens.revokeIfActive(token.id, 'rotated', tx));
      const results = await Promise.all([attempt(), attempt()]);

      expect(results.filter((row) => row !== undefined)).toHaveLength(1);
      expect(results.filter((row) => row === undefined)).toHaveLength(1);
    });

    it('revokeIfActive leaves an already-revoked token untouched and returns undefined', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const token = await seedToken(user.id, client.id, 's'.repeat(64), 'fam-cas', {
        familyId: undefined,
      });

      expect(await tokens.revokeIfActive(token.id, 'rotated')).toMatchObject({
        revoked: true,
        revokedReason: 'rotated',
      });
      expect(await tokens.revokeIfActive(token.id, 'rotated-again')).toBeUndefined();

      const [row] = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, token.id));
      expect(row.revokedReason).toBe('rotated');
    });

    it('revokeAllForUserAndClient ends only that user-client pair (consent revocation)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id, 'client-consent');
      const otherClient = await seedClient(realm.id, 'client-untouched');
      const tokens = createRefreshTokensRepository(db().database.db);

      await seedToken(user.id, client.id, 'm'.repeat(64), 'fam-m', { familyId: undefined });
      await seedToken(user.id, client.id, 'n'.repeat(64), 'fam-n', { familyId: undefined });
      const alreadyRevoked = await seedToken(user.id, client.id, 'o'.repeat(64), 'fam-o', {
        familyId: undefined,
      });
      await tokens.revoke(alreadyRevoked.id, 'rotated');
      const untouched = await seedToken(user.id, otherClient.id, 'p'.repeat(64), 'fam-p', {
        familyId: undefined,
      });

      const revokedCount = await tokens.revokeAllForUserAndClient(
        user.id,
        client.id,
        'consent_revoked'
      );
      expect(revokedCount).toBe(2);

      const remaining = await tokens.findByUserId(user.id);
      expect(remaining.map((t) => t.id)).toEqual([untouched.id]);

      const [previous] = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, alreadyRevoked.id));
      expect(previous.revokedReason).toBe('rotated');
    });

    /**
     * A rotation as the token endpoint runs it — parent revoked and child
     * inserted in one transaction — stopped just short of COMMIT. Returns the
     * child and a `commit` that releases the transaction.
     */
    async function startRotation(parent: RefreshToken, childHash: string) {
      const tokens = createRefreshTokensRepository(db().database.db);
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let written!: (child: RefreshToken) => void;
      const child = new Promise<RefreshToken>((resolve) => {
        written = resolve;
      });
      const transaction = db().database.db.transaction(async (tx) => {
        await tokens.revokeIfActive(parent.id, 'rotated', tx);
        written(
          await tokens.create(
            {
              userId: parent.userId,
              oauthClientId: parent.oauthClientId,
              tokenHash: childHash,
              familyId: parent.familyId,
              familyCreatedAt: parent.familyCreatedAt,
              familySessionExpiresAt: parent.familySessionExpiresAt,
              previousTokenHash: parent.tokenHash,
              scopes: parent.scopes,
              expiresAt: parent.expiresAt,
            },
            tx
          )
        );
        await held;
      });
      return {
        child: await child,
        commit: () => {
          release();
          return transaction;
        },
      };
    }

    // The bulk revocations are one UPDATE each. Started while a rotation is
    // in flight, that UPDATE blocks on the parent, finds it already revoked
    // once the rotation commits and never sees the child. Each revocation
    // must instead wait for the rotation and then end the child too.
    for (const [name, revoke] of [
      [
        'revokeFamily',
        (tokens: RefreshTokensRepository, parent: RefreshToken) =>
          tokens.revokeFamily(parent.familyId, 'replay_detected'),
      ],
      [
        'revokeAllForUserAndClient',
        (tokens: RefreshTokensRepository, parent: RefreshToken) =>
          tokens.revokeAllForUserAndClient(parent.userId, parent.oauthClientId, 'consent_revoked'),
      ],
      [
        'revokeAllForUser',
        (tokens: RefreshTokensRepository, parent: RefreshToken) =>
          tokens.revokeAllForUser(parent.userId, 'logout'),
      ],
      [
        'revokeAllForClient',
        (tokens: RefreshTokensRepository, parent: RefreshToken) =>
          tokens.revokeAllForClient(parent.oauthClientId, 'first_party_profile_removed'),
      ],
    ] as const) {
      it(`${name} reaches the child of a rotation that is in flight (race)`, async () => {
        const realm = await seedRealm();
        const user = await seedUser(realm.id);
        const client = await seedClient(realm.id);
        const tokens = createRefreshTokensRepository(db().database.db);
        const parent = await seedToken(user.id, client.id, 't'.repeat(64), 'fam-in-flight', {
          familyId: undefined,
        });

        const rotation = await startRotation(parent, 'u'.repeat(64));
        const revocation = revoke(tokens, parent);
        // Let the revocation reach the database before the rotation commits.
        await new Promise((resolve) => setTimeout(resolve, 100));
        await rotation.commit();
        await revocation;

        expect(await tokens.findByUserId(user.id)).toHaveLength(0);
        const [child] = await db()
          .database.db.select()
          .from(refreshTokens)
          .where(eq(refreshTokens.id, rotation.child.id));
        expect(child.revoked).toBe(true);
        expect(child.revokedReason).not.toBe('rotated');
      });
    }

    // #631: revokeAllForClient holds one exclusive lock on the client, which
    // every rotation and every insert of the client's tokens holds shared.

    /**
     * Run `body` in a transaction held open until `commit` is called. A body
     * that throws rejects `holdOpen` itself, so a failing case fails instead
     * of hanging.
     */
    async function holdOpen<T>(body: (tx: DbClient) => Promise<T>) {
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let produced!: (value: T) => void;
      let failed!: (error: unknown) => void;
      const result = new Promise<T>((resolve, reject) => {
        produced = resolve;
        failed = reject;
      });
      const transaction = db()
        .database.db.transaction(async (tx) => {
          produced(await body(tx as unknown as DbClient));
          await held;
        })
        .catch((error: unknown) => {
          failed(error);
          throw error;
        });
      return {
        result: await result,
        commit: () => {
          release();
          return transaction;
        },
      };
    }

    /**
     * Wait until `count` sessions wait for an advisory lock: proof that the
     * requests reached Postgres and block on the lock, not merely that they
     * have not answered yet.
     */
    async function untilWaitingOnAdvisoryLocks(count: number): Promise<void> {
      const deadline = Date.now() + 10_000;
      for (;;) {
        const { rows } = await db().database.pool.query<{ waiting: string }>(
          `SELECT count(*) AS waiting FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`
        );
        if (Number(rows[0].waiting) >= count) return;
        if (Date.now() > deadline) {
          throw new Error(`expected ${count} sessions waiting on an advisory lock`);
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }

    /** Whether `promise` has settled, without waiting for it. */
    function tracked<T>(promise: Promise<T>): { promise: Promise<T>; settled: () => boolean } {
      let settled = false;
      void promise.then(
        () => (settled = true),
        () => (settled = true)
      );
      return { promise, settled: () => settled };
    }

    function newToken(userId: string, clientId: string, tokenHash: string) {
      return {
        tokenHash,
        userId,
        oauthClientId: clientId,
        familyCreatedAt: Date.now(),
        familySessionExpiresAt: null,
        scopes: ['read:foo'],
        expiresAt: Date.now() + 600_000,
      };
    }

    it('revokeAllForClient reaches a new family whose insert is in flight (race)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      const issuing = await holdOpen((tx) =>
        tokens.create(newToken(user.id, client.id, 'n'.repeat(64)), tx)
      );
      const revocation = tracked(
        tokens.revokeAllForClient(client.id, 'first_party_profile_removed')
      );
      await untilWaitingOnAdvisoryLocks(1);
      expect(revocation.settled()).toBe(false);
      await issuing.commit();

      expect(await revocation.promise).toBe(1);
      const [row] = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, issuing.result.id));
      expect(row).toMatchObject({ revoked: true, revokedReason: 'first_party_profile_removed' });
    });

    it('a rotation or an insert that starts while revokeAllForClient is open waits for it', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const other = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const parent = await seedToken(user.id, client.id, 'p'.repeat(64), 'fam-open', {
        familyId: undefined,
      });

      const revocation = await holdOpen((tx) =>
        tokens.revokeAllForClient(client.id, 'first_party_profile_removed', tx)
      );
      expect(revocation.result).toBe(1);

      // Both wait on the client's lock: the rotation takes it before it
      // touches its parent row, the insert before it inserts.
      const rotation = tracked(
        db().database.db.transaction((tx) => tokens.revokeIfActive(parent.id, 'rotated', tx))
      );
      const issuing = tracked(tokens.create(newToken(other.id, client.id, 'q'.repeat(64))));
      await untilWaitingOnAdvisoryLocks(2);
      expect(rotation.settled()).toBe(false);
      expect(issuing.settled()).toBe(false);
      await revocation.commit();

      // The rotation finds its parent revoked: the refresh is refused.
      expect(await rotation.promise).toBeUndefined();
      // The family started after the revocation committed is a new one.
      expect(await issuing.promise).toMatchObject({ revoked: false });
      const [stored] = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, parent.id));
      expect(stored.revokedReason).toBe('first_party_profile_removed');
    });

    it('revokeAllForClient revokes expired tokens too, and leaves revoked ones and another client alone', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const otherClient = await seedClient(realm.id, 'client-b');
      const tokens = createRefreshTokensRepository(db().database.db);
      const live = await seedToken(user.id, client.id, 'a'.repeat(64), 'fam-a', {
        familyId: undefined,
      });
      const expired = await seedToken(user.id, client.id, 'b'.repeat(64), 'fam-b', {
        familyId: undefined,
        expiresAt: Date.now() - 1_000,
      });
      const loggedOut = await seedToken(user.id, client.id, 'c'.repeat(64), 'fam-c', {
        familyId: undefined,
      });
      await tokens.revoke(loggedOut.id, 'logout');
      const elsewhere = await seedToken(user.id, otherClient.id, 'd'.repeat(64), 'fam-d', {
        familyId: undefined,
      });

      // An expired token is revoked too: a refresh that read it just before it
      // expired must still lose its compare-and-set.
      expect(await tokens.revokeAllForClient(client.id, 'first_party_profile_removed')).toBe(2);

      const state = async (id: string) =>
        (
          await db()
            .database.db.select({
              revoked: refreshTokens.revoked,
              revokedReason: refreshTokens.revokedReason,
            })
            .from(refreshTokens)
            .where(eq(refreshTokens.id, id))
        )[0];
      expect(await state(live.id)).toEqual({
        revoked: true,
        revokedReason: 'first_party_profile_removed',
      });
      expect(await state(expired.id)).toEqual({
        revoked: true,
        revokedReason: 'first_party_profile_removed',
      });
      expect(await state(loggedOut.id)).toEqual({ revoked: true, revokedReason: 'logout' });
      expect(await state(elsewhere.id)).toEqual({ revoked: false, revokedReason: null });
    });
  });

  // --- code replay revokes the family the code started (#627) --------------

  describe('authorization codes — the refresh family a code started (#627)', () => {
    /** An unspent, PKCE-bound code for `clientId` and `userId`. */
    async function seedCode(clientId: string, userId: string, code: string, expiresAt: number) {
      return createAuthorizationCodesRepository(db().database.db).create({
        code,
        oauthClientId: clientId,
        userId,
        redirectUri: 'https://app.example.com/cb',
        codeChallenge: 'c'.repeat(43),
        codeChallengeMethod: 'S256',
        scopes: ['read:foo'],
        expiresAt,
      });
    }

    /** A live refresh token; `fields` sets its family and the code that started it. */
    async function seedFamilyToken(
      userId: string,
      clientId: string,
      tokenHash: string,
      fields: { familyId?: string; authorizationCodeId?: string } = {}
    ) {
      return createRefreshTokensRepository(db().database.db).create({
        tokenHash,
        userId,
        oauthClientId: clientId,
        familyCreatedAt: Date.now(),
        familySessionExpiresAt: null,
        scopes: ['read:foo'],
        expiresAt: Date.now() + 600_000,
        ...fields,
      });
    }

    /** The refresh token's row as stored. */
    async function tokenRow(id: string): Promise<RefreshToken> {
      const [row] = await db()
        .database.db.select()
        .from(refreshTokens)
        .where(eq(refreshTokens.id, id));
      return row;
    }

    it('findByCodeIncludingUsed returns a spent or expired code that findByCode hides', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);
      const spent = await seedCode(client.id, user.id, 'spent-code', Date.now() + 60_000);
      await codes.markUsed(spent.id);
      await seedCode(client.id, user.id, 'lapsed-code', Date.now() - 1_000);

      expect(await codes.findByCode(realm.id, 'spent-code')).toBeUndefined();
      expect(await codes.findByCode(realm.id, 'lapsed-code')).toBeUndefined();
      expect(await codes.findByCodeIncludingUsed(realm.id, 'spent-code')).toMatchObject({
        id: spent.id,
        used: true,
      });
      expect(await codes.findByCodeIncludingUsed(realm.id, 'lapsed-code')).toMatchObject({
        used: false,
      });
      expect(await codes.findByCodeIncludingUsed(realm.id, 'no-such-code')).toBeUndefined();
      // #489: another realm's code, spent or not, is no row in this realm.
      const otherRealm = await seedRealm('other');
      expect(await codes.findByCodeIncludingUsed(otherRealm.id, 'spent-code')).toBeUndefined();
      expect(await codes.findByCodeIncludingUsed(otherRealm.id, 'lapsed-code')).toBeUndefined();
    });

    it('revokeFamilyByAuthorizationCode revokes the whole family the code started, and only it', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const code = await seedCode(client.id, user.id, 'replayed-code', Date.now() + 60_000);
      const otherCode = await seedCode(client.id, user.id, 'other-code', Date.now() + 60_000);

      // The exchange's token carries the link; a rotation already happened
      // (its parent is `rotated`) and its child does not carry the link.
      const first = await seedFamilyToken(user.id, client.id, 'a'.repeat(64), {
        authorizationCodeId: code.id,
      });
      await tokens.revoke(first.id, 'rotated');
      const child = await seedFamilyToken(user.id, client.id, 'b'.repeat(64), {
        familyId: first.familyId,
      });
      const otherFamily = await seedFamilyToken(user.id, client.id, 'c'.repeat(64), {
        authorizationCodeId: otherCode.id,
      });

      expect(await tokens.revokeFamilyByAuthorizationCode(code.id, 'code_replay')).toEqual({
        familyId: first.familyId,
        revokedCount: 1,
      });

      expect(await tokenRow(child.id)).toMatchObject({
        revoked: true,
        revokedReason: 'code_replay',
      });
      // The rotated parent keeps the reason it was revoked for first.
      expect((await tokenRow(first.id)).revokedReason).toBe('rotated');
      expect((await tokenRow(otherFamily.id)).revoked).toBe(false);
      // A second replay finds nothing left to revoke, and still names the family.
      expect(await tokens.revokeFamilyByAuthorizationCode(code.id, 'code_replay')).toEqual({
        familyId: first.familyId,
        revokedCount: 0,
      });
    });

    it('revokeFamilyByAuthorizationCode revokes nothing for a code that started no family', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);
      const code = await seedCode(client.id, user.id, 'no-family-code', Date.now() + 60_000);
      // An unlinked family of the same user stays live.
      const unlinked = await seedFamilyToken(user.id, client.id, 'd'.repeat(64));

      expect(await tokens.revokeFamilyByAuthorizationCode(code.id, 'code_replay')).toEqual({
        familyId: null,
        revokedCount: 0,
      });
      expect((await tokenRow(unlinked.id)).revoked).toBe(false);
    });

    it('refuses a second token linked to the same code: a code starts one family at most', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const code = await seedCode(client.id, user.id, 'one-family-code', Date.now() + 60_000);
      await seedFamilyToken(user.id, client.id, 'e'.repeat(64), { authorizationCodeId: code.id });

      await expect(
        seedFamilyToken(user.id, client.id, 'f'.repeat(64), { authorizationCodeId: code.id })
      ).rejects.toMatchObject({
        cause: { code: '23505', constraint: 'idx_refresh_tokens_authorization_code_id' },
      });
    });

    it('purging the code clears the link and keeps the family', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const codes = createAuthorizationCodesRepository(db().database.db);
      const code = await seedCode(client.id, user.id, 'purged-code', Date.now() - 1_000);
      const token = await seedFamilyToken(user.id, client.id, 'g'.repeat(64), {
        authorizationCodeId: code.id,
      });

      expect(await codes.deleteExpired()).toBe(1);

      expect(await tokenRow(token.id)).toMatchObject({
        authorizationCodeId: null,
        revoked: false,
      });
    });
  });

  // --- consent soft-delete + scope union ------------------------------------

  describe('oauth consents — soft-delete revoke + upsertGrant scope union', () => {
    it('revoke is a soft-delete: the row is preserved with revokedAt set', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      const grant = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);
      const revoked = await consents.revoke(realm.id, grant.id);
      expect(revoked.revokedAt).toBeTypeOf('number');

      // No longer "active"...
      expect(await consents.findActive(realm.id, user.id, client.id)).toBeUndefined();
      // ...but the audit row physically remains in the table.
      const all = await db()
        .database.db.select()
        .from(oauthConsents)
        .where(eq(oauthConsents.id, grant.id));
      expect(all).toHaveLength(1);
      expect(all[0].revokedAt).toBeTypeOf('number');
    });

    it('upsertGrant unions scopes on the active row instead of dropping any', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);
      const merged = await consents.upsertGrant(realm.id, user.id, client.id, ['write:foo']);

      // Union, sorted — a narrower follow-up grant never removes prior scopes.
      expect(merged.scopes).toEqual(['read:foo', 'write:foo']);

      // Still a single active row (upsert, not insert).
      const active = await consents.listActiveForUser(realm.id, user.id);
      expect(active).toHaveLength(1);
    });

    it('upsertGrant records the scopes per RFC 8707 resource, never across resources', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);
      const [a, b] = ['https://a.example/mcp', 'https://b.example/mcp'];

      const first = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo'], [a]);
      expect(first.resourceScopes).toEqual({ [a]: ['read:foo'] });

      await consents.upsertGrant(realm.id, user.id, client.id, ['write:foo'], [a, b]);
      const merged = await consents.upsertGrant(realm.id, user.id, client.id, ['email']);

      expect(merged.scopes).toEqual(['email', 'read:foo', 'write:foo']);
      expect(merged.resourceScopes).toEqual({
        [a]: ['read:foo', 'write:foo'],
        [b]: ['write:foo'],
      });
    });

    it('a grant without a resource records none (column default)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      const grant = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);
      expect(grant.resourceScopes).toEqual({});
    });

    it('a fresh grant after revoke inserts a NEW active row (partial unique index allows it)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      const first = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);
      await consents.revoke(realm.id, first.id);

      // The partial unique index is `WHERE revoked_at IS NULL`, so granting
      // again does not collide with the revoked row.
      const second = await consents.upsertGrant(realm.id, user.id, client.id, ['write:foo']);
      expect(second.id).not.toBe(first.id);
      expect(second.scopes).toEqual(['write:foo']);

      // Two rows total (one revoked, one active); only one active.
      const allRows = await db()
        .database.db.select()
        .from(oauthConsents)
        .where(eq(oauthConsents.userId, user.id));
      expect(allRows).toHaveLength(2);
      expect(await consents.listActiveForUser(realm.id, user.id)).toHaveLength(1);
    });

    // /oauth/authorize re-reads the consent with `findActiveForShare` in the
    // transaction that inserts the code, so a revocation and a code issued on
    // the consent are ordered: never "revoked, then a code minted on it".
    it('findActiveForShare started while a revocation is uncommitted waits for it and finds no row', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);
      const grant = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);

      let locked: Promise<unknown> | undefined;
      await db().database.db.transaction(async (tx) => {
        await consents.revoke(realm.id, grant.id, tx);
        // The plain read does not wait, and still sees the consent.
        expect(await consents.findActive(realm.id, user.id, client.id)).toBeDefined();
        locked = db().database.db.transaction((readTx) =>
          consents.findActiveForShare(realm.id, user.id, client.id, readTx)
        );
        await new Promise((resolve) => setTimeout(resolve, 200));
      });

      expect(await locked).toBeUndefined();
    });

    it('a revocation started while findActiveForShare holds the row waits until the code is committed', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);
      const codes = createAuthorizationCodesRepository(db().database.db);
      const grant = await consents.upsertGrant(realm.id, user.id, client.id, ['read:foo']);

      let revoked = false;
      let revocation: Promise<unknown> | undefined;
      await db().database.db.transaction(async (tx) => {
        expect(await consents.findActiveForShare(realm.id, user.id, client.id, tx)).toBeDefined();
        revocation = consents.revoke(realm.id, grant.id).then(() => {
          revoked = true;
        });
        await new Promise((resolve) => setTimeout(resolve, 200));
        // The revocation is blocked on the shared lock.
        expect(revoked).toBe(false);
        await codes.create(
          {
            code: 'auth-code-under-lock',
            oauthClientId: client.id,
            userId: user.id,
            redirectUri: 'https://app.example.com/cb',
            codeChallenge: 'challenge',
            codeChallengeMethod: 'S256',
            scopes: ['read:foo'],
            expiresAt: Date.now() + 60_000,
          },
          tx
        );
      });
      await revocation;

      // The code committed first; a sweep in the revocation's transaction
      // (consent revocation invalidating unredeemed codes) would see it.
      expect(revoked).toBe(true);
      expect(await consents.findActive(realm.id, user.id, client.id)).toBeUndefined();
    });
  });

  // --- realm-scoped unique constraints --------------------------------------

  describe('realm-scoped unique constraints', () => {
    it('rejects a duplicate credential (realm, password, email) within the same realm — the #230 registration guard', async () => {
      const realm = await seedRealm();
      const userA = await seedUser(realm.id);
      const userB = await seedUser(realm.id);
      await seedCredential(realm.id, userA.id, 'dup@example.com');

      // Since #230 the credentials unique index is the SOLE duplicate-
      // registration guard (the users email index dropped with the column).
      await expect(seedCredential(realm.id, userB.id, 'dup@example.com')).rejects.toThrow(
        UniqueConstraintError
      );
    });

    it('allows the same credential email across DIFFERENT realms (uniqueness is realm-scoped)', async () => {
      const realmA = await seedRealm('realm-a');
      const realmB = await seedRealm('realm-b');
      const userA = await seedUser(realmA.id);
      const userB = await seedUser(realmB.id);

      const a = await seedCredential(realmA.id, userA.id, 'same@example.com');
      const b = await seedCredential(realmB.id, userB.id, 'same@example.com');

      expect(a.realmId).toBe(realmA.id);
      expect(b.realmId).toBe(realmB.id);
      expect(a.userId).not.toBe(b.userId);
    });

    it('rejects a duplicate client_id within a realm but allows it across realms', async () => {
      const realmA = await seedRealm('client-realm-a');
      const realmB = await seedRealm('client-realm-b');

      await seedClient(realmA.id, 'shared-client');
      // Same client_id in the same realm collides...
      await expect(seedClient(realmA.id, 'shared-client')).rejects.toThrow(UniqueConstraintError);
      // ...but is fine in a different realm.
      const other = await seedClient(realmB.id, 'shared-client');
      expect(other.realmId).toBe(realmB.id);
    });

    it('rejects a duplicate realm name', async () => {
      await seedRealm('unique-realm');
      await expect(seedRealm('unique-realm')).rejects.toThrow(UniqueConstraintError);
    });
  });

  // --- oauth_clients agent classification (ADR-007 §2) ----------------------

  describe('oauth_clients — is_agent classification', () => {
    it('defaults is_agent to false (backward-compatible migration)', async () => {
      const realm = await seedRealm('agent-default-realm');
      // seedClient does not set isAgent, so the column default applies.
      const client = await seedClient(realm.id, 'standard-client');
      expect(client.isAgent).toBe(false);
    });

    it('persists and round-trips an agent client', async () => {
      const realm = await seedRealm('agent-realm');
      const clients = createOAuthClientsRepository(db().database.db);

      const created = await clients.create({
        realmId: realm.id,
        clientId: 'agent-client',
        clientSecretHash: 'secret-hash',
        name: 'Autonomous Agent',
        redirectUris: ['https://agent.example.com/cb'],
        scopes: ['read:foo'],
        grantTypes: ['authorization_code', 'refresh_token'],
        isAgent: true,
      });
      expect(created.isAgent).toBe(true);

      // Reloads carry the flag through findByClientId (the path auth handlers use).
      const reloaded = await clients.findByClientId(realm.id, 'agent-client');
      expect(reloaded?.isAgent).toBe(true);
    });
  });

  describe('oauth_clients — countByDeveloper (per-developer client ceiling)', () => {
    it('counts exactly the rows listByDeveloper returns', async () => {
      const realm = await seedRealm('count-realm');
      const owner = await seedUser(realm.id);
      const other = await seedUser(realm.id);
      const clients = createOAuthClientsRepository(db().database.db);

      const owned = async (clientId: string, developerId: string | null) =>
        clients.create({
          realmId: realm.id,
          clientId,
          clientSecretHash: 'secret-hash',
          name: clientId,
          redirectUris: ['https://app.example.com/cb'],
          scopes: [],
          grantTypes: ['authorization_code'],
          developerId,
        });
      await owned('owned-1', owner.id);
      await owned('owned-2', owner.id);
      await owned('other-1', other.id);
      await owned('anonymous-1', null);

      expect(await clients.countByDeveloper(realm.id, owner.id)).toBe(2);
      expect(await clients.countByDeveloper(realm.id, owner.id)).toBe(
        (await clients.listByDeveloper(realm.id, owner.id)).length
      );
      expect(await clients.countByDeveloper(realm.id, other.id)).toBe(1);
      expect(await clients.countByDeveloper(realm.id, '0190a000-0000-7000-8000-0000000000ff')).toBe(
        0
      );
    });
  });

  describe('oauth_clients — max_agent_mode cap (ADR-007 §2, #184)', () => {
    it('defaults max_agent_mode to null (deny-by-default migration)', async () => {
      const realm = await seedRealm('agent-mode-default-realm');
      // seedClient does not set maxAgentMode, so the nullable column default applies.
      const client = await seedClient(realm.id, 'no-cap-client');
      expect(client.maxAgentMode).toBeNull();
    });

    it('persists and round-trips an operator-set agent mode cap', async () => {
      const realm = await seedRealm('agent-mode-realm');
      const clients = createOAuthClientsRepository(db().database.db);

      const created = await clients.create({
        realmId: realm.id,
        clientId: 'capped-agent-client',
        clientSecretHash: 'secret-hash',
        name: 'Capped Agent',
        redirectUris: ['https://agent.example.com/cb'],
        scopes: ['agent:readonly', 'agent:admin'],
        grantTypes: ['authorization_code', 'refresh_token'],
        isAgent: true,
        maxAgentMode: 'admin',
      });
      expect(created.maxAgentMode).toBe('admin');

      const reloaded = await clients.findByClientId(realm.id, 'capped-agent-client');
      expect(reloaded?.maxAgentMode).toBe('admin');
    });
  });

  // ADR-011 (#434): the ID-JAG targets have a column of their own, apart from
  // `audience`, and only the seed manifest writes it.
  describe('oauth_clients — id_jag_targets (ADR-011, #434)', () => {
    it('defaults to an empty list, which denies both ID-JAG paths', async () => {
      const realm = await seedRealm('id-jag-default-realm');
      const client = await seedClient(realm.id, 'no-targets-client');
      expect(client.idJagTargets).toEqual([]);
    });

    it('keeps the targets apart from the audience', async () => {
      const realm = await seedRealm('id-jag-round-trip-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      await clients.create({
        realmId: realm.id,
        clientId: 'id-jag-agent',
        clientSecretHash: 'secret-hash',
        name: 'ID-JAG Agent',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        audience: ['https://api.example.com'],
        idJagTargets: ['https://as.partner.example', 'https://mcp.partner.example/mcp'],
      });

      const reloaded = await clients.findByClientId(realm.id, 'id-jag-agent');
      expect(reloaded?.audience).toEqual(['https://api.example.com']);
      expect(reloaded?.idJagTargets).toEqual([
        'https://as.partner.example',
        'https://mcp.partner.example/mcp',
      ]);
    });

    it.each([
      ['a string', '"https://as.partner.example"'],
      ['an object', '{"aud": "https://as.partner.example"}'],
      ['JSON null', 'null'],
    ])('refuses %s through the CHECK constraint', async (_label, value) => {
      const realm = await seedRealm('id-jag-check-realm');
      const client = await seedClient(realm.id, 'check-client');
      await expect(
        db().database.pool.query(
          `UPDATE oauth_clients SET id_jag_targets = $1::jsonb WHERE id = $2`,
          [value, client.id]
        )
      ).rejects.toThrow(/oauth_clients_id_jag_targets_is_array/);
    });

    it('is left alone by a CIMD re-resolution', async () => {
      const realm = await seedRealm('id-jag-cimd-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      const insert = {
        realmId: realm.id,
        clientId: 'https://app.example.com/id-jag.json',
        clientSecretHash: 'sentinel-hash',
        name: 'Before',
        redirectUris: ['https://app.example.com/cb'],
        tokenEndpointAuthMethod: 'none' as const,
        enabled: true,
      };
      const created = await clients.upsertCimdClient(insert);
      expect(created.idJagTargets).toEqual([]);

      // Only by hand: no route and no manifest section writes it for CIMD.
      await db().database.pool.query(
        `UPDATE oauth_clients SET id_jag_targets = '["https://as.partner.example"]' WHERE id = $1`,
        [created.id]
      );
      const refreshed = await clients.upsertCimdClient({ ...insert, name: 'After' });
      expect(refreshed.name).toBe('After');
      expect(refreshed.idJagTargets).toEqual(['https://as.partner.example']);
    });
  });

  // --- CIMD upsert never re-enables a row ----------------------------------

  describe('oauth_clients — upsertCimdClient narrows `enabled` only', () => {
    const CIMD_ID = 'https://app.example.com/client.json';

    function cimdInsert(realmId: string, name: string, enabled: boolean) {
      return {
        realmId,
        clientId: CIMD_ID,
        clientSecretHash: 'sentinel-hash',
        name,
        redirectUris: ['https://app.example.com/cb'],
        tokenEndpointAuthMethod: 'none' as const,
        enabled,
      };
    }

    // ANT-2026-SSI34ODQ: the resolver's snapshot still says `true`; the
    // operator disables the client while the resolver waits on the client's
    // own host.
    it('keeps an operator disable that landed after the resolver read the row', async () => {
      const realm = await seedRealm('cimd-disable-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      const created = await clients.upsertCimdClient(cimdInsert(realm.id, 'Before', true));
      expect(created.enabled).toBe(true);

      await clients.update(realm.id, created.id, { enabled: false });
      const refreshed = await clients.upsertCimdClient(cimdInsert(realm.id, 'After', true));

      expect(refreshed.name).toBe('After');
      expect(refreshed.enabled).toBe(false);
      expect((await clients.findByClientId(realm.id, CIMD_ID))?.enabled).toBe(false);
    });

    it('still disables an enabled row when the caller passes false', async () => {
      const realm = await seedRealm('cimd-narrow-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      await clients.upsertCimdClient(cimdInsert(realm.id, 'Before', true));

      const refreshed = await clients.upsertCimdClient(cimdInsert(realm.id, 'After', false));

      expect(refreshed.enabled).toBe(false);
    });
    // ANT-2026-O8U3P920: the document's host chooses the redirect URIs, so a
    // CIMD row never carries the operator's trust marker — not on insert, and
    // a re-resolution clears one set by hand.
    it('never stores provisioned_by_operator = true for a CIMD row', async () => {
      const realm = await seedRealm('cimd-provisioned-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      const created = await clients.upsertCimdClient({
        ...cimdInsert(realm.id, 'Before', true),
        provisionedByOperator: true,
      });
      expect(created.provisionedByOperator).toBe(false);

      await clients.update(realm.id, created.id, { provisionedByOperator: true });
      const refreshed = await clients.upsertCimdClient(cimdInsert(realm.id, 'After', true));
      expect(refreshed.provisionedByOperator).toBe(false);
    });
  });

  // ANT-2026-DR5XI3LV: the suspension column is operator state. The CIMD
  // upsert never names it, so a re-resolution cannot clear it.
  describe('oauth_clients — suspended survives upsertCimdClient', () => {
    it('keeps a suspension set while the row is refreshed from its document', async () => {
      const realm = await seedRealm('cimd-suspended-realm');
      const clients = createOAuthClientsRepository(db().database.db);
      const insert = {
        realmId: realm.id,
        clientId: 'https://app.example.com/suspended.json',
        clientSecretHash: 'sentinel-hash',
        name: 'Before',
        redirectUris: ['https://app.example.com/cb'],
        tokenEndpointAuthMethod: 'none' as const,
        enabled: true,
      };
      const created = await clients.upsertCimdClient(insert);
      expect(created.suspended).toBe(false);
      await db()
        .database.db.update(oauthClients)
        .set({ suspended: true, suspendedAt: Date.now() })
        .where(eq(oauthClients.id, created.id));

      const refreshed = await clients.upsertCimdClient({ ...insert, name: 'After' });

      expect(refreshed.name).toBe('After');
      expect(refreshed.suspended).toBe(true);
      expect(refreshed.suspendedAt).not.toBeNull();
    });
  });

  describe('oauth_clients — provisioned_by_operator default', () => {
    it('defaults to false for a row that does not set it', async () => {
      const realm = await seedRealm('provisioned-default-realm');
      const client = await seedClient(realm.id);
      expect(client.provisionedByOperator).toBe(false);
    });
  });

  // --- per-agent action audit (ADR-007 §2, #186) ---------------------------

  describe('audit_logs — per-agent action audit (ADR-007 §2, #186)', () => {
    it('round-trips agent attribution columns (actor, subject, act chain, mode)', async () => {
      const realm = await seedRealm('agent-audit-realm');
      const subject = await seedUser(realm.id);
      const agentClient = await seedClient(realm.id, 'agent-actor');
      const audit = createAuditLogsRepository(db().database.db);

      const row = await audit.create({
        userId: subject.id,
        oauthClientId: agentClient.id,
        actorClientId: 'agent-actor',
        delegationChain: ['agent-actor', 'prior-agent'],
        scopeMode: 'exec',
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
        ipAddress: '127.0.0.1',
        userAgent: 'vitest',
        metadata: { grantType: 'token-exchange', delegationDepth: 2 },
      });

      expect(row.actorClientId).toBe('agent-actor');
      expect(row.delegationChain).toEqual(['agent-actor', 'prior-agent']);
      expect(row.scopeMode).toBe('exec');
      // The subject of the on-behalf-of action is the end-user.
      expect(row.userId).toBe(subject.id);
    });

    it('accepts the new "agent" event_type enum value', async () => {
      const realm = await seedRealm('agent-event-type-realm');
      const subject = await seedUser(realm.id);
      const agentClient = await seedClient(realm.id, 'agent-evt-actor');
      const audit = createAuditLogsRepository(db().database.db);

      const row = await audit.create({
        userId: subject.id,
        oauthClientId: agentClient.id,
        actorClientId: 'agent-evt-actor',
        event: 'agent.action',
        eventType: 'agent',
        success: true,
      });
      expect(row.eventType).toBe('agent');
    });

    it('leaves agent columns null for ordinary (non-agent) entries — backward compatible', async () => {
      const realm = await seedRealm('plain-audit-realm');
      const user = await seedUser(realm.id);
      const audit = createAuditLogsRepository(db().database.db);

      // An entry written exactly as pre-#186 callers do (no agent fields).
      const row = await audit.create({
        userId: user.id,
        event: 'auth.login.success',
        eventType: 'auth',
        success: true,
      });

      expect(row.actorClientId).toBeNull();
      expect(row.delegationChain).toBeNull();
      expect(row.scopeMode).toBeNull();
    });

    it('findByRealmAndActorClientId returns only an agent’s actions, newest first', async () => {
      const realm = await seedRealm('agent-activity-realm');
      const subject = await seedUser(realm.id);
      const agentA = await seedClient(realm.id, 'agent-a');
      const agentB = await seedClient(realm.id, 'agent-b');
      const audit = createAuditLogsRepository(db().database.db);

      // Two actions by agent-a (different scope modes) and one by agent-b.
      await audit.create({
        userId: subject.id,
        oauthClientId: agentA.id,
        actorClientId: 'agent-a',
        delegationChain: ['agent-a'],
        scopeMode: 'readonly',
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
        createdAt: 1_000,
      });
      await audit.create({
        userId: subject.id,
        oauthClientId: agentA.id,
        actorClientId: 'agent-a',
        delegationChain: ['agent-a'],
        scopeMode: 'exec',
        event: 'oauth.stepup.elevation',
        eventType: 'auth',
        success: true,
        createdAt: 2_000,
      });
      await audit.create({
        userId: subject.id,
        oauthClientId: agentB.id,
        actorClientId: 'agent-b',
        delegationChain: ['agent-b'],
        scopeMode: 'readonly',
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
        createdAt: 1_500,
      });

      const activity = await audit.findByRealmAndActorClientId(realm.id, 'agent-a');
      expect(activity).toHaveLength(2);
      // Newest first (created_at desc).
      expect(activity[0].event).toBe('oauth.stepup.elevation');
      expect(activity[0].scopeMode).toBe('exec');
      expect(activity[1].scopeMode).toBe('readonly');
      // Strictly scoped to agent-a — agent-b's action is not returned.
      expect(activity.every((r) => r.actorClientId === 'agent-a')).toBe(true);

      // eventType filter narrows within the agent's activity.
      const tokenOnly = await audit.findByRealmAndActorClientId(realm.id, 'agent-a', {
        eventType: 'token',
      });
      expect(tokenOnly).toHaveLength(1);
      expect(tokenOnly[0].event).toBe('oauth.token.exchange.success');
    });

    it('findByRealmAndActorClientId is REALM-ISOLATED — same client_id in two realms does not leak', async () => {
      // Two realms each own a client called `agent-shared` (client_id is unique
      // only per realm). Each agent acts once; a query scoped to realm A must
      // return ONLY realm A's row, never realm B's.
      const realmA = await seedRealm('iso-realm-a');
      const realmB = await seedRealm('iso-realm-b');
      const userA = await seedUser(realmA.id);
      const userB = await seedUser(realmB.id);
      const clientA = await seedClient(realmA.id, 'agent-shared');
      const clientB = await seedClient(realmB.id, 'agent-shared');
      const audit = createAuditLogsRepository(db().database.db);

      await audit.create({
        userId: userA.id,
        oauthClientId: clientA.id,
        actorClientId: 'agent-shared',
        delegationChain: ['agent-shared'],
        scopeMode: 'readonly',
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
      });
      await audit.create({
        userId: userB.id,
        oauthClientId: clientB.id,
        actorClientId: 'agent-shared',
        delegationChain: ['agent-shared'],
        scopeMode: 'exec',
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        success: true,
      });

      const activityA = await audit.findByRealmAndActorClientId(realmA.id, 'agent-shared');
      expect(activityA).toHaveLength(1);
      expect(activityA[0].userId).toBe(userA.id);
      expect(activityA[0].scopeMode).toBe('readonly');

      const activityB = await audit.findByRealmAndActorClientId(realmB.id, 'agent-shared');
      expect(activityB).toHaveLength(1);
      expect(activityB[0].userId).toBe(userB.id);
      expect(activityB[0].scopeMode).toBe('exec');
    });
  });

  // --- static developer API keys (ADR-008 §6, #97) -------------------------

  describe('api keys — create / lookup / revoke against real DDL', () => {
    it('persists only the hash + display handles, enforces unique prefix, and revoke is an idempotent soft-delete', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const apiKeys = createApiKeysRepository(db().database.db);

      const created = await apiKeys.create({
        realmId: realm.id,
        clientId: client.id,
        developerId: user.id,
        name: 'laptop',
        keyHash: 'argon2id$opaque-hash',
        prefix: 'qauth_0123456789abcdef',
        last4: 'abcd',
      });
      expect(created.id).toBeTypeOf('string');
      expect(created.revokedAt).toBeNull();
      expect(created.lastUsedAt).toBeNull();

      // Lookup by the public prefix resolves the row; the stored value is the
      // hash, never any plaintext.
      const found = await apiKeys.findByPrefix(realm.id, 'qauth_0123456789abcdef');
      expect(found?.id).toBe(created.id);
      expect(found?.keyHash).toBe('argon2id$opaque-hash');

      // The prefix is unique — a second row reusing it is rejected.
      await expect(
        apiKeys.create({
          realmId: realm.id,
          clientId: client.id,
          developerId: user.id,
          name: 'dup',
          keyHash: 'argon2id$other',
          prefix: 'qauth_0123456789abcdef',
          last4: 'efgh',
        })
      ).rejects.toBeInstanceOf(UniqueConstraintError);

      // listByClient returns the live key.
      const listed = await apiKeys.listByClient(realm.id, client.id);
      expect(listed.map((k) => k.id)).toContain(created.id);

      // Revoke stamps revokedAt; a second revoke is idempotent (revokedAt unchanged).
      const revoked = await apiKeys.revoke(realm.id, created.id);
      expect(revoked?.revokedAt).toBeTypeOf('number');
      const firstRevokedAt = revoked?.revokedAt;
      const again = await apiKeys.revoke(realm.id, created.id);
      expect(again?.revokedAt).toBe(firstRevokedAt);
    });

    it('cascades on client delete and survives developer delete (developerId set null)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const users = createUsersRepository(db().database.db);
      const clients = createOAuthClientsRepository(db().database.db);
      const apiKeys = createApiKeysRepository(db().database.db);

      await apiKeys.create({
        realmId: realm.id,
        clientId: client.id,
        developerId: user.id,
        name: 'k',
        keyHash: 'argon2id$h',
        prefix: 'qauth_aaaaaaaaaaaaaaaa',
        last4: 'aaaa',
      });

      // Deleting the developer nulls developerId but keeps the key row.
      await users.delete(realm.id, user.id);
      const afterUserDelete = await apiKeys.findByPrefix(realm.id, 'qauth_aaaaaaaaaaaaaaaa');
      expect(afterUserDelete).toBeDefined();
      expect(afterUserDelete?.developerId).toBeNull();

      // Deleting the client cascades the key away.
      await clients.delete(realm.id, client.id);
      const afterClientDelete = await apiKeys.findByPrefix(realm.id, 'qauth_aaaaaaaaaaaaaaaa');
      expect(afterClientDelete).toBeUndefined();
    });
  });
});
