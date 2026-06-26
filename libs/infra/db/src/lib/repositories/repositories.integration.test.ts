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
 * Requires Docker. When Docker is unavailable the whole suite is skipped
 * (see the top-level guard) rather than failing the run.
 *
 * Tagged via the `*.integration.test.ts` suffix so the fast unit run and the
 * coverage gate (vitest.config.ts) exclude it — CI runs it via the dedicated
 * `test-integration` target instead.
 */
import { UniqueConstraintError } from '@qauth-labs/shared-errors';
import { isDockerAvailable } from '@qauth-labs/shared-testing';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { oauthConsents, refreshTokens } from '../schema';
import {
  createApiKeysRepository,
  createAuditLogsRepository,
  createAuthorizationCodesRepository,
  createOAuthClientsRepository,
  createOAuthConsentsRepository,
  createRealmsRepository,
  createRefreshTokensRepository,
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
    dockerUp = await isDockerAvailable();
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

  async function seedUser(realmId: string, email = 'user@example.com') {
    const users = createUsersRepository(db().database.db);
    return users.create({
      realmId,
      email,
      // The repo derives emailNormalized when omitted, but NewUser types it as
      // required; pass the lowercased form so the realm-scoped unique index is
      // exercised deterministically.
      emailNormalized: email.toLowerCase(),
      passwordHash: 'argon2-hash',
      emailVerified: true,
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
      const after = await codes.findByCode('auth-code-123');
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

      expect(await codes.findByCode('expired-code')).toBeUndefined();
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
      expect(await tokens.findByTokenHash('c'.repeat(64))).toBeUndefined();
      // ...but the replay-detection lookup still finds the revoked row.
      const replayRow = await tokens.findByTokenHashIncludingRevoked('c'.repeat(64));
      expect(replayRow?.id).toBe(token.id);
      expect(replayRow?.revoked).toBe(true);
    });

    it('revokeAllForUser revokes only that user’s active tokens (logout-all)', async () => {
      const realm = await seedRealm();
      const userA = await seedUser(realm.id, 'a@example.com');
      const userB = await seedUser(realm.id, 'b@example.com');
      const client = await seedClient(realm.id);
      const tokens = createRefreshTokensRepository(db().database.db);

      await seedToken(userA.id, client.id, 'd'.repeat(64), 'fam-a', { familyId: undefined });
      await seedToken(userB.id, client.id, 'e'.repeat(64), 'fam-b', { familyId: undefined });

      await tokens.revokeAllForUser(userA.id, 'logout');

      expect(await tokens.findByUserId(userA.id)).toHaveLength(0);
      expect(await tokens.findByUserId(userB.id)).toHaveLength(1);
    });
  });

  // --- consent soft-delete + scope union ------------------------------------

  describe('oauth consents — soft-delete revoke + upsertGrant scope union', () => {
    it('revoke is a soft-delete: the row is preserved with revokedAt set', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      const grant = await consents.upsertGrant(user.id, client.id, realm.id, ['read:foo']);
      const revoked = await consents.revoke(grant.id);
      expect(revoked.revokedAt).toBeTypeOf('number');

      // No longer "active"...
      expect(await consents.findActive(user.id, client.id)).toBeUndefined();
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

      await consents.upsertGrant(user.id, client.id, realm.id, ['read:foo']);
      const merged = await consents.upsertGrant(user.id, client.id, realm.id, ['write:foo']);

      // Union, sorted — a narrower follow-up grant never removes prior scopes.
      expect(merged.scopes).toEqual(['read:foo', 'write:foo']);

      // Still a single active row (upsert, not insert).
      const active = await consents.listActiveForUser(user.id);
      expect(active).toHaveLength(1);
    });

    it('a fresh grant after revoke inserts a NEW active row (partial unique index allows it)', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm.id);
      const client = await seedClient(realm.id);
      const consents = createOAuthConsentsRepository(db().database.db);

      const first = await consents.upsertGrant(user.id, client.id, realm.id, ['read:foo']);
      await consents.revoke(first.id);

      // The partial unique index is `WHERE revoked_at IS NULL`, so granting
      // again does not collide with the revoked row.
      const second = await consents.upsertGrant(user.id, client.id, realm.id, ['write:foo']);
      expect(second.id).not.toBe(first.id);
      expect(second.scopes).toEqual(['write:foo']);

      // Two rows total (one revoked, one active); only one active.
      const allRows = await db()
        .database.db.select()
        .from(oauthConsents)
        .where(eq(oauthConsents.userId, user.id));
      expect(allRows).toHaveLength(2);
      expect(await consents.listActiveForUser(user.id)).toHaveLength(1);
    });
  });

  // --- realm-scoped unique constraints --------------------------------------

  describe('realm-scoped unique constraints', () => {
    it('rejects a duplicate normalized email within the same realm', async () => {
      const realm = await seedRealm();
      await seedUser(realm.id, 'dup@example.com');

      await expect(seedUser(realm.id, 'dup@example.com')).rejects.toThrow(UniqueConstraintError);
    });

    it('allows the same email across DIFFERENT realms (uniqueness is realm-scoped)', async () => {
      const realmA = await seedRealm('realm-a');
      const realmB = await seedRealm('realm-b');

      const a = await seedUser(realmA.id, 'same@example.com');
      const b = await seedUser(realmB.id, 'same@example.com');

      expect(a.realmId).toBe(realmA.id);
      expect(b.realmId).toBe(realmB.id);
      expect(a.id).not.toBe(b.id);
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

  // --- per-agent action audit (ADR-007 §2, #186) ---------------------------

  describe('audit_logs — per-agent action audit (ADR-007 §2, #186)', () => {
    it('round-trips agent attribution columns (actor, subject, act chain, mode)', async () => {
      const realm = await seedRealm('agent-audit-realm');
      const subject = await seedUser(realm.id, 'subject@example.com');
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
      const subject = await seedUser(realm.id, 'agent-evt@example.com');
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
      const user = await seedUser(realm.id, 'plain@example.com');
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
      const subject = await seedUser(realm.id, 'activity@example.com');
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
      const userA = await seedUser(realmA.id, 'a@example.com');
      const userB = await seedUser(realmB.id, 'b@example.com');
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
      const found = await apiKeys.findByPrefix('qauth_0123456789abcdef');
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
      const listed = await apiKeys.listByClient(client.id);
      expect(listed.map((k) => k.id)).toContain(created.id);

      // Revoke stamps revokedAt; a second revoke is idempotent (revokedAt unchanged).
      const revoked = await apiKeys.revoke(created.id);
      expect(revoked?.revokedAt).toBeTypeOf('number');
      const firstRevokedAt = revoked?.revokedAt;
      const again = await apiKeys.revoke(created.id);
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
      await users.delete(user.id);
      const afterUserDelete = await apiKeys.findByPrefix('qauth_aaaaaaaaaaaaaaaa');
      expect(afterUserDelete).toBeDefined();
      expect(afterUserDelete?.developerId).toBeNull();

      // Deleting the client cascades the key away.
      await clients.delete(client.id);
      const afterClientDelete = await apiKeys.findByPrefix('qauth_aaaaaaaaaaaaaaaa');
      expect(afterClientDelete).toBeUndefined();
    });
  });
});
