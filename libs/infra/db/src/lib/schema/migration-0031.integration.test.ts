/**
 * Seed-then-migrate test for migration 0031: every `audit_logs` row copied
 * into the event store (ADR-019 Decision 8, issue #458).
 *
 * A database at 0030 holds audit rows of every event string the auth server
 * and the client-suspension tool ever wrote, with the metadata they wrote.
 * After the upgrade, each row is one event: the mapped type, its timestamp,
 * its realm, and an envelope the event contract accepts (`parseEvent`), read
 * back through the events repository. `audit_logs` is left as it was.
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside the suite's one database, and upgrades to
 * 0031 itself, not to the newest migration, so a later migration cannot change
 * what this suite pins.
 */
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { LEGACY_EVENT_MAP, legacyEventMapping, parseEvent } from '@qauth-labs/shared-events';
import {
  applyQauthMigrations,
  QAUTH_MIGRATIONS_FOLDER,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { eventStreamStart } from '../events/position';
import { createEventsRepository } from '../repositories/events.repository';

const MIGRATION_IDX = 31;
const MIGRATION_TAG = '0031_audit_logs_backfill';

interface JournalEntry {
  idx: number;
  tag: string;
}

/**
 * A copy of the migrations folder that stops before `idx`, so the drizzle
 * migrator can bring a database to exactly that schema and record it in its
 * own journal table.
 */
function migrationsFolderBefore(idx: number): string {
  const journal = JSON.parse(
    readFileSync(path.join(QAUTH_MIGRATIONS_FOLDER, 'meta/_journal.json'), 'utf8')
  ) as { entries: JournalEntry[] };
  const entries = journal.entries.filter((e) => e.idx < idx);

  const folder = mkdtempSync(path.join(tmpdir(), 'qauth-migrations-'));
  mkdirSync(path.join(folder, 'meta'));
  writeFileSync(
    path.join(folder, 'meta/_journal.json'),
    JSON.stringify({ ...journal, entries }, null, 2)
  );
  for (const entry of entries) {
    copyFileSync(
      path.join(QAUTH_MIGRATIONS_FOLDER, `${entry.tag}.sql`),
      path.join(folder, `${entry.tag}.sql`)
    );
  }
  return folder;
}

/** An audit row as the old writers inserted it. */
interface AuditSeed {
  readonly event: string;
  readonly eventType: string;
  readonly userId?: string | null;
  readonly oauthClientId?: string | null;
  readonly success?: boolean;
  readonly ipAddress?: string | null;
  readonly userAgent?: string | null;
  readonly actorClientId?: string | null;
  readonly delegationChain?: string[] | null;
  readonly scopeMode?: string | null;
  readonly metadata?: Record<string, unknown> | null;
  /** A fixed id, to pin how a row's id becomes the event id. */
  readonly id?: string;
}

describe('migration 0031 — audit_logs copied into events (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  let before0031: string | undefined;
  let through0031: string | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
    before0031 = migrationsFolderBefore(MIGRATION_IDX);
    through0031 = migrationsFolderBefore(MIGRATION_IDX + 1);
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    for (const folder of [before0031, through0031]) {
      if (folder) rmSync(folder, { recursive: true, force: true });
    }
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container || !before0031 || !through0031) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA IF EXISTS drizzle CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
    );
    await applyQauthMigrations(container.connectionString, before0031);
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  async function upgrade(): Promise<void> {
    if (!container || !through0031) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through0031);
  }

  async function one(statement: string, params: unknown[] = []): Promise<string> {
    const { rows } = await db().query(statement, params);
    return rows[0].id as string;
  }

  async function insertAudit(seed: AuditSeed, createdAt: number): Promise<string> {
    const columns = [
      'user_id',
      'oauth_client_id',
      'event',
      'event_type',
      'success',
      'ip_address',
      'user_agent',
      'actor_client_id',
      'delegation_chain',
      'scope_mode',
      'metadata',
      'created_at',
    ];
    const values: unknown[] = [
      seed.userId ?? null,
      seed.oauthClientId ?? null,
      seed.event,
      seed.eventType,
      seed.success ?? true,
      seed.ipAddress ?? null,
      seed.userAgent ?? null,
      seed.actorClientId ?? null,
      seed.delegationChain === undefined || seed.delegationChain === null
        ? null
        : JSON.stringify(seed.delegationChain),
      seed.scopeMode ?? null,
      seed.metadata === undefined || seed.metadata === null ? null : JSON.stringify(seed.metadata),
      createdAt,
    ];
    if (seed.id !== undefined) {
      columns.unshift('id');
      values.unshift(seed.id);
    }
    const placeholders = values.map((_, i) => `$${i + 1}`).join(', ');
    return one(
      `INSERT INTO audit_logs (${columns.join(', ')}) VALUES (${placeholders}) RETURNING id`,
      values
    );
  }

  interface World {
    readonly realmId: string;
    readonly operatorRealmId: string;
    readonly otherRealmId: string;
    readonly userId: string;
    readonly otherUserId: string;
    readonly clientRowId: string;
    readonly otherClientRowId: string;
  }

  /**
   * Three realms: the operator realm (the default), the realm of the user and
   * the client most rows name, and a third that only a user, a client or the
   * metadata of a wallet presentation names.
   */
  async function seedWorld(): Promise<World> {
    const operatorRealmId = await one(
      `INSERT INTO realms (name, is_operator) VALUES ('m0031-operator', true) RETURNING id`
    );
    const realmId = await one(`INSERT INTO realms (name) VALUES ('m0031') RETURNING id`);
    const otherRealmId = await one(`INSERT INTO realms (name) VALUES ('m0031-other') RETURNING id`);
    const userId = await one(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [realmId]);
    const otherUserId = await one(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      otherRealmId,
    ]);
    const clientRowId = await one(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, 'portal', 'h', 'portal', '["https://app.example.com/cb"]') RETURNING id`,
      [realmId]
    );
    const otherClientRowId = await one(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, 'other-app', 'h', 'other', '["https://other.example.com/cb"]') RETURNING id`,
      [otherRealmId]
    );
    return {
      realmId,
      operatorRealmId,
      otherRealmId,
      userId,
      otherUserId,
      clientRowId,
      otherClientRowId,
    };
  }

  const CONSENT_ID = '0192a7c1-5e2f-7a3b-8c4d-5e6f7a8b9c0d';
  const FAMILY_ID = '0192a7c1-5e2f-7a3b-9c4d-5e6f7a8b9c0e';

  /**
   * One audit row per event string, with the metadata the old writer gave it.
   * Every row of `LEGACY_EVENT_MAP` whose source is an audit row appears; the
   * test below checks that.
   */
  function auditSeeds(w: World): AuditSeed[] {
    const browser = { ipAddress: '::ffff:203.0.113.9', userAgent: 'Mozilla/5.0 (m0031)' };
    return [
      {
        event: 'user.login.success',
        eventType: 'auth',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        ...browser,
        metadata: { sessionId: '0192a7c1-0000-7000-8000-000000000001' },
      },
      {
        event: 'user.login.failure',
        eventType: 'auth',
        success: false,
        ...browser,
        metadata: { email: 'someone@example.com', error: 'Invalid credentials' },
      },
      {
        event: 'ui.login.success',
        eventType: 'auth',
        userId: w.userId,
        ...browser,
        metadata: { sessionId: 's', returnTo: '/oauth/authorize?client_id=portal' },
      },
      {
        event: 'ui.login.failure',
        eventType: 'auth',
        success: false,
        userId: w.userId,
        ...browser,
        metadata: { email: 'user@example.com', error: 'Email address not verified' },
      },
      { event: 'ui.login.csrf_failure', eventType: 'security', success: false, ...browser },
      {
        event: 'ui.wallet_login.success',
        eventType: 'auth',
        userId: w.otherUserId,
        ...browser,
        metadata: { sessionId: 's', verifierProfile: 'haip-1.0' },
      },
      {
        event: 'ui.wallet_login.failure',
        eventType: 'auth',
        success: false,
        ...browser,
        metadata: { assertedIdentifier: 'user@example.com', reason: 'not_resolved' },
      },
      { event: 'ui.wallet_login.csrf_failure', eventType: 'security', success: false },
      {
        event: 'user.logout.success',
        eventType: 'auth',
        userId: w.userId,
        metadata: { tokenExpired: false },
      },
      {
        event: 'user.logout.failure',
        eventType: 'auth',
        success: false,
        metadata: { error: 'jwt malformed', tokenSub: 'portal' },
      },
      {
        event: 'oauth.authorize.success',
        eventType: 'token',
        userId: w.userId,
        oauthClientId: w.clientRowId,
      },
      {
        event: 'oauth.authorize.failure',
        eventType: 'token',
        success: false,
        oauthClientId: w.clientRowId,
        metadata: { error: 'redirect_uri not registered', client_id: 'portal' },
      },
      {
        event: 'oauth.stepup.required',
        eventType: 'security',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: {
          client_id: 'portal',
          reason: 'fresh_authentication_required',
          dangerous: ['admin:write'],
          prompt: null,
          maxAge: 300,
        },
      },
      {
        event: 'oauth.stepup.elevation',
        eventType: 'security',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        actorClientId: 'portal',
        scopeMode: 'admin',
        metadata: {
          client_id: 'portal',
          dangerousScopes: ['admin:write'],
          scopes: ['openid', 'admin:write'],
          authTime: 1_790_000_000_123,
        },
      },
      {
        event: 'oauth.consent.granted',
        eventType: 'auth',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: {
          client_id: 'portal',
          scopes: ['openid'],
          remembered: true,
          dangerousScopes: [],
        },
      },
      {
        event: 'oauth.consent.denied',
        eventType: 'auth',
        success: false,
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: {
          error: 'invalid_scope',
          reason: 'consent_scope_mismatch',
          client_id: 'portal',
          bound: 'openid',
          posted: 'openid admin',
        },
      },
      {
        event: 'oauth.consent.revoked',
        eventType: 'auth',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { consentId: CONSENT_ID, refreshTokensRevoked: 2 },
      },
      {
        event: 'oauth.consent.csrf_failure',
        eventType: 'security',
        success: false,
        userId: w.userId,
        metadata: { client_id: 'portal' },
      },
      {
        event: 'consents.revoke.csrf_failure',
        eventType: 'security',
        success: false,
        userId: w.userId,
        metadata: { reason: 'missing_or_mismatched_csrf_token' },
      },
      {
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        actorClientId: 'agent-b',
        delegationChain: ['agent-b', 'agent-a'],
        scopeMode: 'exec',
        metadata: {
          grantType: 'token-exchange',
          delegationDepth: 2,
          scope: 'openid notes:read',
          audience: ['https://rs.example.com'],
          expiresIn: 900,
          actorTokenSubject: 'agent-b',
        },
      },
      {
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: {
          grantType: 'refresh_token',
          familyId: FAMILY_ID,
          rotatedFromTokenId: '0192a7c1-0000-7000-8000-000000000002',
          scope: 'openid',
        },
      },
      {
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        metadata: { error: 'Client authentication failed', grantType: 'client_credentials' },
      },
      {
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        oauthClientId: w.clientRowId,
        metadata: { error: 'invalid_grant', grantType: 'authorization_code' },
      },
      {
        event: 'oauth.revoke.success',
        eventType: 'token',
        oauthClientId: w.clientRowId,
        metadata: { tokenTypeHint: 'refresh_token' },
      },
      {
        event: 'oauth.revoke.failure',
        eventType: 'token',
        success: false,
        metadata: { error: 'Client authentication failed' },
      },
      {
        event: 'oauth.introspect.success',
        eventType: 'token',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { tokenClientId: 'portal' },
      },
      {
        event: 'oauth.introspect.failure',
        eventType: 'token',
        success: false,
        oauthClientId: w.clientRowId,
        metadata: { error: 'Token revoked' },
      },
      { event: 'oauth.userinfo.success', eventType: 'token', userId: w.userId, metadata: {} },
      {
        event: 'oauth.userinfo.failure',
        eventType: 'token',
        success: false,
        metadata: { error: 'Access token subject is not a user', tokenSub: 'portal' },
      },
      {
        event: 'oauth.client.registered',
        eventType: 'client',
        oauthClientId: w.otherClientRowId,
        metadata: {
          clientId: 'other-app',
          registrationType: 'dynamic',
          isPublic: true,
          isAgent: false,
          grantTypes: ['authorization_code', 'refresh_token'],
          scopes: ['openid'],
        },
      },
      {
        event: 'oauth.client.created',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: {
          clientId: 'portal',
          isPublic: false,
          grantTypes: ['authorization_code'],
          tokenEndpointAuthMethod: 'client_secret_basic',
        },
      },
      {
        event: 'oauth.client.updated',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { clientId: 'portal', fields: ['name', 'redirectUris'] },
      },
      {
        // A deleted client: the row is gone, the metadata keeps its client_id.
        event: 'oauth.client.deleted',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: null,
        metadata: { clientId: 'gone-app' },
      },
      {
        event: 'oauth.client.secret_regenerated',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { clientId: 'portal' },
      },
      {
        event: 'oauth.client.suspended',
        eventType: 'client',
        oauthClientId: w.clientRowId,
        metadata: { clientId: 'portal', by: 'operator', tool: 'db:suspend-oauth-client' },
      },
      {
        event: 'oauth.client.suspension_lifted',
        eventType: 'client',
        oauthClientId: w.clientRowId,
        metadata: { clientId: 'portal', by: 'operator', tool: 'db:suspend-oauth-client' },
      },
      {
        event: 'api_key.created',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { apiKeyId: 'key-1', prefix: 'qk_live', clientId: 'portal' },
      },
      {
        event: 'api_key.revoked',
        eventType: 'client',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        metadata: { apiKeyId: 'key-1', prefix: 'qk_live', clientId: 'portal' },
      },
      {
        event: 'auth.wallet_link.success',
        eventType: 'auth',
        userId: w.userId,
        ...browser,
        metadata: {
          credentialId: '0192a7c1-0000-7000-8000-000000000003',
          subjectSource: 'asserted-lookup',
          rebound: false,
          verifierProfile: 'oid4vp-1.0-base',
        },
      },
      {
        event: 'auth.wallet_link.failure',
        eventType: 'auth',
        success: false,
        userId: w.userId,
        metadata: { reason: 'conflict', verifierProfile: 'oid4vp-1.0-base' },
      },
      {
        event: 'auth.wallet_link.csrf_failure',
        eventType: 'security',
        success: false,
        userId: w.userId,
        metadata: { reason: 'missing_or_mismatched_csrf_token' },
      },
      {
        event: 'oid4vp.response.received',
        eventType: 'auth',
        metadata: {
          requestStateId: '0192a7c1-0000-7000-8000-000000000004',
          realmId: w.otherRealmId,
          verifierProfile: 'haip-1.0',
          presentationCount: 1,
          authenticated: false,
        },
      },
    ];
  }

  async function readAllEvents(realmIds: readonly string[]) {
    const repository = createEventsRepository(drizzle(db()));
    const all = [];
    for (const realmId of realmIds) {
      const page = await repository.readAfter(realmId, eventStreamStart(realmId), 1000);
      all.push(...page.events.map((stored) => stored.event));
    }
    return all;
  }

  it('seeds a row of every event string an audit row was ever written with', () => {
    const seeded = new Set(auditSeeds({} as World).map((seed) => seed.event));
    const auditNames = LEGACY_EVENT_MAP.filter((m) => m.source === 'audit').map((m) => m.event);
    expect([...seeded].sort()).toEqual([...new Set(auditNames)].sort());
  });

  it('copies every row, keeps its time, maps its type and builds events the contract accepts', async () => {
    const w = await seedWorld();
    const seeds = auditSeeds(w);
    const base = 1_791_000_000_000;
    const auditIds = new Map<string, AuditSeed>();
    for (const [i, seed] of seeds.entries()) {
      auditIds.set(await insertAudit(seed, base + i * 1000), seed);
    }

    await upgrade();

    const { rows: counts } = await db().query(
      `SELECT (SELECT count(*) FROM audit_logs)::int AS audit, (SELECT count(*) FROM events)::int AS events`
    );
    expect(counts[0].events).toBe(seeds.length);
    expect(counts[0].events).toBe(counts[0].audit);

    const events = await readAllEvents([w.realmId, w.operatorRealmId, w.otherRealmId]);
    expect(events).toHaveLength(seeds.length);

    for (const event of events) {
      const seed = auditIds.get(event.id);
      expect(seed, `event ${event.id} keeps its audit row's id`).toBeDefined();
      if (!seed) continue;
      const index = seeds.indexOf(seed);
      // The type the map gives, and the time the row was written.
      expect(event.type, seed.event).toBe(legacyEventMapping(seed.event)?.type);
      expect(Date.parse(event.time), seed.event).toBe(base + index * 1000);
      // An envelope the contract accepts: the type's schema, the payload rules
      // and the subject.
      expect(() => parseEvent(event), `${seed.event}: ${JSON.stringify(event)}`).not.toThrow();
      // The members the old name implies.
      for (const [member, value] of Object.entries(legacyEventMapping(seed.event)?.data ?? {})) {
        expect(event.data[member], `${seed.event}: ${member}`).toBe(value);
      }
    }
  });

  it('takes the realm from the user, else the client, else the metadata, else the default realm', async () => {
    const w = await seedWorld();
    const at = 1_791_000_000_000;
    const byUser = await insertAudit(
      { event: 'oauth.userinfo.success', eventType: 'token', userId: w.otherUserId },
      at
    );
    const byClient = await insertAudit(
      {
        event: 'oauth.revoke.failure',
        eventType: 'token',
        success: false,
        oauthClientId: w.otherClientRowId,
        metadata: { error: 'invalid_client' },
      },
      at + 1
    );
    const byMetadata = await insertAudit(
      {
        event: 'oid4vp.response.received',
        eventType: 'auth',
        metadata: { realmId: w.otherRealmId, verifierProfile: 'haip-1.0', presentationCount: 1 },
      },
      at + 2
    );
    const byDefault = await insertAudit(
      {
        event: 'oauth.token.exchange.failure',
        eventType: 'token',
        success: false,
        metadata: { error: 'unsupported_grant_type: ID-JAG is not enabled' },
      },
      at + 3
    );
    // A user deleted since: `set null` left the row, which falls back to its
    // client's realm.
    const deletedUser = await insertAudit(
      {
        event: 'oauth.authorize.success',
        eventType: 'token',
        userId: null,
        oauthClientId: w.otherClientRowId,
      },
      at + 4
    );

    await upgrade();

    const { rows } = await db().query<{ id: string; realm_id: string }>(
      `SELECT id, realm_id FROM events`
    );
    const realmOf = new Map(rows.map((row) => [row.id, row.realm_id]));
    expect(realmOf.get(byUser)).toBe(w.otherRealmId);
    expect(realmOf.get(byClient)).toBe(w.otherRealmId);
    expect(realmOf.get(byMetadata)).toBe(w.otherRealmId);
    expect(realmOf.get(byDefault)).toBe(w.operatorRealmId);
    expect(realmOf.get(deletedUser)).toBe(w.otherRealmId);
  });

  it('carries the agent fields in the actor and the data', async () => {
    const w = await seedWorld();
    const id = await insertAudit(
      {
        event: 'oauth.token.exchange.success',
        eventType: 'token',
        userId: w.userId,
        oauthClientId: w.clientRowId,
        actorClientId: 'agent-b',
        delegationChain: ['agent-b', 'agent-a'],
        scopeMode: 'exec',
        ipAddress: '::ffff:198.51.100.7',
        userAgent: 'agent/1.0',
        metadata: {
          grantType: 'token-exchange',
          delegationDepth: 2,
          scope: 'openid notes:read',
          audience: 'https://rs.example.com',
          expiresIn: 900,
          familyId: FAMILY_ID,
          rotatedFromTokenId: 'x',
        },
      },
      1_791_000_000_000
    );

    await upgrade();

    const [event] = await readAllEvents([w.realmId]);
    expect(event).toEqual({
      id,
      type: 'urn:qauth:event:token.issued:v1-rc.0',
      time: new Date(1_791_000_000_000).toISOString(),
      realm: w.realmId,
      category: 'user',
      actor: { type: 'client', id: 'agent-b', delegationChain: ['agent-b', 'agent-a'] },
      subject: { type: 'user', id: w.userId },
      client: { id: 'portal' },
      request: { ip: '198.51.100.7', userAgent: 'agent/1.0' },
      data: {
        grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
        scopes: ['openid', 'notes:read'],
        audience: ['https://rs.example.com'],
        expiresIn: 900,
        refreshFamilyId: FAMILY_ID,
        delegationDepth: 2,
        scopeMode: 'exec',
      },
    });
  });

  it('copies nothing it may not: no address, message, session id or token subject', async () => {
    const w = await seedWorld();
    const seeds = auditSeeds(w);
    for (const [i, seed] of seeds.entries()) await insertAudit(seed, 1_791_000_000_000 + i);

    await upgrade();

    const { rows } = await db().query<{ data: Record<string, unknown> }>(`SELECT data FROM events`);
    const stored = JSON.stringify(rows.map((row) => row.data));
    for (const leaked of [
      '@example.com',
      'Invalid credentials',
      'Client authentication failed',
      'sessionId',
      'tokenSub',
      'rotatedFromTokenId',
      'assertedIdentifier',
      'requestStateId',
    ]) {
      expect(stored).not.toContain(leaked);
    }
  });

  it('gives an older row a UUIDv7 made from its time, the same on every run', async () => {
    const w = await seedWorld();
    const v4 = '3f6c2a1b-9d8e-4f7a-b6c5-d4e3f2a1b0c9';
    const at = 1_791_000_000_000;
    await insertAudit(
      { id: v4, event: 'oauth.userinfo.success', eventType: 'token', userId: w.userId },
      at
    );

    await upgrade();

    const { rows } = await db().query<{ id: string }>(`SELECT id FROM events`);
    expect(rows).toHaveLength(1);
    const id = rows[0].id;
    // 48 bits of the row's created_at, version 7, the old id's other bits.
    expect(id.replace(/-/g, '').slice(0, 12)).toBe(at.toString(16).padStart(12, '0'));
    expect(id[14]).toBe('7');
    expect(id.slice(15, 18)).toBe(v4.slice(15, 18));
    expect(id.slice(24)).toBe(v4.slice(24));

    // The copy is idempotent: running its statements again adds nothing.
    const statements = readFileSync(
      path.join(QAUTH_MIGRATIONS_FOLDER, `${MIGRATION_TAG}.sql`),
      'utf8'
    )
      .split('--> statement-breakpoint')
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0);
    const client = await db().connect();
    try {
      for (const statement of statements) await client.query(statement);
    } finally {
      client.release();
    }
    const { rows: after } = await db().query<{ id: string }>(`SELECT id FROM events`);
    expect(after).toEqual([{ id }]);
  });

  it('leaves audit_logs in place, row for row', async () => {
    const w = await seedWorld();
    const seeds = auditSeeds(w);
    for (const [i, seed] of seeds.entries()) await insertAudit(seed, 1_791_000_000_000 + i);
    const { rows: before } = await db().query(`SELECT * FROM audit_logs ORDER BY id`);

    await upgrade();

    const { rows: after } = await db().query(`SELECT * FROM audit_logs ORDER BY id`);
    expect(after).toEqual(before);
  });

  it('upgrades a database with no audit rows', async () => {
    await upgrade();
    const { rows } = await db().query(`SELECT count(*)::int AS n FROM events`);
    expect(rows[0].n).toBe(0);
  });
});
