import { rmSync } from 'node:fs';

import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { defaultsFromEnv } from '@qauth-labs/fastify-plugin-realm-policy';
import {
  applyQauthMigrations,
  qauthMigrationsFolderWithFirst,
  requireDockerOrSkip,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * REALM POLICIES AT BOOT, ON THE REAL AUTH SERVER (ADR-019 Decision 10,
 * issue #516).
 *
 * The environment only seeds: a fresh database's default realm gets
 * `defaultsFromEnv`, a default realm from before migration 0046 gets the
 * environment's values at the first boot after the upgrade and keeps the
 * settings its row held, and no later boot changes the realm, whatever the
 * environment says. The boot warns once for each set key whose policy the
 * server reads from the realm row; a key whose area still reads the
 * environment gets an info line (the harness passes warnings only), since the
 * server still applies it.
 *
 * The upgrade case rebuilds the schema through migration 0045, writes the
 * default realm as the previous release leaves it, and applies the rest, as
 * the migration runner of the new release does.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const IGNORED = 'only seeds new realms and is ignored';
const KEPT = 'from its row, which differs from the environment';

/** The policy keys these tests set; the harness clears only its own prefixes between boots. */
const POLICY_KEYS = [
  'ACCESS_TOKEN_LIFESPAN',
  'REFRESH_TOKEN_LIFESPAN',
  'PASSWORD_MIN_SCORE',
  'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
  'FAILED_LOGIN_MAX_ATTEMPTS',
] as const;

interface LogLine {
  readonly msg: string;
  readonly variable?: string;
  readonly policy?: string;
  readonly [field: string]: unknown;
}

describe('realm policies at boot on the auth server (#516)', () => {
  let infra: E2eInfrastructure | undefined;
  let admin: FastifyInstance | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const throughPrevious = qauthMigrationsFolderWithFirst(46);

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
    admin = Fastify({ logger: false });
    await admin.register(databasePlugin, {
      config: { connectionString: infra.postgres.connectionString },
    });
    await admin.ready();
  }, 240_000);

  afterAll(async () => {
    await admin?.close();
    await infra?.teardown();
    rmSync(throughPrevious, { recursive: true, force: true });
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await database().dbPool.query(truncateDomainTablesStatement());
  });

  afterEach(() => {
    for (const key of POLICY_KEYS) delete process.env[key];
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  function environment(policyKeys: Partial<Record<(typeof POLICY_KEYS)[number], string>>) {
    if (!infra || !jwt) throw new Error('database not started');
    return { ...baseEnvironment(infra, jwt), ...policyKeys };
  }

  /** Boot the auth server under `env`, run `check` on it, close it; the warnings it logged. */
  async function boot(
    env: Record<string, string>,
    check: (app: FastifyInstance) => Promise<void> = async () => undefined
  ): Promise<LogLine[]> {
    const lines: LogLine[] = [];
    // bootAuthServer clears only its own prefixes, so one boot's keys would
    // reach the next.
    for (const key of POLICY_KEYS) delete process.env[key];
    const server = await bootAuthServer(env, {
      logStream: { write: (chunk: string) => lines.push(JSON.parse(chunk) as LogLine) },
    });
    try {
      await check(server.app);
    } finally {
      await server.close();
    }
    return lines;
  }

  async function defaultRealmRow(): Promise<Record<string, unknown>> {
    const { rows } = await database().dbPool.query(`SELECT * FROM realms WHERE name = 'master'`);
    expect(rows).toHaveLength(1);
    return rows[0];
  }

  it('gives a fresh database a default realm whose policies equal defaultsFromEnv', async () => {
    const env = environment({
      ACCESS_TOKEN_LIFESPAN: '600',
      PASSWORD_MIN_SCORE: '3',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid profile',
    });

    const warnings = await boot(env, async (app) => {
      const realm = await app.repositories.realms.findByName('master');
      const snapshot = await app.policyStore.get(realm?.id ?? '');
      expect(snapshot).toMatchObject({ version: 1, hasPolicies: true });
      expect(snapshot?.policies).toEqual(defaultsFromEnv(env));
    });

    expect(warnings.filter((line) => line.msg.includes(IGNORED))).toEqual([]);
    expect(await defaultRealmRow()).toMatchObject({
      access_token_lifespan: '600',
      dynamic_registration_allowed_scopes: ['openid', 'profile'],
      max_environment_laxity: 'production',
      policies_version: 1,
    });
  });

  it('upgrades a database with a pre-existing default realm: the first boot moves the environment onto it, and only that boot', async () => {
    if (!infra) throw new Error('database not started');
    const pool = database().dbPool;
    const url = infra.postgres.connectionString;
    await pool.query(
      'DROP SCHEMA public CASCADE; CREATE SCHEMA public; DROP SCHEMA IF EXISTS drizzle CASCADE;'
    );
    await applyQauthMigrations(url, throughPrevious);
    // The default realm as the previous release leaves it: its issuer and
    // host, the operator flag, an environment ceiling the operator set, and
    // no registration yet (an empty allowlist).
    const {
      rows: [realm],
    } = await pool.query<{ id: string }>(
      `INSERT INTO realms (name, issuer, is_operator, max_environment_laxity)
       VALUES ('master', 'https://auth.example.com', true, 'staging') RETURNING id`
    );
    await pool.query(
      `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ('auth.example.com', $1, 'primary')`,
      [realm.id]
    );
    await pool.query(`INSERT INTO users (realm_id, first_name) VALUES ($1, 'Ada')`, [realm.id]);
    // A second realm whose allowlist an earlier release copied from an
    // environment value with a repeat, as `/oauth/register` wrote it.
    const {
      rows: [legacy],
    } = await pool.query<{ id: string }>(
      `INSERT INTO realms (name, dynamic_registration_allowed_scopes)
       VALUES ('legacy', '["openid", "email", "openid"]'::jsonb) RETURNING id`
    );
    const users = async () => (await pool.query('SELECT * FROM users ORDER BY id')).rows;
    const usersBefore = await users();
    await applyQauthMigrations(url);
    expect(await defaultRealmRow()).toMatchObject({ policies_version: 0, policies: {} });

    // The first boot after the upgrade.
    const first = environment({
      ACCESS_TOKEN_LIFESPAN: '600',
      REFRESH_TOKEN_LIFESPAN: '7200',
      PASSWORD_MIN_SCORE: '3',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid profile',
    });
    const expected = {
      ...defaultsFromEnv(first),
      posture: { maxEnvironmentLaxity: 'staging' },
    };
    const firstWarnings = await boot(first, async (app) => {
      const snapshot = await app.policyStore.get(realm.id);
      expect(snapshot).toMatchObject({ version: 1, hasPolicies: true });
      expect(snapshot?.policies).toEqual(expected);
      // The repeat is dropped, as defaultsFromEnv drops one, and the boot goes on.
      expect(
        (await app.policyStore.get(legacy.id))?.policies.registration
          .dynamicRegistrationAllowedScopes
      ).toEqual(['openid', 'email']);
    });
    expect(firstWarnings.filter((line) => line.msg.includes(IGNORED))).toEqual([]);
    // Each value a row kept over a different seed is named, once: the default
    // realm's ceiling, and the legacy realm's allowlist.
    expect(firstWarnings.filter((line) => line.msg.includes(KEPT))).toEqual([
      expect.objectContaining({ realm: 'master', policy: 'posture.maxEnvironmentLaxity' }),
      expect.objectContaining({
        realm: 'legacy',
        policy: 'registration.dynamicRegistrationAllowedScopes',
        variable: 'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
      }),
    ]);
    const filled = await defaultRealmRow();
    expect(filled).toMatchObject({
      id: realm.id,
      access_token_lifespan: '600',
      refresh_token_lifespan: '7200',
      dynamic_registration_allowed_scopes: ['openid', 'profile'],
      max_environment_laxity: 'staging',
      policies_version: 1,
    });
    expect(await users()).toEqual(usersBefore);

    // A later boot with other values changes nothing, and names each key once.
    const second = environment({
      ACCESS_TOKEN_LIFESPAN: '1200',
      PASSWORD_MIN_SCORE: '1',
      DEFAULT_DYNAMIC_REGISTRATION_SCOPES: 'openid email offline_access',
    });
    const secondWarnings = await boot(second, async (app) => {
      expect((await app.policyStore.get(realm.id))?.policies).toEqual(expected);
    });
    expect(await defaultRealmRow()).toEqual(filled);
    expect(secondWarnings.filter((line) => line.msg.includes(KEPT))).toEqual([]);
    const ignored = secondWarnings.filter((line) => line.msg.includes(IGNORED));
    // The allowlist's area reads the realm row: its key is ignored, once.
    expect(ignored).toEqual([
      expect.objectContaining({
        variable: 'DEFAULT_DYNAMIC_REGISTRATION_SCOPES',
        policy: 'registration.dynamicRegistrationAllowedScopes',
        realm: 'master',
      }),
    ]);
    // The allowlist changed in the environment, to a looser list: the stored,
    // stricter one applies, and no further warning is needed (#529).
    expect(secondWarnings.filter((line) => line.environment !== undefined)).toEqual([]);
    // The token lifetimes and the password policy still read the
    // environment (#527, #528): no warning tells the operator to drop them.
    expect(ignored.map((line) => line.variable)).not.toContain('ACCESS_TOKEN_LIFESPAN');
    expect(ignored.map((line) => line.variable)).not.toContain('PASSWORD_MIN_SCORE');
  });
});
