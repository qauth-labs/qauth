import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import * as net from 'node:net';

import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

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

/**
 * THE BREAK-GLASS CLI (ADR-019 Decisions 7 and 9, issue #602), against a
 * real Postgres and Redis.
 *
 * `enrol-admin` creates an admin account with no credential, its grant and a
 * token that works once and is stored only as its hash; `retire-key` runs
 * the emergency retirement. Each writes its admin audit row and its
 * `admin.break_glass_used` event before it changes anything, and changes
 * nothing when either cannot be written: test triggers refuse a change made
 * before the record, or refuse the record itself. The process opens no
 * listening socket. The enrolled admin is refused as an approver for 7 days,
 * by the two-admin rule read at a given clock.
 *
 * The commands run over a booted server's plugins (`breakGlassDependencies`),
 * and once as their own process (`runBreakGlassProcess`), in this one. App
 * modules are imported after each boot, so they are the instances the
 * server loaded.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const OPERATOR = Object.freeze({ name: 'break-glass-operator', uid: 4242, host: 'db-host-1' });
const USED = 'urn:qauth:event:admin.break_glass_used:v1-rc.0';
const DAY = 24 * 60 * 60 * 1000;
const WINDOW = 7 * DAY;

describe('the break-glass CLI (#602)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

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
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    const server = await bootAuthServer(variables());
    await server.app.dbPool.query(truncateDomainTablesStatement());
    await server.app.redis.flushdb();
    await server.close();
  }, 120_000);

  afterEach(async () => {
    vi.restoreAllMocks();
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  /** A deployment with no key variable: the store holds the keys, which a retirement changes. */
  function variables(): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const environment: Record<string, string> = { ...baseEnvironment(infra, jwt) };
    delete environment['JWT_PRIVATE_KEY'];
    delete environment['JWT_PUBLIC_KEY'];
    return environment;
  }

  async function boot(): Promise<FastifyInstance> {
    const server = await bootAuthServer(variables());
    booted.push(server);
    return server.app;
  }

  async function realmOf(app: FastifyInstance) {
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error(`no realm ${E2E_REALM_NAME}`);
    return realm;
  }

  /** The group's commands over the booted server's plugins, and what they print. */
  async function cli(app: FastifyInstance) {
    const { breakGlassDependencies } = await import('./helpers/break-glass-host');
    const { parseBreakGlassArguments, runBreakGlass } = await import('./helpers/break-glass');
    const { env } = await import('../config/env');
    const out: string[] = [];
    const err: string[] = [];
    const deps = breakGlassDependencies(app, {
      kekEnv: process.env,
      signing: {
        enabledSignatureAlgorithms: env.enabledSignatureAlgorithms,
        hybridSigning: env.HYBRID_SIGNING_ENABLED,
      },
      operator: () => OPERATOR,
      out: (line) => out.push(line),
      err: (line) => err.push(line),
    });
    return {
      out,
      err,
      run: async (...argv: string[]): Promise<number> => {
        const command = parseBreakGlassArguments(argv);
        if (command === 'help') throw new Error('not a command');
        return runBreakGlass(command, deps);
      },
    };
  }

  /** The URL `enrol-admin` printed, and its token. */
  function printedUrl(out: readonly string[]): { url: string; token: string } {
    const line = out.find((printed) => printed.includes('#token='));
    if (line === undefined) throw new Error('no enrolment URL printed');
    const url = line.trim();
    return { url, token: url.slice(url.indexOf('#token=') + '#token='.length) };
  }

  async function activeKid(app: FastifyInstance): Promise<string> {
    const { rows } = await app.dbPool.query<{ kid: string }>(
      `SELECT kid FROM realm_keys
        WHERE realm_id = $1 AND purpose = 'token_signing' AND status = 'active' AND algorithm = 'EdDSA'`,
      [(await realmOf(app)).id]
    );
    if (rows[0] === undefined) throw new Error('no active EdDSA key');
    return rows[0].kid;
  }

  async function count(app: FastifyInstance, sql: string, params: unknown[] = []): Promise<number> {
    const { rows } = await app.dbPool.query<{ n: number }>(sql, params);
    return rows[0]?.n ?? 0;
  }

  /** What the commands may have changed, counted. */
  async function state(app: FastifyInstance) {
    const realm = (await realmOf(app)).id;
    return {
      users: await count(app, 'SELECT count(*)::int AS n FROM users'),
      grants: await count(app, 'SELECT count(*)::int AS n FROM admin_grants'),
      enrolments: await count(app, 'SELECT count(*)::int AS n FROM admin_enrolments'),
      compromised: await count(
        app,
        `SELECT count(*)::int AS n FROM realm_keys WHERE realm_id = $1 AND status = 'compromised'`,
        [realm]
      ),
      audit: await count(app, 'SELECT count(*)::int AS n FROM admin_audit_log'),
      announced: await count(app, 'SELECT count(*)::int AS n FROM events WHERE type = $1', [USED]),
    };
  }

  /** Run `work` with a test trigger in place, dropped after it. */
  async function withTriggers(
    app: FastifyInstance,
    install: string,
    drop: string,
    work: () => Promise<void>
  ): Promise<void> {
    await app.dbPool.query(install);
    try {
      await work();
    } finally {
      await app.dbPool.query(drop);
    }
  }

  it('enrol-admin creates an account with no credential, its grant, and a token that works once, stored only as its hash', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const { run, out, err } = await cli(app);

    expect(await run('enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'security-admin')).toBe(0);
    expect(err).toEqual([]);
    const { url, token } = printedUrl(out);
    expect(url.startsWith(`${realm.issuer}/ui/admin-enrolment#token=`)).toBe(true);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);

    const { rows: enrolments } = await app.dbPool.query(
      'SELECT user_id, realm_id, token_hash, created_at, expires_at, used_at FROM admin_enrolments'
    );
    expect(enrolments).toHaveLength(1);
    const enrolment = enrolments[0];
    expect(enrolment.realm_id).toBe(realm.id);
    expect(Number(enrolment.expires_at) - Number(enrolment.created_at)).toBe(60 * 60_000);
    expect(enrolment.used_at).toBeNull();
    const accountId: string = enrolment.user_id;
    expect(out[0]).toContain(`Enrolled admin account ${accountId} in realm ${E2E_REALM_NAME}`);

    // The account: a user of the realm with no password and no credential.
    const { rows: users } = await app.dbPool.query(
      'SELECT realm_id, enabled, is_service_account FROM users WHERE id = $1',
      [accountId]
    );
    expect(users).toEqual([{ realm_id: realm.id, enabled: true, is_service_account: false }]);
    expect(
      await count(app, 'SELECT count(*)::int AS n FROM user_credentials WHERE user_id = $1', [
        accountId,
      ])
    ).toBe(0);
    // Its grant, on its own realm, created by no account.
    const { rows: grants } = await app.dbPool.query(
      'SELECT built_in_role, target_realm_id, created_by, revoked_at FROM admin_grants WHERE user_id = $1',
      [accountId]
    );
    expect(grants).toEqual([
      {
        built_in_role: 'security-admin',
        target_realm_id: realm.id,
        created_by: null,
        revoked_at: null,
      },
    ]);

    // Only the token's hash is stored, in no other spelling of the token.
    expect(enrolment.token_hash).toEqual(
      createHash('sha256').update(Buffer.from(token, 'base64url')).digest()
    );
    const { rows: stored } = await app.dbPool.query<{ row: string }>(
      'SELECT row_to_json(e)::text AS row FROM admin_enrolments e'
    );
    expect(stored[0]?.row).not.toContain(token);
    expect(stored[0]?.row).not.toContain(Buffer.from(token, 'base64url').toString('hex'));
    // Nor in the record of the run.
    const { rows: recorded } = await app.dbPool.query<{ row: string }>(
      `SELECT row_to_json(a)::text AS row FROM admin_audit_log a WHERE operation_id = 'breakGlass.enrolAdmin'`
    );
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.row).not.toContain(token);

    // The token works once.
    const enrolled = app.repositories.adminEnrolments;
    expect(await enrolled.redeem(realm.id, token, Date.now())).toMatchObject({
      userId: accountId,
      realmId: realm.id,
    });
    expect(await enrolled.redeem(realm.id, token, Date.now())).toBeUndefined();
  }, 180_000);

  it('refuses an expired token, and a used one, alike', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const { run, out } = await cli(app);

    expect(
      await run('enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'viewer', '--expires-in', '1')
    ).toBe(0);
    const { token } = printedUrl(out);
    const { rows } = await app.dbPool.query<{ created_at: string; expires_at: string }>(
      'SELECT created_at, expires_at FROM admin_enrolments'
    );
    const createdAt = Number(rows[0]?.created_at);
    expect(Number(rows[0]?.expires_at)).toBe(createdAt + 60_000);

    const enrolled = app.repositories.adminEnrolments;
    expect(await enrolled.redeem(realm.id, token, createdAt + 60_000)).toBeUndefined();
    expect(await enrolled.redeem(realm.id, token, createdAt + DAY)).toBeUndefined();
    // Before it expires it works, once.
    expect(await enrolled.redeem(realm.id, token, createdAt + 59_000)).toBeDefined();
    expect(await enrolled.redeem(realm.id, token, createdAt + 59_500)).toBeUndefined();
  }, 180_000);

  it('writes the audit row and the event before it changes anything, for each command', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const kid = await activeKid(app);
    const { run, out, err } = await cli(app);

    // A change made before its run's record, in the same transaction, is refused.
    const guarded = [
      ['users', 'INSERT', 'breakGlass.enrolAdmin', 'enrol-admin'],
      ['admin_enrolments', 'INSERT', 'breakGlass.enrolAdmin', 'enrol-admin'],
      ['admin_grants', 'INSERT', 'breakGlass.enrolAdmin', 'enrol-admin'],
      ['realm_keys', 'INSERT OR UPDATE', 'breakGlass.retireKey', 'retire-key'],
      ['refresh_tokens', 'UPDATE', 'breakGlass.retireKey', 'retire-key'],
    ] as const;
    await withTriggers(
      app,
      `CREATE FUNCTION break_glass_test_recorded_first() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN
         IF NOT EXISTS (SELECT 1 FROM admin_audit_log WHERE operation_id = TG_ARGV[0])
            OR NOT EXISTS (SELECT 1 FROM events WHERE type = '${USED}' AND data->>'command' = TG_ARGV[1]) THEN
           RAISE EXCEPTION 'changed before the break-glass record';
         END IF;
         RETURN NEW;
       END $$;
       ${guarded
         .map(
           ([table, events, operation, command]) =>
             `CREATE TRIGGER break_glass_test_${table} BEFORE ${events} ON ${table}
                FOR EACH ROW EXECUTE FUNCTION break_glass_test_recorded_first('${operation}', '${command}');`
         )
         .join('\n')}`,
      `${guarded.map(([table]) => `DROP TRIGGER break_glass_test_${table} ON ${table};`).join('\n')}
       DROP FUNCTION break_glass_test_recorded_first();`,
      async () => {
        expect(await run('enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'editor')).toBe(0);
        expect(await run('retire-key', '--realm', E2E_REALM_NAME, '--kid', kid, '--confirm')).toBe(
          0
        );
      }
    );
    expect(err).toEqual([]);
    expect(out).toContain(`Retired ${kid} (EdDSA, was active): compromised.`);

    // The rows: the break-glass operator, the user and uid, the host, the
    // command and its arguments; the retirement's own row after its run's.
    const { rows: audit } = await app.dbPool.query(
      `SELECT operation_id, actor_kind, actor_id, actor_realm_id, operation_class, masked_diff
         FROM admin_audit_log WHERE realm_id = $1 AND actor_kind = 'break_glass_operator'
        ORDER BY seq`,
      [realm.id]
    );
    expect(audit.map((row) => row.operation_id)).toEqual([
      'breakGlass.enrolAdmin',
      'breakGlass.retireKey',
      'keys.retire',
    ]);
    for (const row of audit) {
      expect(row).toMatchObject({
        actor_kind: 'break_glass_operator',
        actor_id: OPERATOR.name,
        actor_realm_id: null,
        operation_class: 'security',
      });
    }
    expect(audit[0]?.masked_diff).toMatchObject({
      before: null,
      after: {
        run: {
          command: 'enrol-admin',
          arguments: { realm: E2E_REALM_NAME, role: 'editor' },
          operatingSystemUser: { name: OPERATOR.name, uid: OPERATOR.uid },
          host: OPERATOR.host,
        },
        grant: { role: 'editor', targetRealmId: realm.id },
      },
    });
    expect(audit[1]?.masked_diff).toMatchObject({
      after: {
        run: {
          command: 'retire-key',
          arguments: { realm: E2E_REALM_NAME, kid, confirm: true },
          operatingSystemUser: { name: OPERATOR.name, uid: OPERATOR.uid },
          host: OPERATOR.host,
        },
        retirement: { kid },
      },
    });
    // The critical event of each run, an admin event of the realm.
    const { rows: events } = await app.dbPool.query(
      `SELECT category, actor_type, actor_id, data FROM events WHERE realm_id = $1 AND type = $2
        ORDER BY id`,
      [realm.id, USED]
    );
    expect(events).toEqual([
      {
        category: 'admin',
        actor_type: 'operator_cli',
        actor_id: OPERATOR.name,
        data: { command: 'enrol-admin' },
      },
      {
        category: 'admin',
        actor_type: 'operator_cli',
        actor_id: OPERATOR.name,
        data: { command: 'retire-key' },
      },
    ]);
  }, 180_000);

  for (const [what, table, condition] of [
    ['the audit row', 'admin_audit_log', `NEW.operation_id LIKE 'breakGlass.%'`],
    ['the event', 'events', `NEW.type = '${USED}'`],
  ] as const) {
    it(`changes nothing when ${what} cannot be written`, async () => {
      const app = await boot();
      const kid = await activeKid(app);
      const { run, out, err } = await cli(app);
      const before = await state(app);

      await withTriggers(
        app,
        `CREATE FUNCTION break_glass_test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF ${condition} THEN RAISE EXCEPTION 'the record is refused'; END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER break_glass_test_refuse BEFORE INSERT ON ${table}
           FOR EACH ROW EXECUTE FUNCTION break_glass_test_refuse();`,
        `DROP TRIGGER break_glass_test_refuse ON ${table};
         DROP FUNCTION break_glass_test_refuse();`,
        async () => {
          expect(await run('enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'viewer')).toBe(1);
          expect(
            await run('retire-key', '--realm', E2E_REALM_NAME, '--kid', kid, '--confirm')
          ).toBe(1);
        }
      );
      expect(await state(app)).toEqual(before);
      expect(await activeKid(app)).toBe(kid);
      expect(out.some((line) => line.includes('#token='))).toBe(false);
      expect(err).toEqual([
        expect.stringMatching(/^break-glass enrol-admin: .*Nothing was changed\.$/),
        expect.stringMatching(/^break-glass retire-key: .*Nothing was changed\.$/),
      ]);
    }, 180_000);
  }

  it('runs as its own process without opening a listening socket or making an HTTP call', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    // Only the database and the KEK the boot left: the server itself goes.
    await Promise.all(booted.splice(0).map(async (server) => server.close()));

    const servers = () =>
      process.getActiveResourcesInfo().filter((resource) => resource === 'TCPServerWrap').length;
    const require = createRequire(__filename);
    const http = require('node:http') as typeof import('node:http');
    const https = require('node:https') as typeof import('node:https');
    const listen = vi.spyOn(net.Server.prototype, 'listen');
    const httpRequest = vi.spyOn(http, 'request');
    const httpsRequest = vi.spyOn(https, 'request');
    const fetch = vi.spyOn(globalThis, 'fetch');
    const baseline = servers();
    const during: number[] = [];

    const { runBreakGlassProcess } = await import('./helpers/break-glass-host');
    const out: string[] = [];
    const err: string[] = [];
    const code = await runBreakGlassProcess(
      ['enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'security-admin'],
      process.env,
      {
        // Read while the process's plugins are open, after the change.
        out: (line) => {
          during.push(servers());
          out.push(line);
        },
        err: (line) => err.push(line),
      }
    );

    expect(err).toEqual([]);
    expect(code).toBe(0);
    expect(printedUrl(out).url.startsWith(`${realm.issuer}/ui/admin-enrolment#token=`)).toBe(true);
    expect(during.length).toBeGreaterThan(0);
    expect(new Set(during)).toEqual(new Set([baseline]));
    expect(listen).not.toHaveBeenCalled();
    expect(httpRequest).not.toHaveBeenCalled();
    expect(httpsRequest).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    // Recorded with the operating system's user, not a given one.
    const { rows } = await infraQuery(
      `SELECT actor_id, masked_diff FROM admin_audit_log WHERE operation_id = 'breakGlass.enrolAdmin'`
    );
    const { hostOperator } = await import('./helpers/break-glass-host');
    const operator = hostOperator();
    expect(rows).toEqual([
      expect.objectContaining({
        actor_id: operator.name,
        masked_diff: expect.objectContaining({
          after: expect.objectContaining({
            run: expect.objectContaining({
              operatingSystemUser: { name: operator.name, uid: operator.uid },
              host: operator.host,
            }),
          }),
        }),
      }),
    ]);
  }, 180_000);

  /** A query through a server booted for it alone. */
  async function infraQuery(sql: string) {
    const server = await bootAuthServer(variables());
    try {
      return await server.app.dbPool.query(sql);
    } finally {
      await server.close();
    }
  }

  it('leaves the enrolled admin unable to approve for 7 days, by the two-admin rule at a given clock', async () => {
    const app = await boot();
    const realm = await realmOf(app);
    const { run } = await cli(app);
    expect(await run('enrol-admin', '--realm', E2E_REALM_NAME, '--role', 'security-admin')).toBe(0);
    const { rows } = await app.dbPool.query<{ user_id: string }>(
      'SELECT user_id FROM admin_enrolments'
    );
    const accountId = rows[0]?.user_id as string;

    const { approverRefusal, loadApprover } = await import('./admin/approvals/two-admin');
    const loaded = await loadApprover(app, { realmId: realm.id, accountId, kind: 'human' }, realm);
    if (loaded === undefined) throw new Error('the enrolled account is not found');
    const { record } = loaded;
    expect(loaded.createdBy).toBeNull();
    const made = Math.max(record.createdAt, ...record.grants.map((grant) => grant.createdAt));
    // Another admin of the realm asks; the enrolled one would approve.
    const requester = { realmId: realm.id, accountId: randomUUID(), kind: 'human' as const };
    const refusalAt = (at: number) =>
      approverRefusal(record, { realmId: realm.id, requester, createdAt: at }, realm, at);

    for (const at of [made + 1, made + DAY, made + WINDOW - 60_000, made + WINDOW - 1]) {
      expect(['new-account', 'new-grant']).toContain(refusalAt(at));
    }
    // From the end of the window it may approve: the security-admin role
    // gives `approvals.approve`.
    expect(refusalAt(made + WINDOW)).toBeNull();
    expect(refusalAt(made + WINDOW + DAY)).toBeNull();
  }, 180_000);
});
