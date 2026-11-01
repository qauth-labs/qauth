import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  E2E_PASSWORD,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  provisionRealmKeys,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { type SmtpFixture, startSmtpFixture } from '../testing/smtp-fixture';

/**
 * EACH REALM'S MAIL TRANSPORT, ON THE REAL AUTH SERVER (ADR-019 Decisions 9
 * and 10, issue #529).
 *
 * A realm's mail goes through the transport its policies name, with the SMTP
 * password its secret store holds encrypted. The suite boots the real server
 * on Postgres and Redis containers, with two local SMTP fixtures standing for
 * two realms' mail servers, and checks:
 *
 * - two realms send through their own SMTP servers, signing in with their own
 *   passwords;
 * - an update of a realm's password or transport reaches its next mail,
 *   without a restart;
 * - no table holds a password in the clear, the realm row included;
 * - the first boot seeds the default realm's password from SMTP_PASSWORD, and
 *   no later boot does, whatever SMTP_PASSWORD then says;
 * - a password the first boot lacked is seeded by the boot that has it, and a
 *   realm whose stored transport is the environment's gets it too.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const PASSWORD_A = 'realm-a-smtp-password-kept-encrypted';
const PASSWORD_B = 'realm-b-smtp-password-kept-encrypted';
const PASSWORD_B_ROTATED = 'realm-b-rotated-smtp-password-kept-encrypted';
const LATER_ENVIRONMENT_PASSWORD = 'a-later-environment-password-never-stored';

/** A password and the encoded forms it could hide in: base64, base64url, hex, and SMTP AUTH PLAIN. */
function encodedForms(password: string, user: string): string[] {
  const bytes = Buffer.from(password, 'utf8');
  return [
    password,
    bytes.toString('base64'),
    bytes.toString('base64url'),
    bytes.toString('hex'),
    Buffer.from(`\u0000${user}\u0000${password}`, 'utf8').toString('base64'),
  ];
}

const HOST_B = 'beta.example.com';

/** The mail keys these tests set; the harness clears SMTP_* and RESEND_* itself. */
const MAIL_KEYS = ['EMAIL_PROVIDER'] as const;

/** `env` without `keys`. */
function without(env: Record<string, string>, ...keys: string[]): Record<string, string> {
  return Object.fromEntries(Object.entries(env).filter(([key]) => !keys.includes(key)));
}

interface LogLine {
  readonly msg: string;
  readonly variable?: string;
  readonly policy?: string;
  readonly [field: string]: unknown;
}

describe('each realm sends through its own mail transport (#529)', () => {
  let infra: E2eInfrastructure | undefined;
  let admin: FastifyInstance | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const fixtures: SmtpFixture[] = [];
  const servers: { close(): Promise<void> }[] = [];
  let nextAddress = 0;

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
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await database().dbPool.query(truncateDomainTablesStatement());
  });

  afterEach(async () => {
    for (const server of servers.splice(0)) await server.close();
    for (const fixture of fixtures.splice(0)) await fixture.close();
    for (const key of MAIL_KEYS) delete process.env[key];
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  async function smtpFixture(): Promise<SmtpFixture> {
    const fixture = await startSmtpFixture();
    fixtures.push(fixture);
    return fixture;
  }

  /** The environment of a deployment that sends through `fixture`, signing in with `password`. */
  function smtpEnvironment(fixture: SmtpFixture, password: string): Record<string, string> {
    if (!infra || !jwt) throw new Error('database not started');
    return {
      ...baseEnvironment(infra, jwt),
      EMAIL_PROVIDER: 'smtp',
      SMTP_HOST: fixture.host,
      SMTP_PORT: String(fixture.port),
      SMTP_SECURE: 'false',
      SMTP_USER: 'mailer-a',
      SMTP_PASSWORD: password,
      // The fixtures are plaintext relays on loopback, which only the
      // operator's switches let a realm reach (review of #937).
      SMTP_ALLOW_PLAINTEXT: 'true',
      SMTP_ALLOWED_HOSTS: fixture.host,
    };
  }

  /** Boot the server under `env`; its warnings go to `lines`. */
  async function boot(env: Record<string, string>, lines: LogLine[] = []) {
    const server = await bootAuthServer(env, {
      logStream: { write: (chunk: string) => lines.push(JSON.parse(chunk) as LogLine) },
    });
    servers.push(server);
    return server.app;
  }

  /** Register `email` at `host`, from an address of its own (3 registrations an hour per address). */
  async function register(app: FastifyInstance, email: string, host?: string): Promise<void> {
    nextAddress += 1;
    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      remoteAddress: `198.51.100.${nextAddress}`,
      ...(host === undefined ? {} : { headers: { host } }),
      payload: { email, password: E2E_PASSWORD },
    });
    expect(response.statusCode, response.body).toBe(202);
  }

  /** A second realm on `HOST_B` with its own keys, and its smtp transport set to `fixture`. */
  async function realmB(app: FastifyInstance, fixture: SmtpFixture, password: string) {
    const { realm } = await app.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    // Its data-at-rest key encrypts its secrets; creating a realm row creates none.
    await provisionRealmKeys(app, 'beta');
    const current = await app.policyStore.get(realm.id);
    await app.policyStore.update(
      realm.id,
      {
        mail: {
          provider: 'smtp',
          smtp: {
            host: fixture.host,
            port: fixture.port,
            secure: false,
            user: 'mailer-b',
            password,
          },
        },
      },
      { expectedVersion: current?.version ?? 0 }
    );
    return realm;
  }

  /** Every row of every table of the schema, as text. */
  async function databaseDump(): Promise<string> {
    const pool = database().dbPool;
    const { rows: tables } = await pool.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY table_name`
    );
    const dumps: string[] = [];
    for (const { table_name } of tables) {
      const { rows } = await pool.query(`SELECT t::text AS row FROM "${table_name}" t`);
      dumps.push(...rows.map((row: { row: string }) => `${table_name}: ${row.row}`));
    }
    return dumps.join('\n');
  }

  it('sends two realms through two SMTP servers, with their own passwords', async () => {
    const serverA = await smtpFixture();
    const serverB = await smtpFixture();
    const app = await boot(smtpEnvironment(serverA, PASSWORD_A));
    await realmB(app, serverB, PASSWORD_B);

    await register(app, 'alice@example.com');
    await register(app, 'bob@example.com', HOST_B);

    const [toA] = await serverA.waitForMessages(1);
    const [toB] = await serverB.waitForMessages(1);
    expect(toA?.to).toEqual(['alice@example.com']);
    expect(toB?.to).toEqual(['bob@example.com']);
    // Each server saw only its realm's sign-in.
    expect(serverA.logins).toEqual([{ user: 'mailer-a', password: PASSWORD_A, accepted: true }]);
    expect(serverB.logins).toEqual([{ user: 'mailer-b', password: PASSWORD_B, accepted: true }]);
    // The sender of both is the realm's own: the seeded name and address.
    for (const message of [toA, toB]) {
      expect(message?.from).toBe('no-reply@auth.example.com');
      expect(message?.data).toMatch(/^From: QAuth <no-reply@auth\.example\.com>\r?$/m);
    }
  });

  it('sends the next mail with a changed password or transport, without a restart', async () => {
    const serverA = await smtpFixture();
    const serverB = await smtpFixture();
    const app = await boot(smtpEnvironment(serverA, PASSWORD_A));
    const realm = await realmB(app, serverB, PASSWORD_B);
    await register(app, 'bob@example.com', HOST_B);
    await serverB.waitForMessages(1);

    // A new password: the next mail signs in with it.
    const before = await app.policyStore.get(realm.id);
    await app.policyStore.update(
      realm.id,
      { mail: { smtp: { password: PASSWORD_B_ROTATED } } },
      { expectedVersion: before?.version ?? 0 }
    );
    await register(app, 'carol@example.com', HOST_B);
    await serverB.waitForMessages(2);
    expect(serverB.logins.map((login) => login.password)).toEqual([PASSWORD_B, PASSWORD_B_ROTATED]);

    // Another server: the next mail goes there. The update gives the
    // password again, which a change of the server must (review of #937).
    const moved = await app.policyStore.get(realm.id);
    await app.policyStore.update(
      realm.id,
      { mail: { smtp: { port: serverA.port, password: PASSWORD_B_ROTATED } } },
      { expectedVersion: moved?.version ?? 0 }
    );
    await register(app, 'dave@example.com', HOST_B);
    const atA = await serverA.waitForMessages(1);
    expect(atA.map((message) => message.to)).toEqual([['dave@example.com']]);
    expect(serverA.logins.at(-1)).toEqual({
      user: 'mailer-b',
      password: PASSWORD_B_ROTATED,
      accepted: true,
    });
    expect(serverB.messages).toHaveLength(2);
  });

  it('holds no password in the clear: not in realm_secrets, not on the realm row, nowhere', async () => {
    const serverA = await smtpFixture();
    const serverB = await smtpFixture();
    const app = await boot(smtpEnvironment(serverA, PASSWORD_A));
    const realm = await realmB(app, serverB, PASSWORD_B);
    await register(app, 'alice@example.com');
    await serverA.waitForMessages(1);

    const { rows: secrets } = await database().dbPool.query<{
      realm_id: string;
      name: string;
      ciphertext: string | null;
      key_id: string | null;
    }>('SELECT realm_id, name, ciphertext, key_id FROM realm_secrets ORDER BY realm_id, name');
    const defaultRealm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    // UUIDv7 ids: the default realm, created at boot, sorts first.
    expect(secrets.map((row) => [row.realm_id, row.name, row.ciphertext === null])).toEqual([
      [defaultRealm?.id, 'mail.resend.apiKey', true],
      [defaultRealm?.id, 'mail.smtp.password', false],
      [realm.id, 'mail.smtp.password', false],
    ]);
    for (const row of secrets.filter((secret) => secret.ciphertext !== null)) {
      expect(row.ciphertext).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
      expect(row.ciphertext?.split('.')[1]).toBe(row.key_id);
    }

    // Every row of every table, the realm rows included, in the forms Postgres
    // prints them (jsonb, bytea as hex, text as it is).
    const dump = await databaseDump();
    const forms = [
      ...encodedForms(PASSWORD_A, 'mailer-a'),
      ...encodedForms(PASSWORD_B, 'mailer-b'),
    ];
    expect(forms.filter((form) => dump.includes(form))).toEqual([]);
    // The realm rows' policies hold no member for a secret at all: not its
    // value, and not whether it is set.
    const { rows: stored } = await database().dbPool.query<{ policies: string }>(
      'SELECT policies::text AS policies FROM realms'
    );
    expect(stored).toHaveLength(2);
    for (const { policies } of stored) {
      // The `password` group is the password policy; the mail group is the one
      // that has secret fields.
      const mail = JSON.stringify((JSON.parse(policies) as { mail?: unknown }).mail);
      expect(mail).toContain('"smtp"');
      expect(mail).not.toMatch(/"(password|passwordSet|apiKey|apiKeySet)"/);
    }
    // The representation shows passwordSet.
    const representation = await app.policyStore.representation(realm.id);
    if (representation === undefined) throw new Error('no representation of realm beta');
    const { mail } = representation.policies as { mail: { smtp: Record<string, unknown> } };
    expect(mail.smtp).toMatchObject({ passwordSet: true, user: 'mailer-b' });
    expect(JSON.stringify(representation)).not.toContain(PASSWORD_B);
  });

  it("refuses a realm's local SMTP host the operator does not list, and a plaintext relay without the switch", async () => {
    const serverA = await smtpFixture();
    const app = await boot(without(smtpEnvironment(serverA, PASSWORD_A), 'SMTP_ALLOWED_HOSTS'));
    const realm = await app.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('no default realm');
    // The policy update refuses the loopback host...
    const current = await app.policyStore.get(realm.id);
    await expect(
      app.policyStore.update(
        realm.id,
        { mail: { smtp: { host: '127.0.0.1', port: serverA.port, password: PASSWORD_B } } },
        { expectedVersion: current?.version ?? 0 }
      )
    ).rejects.toMatchObject({ issues: [expect.objectContaining({ path: 'mail.smtp.host' })] });
    // ...and the environment's, filled at boot, is refused when it connects:
    // the registration still answers, and no mail reaches the relay.
    await register(app, 'henry@example.com');
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(serverA.messages).toEqual([]);
    expect(serverA.logins).toEqual([]);
    for (const server of servers.splice(0)) await server.close();

    // Listed, but with STARTTLS required: the plaintext relay is not used.
    const strictApp = await boot(
      without(smtpEnvironment(serverA, PASSWORD_A), 'SMTP_ALLOW_PLAINTEXT')
    );
    await register(strictApp, 'iris@example.com');
    await new Promise((resolve) => setTimeout(resolve, 500));
    expect(serverA.logins).toEqual([]);
  });

  it('seeds the default realm from SMTP_PASSWORD at the first boot, once and never again', async () => {
    const serverA = await smtpFixture();
    const first: LogLine[] = [];
    const firstApp = await boot(smtpEnvironment(serverA, PASSWORD_A), first);
    const realm = await firstApp.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('no default realm');
    expect(await firstApp.realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(true);
    await register(firstApp, 'dana@example.com');
    await serverA.waitForMessages(1);
    expect(serverA.logins.at(-1)?.password).toBe(PASSWORD_A);
    const seeded = await database().dbPool.query(
      'SELECT name, ciphertext, key_id, updated_at FROM realm_secrets WHERE realm_id = $1 ORDER BY name',
      [realm.id]
    );
    // The environment set no API key: recorded as unset, so it is not seeded later.
    expect(seeded.rows.map((row) => [row.name, row.ciphertext === null])).toEqual([
      ['mail.resend.apiKey', true],
      ['mail.smtp.password', false],
    ]);
    expect(first.filter((line) => line.variable === 'SMTP_PASSWORD')).toEqual([]);
    for (const server of servers.splice(0)) await server.close();

    // A later boot: SMTP_PASSWORD and RESEND_API_KEY now say something else.
    const second: LogLine[] = [];
    const secondApp = await boot(
      { ...smtpEnvironment(serverA, LATER_ENVIRONMENT_PASSWORD), RESEND_API_KEY: 're_later' },
      second
    );
    const again = await database().dbPool.query(
      'SELECT name, ciphertext, key_id, updated_at FROM realm_secrets WHERE realm_id = $1 ORDER BY name',
      [realm.id]
    );
    expect(again.rows).toEqual(seeded.rows);
    expect(await secondApp.realmSecretStore?.isSet(realm.id, 'mail.resend.apiKey')).toBe(false);
    // Each secret key the environment still sets is named once, never its value.
    expect(
      second
        .filter((line) => line.msg.includes('only seeds the first realm'))
        .map((line) => [line.variable, line.policy])
    ).toEqual([
      ['SMTP_PASSWORD', 'mail.smtp.password'],
      ['RESEND_API_KEY', 'mail.resend.apiKey'],
    ]);
    expect(JSON.stringify([first, second])).not.toContain(PASSWORD_A);
    expect(JSON.stringify(second)).not.toContain(LATER_ENVIRONMENT_PASSWORD);

    // And the mail still goes out with the stored password.
    await register(secondApp, 'erin@example.com');
    await serverA.waitForMessages(2);
    expect(serverA.logins.at(-1)?.password).toBe(PASSWORD_A);
  });

  it('seeds the password at a later boot when the first boot lacked it and the transport needs it', async () => {
    const serverA = await smtpFixture();
    const firstApp = await boot(without(smtpEnvironment(serverA, PASSWORD_A), 'SMTP_PASSWORD'));
    const realm = await firstApp.repositories.realms.findByName(E2E_REALM_NAME);
    if (!realm) throw new Error('no default realm');
    const rows = async () =>
      (
        await database().dbPool.query<{ name: string; set: boolean }>(
          'SELECT name, ciphertext IS NOT NULL AS set FROM realm_secrets WHERE realm_id = $1 ORDER BY name',
          [realm.id]
        )
      ).rows;
    // smtp needs the password: no row records it unset. The API key, which
    // smtp does not need, is recorded unset as before.
    expect(await rows()).toEqual([{ name: 'mail.resend.apiKey', set: false }]);
    for (const server of servers.splice(0)) await server.close();

    const secondApp = await boot(smtpEnvironment(serverA, PASSWORD_A));
    expect(await rows()).toEqual([
      { name: 'mail.resend.apiKey', set: false },
      { name: 'mail.smtp.password', set: true },
    ]);
    await register(secondApp, 'frank@example.com');
    await serverA.waitForMessages(1);
    expect(serverA.logins).toEqual([{ user: 'mailer-a', password: PASSWORD_A, accepted: true }]);
  });

  it("seeds another realm whose stored transport is the environment's, as the upgrade's fill leaves every realm", async () => {
    const serverA = await smtpFixture();
    const firstApp = await boot(smtpEnvironment(serverA, PASSWORD_A));
    // A realm whose policies the environment seeded, as the first boot after
    // the upgrade fills every realm: the environment's transport, no secret.
    const { realm } = await firstApp.repositories.realms.createWithPrimaryHost(
      { name: 'beta', issuer: `https://${HOST_B}`, enabled: true },
      HOST_B
    );
    await provisionRealmKeys(firstApp, 'beta');
    expect(await firstApp.realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(false);
    for (const server of servers.splice(0)) await server.close();

    const lines: LogLine[] = [];
    const secondApp = await boot(smtpEnvironment(serverA, PASSWORD_A), lines);
    expect(await secondApp.realmSecretStore?.isSet(realm.id, 'mail.smtp.password')).toBe(true);
    // Nothing else is written for it: no row records its API key unset.
    expect(
      (
        await database().dbPool.query('SELECT name FROM realm_secrets WHERE realm_id = $1', [
          realm.id,
        ])
      ).rows
    ).toEqual([{ name: 'mail.smtp.password' }]);
    expect(
      lines.filter((line) => line.realm === 'beta' && line.policy === 'mail.smtp.password')
    ).toEqual([expect.objectContaining({ variable: 'SMTP_PASSWORD' })]);

    await register(secondApp, 'grace@example.com', HOST_B);
    const [message] = await serverA.waitForMessages(1);
    expect(message?.to).toEqual(['grace@example.com']);
    expect(serverA.logins.at(-1)).toEqual({
      user: 'mailer-a',
      password: PASSWORD_A,
      accepted: true,
    });
    expect(JSON.stringify(lines)).not.toContain(PASSWORD_A);
  });
});
