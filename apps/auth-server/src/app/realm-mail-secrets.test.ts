import { Writable } from 'node:stream';

import { DATABASE_PLUGIN_NAME } from '@qauth-labs/fastify-plugin-db';
import { emailPlugin } from '@qauth-labs/fastify-plugin-email';
import {
  createRealmSecretStoreOfRealms,
  defaultsFromEnv,
  diffPolicies,
  PolicyValidationError,
  REALM_POLICY_SCHEMA_VERSION,
  realmPolicyPlugin,
} from '@qauth-labs/fastify-plugin-realm-policy';
import { buildAdminDiff, type JsonObject } from '@qauth-labs/shared-events';
import Fastify, { type FastifyInstance, LogController } from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, describe, expect, it, vi } from 'vitest';

// `config/logger` reads the environment at import; the handler does not.
vi.mock('../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import { buildLoggerOptions } from '../config/logger';
import { type SmtpFixture, startSmtpFixture } from '../testing/smtp-fixture';
import { UnprocessableContentError } from './helpers/api-request-errors';
import { unprocessablePolicyField, updateRealmPolicies } from './helpers/realm-policy-update';
import { realmMailSource } from './helpers/realm-secrets';
import errorHandler from './plugins/error-handler';

/**
 * A realm's mail secrets never reach a log line, an error, a response or an
 * audit diff (#529): the SMTP password goes from a policy update to the
 * secret store, encrypted, and from there to the SMTP server only.
 *
 * The server here is the real error handler, the real policy and secret
 * stores over an in-memory realms table, the real mail sender and a real
 * pino logger with the auth server's redaction, writing to a capture. The
 * policy route logs its request body on purpose, as a careless handler could.
 */

const REALM_ID = '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f80';
const PASSWORD = 'smtp-password-that-no-log-holds';
const WRONG_PASSWORD = 'wrong-smtp-password-no-log-holds';
const API_KEY = 're_resend-key-that-no-log-holds';
/** The SMTP `AUTH PLAIN` form of the passwords, which must not leak either. */
const PLAIN_FORMS = [PASSWORD, WRONG_PASSWORD].map((password) =>
  Buffer.from(`\u0000mailer\u0000${password}`, 'utf8').toString('base64')
);
const SECRETS = [PASSWORD, WRONG_PASSWORD, API_KEY, ...PLAIN_FORMS];

/** A realm row with policies, as the realms table returns one. */
function realmRow() {
  const policies = defaultsFromEnv({ EMAIL_FROM_ADDRESS: 'no-reply@example.com' });
  return {
    id: REALM_ID,
    name: 'master',
    policies,
    policySchemaVersion: REALM_POLICY_SCHEMA_VERSION,
    policiesVersion: 1,
    accessTokenLifespan: policies.tokens.accessTokenLifespanSeconds,
    refreshTokenLifespan: policies.tokens.refreshTokenLifespanSeconds,
    dynamicRegistrationAllowedScopes: policies.registration.dynamicRegistrationAllowedScopes,
    maxEnvironmentLaxity: policies.posture.maxEnvironmentLaxity,
  };
}

/** The realms table and `realm_secrets`, in memory, and every value written to either. */
function memoryTables() {
  let row = realmRow();
  const secretRows = new Map<string, { ciphertext: string | null; keyId: string | null }>();
  const recordOf = () => ({
    realmId: row.id,
    realmName: row.name,
    version: row.policiesVersion,
    schemaVersion: row.policySchemaVersion,
    document: structuredClone(row.policies) as unknown as Record<string, unknown>,
    keptOnFill: {},
  });
  const realms = {
    findById: vi.fn(async () => structuredClone(row)),
    listPolicyRecords: vi.fn(async () => [recordOf()]),
    lockPolicyRecord: vi.fn(async () => recordOf()),
    writePolicies: vi.fn(
      async (
        _realmId: string,
        write: { document: Record<string, unknown>; expectedVersion: number }
      ) => {
        if (write.expectedVersion !== row.policiesVersion) return undefined;
        row = {
          ...row,
          policies: write.document as unknown as typeof row.policies,
          policiesVersion: row.policiesVersion + 1,
        };
        return structuredClone(row);
      }
    ),
  };
  const repository = {
    find: vi.fn(async (realmId: string, name: string) => {
      const stored = secretRows.get(`${realmId} ${name}`);
      return stored === undefined ? undefined : { realmId, name, updatedAt: 0, ...stored };
    }),
    write: vi.fn(
      async (
        realmId: string,
        name: string,
        value: { ciphertext: string; keyId: string } | null
      ) => {
        secretRows.set(`${realmId} ${name}`, value ?? { ciphertext: null, keyId: null });
      }
    ),
    insertIfAbsent: vi.fn(async () => true),
  };
  const dump = () => JSON.stringify([row, [...secretRows]]);
  return { realms, repository, dump, version: () => row.policiesVersion };
}

/** A stand-in for the signer's data-at-rest operations, in its format. */
const flip = (bytes: Buffer) => Buffer.from(bytes.map((byte) => byte ^ 0x5a));
const cipher = {
  encrypt: async ({ plaintext }: { plaintext: string }) =>
    `v1.kid-1.${'A'.repeat(16)}.${flip(Buffer.from(plaintext, 'utf8')).toString('base64url')}`,
  decrypt: async ({ ciphertext }: { ciphertext: string }) =>
    flip(Buffer.from(ciphertext.split('.')[3] ?? '', 'base64url')).toString('utf8'),
};

let fixture: SmtpFixture | undefined;
afterEach(async () => {
  await fixture?.close();
  fixture = undefined;
});

async function buildServer() {
  const captured: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, done) {
      captured.push(chunk.toString());
      done();
    },
  });
  const options = buildLoggerOptions({ LOG_LEVEL: 'info', LOG_PRETTY: false, NODE_ENV: 'test' });
  const app = Fastify({
    logger: { ...(options as object), stream },
    logController: new LogController({ disableRequestLogging: false }),
  });
  const tables = memoryTables();
  await app.register(
    fp(
      async (instance: FastifyInstance) => {
        instance.decorate('db', {
          transaction: (work: (tx: unknown) => Promise<unknown>) => work({}),
        } as unknown as FastifyInstance['db']);
      },
      { name: DATABASE_PLUGIN_NAME }
    )
  );
  await app.register(errorHandler);
  const secrets = createRealmSecretStoreOfRealms({ repository: tables.repository, cipher });
  await app.register(realmPolicyPlugin, {
    seeds: defaultsFromEnv({}),
    realms: tables.realms as never,
    secrets,
    // The SMTP fixture is a plaintext relay on loopback: only the operator's
    // switches let a realm reach it (review of #937).
    allowedSmtpHosts: ['127.0.0.1'],
  });
  await app.register(emailPlugin, {
    source: realmMailSource(app, secrets, new Map()),
    smtp: { allowPlaintext: true, allowedHosts: ['127.0.0.1'] },
  });

  app.patch('/admin/v1-rc.0/realms/:realmId/policies', async (request) => {
    // On purpose: a handler that logs the patch it was sent.
    request.log.info({ patch: request.body }, 'realm policy patch received');
    const snapshot = await updateRealmPolicies(app, REALM_ID, request.body, {
      expectedVersion: tables.version(),
    });
    request.log.info({ diff: diffPolicies(realmRow().policies, request.body) }, 'policy diff');
    return (await app.policyStore.representation(snapshot.realmId))?.policies;
  });
  app.post('/send', async (request) => {
    try {
      const result = await app.emailService.sendVerificationEmail(
        REALM_ID,
        'user@example.com',
        'token',
        { baseUrl: 'https://auth.example.com' }
      );
      if (!result.success) request.log.error({ result }, 'Failed to send verification email');
      return { sent: result.success };
    } catch (error) {
      request.log.error(error, 'Failed to send verification email');
      return { sent: false };
    }
  });
  await app.ready();
  return { app, captured, tables };
}

/** Every secret found in `text`. */
const leaksIn = (text: string) => SECRETS.filter((secret) => text.includes(secret));

describe('realm mail secrets stay out of logs, errors and diffs (#529)', () => {
  it('refuses smtp without a password with 422, and logs, answers and stores no secret', async () => {
    const { app, captured, tables } = await buildServer();
    fixture = await startSmtpFixture({ password: PASSWORD });

    // smtp, a password, but no user: refused as a whole.
    const refused = await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: {
        mail: {
          provider: 'smtp',
          smtp: { host: fixture.host, port: fixture.port, password: PASSWORD },
        },
      },
    });
    expect(refused.statusCode).toBe(422);
    expect(refused.json()).toMatchObject({ status: 422, code: 'unprocessable_content' });
    expect(refused.json().errors).toContainEqual({
      pointer: '/mail/smtp/user',
      message: 'mail.smtp.user is required when mail.provider is smtp',
    });

    // smtp without any password: refused, naming it.
    const noPassword = await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: {
        mail: {
          provider: 'smtp',
          smtp: { host: fixture.host, port: fixture.port, user: 'mailer' },
        },
      },
    });
    expect(noPassword.statusCode).toBe(422);
    expect(noPassword.json().errors).toEqual([
      {
        pointer: '/mail/smtp/password',
        message: 'mail.smtp.password must be set when mail.provider is smtp',
      },
    ]);
    expect(tables.version()).toBe(1);

    await app.close();
    const everything = [captured.join(''), refused.body, noPassword.body, tables.dump()].join('\n');
    expect(leaksIn(everything)).toEqual([]);
    // The body the handler logged is there, with the password censored.
    expect(captured.join('')).toContain('realm policy patch received');
    expect(captured.join('')).toContain('[Redacted]');
  });

  it('stores the password encrypted, shows passwordSet, and sends with it, all with no secret in sight', async () => {
    const { app, captured, tables } = await buildServer();
    fixture = await startSmtpFixture({ password: PASSWORD });

    const updated = await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: {
        mail: {
          provider: 'smtp',
          smtp: {
            host: fixture.host,
            port: fixture.port,
            secure: false,
            user: 'mailer',
            password: PASSWORD,
          },
        },
      },
    });
    expect(updated.statusCode, updated.body).toBe(200);
    expect(updated.json().mail.smtp).toMatchObject({ passwordSet: true });
    expect(updated.json().mail.smtp).not.toHaveProperty('password');

    const sent = await app.inject({ method: 'POST', url: '/send' });
    expect(sent.json()).toEqual({ sent: true });
    expect(fixture.logins).toEqual([{ user: 'mailer', password: PASSWORD, accepted: true }]);
    expect(fixture.messages[0]?.to).toEqual(['user@example.com']);

    await app.close();
    const everything = [captured.join(''), updated.body, sent.body, tables.dump()].join('\n');
    expect(leaksIn(everything)).toEqual([]);
  });

  it('logs a failed sign-in at the SMTP server and a missing secret without either value', async () => {
    const { app, captured, tables } = await buildServer();
    // The server takes another password than the realm stores.
    fixture = await startSmtpFixture({ password: 'the-server-wants-another' });
    const transport = {
      provider: 'smtp',
      smtp: { host: fixture.host, port: fixture.port, secure: false, user: 'mailer' },
    };
    await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: { mail: { ...transport, smtp: { ...transport.smtp, password: WRONG_PASSWORD } } },
    });
    const refused = await app.inject({ method: 'POST', url: '/send' });
    expect(refused.json()).toEqual({ sent: false });
    expect(fixture.logins).toEqual([{ user: 'mailer', password: WRONG_PASSWORD, accepted: false }]);

    // Resend, with its API key, then the key cleared behind the store's back:
    // the sender cannot build the transport and says which path is missing.
    await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: { mail: { provider: 'resend', resend: { apiKey: API_KEY } } },
    });
    await tables.repository.write(REALM_ID, 'mail.resend.apiKey', null);
    await app.inject({
      method: 'PATCH',
      url: `/admin/v1-rc.0/realms/${REALM_ID}/policies`,
      payload: { mail: { fromName: 'Another name' } },
    });
    await app.inject({ method: 'POST', url: '/send' });

    await app.close();
    const log = captured.join('');
    expect(log).toContain('Failed to send verification email');
    expect(log).toContain('mail.resend.apiKey');
    expect(leaksIn(log)).toEqual([]);
  });

  it('keeps every secret out of the policy diff and the admin audit diff', () => {
    const before = realmRow().policies;
    const patch = {
      mail: { provider: 'smtp', smtp: { host: 'smtp.example.com', password: PASSWORD } },
    };

    const policyDiff = diffPolicies(before, patch, { setSecrets: [] });
    expect(policyDiff.changes.find((change) => change.path === 'mail.smtp.password')).toMatchObject(
      {
        before: false,
        after: true,
        secret: true,
      }
    );
    expect(leaksIn(JSON.stringify(policyDiff))).toEqual([]);

    const auditDiff = buildAdminDiff(
      before as unknown as JsonObject,
      {
        ...before,
        mail: { ...before.mail, ...patch.mail, smtp: { ...before.mail.smtp, ...patch.mail.smtp } },
      } as unknown as JsonObject
    );
    expect(auditDiff.find((change) => change.path === '/mail/smtp/password')).toMatchObject({
      after: '***',
    });
    expect(leaksIn(JSON.stringify(auditDiff))).toEqual([]);
  });

  it('refuses through the merge patch convention: 422 with a pointer per refused field', async () => {
    const policyStore = {
      update: vi.fn(async () => {
        throw new PolicyValidationError('The realm policies are not valid', [
          { path: 'mail.smtp.password', message: 'must be set when mail.provider is smtp' },
          { path: '', message: 'a policy patch is a JSON object' },
        ]);
      }),
    } as unknown as FastifyInstance['policyStore'];

    const refused = await updateRealmPolicies({ policyStore }, REALM_ID, {}, { expectedVersion: 1 })
      .then(() => undefined)
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(UnprocessableContentError);
    expect((refused as UnprocessableContentError).statusCode).toBe(422);
    expect((refused as UnprocessableContentError).fields).toEqual([
      {
        pointer: '/mail/smtp/password',
        message: 'mail.smtp.password must be set when mail.provider is smtp',
      },
      { pointer: '', message: 'a policy patch is a JSON object' },
    ]);
    expect(unprocessablePolicyField({ path: 'a~b.c/d', message: 'x' }).pointer).toBe('/a~0b/c~1d');
  });
});
