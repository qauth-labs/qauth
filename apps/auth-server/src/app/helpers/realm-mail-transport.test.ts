import { defaultsFromEnv, type RealmPolicySnapshot } from '@qauth-labs/fastify-plugin-realm-policy';
import { describe, expect, it, vi } from 'vitest';

import {
  logRefusedMailTransports,
  plaintextRelayError,
  refusedSmtpHostError,
} from './realm-mail-transport';

/** A realm whose policies the environment `env` filled. */
interface RealmSetup {
  readonly id: string;
  readonly name: string;
  readonly env: Record<string, string>;
}

const smtp = (host: string, secure = 'false') => ({
  EMAIL_PROVIDER: 'smtp',
  EMAIL_FROM_ADDRESS: 'no-reply@example.com',
  SMTP_HOST: host,
  SMTP_PORT: '25',
  SMTP_SECURE: secure,
  SMTP_USER: 'mailer',
});

function run(
  realms: RealmSetup[],
  switches: { allowPlaintext?: boolean; allowedHosts?: string[] } = {}
) {
  const error = vi.fn();
  const warn = vi.fn();
  const done = logRefusedMailTransports(
    {
      realms: {
        listPolicyRecords: vi.fn(async () =>
          realms.map((realm) => ({ realmId: realm.id, realmName: realm.name }) as never)
        ),
      },
      policies: {
        get: vi.fn(async (realmId: string) => {
          const realm = realms.find((candidate) => candidate.id === realmId);
          if (realm?.name === 'broken') throw new Error('refused policies');
          return realm === undefined
            ? undefined
            : ({ policies: defaultsFromEnv(realm.env) } as unknown as RealmPolicySnapshot);
        }),
      },
      log: { error, warn },
    },
    { allowPlaintext: switches.allowPlaintext ?? false, allowedHosts: switches.allowedHosts ?? [] }
  );
  return { done, error, warn };
}

describe('logRefusedMailTransports (review of #937)', () => {
  it('names each realm whose local or private relay the connection now refuses, with the keys to set', async () => {
    const { done, error } = run([
      { id: 'r1', name: 'master', env: smtp('localhost') },
      { id: 'r2', name: 'acme', env: smtp('10.0.0.25', 'true') },
      { id: 'r3', name: 'meta', env: smtp('169.254.169.254') },
    ]);
    await done;

    expect(error.mock.calls).toEqual([
      [
        {
          realm: 'master',
          realmId: 'r1',
          policy: 'mail.smtp.host',
          host: 'localhost',
          variable: ['SMTP_ALLOWED_HOSTS', 'SMTP_ALLOW_PLAINTEXT'],
        },
        refusedSmtpHostError('master', 'localhost', false, true),
      ],
      [
        {
          realm: 'acme',
          realmId: 'r2',
          policy: 'mail.smtp.host',
          host: '10.0.0.25',
          variable: ['SMTP_ALLOWED_HOSTS'],
        },
        refusedSmtpHostError('acme', '10.0.0.25', false, false),
      ],
      [
        { realm: 'meta', realmId: 'r3', policy: 'mail.smtp.host', host: '169.254.169.254' },
        refusedSmtpHostError('meta', '169.254.169.254', true, false),
      ],
    ]);
    expect(error.mock.calls[0]?.[1]).toContain('needs localhost in SMTP_ALLOWED_HOSTS');
    expect(error.mock.calls[0]?.[1]).toContain('SMTP_ALLOW_PLAINTEXT=true');
  });

  it('names a listed relay that starts in the clear while STARTTLS is required, and nothing once both keys are set', async () => {
    const listed = run([{ id: 'r1', name: 'master', env: smtp('LocalHost.') }], {
      allowedHosts: ['localhost'],
    });
    await listed.done;
    expect(listed.error.mock.calls).toEqual([
      [
        {
          realm: 'master',
          realmId: 'r1',
          policy: 'mail.smtp.secure',
          host: 'localhost',
          variable: ['SMTP_ALLOW_PLAINTEXT'],
        },
        plaintextRelayError('master', 'localhost'),
      ],
    ]);

    const both = run([{ id: 'r1', name: 'master', env: smtp('localhost') }], {
      allowedHosts: ['localhost'],
      allowPlaintext: true,
    });
    await both.done;
    expect(both.error).not.toHaveBeenCalled();
  });

  it('names no public host, no other transport, and goes on past a realm it cannot read', async () => {
    const { done, error, warn } = run([
      { id: 'r0', name: 'broken', env: {} },
      // STARTTLS on 587 is the usual public setup: not named.
      { id: 'r1', name: 'master', env: smtp('smtp.example.com') },
      { id: 'r2', name: 'public-ip', env: smtp('93.184.216.34') },
      { id: 'r3', name: 'mock', env: {} },
      { id: 'r4', name: 'resend', env: { EMAIL_PROVIDER: 'resend' } },
      // A name is not resolved at boot: its mail names it when it connects.
      { id: 'r5', name: 'internal', env: smtp('relay.internal') },
      { id: 'r6', name: 'last', env: smtp('127.0.0.1') },
    ]);
    await done;
    expect(error.mock.calls.map(([fields]) => fields.realm)).toEqual(['last']);
    expect(warn).not.toHaveBeenCalled();
  });
});
