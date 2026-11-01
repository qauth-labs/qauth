import nodemailer from 'nodemailer';
import { describe, expect, it, vi } from 'vitest';

import type { EmailOptions, EmailProvider } from '../types';
import { createEmailProvider, formatMailbox, type MailTransport } from './provider-factory';
import { MockEmailProvider } from './providers/mock.provider';
import { ResendEmailProvider } from './providers/resend.provider';
import { SmtpEmailProvider } from './providers/smtp.provider';
import {
  createRealmMailService,
  type RealmMailRead,
  type RealmMailSecretPath,
  type RealmMailSettings,
  RealmMailUnavailableError,
} from './realm-mail';

vi.mock('nodemailer', () => ({
  default: { createTransport: vi.fn(() => ({ sendMail: vi.fn() })) },
}));

const REALM_A = '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f80';
const REALM_B = '0190a6d4-5b8e-7c3a-9f12-3b4c5d6e7f81';
const PASSWORD_A = 'realm-a-smtp-password-never-shown';
const PASSWORD_B = 'realm-b-smtp-password-never-shown';
const LINK = { baseUrl: 'https://auth.example.com' };

const MOCK: RealmMailSettings = {
  provider: 'mock',
  fromAddress: 'no-reply@example.com',
  fromName: 'QAuth',
  smtp: { host: null, port: null, secure: true, user: null },
};

function smtp(host: string): RealmMailSettings {
  return {
    provider: 'smtp',
    fromAddress: `no-reply@${host}`,
    fromName: 'Example',
    smtp: { host, port: 2525, secure: false, user: 'mailer' },
  };
}

/** A realm the source reads: its settings, counter and secrets, each changeable. */
interface FakeRealm {
  version: number;
  mail: RealmMailSettings;
  secrets: Partial<Record<RealmMailSecretPath, string>>;
}

function fakeSource(realms: Record<string, FakeRealm>) {
  const secretReads: { realmId: string; path: RealmMailSecretPath }[] = [];
  const source = {
    read: vi.fn(async (realmId: string): Promise<RealmMailRead | undefined> => {
      const realm = realms[realmId];
      if (realm === undefined) return undefined;
      return {
        version: realm.version,
        mail: structuredClone(realm.mail),
        secretOf: async (path) => {
          secretReads.push({ realmId, path });
          return realm.secrets[path];
        },
      };
    }),
  };
  return { source, secretReads };
}

/** A provider per transport built, recording the transport and every mail it sends. */
function recordingProviders() {
  const built: { transport: MailTransport; sent: EmailOptions[] }[] = [];
  const createProvider = vi.fn((transport: MailTransport): EmailProvider => {
    const entry = { transport, sent: [] as EmailOptions[] };
    built.push(entry);
    return {
      async sendEmail(mail) {
        entry.sent.push(mail);
        return { success: true, messageId: `sent-${built.length}` };
      },
    };
  });
  return { built, createProvider };
}

describe('createEmailProvider', () => {
  it('builds each transport QAuth sends through', () => {
    expect(createEmailProvider({ provider: 'mock' })).toBeInstanceOf(MockEmailProvider);
    expect(createEmailProvider({ provider: 'resend', apiKey: 're_key' })).toBeInstanceOf(
      ResendEmailProvider
    );
    const provider = createEmailProvider({
      provider: 'smtp',
      host: 'smtp.example.com',
      port: 587,
      secure: false,
      user: 'mailer',
      password: PASSWORD_A,
    });
    expect(provider).toBeInstanceOf(SmtpEmailProvider);
    expect(nodemailer.createTransport).toHaveBeenLastCalledWith(
      expect.objectContaining({
        host: 'smtp.example.com',
        port: 587,
        secure: false,
        auth: { user: 'mailer', pass: PASSWORD_A },
      })
    );
  });
});

describe('formatMailbox', () => {
  it('writes the sender name before the address', () => {
    expect(formatMailbox('QAuth', 'no-reply@example.com')).toBe('QAuth <no-reply@example.com>');
    expect(formatMailbox('Example Corp', 'a@example.com')).toBe('Example Corp <a@example.com>');
  });

  it('gives the address alone when there is no name', () => {
    expect(formatMailbox('', 'a@example.com')).toBe('a@example.com');
    expect(formatMailbox(null, 'a@example.com')).toBe('a@example.com');
    expect(formatMailbox('   ', 'a@example.com')).toBe('a@example.com');
  });

  it('quotes a name a phrase cannot hold, so it never adds an address or a header', () => {
    expect(formatMailbox('Example, Inc.', 'a@example.com')).toBe('"Example, Inc." <a@example.com>');
    expect(formatMailbox('Evil <x@evil.example>', 'a@example.com')).toBe(
      '"Evil <x@evil.example>" <a@example.com>'
    );
    expect(formatMailbox('Say "hi" \\ there', 'a@example.com')).toBe(
      '"Say \\"hi\\" \\\\ there" <a@example.com>'
    );
    expect(formatMailbox('Line\r\nBcc: x@evil.example', 'a@example.com')).toBe(
      '"Line  Bcc: x@evil.example" <a@example.com>'
    );
  });
});

describe('createRealmMailService (#529)', () => {
  it('sends each realm through its own transport, from its own sender', async () => {
    const { source } = fakeSource({
      [REALM_A]: {
        version: 1,
        mail: smtp('smtp-a.example.com'),
        secrets: { 'mail.smtp.password': PASSWORD_A },
      },
      [REALM_B]: {
        version: 1,
        mail: smtp('smtp-b.example.com'),
        secrets: { 'mail.smtp.password': PASSWORD_B },
      },
    });
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider });

    await service.sendVerificationEmail(REALM_A, 'a@example.com', 'token-a', LINK);
    await service.sendAccountExistsEmail(REALM_B, 'b@example.com');

    expect(built.map((entry) => entry.transport)).toEqual([
      {
        provider: 'smtp',
        host: 'smtp-a.example.com',
        port: 2525,
        secure: false,
        user: 'mailer',
        password: PASSWORD_A,
      },
      {
        provider: 'smtp',
        host: 'smtp-b.example.com',
        port: 2525,
        secure: false,
        user: 'mailer',
        password: PASSWORD_B,
      },
    ]);
    expect(built[0]?.sent.map((mail) => [mail.to, mail.from])).toEqual([
      ['a@example.com', 'Example <no-reply@smtp-a.example.com>'],
    ]);
    expect(built[1]?.sent.map((mail) => [mail.to, mail.from])).toEqual([
      ['b@example.com', 'Example <no-reply@smtp-b.example.com>'],
    ]);
    expect(built[0]?.sent[0]?.text).toContain('token-a');
  });

  it('keeps a realm sender for its policy counter, and builds it anew when the counter moves', async () => {
    const realm: FakeRealm = {
      version: 4,
      mail: smtp('smtp-a.example.com'),
      secrets: { 'mail.smtp.password': PASSWORD_A },
    };
    const { source, secretReads } = fakeSource({ [REALM_A]: realm });
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider });

    await service.sendVerificationEmail(REALM_A, 'a@example.com', 't1', LINK);
    await service.sendVerificationEmail(REALM_A, 'a@example.com', 't2', LINK);
    // Every mail reads the policies, and a build reads them once more after
    // the secret; the secret is read once per counter.
    expect(source.read).toHaveBeenCalledTimes(3);
    expect(secretReads).toHaveLength(1);
    expect(built).toHaveLength(1);

    // An update stores a new password and raises the counter: the next mail uses it.
    realm.secrets['mail.smtp.password'] = PASSWORD_B;
    realm.version = 5;
    await service.sendVerificationEmail(REALM_A, 'a@example.com', 't3', LINK);
    expect(built).toHaveLength(2);
    expect(built[1]?.transport).toMatchObject({ password: PASSWORD_B });
    expect(built[1]?.sent).toHaveLength(1);

    // A transport change, too.
    realm.mail = MOCK;
    realm.version = 6;
    await service.sendVerificationEmail(REALM_A, 'a@example.com', 't4', LINK);
    expect(built[2]?.transport).toEqual({ provider: 'mock' });
    expect(built[2]?.sent[0]?.from).toBe('QAuth <no-reply@example.com>');
  });

  it('sends through the mock provider with no secret', async () => {
    const { source, secretReads } = fakeSource({
      [REALM_A]: { version: 1, mail: MOCK, secrets: {} },
    });
    const service = createRealmMailService({ source });

    const result = await service.sendVerificationEmail(REALM_A, 'a@example.com', 'token', LINK);

    expect(result.success).toBe(true);
    expect(secretReads).toEqual([]);
  });

  it('refuses a realm whose transport lacks a secret or a field, naming the path only', async () => {
    const realms: Record<string, FakeRealm> = {
      [REALM_A]: { version: 1, mail: smtp('smtp-a.example.com'), secrets: {} },
      [REALM_B]: {
        version: 1,
        mail: { ...MOCK, provider: 'resend' },
        secrets: { 'mail.smtp.password': PASSWORD_B },
      },
    };
    const { source } = fakeSource(realms);
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider });

    await expect(
      service.sendVerificationEmail(REALM_A, 'a@example.com', 't', LINK)
    ).rejects.toThrow(
      new RealmMailUnavailableError(
        REALM_A,
        'mail.smtp.password is not set, and mail.provider is smtp'
      )
    );
    await expect(service.sendAccountExistsEmail(REALM_B, 'b@example.com')).rejects.toThrow(
      'mail.resend.apiKey is not set'
    );
    realms[REALM_A] = {
      version: 2,
      mail: {
        ...smtp('smtp-a.example.com'),
        smtp: { host: 'h', port: null, secure: true, user: 'u' },
      },
      secrets: { 'mail.smtp.password': PASSWORD_A },
    };
    const refused = await service
      .sendAccountExistsEmail(REALM_A, 'a@example.com')
      .catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(RealmMailUnavailableError);
    expect((refused as Error).message).toContain('mail.smtp.port');
    expect((refused as Error).message).not.toContain(PASSWORD_A);
    expect(built).toEqual([]);
  });

  it('tries again on the next mail once the secret is set', async () => {
    const realm: FakeRealm = { version: 1, mail: smtp('smtp-a.example.com'), secrets: {} };
    const { source } = fakeSource({ [REALM_A]: realm });
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider });

    await expect(service.sendAccountExistsEmail(REALM_A, 'a@example.com')).rejects.toThrow();
    // The same counter: the secret store gained the value through the boot seed.
    realm.secrets['mail.smtp.password'] = PASSWORD_A;
    await service.sendAccountExistsEmail(REALM_A, 'a@example.com');
    expect(built).toHaveLength(1);
  });

  it('wraps a secret that cannot be read, without its value', async () => {
    const service = createRealmMailService({
      source: {
        read: async () => ({
          version: 1,
          mail: smtp('smtp-a.example.com'),
          secretOf: async () => {
            throw new Error('ciphertext did not authenticate');
          },
        }),
      },
    });

    const refused = await service
      .sendAccountExistsEmail(REALM_A, 'a@example.com')
      .catch((error: unknown) => error);

    expect(refused).toBeInstanceOf(RealmMailUnavailableError);
    expect((refused as Error).message).toBe(
      `The realm ${REALM_A} cannot send mail: mail.smtp.password cannot be read`
    );
    expect((refused as Error).cause).toBeInstanceOf(Error);
  });

  it('never pairs the policies of one update with the secret of another', async () => {
    // An update moves the realm to another host and password between the
    // read of its policies and the read of its secret.
    const realm: FakeRealm = {
      version: 1,
      mail: smtp('old.example.com'),
      secrets: { 'mail.smtp.password': PASSWORD_A },
    };
    const reads: number[] = [];
    let moved = false;
    const source = {
      read: async (): Promise<RealmMailRead> => {
        reads.push(realm.version);
        const snapshot = { version: realm.version, mail: structuredClone(realm.mail) };
        return {
          ...snapshot,
          secretOf: async (path) => {
            if (!moved) {
              moved = true;
              realm.version = 2;
              realm.mail = smtp('new.example.com');
              realm.secrets['mail.smtp.password'] = PASSWORD_B;
            }
            return realm.secrets[path];
          },
        };
      },
    };
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider });

    await service.sendAccountExistsEmail(REALM_A, 'a@example.com');

    // One provider, for the policies and the secret of the same update.
    expect(built.map((entry) => entry.transport)).toEqual([
      expect.objectContaining({ host: 'new.example.com', password: PASSWORD_B }),
    ]);
    expect(reads).toEqual([1, 2, 2]);
  });

  it('gives up when the policies change at every read, building nothing', async () => {
    let version = 0;
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({
      source: {
        read: async () => ({
          version: (version += 1),
          mail: smtp('smtp.example.com'),
          secretOf: async () => PASSWORD_A,
        }),
      },
      createProvider,
    });

    await expect(service.sendAccountExistsEmail(REALM_A, 'a@example.com')).rejects.toThrow(
      'changed each time'
    );
    expect(built).toEqual([]);
  });

  it('refuses an unknown realm', async () => {
    const service = createRealmMailService({ source: fakeSource({}).source });
    await expect(service.sendAccountExistsEmail(REALM_A, 'a@example.com')).rejects.toBeInstanceOf(
      RealmMailUnavailableError
    );
  });

  it('keeps at most maxRealms senders, the one used longest ago going first', async () => {
    const ids = ['r1', 'r2', 'r3'];
    const { source } = fakeSource(
      Object.fromEntries(ids.map((id) => [id, { version: 1, mail: MOCK, secrets: {} }]))
    );
    const { built, createProvider } = recordingProviders();
    const service = createRealmMailService({ source, createProvider, maxRealms: 2 });

    await service.sendAccountExistsEmail('r1', 'a@example.com');
    await service.sendAccountExistsEmail('r2', 'a@example.com');
    await service.sendAccountExistsEmail('r1', 'a@example.com');
    await service.sendAccountExistsEmail('r3', 'a@example.com');
    expect(built).toHaveLength(3);
    // r2 was dropped, r1 kept.
    await service.sendAccountExistsEmail('r1', 'a@example.com');
    expect(built).toHaveLength(3);
    await service.sendAccountExistsEmail('r2', 'a@example.com');
    expect(built).toHaveLength(4);
  });

  it('never puts a secret in a result or an error when the transport fails', async () => {
    vi.mocked(nodemailer.createTransport).mockReturnValueOnce({
      sendMail: vi.fn(async () => {
        throw new Error('Invalid login: 535 5.7.8 Authentication failed');
      }),
    } as unknown as ReturnType<typeof nodemailer.createTransport>);
    const { source } = fakeSource({
      [REALM_A]: {
        version: 1,
        mail: smtp('smtp-a.example.com'),
        secrets: { 'mail.smtp.password': PASSWORD_A },
      },
    });
    const service = createRealmMailService({ source });

    const result = await service.sendVerificationEmail(REALM_A, 'a@example.com', 't', LINK);

    expect(result.success).toBe(false);
    expect(JSON.stringify(result)).not.toContain(PASSWORD_A);
  });
});
