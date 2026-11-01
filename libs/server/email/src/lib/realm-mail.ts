import type {
  EmailOptions,
  EmailProvider,
  EmailResult,
  EmailService,
  EmailServiceConfig,
  VerificationLink,
} from '../types';
import { createEmailService } from './email-service';
import { createEmailProvider, formatMailbox, type MailTransport } from './provider-factory';

/**
 * Each realm's mail sender (ADR-019 Decision 10, issue #529).
 *
 * A realm's transport and sender are realm policies (`mail.*`), and its SMTP
 * password or Resend API key sits in its secret store. The sender of a realm
 * is built on the realm's first mail from what it reads then, and kept for
 * the policy counter it was read at: every mail reads the realm's policies
 * again, and a mail after a change of them, a secret's included, builds the
 * sender anew. So a transport change takes effect on the next mail, without
 * a restart.
 */

/** A realm's mail transport and sender, as its policies hold them (`mail.*`, without the secrets). */
export interface RealmMailSettings {
  readonly provider: 'mock' | 'resend' | 'smtp';
  readonly fromAddress: string | null;
  readonly fromName: string;
  readonly smtp: {
    readonly host: string | null;
    readonly port: number | null;
    readonly secure: boolean;
    readonly user: string | null;
  };
}

/** The secret fields of a realm's mail transport, by their policy path. */
export type RealmMailSecretPath = 'mail.smtp.password' | 'mail.resend.apiKey';

/** One read of a realm's mail policies. */
export interface RealmMailRead {
  /** The realm's policy counter (`policies_version`) the settings were read at. */
  readonly version: number;
  readonly mail: RealmMailSettings;
  /**
   * The value of a secret of the transport, or `undefined` when it holds
   * none. Called only to build the transport, and never logged.
   */
  secretOf(path: RealmMailSecretPath): Promise<string | undefined>;
}

/** Where the mail sender reads a realm's mail policies: the policy store and the secret store. */
export interface RealmMailSource {
  /** The realm's mail policies now, or `undefined` when there is no such realm. */
  read(realmId: string): Promise<RealmMailRead | undefined>;
}

/**
 * A realm cannot send mail: there is no such realm, or its transport lacks
 * what it sends with. The message names the realm id and the policy path,
 * never a value.
 */
export class RealmMailUnavailableError extends Error {
  override readonly name = 'RealmMailUnavailableError';

  constructor(
    readonly realmId: string,
    reason: string,
    options?: { cause?: unknown }
  ) {
    super(`The realm ${realmId} cannot send mail: ${reason}`, options);
  }
}

/**
 * The mail service of a server with several realms: each mail names the realm
 * it is sent for, and goes out through that realm's transport, from its
 * sender.
 */
export interface RealmEmailService {
  /**
   * Send a verification email for the realm `realmId`.
   *
   * @throws RealmMailUnavailableError when the realm cannot send mail
   */
  sendVerificationEmail(
    realmId: string,
    to: string,
    token: string,
    link: VerificationLink,
    options?: Partial<EmailOptions>
  ): Promise<EmailResult>;

  /**
   * Tell the owner of an address, in the realm `realmId`, that someone tried
   * to register it again. No link, no token.
   *
   * @throws RealmMailUnavailableError when the realm cannot send mail
   */
  sendAccountExistsEmail(
    realmId: string,
    to: string,
    options?: Partial<EmailOptions>
  ): Promise<EmailResult>;
}

/** What {@link createRealmMailService} takes. */
export interface RealmMailServiceOptions {
  readonly source: RealmMailSource;
  /** The configuration every realm's service shares; the sender comes from the realm. */
  readonly serviceConfig?: Omit<EmailServiceConfig, 'defaultFrom'>;
  /** Builds the provider of a transport; {@link createEmailProvider} unless a test passes its own. */
  readonly createProvider?: (transport: MailTransport) => EmailProvider;
  /** How many realms' senders to keep; the one used longest ago goes first. 256 by default. */
  readonly maxRealms?: number;
}

const DEFAULT_MAX_REALMS = 256;

/** How often a sender is read again when the realm's policies move while it is built. */
const MAX_BUILD_ATTEMPTS = 3;

/** What a realm's transport needs before it can send, as policy paths. */
function missing(realmId: string, path: string, provider: string): RealmMailUnavailableError {
  return new RealmMailUnavailableError(
    realmId,
    `${path} is not set, and mail.provider is ${provider}`
  );
}

/**
 * The transport `read` describes, with its secret.
 *
 * @throws RealmMailUnavailableError naming the first path it lacks
 */
async function transportOf(realmId: string, read: RealmMailRead): Promise<MailTransport> {
  const { mail } = read;
  if (mail.provider === 'mock') return { provider: 'mock' };
  if (mail.fromAddress === null) throw missing(realmId, 'mail.fromAddress', mail.provider);
  const secret = async (path: RealmMailSecretPath) => {
    let value: string | undefined;
    try {
      value = await read.secretOf(path);
    } catch (error) {
      throw new RealmMailUnavailableError(realmId, `${path} cannot be read`, { cause: error });
    }
    if (value === undefined) throw missing(realmId, path, mail.provider);
    return value;
  };
  if (mail.provider === 'resend') {
    return { provider: 'resend', apiKey: await secret('mail.resend.apiKey') };
  }
  const { host, port, secure, user } = mail.smtp;
  if (host === null) throw missing(realmId, 'mail.smtp.host', 'smtp');
  if (port === null) throw missing(realmId, 'mail.smtp.port', 'smtp');
  if (user === null) throw missing(realmId, 'mail.smtp.user', 'smtp');
  return {
    provider: 'smtp',
    host,
    port,
    secure,
    user,
    password: await secret('mail.smtp.password'),
  };
}

/**
 * Create the mail service of every realm over `options.source`. Each mail
 * reads the realm's mail policies, and the sender built for the counter it
 * read is reused until the counter moves (#529).
 */
export function createRealmMailService(options: RealmMailServiceOptions): RealmEmailService {
  const { source } = options;
  const createProvider = options.createProvider ?? createEmailProvider;
  const maxRealms = options.maxRealms ?? DEFAULT_MAX_REALMS;
  /** By realm id, in the order they were last used. */
  const senders = new Map<
    string,
    { readonly version: number; readonly service: Promise<EmailService> }
  >();

  /**
   * The transport of the realm's policies as they are once its secret is in
   * hand. The policies and the secret are two reads, and an update that
   * changes both (a new host and its password) can commit between them: the
   * transport would pair the old host with the new password, and hand that
   * password to the host the update moves away from. So the counter is read
   * again after the secret, and a counter that moved starts over from the
   * policies it now names. A `mock` transport reads no secret.
   */
  async function consistentTransport(
    realmId: string,
    first: RealmMailRead
  ): Promise<{ read: RealmMailRead; transport: MailTransport }> {
    let read = first;
    for (let attempt = 1; ; attempt += 1) {
      const transport = await transportOf(realmId, read);
      if (transport.provider === 'mock') return { read, transport };
      const again = await source.read(realmId);
      if (again === undefined)
        throw new RealmMailUnavailableError(realmId, 'there is no such realm');
      if (again.version === read.version) return { read, transport };
      if (attempt >= MAX_BUILD_ATTEMPTS) {
        throw new RealmMailUnavailableError(
          realmId,
          'its mail policies changed each time its transport was read'
        );
      }
      read = again;
    }
  }

  async function build(realmId: string, first: RealmMailRead): Promise<EmailService> {
    const { read, transport } = await consistentTransport(realmId, first);
    const provider = createProvider(transport);
    const { fromAddress, fromName } = read.mail;
    return createEmailService(provider, {
      ...options.serviceConfig,
      ...(fromAddress === null ? {} : { defaultFrom: formatMailbox(fromName, fromAddress) }),
    });
  }

  async function serviceOf(realmId: string): Promise<EmailService> {
    const read = await source.read(realmId);
    if (read === undefined) throw new RealmMailUnavailableError(realmId, 'there is no such realm');
    const kept = senders.get(realmId);
    senders.delete(realmId);
    if (kept !== undefined && kept.version === read.version) {
      senders.set(realmId, kept);
      return kept.service;
    }
    const service = build(realmId, read);
    const entry = { version: read.version, service };
    senders.set(realmId, entry);
    // A sender that could not be built is not kept: the next mail tries again.
    service.catch(() => {
      if (senders.get(realmId) === entry) senders.delete(realmId);
    });
    while (senders.size > maxRealms) {
      const oldest = senders.keys().next().value;
      if (oldest === undefined) break;
      senders.delete(oldest);
    }
    return service;
  }

  // Not frozen, as `createEmailService`'s object is not: a test suite wraps a
  // method to read the mail it sends.
  return {
    async sendVerificationEmail(
      realmId: string,
      to: string,
      token: string,
      link: VerificationLink,
      mailOptions?: Partial<EmailOptions>
    ): Promise<EmailResult> {
      return (await serviceOf(realmId)).sendVerificationEmail(to, token, link, mailOptions);
    },

    async sendAccountExistsEmail(
      realmId: string,
      to: string,
      mailOptions?: Partial<EmailOptions>
    ): Promise<EmailResult> {
      return (await serviceOf(realmId)).sendAccountExistsEmail(to, mailOptions);
    },
  };
}
