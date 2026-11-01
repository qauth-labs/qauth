import type {
  EmailServiceConfig,
  MailTransportProvider,
  RealmMailSource,
} from '@qauth-labs/server-email';
import {
  constantTimeCompare,
  generateVerificationToken,
  hashToken,
  isValidTokenFormat,
} from '@qauth-labs/server-email';
import type { FastifyPluginOptions } from 'fastify';

/** The mail transports a realm can select (`mail.provider`). */
export type EmailProviderType = MailTransportProvider;

/**
 * Email plugin configuration options.
 *
 * The plugin holds no transport of its own: each realm's mail goes through
 * the transport and from the sender its policies name, with the secret its
 * secret store holds (#529). `source` is where the plugin reads them.
 */
export interface EmailPluginOptions extends FastifyPluginOptions {
  /** Where each realm's mail transport, sender and secrets are read, on every mail. */
  source: RealmMailSource;
  /** What every realm's mail shares; the sender comes from the realm's policies. */
  serviceConfig?: Omit<Partial<EmailServiceConfig>, 'defaultFrom'>;
  /**
   * The operator's switches for every realm's smtp transport (review of
   * #937): `allowPlaintext` (`SMTP_ALLOW_PLAINTEXT`) lets a transport with
   * `mail.smtp.secure` off send without STARTTLS, and `allowedHosts`
   * (`SMTP_ALLOWED_HOSTS`) lets it reach those hosts although they are not
   * public. Both off when absent: public addresses only, STARTTLS required.
   */
  smtp?: {
    readonly allowPlaintext?: boolean;
    readonly allowedHosts?: readonly string[];
  };
}

/**
 * Email verification token utilities interface
 * Provides token generation and validation utilities for email verification
 */
export interface EmailVerificationTokenUtils {
  generateVerificationToken: typeof generateVerificationToken;
  hashToken: typeof hashToken;
  isValidTokenFormat: typeof isValidTokenFormat;
  constantTimeCompare: typeof constantTimeCompare;
}
