import {
  constantTimeCompare,
  createRealmMailService,
  generateVerificationToken,
  hashToken,
  isValidTokenFormat,
  normalizeSmtpHost,
  type RealmEmailService,
} from '@qauth-labs/server-email';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { EmailPluginOptions, EmailVerificationTokenUtils } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The mail service of every realm (#529): each mail names its realm and
     * goes out through that realm's transport, from its sender.
     */
    emailService: RealmEmailService;
    emailVerificationTokenUtils: EmailVerificationTokenUtils;
  }
}

/**
 * Fastify plugin for the email service. Decorates the instance with
 * `emailService`, the mail service of every realm (ADR-019 Decision 10,
 * #529), and `emailVerificationTokenUtils`.
 *
 * Each realm's mail goes through the transport its policies select
 * (`mail.provider`: `mock`, `smtp` or `resend`), from the sender they name,
 * with the password or API key its secret store holds. Every mail reads the
 * realm's policies through `options.source`; the transport built for the
 * policy counter it read is kept until the counter moves, so a change takes
 * effect on the next mail without a restart.
 *
 * @example
 * ```typescript
 * await fastify.register(emailPlugin, {
 *   source: { read: (realmId) => readRealmMailPolicies(realmId) },
 *   serviceConfig: { verificationTokenExpiry: 86400 },
 * });
 *
 * // Use in routes; the link starts at the issuer of the account's realm
 * await fastify.emailService.sendVerificationEmail(realm.id, 'user@example.com', token, {
 *   baseUrl: 'https://auth.example.com',
 * });
 * ```
 */
export const emailPlugin = fp<EmailPluginOptions>(
  async (fastify: FastifyInstance, options: EmailPluginOptions) => {
    fastify.decorate(
      'emailService',
      createRealmMailService({
        source: options.source,
        ...(options.serviceConfig === undefined ? {} : { serviceConfig: options.serviceConfig }),
        smtp: {
          allowPlaintext: options.smtp?.allowPlaintext === true,
          allowedHosts: new Set((options.smtp?.allowedHosts ?? []).map(normalizeSmtpHost)),
        },
      })
    );
    fastify.decorate('emailVerificationTokenUtils', {
      generateVerificationToken,
      hashToken,
      isValidTokenFormat,
      constantTimeCompare,
    });

    fastify.log.debug('Email plugin registered: each realm sends through its own transport');
  },
  {
    name: packageJson.name,
  }
);
