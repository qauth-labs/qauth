import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';

const link = groupDocsLink('mail');

/** No line break: these values end up in a mail header or an SMTP command. */
const SINGLE_LINE = /^[^\r\n]*$/;

/**
 * Mail (`mail`, #514; read from the realm row by #529).
 *
 * The transport and the sender decide which mailbox receives a verification
 * or recovery link, so every change of them is a security operation in either
 * direction (ADR-019 Decision 7, "the realm's mail transport and sender",
 * `credential-path`). The verification link's lifetime is a token lifetime:
 * lengthening it is a security operation (`posture-loosening`), as for the
 * lifetimes of `tokens` (#508), and shortening it is a write. Whether a resend
 * invalidates the earlier links changes no such path, so it is a write field.
 * Every field describes the environment the realm
 * sends mail from, so a sandbox promotion leaves it out unless it is
 * selected.
 *
 * The SMTP password and the Resend API key are secrets: write-only, never in
 * the stored document, shown as `passwordSet` and `apiKeySet`. The secret
 * store of CFG-07 keeps their values. A mail link's base is not a policy: it
 * comes from the realm's host (#490).
 */
export const MAIL_POLICY_GROUP = {
  provider: policyField(z.enum(['mock', 'resend', 'smtp']), {
    seedEnv: 'EMAIL_PROVIDER',
    default: 'mock',
    direction: 'opaque',
    securityWhen: 'any-change',
    effects: ['credential-path'],
    secret: false,
    environmentBound: true,
    doc: {
      summary: 'Which transport sends the realm mail: mock (logs only), resend or smtp.',
      link,
    },
  }),
  fromAddress: policyField(z.email().max(254).nullable(), {
    seedEnv: 'EMAIL_FROM_ADDRESS',
    default: null,
    direction: 'opaque',
    securityWhen: 'any-change',
    effects: ['credential-path'],
    secret: false,
    environmentBound: true,
    doc: {
      summary: 'The address the realm mail is sent from.',
      link,
    },
  }),
  fromName: policyField(z.string().min(1).max(100).regex(SINGLE_LINE), {
    seedEnv: 'EMAIL_FROM_NAME',
    default: 'QAuth',
    direction: 'opaque',
    securityWhen: 'any-change',
    effects: ['credential-path'],
    secret: false,
    environmentBound: true,
    doc: {
      summary: 'The sender name the realm mail shows.',
      link,
    },
  }),
  smtp: {
    host: policyField(
      z
        .string()
        .min(1)
        .max(253)
        .regex(/^[^\s/@]+$/)
        .nullable(),
      {
        seedEnv: 'SMTP_HOST',
        default: null,
        direction: 'opaque',
        securityWhen: 'any-change',
        effects: ['credential-path'],
        secret: false,
        environmentBound: true,
        doc: {
          summary: 'The SMTP server the smtp transport connects to.',
          link,
        },
      }
    ),
    port: policyField(z.number().int().min(1).max(65535).nullable(), {
      seedEnv: 'SMTP_PORT',
      default: null,
      direction: 'opaque',
      securityWhen: 'any-change',
      effects: ['credential-path'],
      secret: false,
      environmentBound: true,
      doc: {
        summary: 'The port of the SMTP server.',
        link,
      },
    }),
    secure: policyField(z.boolean(), {
      seedEnv: 'SMTP_SECURE',
      default: true,
      direction: 'opaque',
      securityWhen: 'any-change',
      effects: ['credential-path'],
      secret: false,
      environmentBound: true,
      doc: {
        summary: 'Whether the SMTP connection uses TLS from its start.',
        link,
      },
    }),
    user: policyField(z.string().min(1).max(255).regex(SINGLE_LINE).nullable(), {
      seedEnv: 'SMTP_USER',
      default: null,
      direction: 'opaque',
      securityWhen: 'any-change',
      effects: ['credential-path'],
      secret: false,
      environmentBound: true,
      doc: {
        summary: 'The user name the smtp transport signs in with.',
        link,
      },
    }),
    password: policyField(z.string().min(1).max(1024), {
      seedEnv: 'SMTP_PASSWORD',
      default: null,
      direction: 'opaque',
      securityWhen: 'any-change',
      effects: ['credential-path'],
      secret: true,
      environmentBound: true,
      doc: {
        summary: 'The password the smtp transport signs in with.',
        link,
      },
    }),
  },
  resend: {
    apiKey: policyField(z.string().min(1).max(1024), {
      seedEnv: 'RESEND_API_KEY',
      default: null,
      direction: 'opaque',
      securityWhen: 'any-change',
      effects: ['credential-path'],
      secret: true,
      environmentBound: true,
      doc: {
        summary: 'The API key the resend transport sends with.',
        link,
      },
    }),
  },
  verificationTokenExpirySeconds: policyField(z.number().int().min(3600), {
    seedEnv: 'EMAIL_VERIFICATION_TOKEN_EXPIRY',
    default: 86400,
    direction: 'lower-is-stricter',
    securityWhen: 'loosening',
    effects: ['posture-loosening'],
    secret: false,
    environmentBound: true,
    doc: {
      summary: 'How long a verification link is valid, in seconds, at least one hour.',
      link,
    },
  }),
  invalidateExistingTokensOnResend: policyField(z.boolean(), {
    seedEnv: 'EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND',
    default: true,
    direction: 'true-is-stricter',
    securityWhen: 'never',
    effects: [],
    secret: false,
    environmentBound: true,
    doc: {
      summary:
        'Whether sending a new verification link makes the earlier ones invalid, so only the latest works.',
      link,
    },
  }),
} as const;
