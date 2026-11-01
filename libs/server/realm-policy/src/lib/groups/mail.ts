import { isIP } from 'node:net';
import { isDeepStrictEqual } from 'node:util';

import { isCloudMetadataAddress, isPublicUnicastAddress } from '@qauth-labs/server-egress';
import { z } from 'zod';

import { groupDocsLink } from '../docs';
import { policyField } from '../field';
import type { PolicyIssue } from '../registry';
import type { PolicyRule } from '../rules';

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
 * the stored document, shown as `passwordSet` and `apiKeySet`. The realm's
 * secret store keeps their values, encrypted (`realm_secrets`, #529). A mail
 * link's base is not a policy: it comes from the realm's host (#490).
 *
 * The realm's mail sender reads the transport and the sender from the realm
 * row since #529, building the transport on the first mail after a change;
 * {@link mailTransportIssues} keeps an update from storing a transport that
 * cannot send.
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

/** An SMTP host as the checks compare it: lower case, no trailing dot, an IPv6 literal without brackets. */
export function normalizeSmtpHost(host: string): string {
  return host
    .trim()
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/^\[(.*)\]$/, '$1');
}

/** Whether `host` (normalized) names the local machine by name: `localhost` or a name under it. */
function isLocalhostName(host: string): boolean {
  return host === 'localhost' || host.endsWith('.localhost');
}

/**
 * Why a realm may not name `host` as its SMTP server (review of #937), or
 * `undefined` when it may. A realm admin sets the host, so it is held to what
 * a destination a realm admin sets may be (ADR-019 Decision 8): `localhost`,
 * or an IP literal that is not a public unicast address, is refused unless
 * `allowedHosts` (`SMTP_ALLOWED_HOSTS`, normalized) names it, and a cloud
 * metadata address always. A name is resolved, and its addresses held to the
 * same, only when the transport connects.
 */
export function smtpHostRefusal(
  host: string,
  allowedHosts: ReadonlySet<string> = new Set()
): string | undefined {
  const normalized = normalizeSmtpHost(host);
  const literal = isIP(normalized) !== 0;
  if (literal && isCloudMetadataAddress(normalized)) return 'must not be a cloud metadata address';
  if (allowedHosts.has(normalized)) return undefined;
  if (isLocalhostName(normalized) || (literal && !isPublicUnicastAddress(normalized))) {
    return 'must be a public host: localhost and loopback, private, link-local and unique-local addresses are refused unless SMTP_ALLOWED_HOSTS names the host';
  }
  return undefined;
}

/** The mail group as {@link mailTransportIssues} reads it from a parsed document. */
interface MailTransportFields {
  readonly provider: 'mock' | 'resend' | 'smtp';
  readonly fromAddress: string | null;
  readonly smtp: {
    readonly host: string | null;
    readonly port: number | null;
    readonly secure: boolean;
    readonly user: string | null;
  };
}

/** The secret fields of the mail transports. */
const MAIL_SECRET_PATHS = ['mail.smtp.password', 'mail.resend.apiKey'] as const;

/**
 * What the mail transport of `policies` lacks to send (#529), with the
 * secrets `isSet` says hold a value: one issue per missing path, never a
 * value.
 *
 * - `smtp` needs `mail.smtp.host`, `mail.smtp.port` and `mail.smtp.user`, and
 *   `mail.smtp.password` set;
 * - `resend` needs `mail.resend.apiKey` set;
 * - both need `mail.fromAddress`, the address every mail is sent from;
 * - `mock` sends nothing, and needs nothing.
 *
 * The boot names these for the default realm; {@link mailTransportIssues}
 * refuses an update that brings one in.
 */
export function mailTransportGaps(
  policies: Readonly<Record<string, unknown>>,
  isSet: (path: string) => boolean
): PolicyIssue[] {
  const mail = policies['mail'] as MailTransportFields | undefined;
  if (mail === undefined || mail.provider === 'mock') return [];
  const why = `is required when mail.provider is ${mail.provider}`;
  const issues: PolicyIssue[] = [];
  if (mail.fromAddress === null) issues.push({ path: 'mail.fromAddress', message: why });
  if (mail.provider === 'smtp') {
    if (mail.smtp.host === null) issues.push({ path: 'mail.smtp.host', message: why });
    if (mail.smtp.port === null) issues.push({ path: 'mail.smtp.port', message: why });
    if (mail.smtp.user === null) issues.push({ path: 'mail.smtp.user', message: why });
    if (!isSet('mail.smtp.password')) {
      issues.push({
        path: 'mail.smtp.password',
        message: `must be set when mail.provider is smtp`,
      });
    }
  } else if (!isSet('mail.resend.apiKey')) {
    issues.push({
      path: 'mail.resend.apiKey',
      message: `must be set when mail.provider is resend`,
    });
  }
  return issues;
}

/**
 * The fields of the smtp transport that say where its password goes: a
 * change of any of them, or a move to smtp, sends the stored password to a
 * server it was not given for, unless the same update gives it again.
 */
function smtpDestinationChanges(before: MailTransportFields, after: MailTransportFields): string[] {
  if (after.provider !== 'smtp') return [];
  const changed: string[] = [];
  if (before.provider !== 'smtp') changed.push('mail.provider');
  if (before.smtp.host !== after.smtp.host) changed.push('mail.smtp.host');
  if (before.smtp.port !== after.smtp.port) changed.push('mail.smtp.port');
  if (before.smtp.secure !== after.smtp.secure) changed.push('mail.smtp.secure');
  return changed;
}

/**
 * The realm policy rule of the mail transport (#529): a policy update must
 * leave the realm's transport able to send, and must not send its password
 * to a server it was not given for.
 *
 * - An update that changes nothing of `mail` and writes no mail secret is not
 *   checked: a realm whose transport lacks something (filled from an
 *   incomplete environment) can still change its other policies.
 * - Otherwise it is refused for each gap of {@link mailTransportGaps} it
 *   brings in. A gap the realm had before the update is not its doing.
 * - An update that selects smtp, or changes `mail.smtp.host`, `port` or
 *   `secure` while the transport is smtp, and leaves a password stored must
 *   set `mail.smtp.password` too: the stored password would otherwise go to
 *   the new server on the next mail.
 * - An update that brings in an smtp host must name one a realm may
 *   ({@link smtpHostRefusal}): not `localhost`, a non-public IP literal or a
 *   cloud metadata address, unless the operator allows the host
 *   (`options.allowedSmtpHosts`, never for a metadata address).
 *
 * Until #529 the boot refused an incomplete environment; the check moved to
 * the update, since the realm row holds the transport now. The issues name
 * paths, never a value.
 */
export function createMailTransportRule(options: MailTransportRuleOptions = {}): PolicyRule {
  const allowedSmtpHosts = new Set([...(options.allowedSmtpHosts ?? [])].map(normalizeSmtpHost));
  return (policies, context) => {
    const after = policies['mail'] as MailTransportFields | undefined;
    const before = context.previous['mail'] as MailTransportFields | undefined;
    if (after === undefined) return [];
    const writesSecret = MAIL_SECRET_PATHS.some((path) => context.written(path) !== undefined);
    if (!writesSecret && isDeepStrictEqual(before, after)) return [];

    const known = (issue: PolicyIssue, list: readonly PolicyIssue[]) =>
      list.some((other) => other.path === issue.path && other.message === issue.message);
    const previousGaps =
      before === undefined ? [] : mailTransportGaps(context.previous, context.wasSet);
    const issues = mailTransportGaps(policies, context.isSet).filter(
      (issue) => !known(issue, previousGaps)
    );

    const changed = before === undefined ? [] : smtpDestinationChanges(before, after);
    // Only a password the update carries over can reach the new server: one
    // the realm lacks is the gap above.
    if (
      changed.length > 0 &&
      context.written('mail.smtp.password') !== 'set' &&
      context.isSet('mail.smtp.password')
    ) {
      const issue = {
        path: 'mail.smtp.password',
        message: `must be given again when ${changed.join(', ')} ${changed.length === 1 ? 'changes' : 'change'}`,
      };
      if (!known(issue, issues)) issues.push(issue);
    }
    // A new smtp server, set by a realm admin, is held to what such a
    // destination may be; the environment's, filled at boot, is not
    // re-checked here, and every connection checks the addresses again.
    if (
      after.provider === 'smtp' &&
      after.smtp.host !== null &&
      (before === undefined || before.provider !== 'smtp' || before.smtp.host !== after.smtp.host)
    ) {
      const refusal = smtpHostRefusal(after.smtp.host, allowedSmtpHosts);
      if (refusal !== undefined) issues.push({ path: 'mail.smtp.host', message: refusal });
    }
    return issues;
  };
}

/** What {@link createMailTransportRule} takes. */
export interface MailTransportRuleOptions {
  /**
   * `SMTP_ALLOWED_HOSTS`: the SMTP hosts the operator lets a realm name
   * although they are not public. Never a cloud metadata address.
   */
  readonly allowedSmtpHosts?: Iterable<string>;
}

/** The mail rule with no host the operator allows: what the store runs unless the server passes its own. */
export const mailTransportIssues: PolicyRule = createMailTransportRule();
