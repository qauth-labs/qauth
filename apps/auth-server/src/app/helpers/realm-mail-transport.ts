import {
  normalizeSmtpHost,
  type RealmPolicyStoreOfRealms,
  smtpHostRefusal,
} from '@qauth-labs/fastify-plugin-realm-policy';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

/** The operator's SMTP switches, as the environment sets them (review of #937). */
export interface SmtpOperatorSwitches {
  /** `SMTP_ALLOW_PLAINTEXT`. */
  readonly allowPlaintext: boolean;
  /** `SMTP_ALLOWED_HOSTS`, as the environment schema reads them. */
  readonly allowedHosts: readonly string[];
}

/** What {@link logRefusedMailTransports} reads through. */
export interface RefusedMailTransportDependencies {
  readonly realms: Pick<FastifyInstance['repositories']['realms'], 'listPolicyRecords'>;
  readonly policies: Pick<RealmPolicyStoreOfRealms, 'get'>;
  readonly log: Pick<FastifyBaseLogger, 'error' | 'warn'>;
}

/** Logged for a realm whose stored SMTP host its connection now refuses. */
export function refusedSmtpHostError(
  realmName: string,
  host: string,
  metadata: boolean,
  plaintextToo: boolean
): string {
  if (metadata) {
    return `the realm "${realmName}" cannot send mail: its mail.smtp.host ${host} is a cloud metadata address, which no setting makes reachable; change the realm's mail.smtp.host`;
  }
  return `the realm "${realmName}" cannot send mail: its mail.smtp.host ${host} is localhost or a non-public address, which needs ${host} in SMTP_ALLOWED_HOSTS${plaintextToo ? ', and SMTP_ALLOW_PLAINTEXT=true for a relay without STARTTLS (its mail.smtp.secure is false)' : ''}; set it, or change the realm's mail.smtp.host`;
}

/** Logged for a realm whose listed, non-public relay starts in the clear while STARTTLS is required. */
export function plaintextRelayError(realmName: string, host: string): string {
  return `the realm "${realmName}" cannot send mail through ${host} unless that relay offers STARTTLS with a certificate valid for ${host}: its mail.smtp.secure is false and STARTTLS is now required; set SMTP_ALLOW_PLAINTEXT=true for a plaintext relay`;
}

/**
 * The boot's check of every realm's stored smtp transport against the
 * operator's switches (review of #937). Since the connection requires
 * STARTTLS and a public address, a deployment that sent through a local
 * plaintext relay (a `localhost` postfix, a relay on a private network,
 * Mailpit) would stop sending its verification mail with nothing said. So
 * each boot logs an error, once per realm, naming the realm, the host and the
 * key to set:
 *
 * - a host that is `localhost` or a non-public IP literal and not in
 *   `SMTP_ALLOWED_HOSTS` (with `SMTP_ALLOW_PLAINTEXT` too when the transport
 *   starts in the clear), or a cloud metadata address, which nothing opens;
 * - a host `SMTP_ALLOWED_HOSTS` lists, which is a non-public relay, whose
 *   transport starts in the clear (`mail.smtp.secure` false) while
 *   `SMTP_ALLOW_PLAINTEXT` is off.
 *
 * It resolves no name: a name is checked only when a mail connects, so one
 * that resolves to a private address is named then, in that mail's failure.
 * A public host whose transport starts in the clear is not named: STARTTLS
 * on port 587 is the usual setup. It never refuses the boot, so a deployment
 * that sends no mail still serves.
 */
export async function logRefusedMailTransports(
  deps: RefusedMailTransportDependencies,
  switches: SmtpOperatorSwitches
): Promise<void> {
  const allowed = new Set(switches.allowedHosts.map(normalizeSmtpHost));
  for (const record of await deps.realms.listPolicyRecords()) {
    let mail;
    try {
      mail = (await deps.policies.get(record.realmId))?.policies.mail;
    } catch {
      // A realm whose stored policies this release refuses is named by the
      // default realm's boot step and the secret seed.
      continue;
    }
    if (mail === undefined || mail.provider !== 'smtp' || mail.smtp.host === null) continue;
    const host = normalizeSmtpHost(mail.smtp.host);
    const fields = {
      realm: record.realmName,
      realmId: record.realmId,
      policy: 'mail.smtp.host',
      host,
    };
    const plaintext = !mail.smtp.secure && !switches.allowPlaintext;
    const refusal = smtpHostRefusal(host, allowed);
    if (refusal !== undefined) {
      const metadata = refusal.includes('metadata');
      deps.log.error(
        metadata
          ? fields
          : {
              ...fields,
              variable: plaintext
                ? ['SMTP_ALLOWED_HOSTS', 'SMTP_ALLOW_PLAINTEXT']
                : ['SMTP_ALLOWED_HOSTS'],
            },
        refusedSmtpHostError(record.realmName, host, metadata, plaintext && !metadata)
      );
      continue;
    }
    if (allowed.has(host) && plaintext) {
      deps.log.error(
        { ...fields, policy: 'mail.smtp.secure', variable: ['SMTP_ALLOW_PLAINTEXT'] },
        plaintextRelayError(record.realmName, host)
      );
    }
  }
}
