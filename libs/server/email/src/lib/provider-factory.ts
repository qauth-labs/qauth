import type { EmailProvider } from '../types';
import { MockEmailProvider } from './providers/mock.provider';
import { ResendEmailProvider } from './providers/resend.provider';
import { SmtpEmailProvider } from './providers/smtp.provider';

/**
 * A mail transport with everything it sends with (#529): what a realm's
 * `mail.*` policies and its secret store give the realm's mail sender.
 */
export type MailTransport =
  | { readonly provider: 'mock' }
  | {
      readonly provider: 'smtp';
      readonly host: string;
      readonly port: number;
      readonly secure: boolean;
      readonly user: string;
      readonly password: string;
    }
  | { readonly provider: 'resend'; readonly apiKey: string };

/** The transports QAuth sends through. */
export type MailTransportProvider = MailTransport['provider'];

/**
 * The provider that sends through `transport`. The password or API key goes
 * to the transport's client only: the provider never returns it, and nothing
 * here logs it.
 */
export function createEmailProvider(transport: MailTransport): EmailProvider {
  switch (transport.provider) {
    case 'mock':
      return new MockEmailProvider();
    case 'smtp':
      return new SmtpEmailProvider({
        host: transport.host,
        port: transport.port,
        secure: transport.secure,
        auth: { user: transport.user, pass: transport.password },
      });
    case 'resend':
      return new ResendEmailProvider({ apiKey: transport.apiKey });
    default: {
      const unknown: never = transport;
      throw new Error(
        `Unknown mail transport: ${String((unknown as { provider?: unknown }).provider)}`
      );
    }
  }
}

/** Whether `character` is a C0 control character or DEL, which no header may carry. */
const isControl = (character: string) => {
  const code = character.codePointAt(0) ?? 0;
  return code < 0x20 || code === 0x7f;
};

/** A display name that is a phrase of RFC 5322 atoms, written as it is. */
const ATOM_PHRASE = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+( [A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;

/**
 * The `From` mailbox of `address` with the display name `name`
 * (RFC 5322 §3.4): `QAuth <no-reply@example.com>`, or `address` alone when
 * there is no name. A name with any other character is a quoted string, its
 * quotes and backslashes escaped and any control character a space, so a
 * name can neither add an address nor a header.
 */
export function formatMailbox(name: string | null | undefined, address: string): string {
  const cleaned = [...(name ?? '')]
    .map((character) => (isControl(character) ? ' ' : character))
    .join('')
    .trim();
  if (cleaned === '') return address;
  const display = ATOM_PHRASE.test(cleaned)
    ? cleaned
    : `"${cleaned.replace(/["\\]/g, (character) => `\\${character}`)}"`;
  return `${display} <${address}>`;
}
