import { setTimeout as delay } from 'node:timers/promises';

/**
 * The verification mail, read from the Mailpit instance the target delivers
 * to over SMTP (`QAUTH_WIRE_MAIL_URL`).
 *
 * The server sends the link `…/auth/verify?token=<64 hex>`; the token is taken
 * from the mail's text or HTML, and the suite then verifies the account the
 * way a person does (`POST /auth/verify` with the token and the password).
 */

/** A verification token in the mail's link. */
const TOKEN = /[?&]token=([0-9a-f]{64})\b/i;

/** The token of a verification link in a mail's text, or undefined. */
export function verificationTokenIn(text: string): string | undefined {
  return TOKEN.exec(text)?.[1];
}

async function getJson(url: string): Promise<Record<string, unknown>> {
  const response = await fetch(url, { redirect: 'manual' });
  const text = await response.text();
  if (response.status !== 200) {
    throw new Error(`GET ${url} answered ${response.status}: ${text.slice(0, 300)}`);
  }
  return JSON.parse(text) as Record<string, unknown>;
}

/**
 * Wait for a mail to `address` that carries a verification link, and return
 * its token. Registration sends the mail off the request path, so it may
 * arrive after the response.
 *
 * @param mailUrl Mailpit's HTTP address, e.g. `http://localhost:8025`
 * @throws when no such mail arrives within `timeoutMs`
 */
export async function waitForVerificationToken(
  mailUrl: string,
  address: string,
  timeoutMs = 15_000
): Promise<string> {
  const base = mailUrl.replace(/\/$/, '');
  const search = `${base}/api/v1/search?query=${encodeURIComponent(`to:"${address}"`)}`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await getJson(search);
    const messages = Array.isArray(result['messages'])
      ? (result['messages'] as { ID?: unknown }[])
      : [];
    for (const message of messages) {
      if (typeof message.ID !== 'string') continue;
      const full = await getJson(`${base}/api/v1/message/${encodeURIComponent(message.ID)}`);
      const token = verificationTokenIn(
        `${String(full['Text'] ?? '')}\n${String(full['HTML'] ?? '')}`
      );
      if (token) return token;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `no verification mail to ${address} reached ${base} within ${timeoutMs} ms ` +
          `(${messages.length} mail(s) to the address)`
      );
    }
    await delay(200);
  }
}
