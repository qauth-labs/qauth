import { setTimeout as delay } from 'node:timers/promises';

/**
 * The verification mail, read from the Mailpit instance the servers deliver to
 * over SMTP (`EMAIL_PROVIDER=smtp`).
 *
 * Every release since 0.1.0 refuses a password sign-in until the address is
 * verified (`REQUIRE_VERIFIED_ACCOUNT`, default true), so the test verifies
 * each account the way a person does: the token from the mail, then
 * `POST /auth/verify`. That also checks that the verified state survives the
 * upgrade, which a mock mail provider could not.
 */

/** A verification token in the mail's link: `…/auth/verify?token=<64 hex>`. */
const TOKEN = /[?&]token=([0-9a-f]{64})\b/i;

/** The token of a verification link in a mail's text, or undefined. */
export function verificationTokenIn(text: string): string | undefined {
  return TOKEN.exec(text)?.[1];
}

async function getJson(url: string): Promise<Record<string, unknown>> {
  const response = await fetch(url);
  if (response.status !== 200) {
    throw new Error(`GET ${url} answered ${response.status}: ${await response.text()}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

/**
 * Wait for the newest mail to `address` that carries a verification link, and
 * return its token. Registration sends the mail off the request path, so it
 * may arrive after the response.
 *
 * @param mailUrl Mailpit's HTTP address, e.g. `http://localhost:8025`
 * @throws when no such mail arrives within `timeoutMs`
 */
export async function waitForVerificationToken(
  mailUrl: string,
  address: string,
  timeoutMs = 20_000
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  const search = `${mailUrl.replace(/\/$/, '')}/api/v1/search?query=${encodeURIComponent(`to:"${address}"`)}`;
  for (;;) {
    const result = await getJson(search);
    // Mailpit lists the newest first.
    const messages = Array.isArray(result['messages'])
      ? (result['messages'] as { ID?: unknown }[])
      : [];
    for (const message of messages) {
      if (typeof message.ID !== 'string') continue;
      const full = await getJson(`${mailUrl.replace(/\/$/, '')}/api/v1/message/${message.ID}`);
      const token = verificationTokenIn(
        `${String(full['Text'] ?? '')}\n${String(full['HTML'] ?? '')}`
      );
      if (token) return token;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `No verification mail to ${address} reached ${mailUrl} within ${timeoutMs} ms ` +
          `(${messages.length} mail(s) to the address).`
      );
    }
    await delay(250);
  }
}
