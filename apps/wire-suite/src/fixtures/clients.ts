import { type SeededClient, wireConfig } from '../config';

/**
 * The clients a test may use.
 *
 * The suite never creates a client through the server's own routes. The CI job
 * provisions them from `seed/clients.json` with the operator seed command
 * before the server starts, and hands the ids and the generated secrets to the
 * suite through the environment (`QAUTH_WIRE_CLIENT_ID`,
 * `QAUTH_WIRE_CLIENT_SECRET`).
 */

/** The scope the seed manifest grants the confidential client. */
export const SEEDED_CLIENT_SCOPE = 'wire:read';

/** The confidential client: `client_secret_basic`, `client_credentials` among its grants. */
export function confidentialClient(): SeededClient {
  return wireConfig().confidentialClient;
}

/** An RFC 6749 §2.3.1 `Authorization: Basic` value for a client. */
export function basicAuthorization(client: SeededClient): string {
  const encode = (value: string) => encodeURIComponent(value).replace(/%20/g, '+');
  const credentials = `${encode(client.id)}:${encode(client.secret)}`;
  return `Basic ${Buffer.from(credentials, 'utf8').toString('base64')}`;
}
