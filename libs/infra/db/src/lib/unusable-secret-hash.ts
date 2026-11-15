/**
 * The `client_secret_hash` of a client that has no secret (#1138).
 *
 * The column is NOT NULL, so a client that authenticates with
 * `private_key_jwt` or as a public client (`none`) still stores a value
 * there. This is that value, for every operator path that writes such a
 * client: the seed manifest's `clients` and `cimd_clients` entries and the
 * system client's provisioner. The auth server keeps a copy of its own for
 * the system client it creates (`helpers/oauth-client.ts`), since an app may
 * not import this library.
 *
 * Reaches only `node:crypto`, so the migration runner's bundle of
 * `@qauth-labs/infra-db/system-client` stays as it is.
 */
import { randomBytes } from 'node:crypto';

/**
 * A value no secret can match: a well-formed argon2id string, with the
 * parameters the auth server hashes with, of a random salt and a random
 * digest that is the hash of nothing. Nobody holds a secret for it, so
 * nothing is returned or printed with it, and a later change of the client's
 * method to `client_secret_basic` or `client_secret_post` leaves a client no
 * secret authenticates until an operator issues one.
 */
export function unusableSecretHash(): string {
  const salt = randomBytes(16).toString('base64').replace(/=+$/, '');
  const digest = randomBytes(32).toString('base64').replace(/=+$/, '');
  return `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest}`;
}
