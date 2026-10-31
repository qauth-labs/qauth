import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/** The `client_id` of the system client, the same in every realm. */
export function systemClientId(): string {
  return env.SYSTEM_CLIENT_ID || 'system';
}

/**
 * A value for the NOT NULL `client_secret_hash` that no secret can match: a
 * well-formed argon2id string of random bytes, as the CIMD sentinel is
 * (`cimdSentinelSecretHash`). The system client authenticates with
 * `private_key_jwt`, which every client-authentication path checks before a
 * secret, so it has no secret at all.
 */
function unusableSecretHash(): string {
  const salt = randomBytes(16).toString('base64').replace(/=+$/, '');
  const digest = randomBytes(32).toString('base64').replace(/=+$/, '');
  return `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${digest}`;
}

/**
 * Get or create the system client of a realm: the developer portal's client,
 * the one `/auth/login` issues its tokens under and `assertManagementToken`
 * pins.
 *
 * The operator provisions it (ADR-017 phase F0, #631): the migration runner
 * (`SYSTEM_CLIENT_REDIRECT_URI` and the portal's keys) or the seed manifest's
 * `system_client` section writes a `private_key_jwt` client with the
 * `web_redirect` first-party profile and the portal's callback. An existing
 * row is read as it is, whatever an earlier release or the operator wrote.
 *
 * When no row exists yet (a new deployment whose operator has not provisioned
 * it), this creates a placeholder that holds no secret and no keys, so it can
 * authenticate nowhere: `private_key_jwt` with no key set, no redirect URI and
 * no first-party profile, which only an operator path sets. Until #631 this
 * created a secret-based row with a random secret nobody held. The row is
 * created with no `audience`, so the token `/auth/login` mints carries the
 * system client's `client_id` as its `aud`, as before #509; this release only
 * ACCEPTS the developer API's audience on a system-client token
 * (`assertManagementToken`, userinfo), and a later release mints it (#524).
 */
export async function getOrCreateSystemClient(realmId: string, fastify: FastifyInstance) {
  const clientId = systemClientId();

  let client = await fastify.repositories.oauthClients.findByClientId(realmId, clientId);

  if (!client) {
    client = await fastify.repositories.oauthClients.create({
      realmId,
      clientId,
      clientSecretHash: unusableSecretHash(),
      name: 'System Client',
      redirectUris: [],
      grantTypes: ['refresh_token'],
      tokenEndpointAuthMethod: 'private_key_jwt',
      jwks: null,
      jwksUri: null,
      requirePkce: true,
      developerId: null,
      // The server provisions this placeholder itself, for its own first-party
      // login (ANT-2026-O8U3P920). It registers no redirect URI, so the marker
      // never sends an error response anywhere; it is set so that every
      // server-written client carries it consistently.
      provisionedByOperator: true,
    });
  }

  return client;
}
