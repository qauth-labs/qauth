import { randomBytes } from 'node:crypto';

import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { API_FAMILY_AUDIENCES } from '../api-conventions/families';

/** The `client_id` of the system client, the same in every realm. */
export function systemClientId(): string {
  return env.SYSTEM_CLIENT_ID || 'system';
}

/**
 * The `audience` of the system client: the developer API's (ADR-019 Decision
 * 7, #524). `/auth/login` mints the developer portal's token for this client,
 * so the token carries exactly the developer audience, which the developer
 * API's guard (`requireFamilyToken('developer')`) requires and the
 * deprecated `/api/*` routes (`assertManagementToken`) accept.
 *
 * Expand, then contract (ADR-018 §5): the release of #509 (#869) made every
 * node ACCEPT this audience on a portal token; this one MINTS it, and no
 * longer accepts the system client's `client_id` as a portal token's
 * audience.
 */
export const SYSTEM_CLIENT_AUDIENCE: readonly string[] = [API_FAMILY_AUDIENCES.developer];

/** Whether a stored `audience` is exactly {@link SYSTEM_CLIENT_AUDIENCE}. */
export function hasSystemClientAudience(audience: readonly string[] | null | undefined): boolean {
  return (
    Array.isArray(audience) &&
    audience.length === SYSTEM_CLIENT_AUDIENCE.length &&
    SYSTEM_CLIENT_AUDIENCE.every((value, index) => audience[index] === value)
  );
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
 * row is read as it is, whatever an earlier release or the operator wrote,
 * with one exception: a row whose audience is not
 * {@link SYSTEM_CLIENT_AUDIENCE} (one created before #524 has none, so its
 * tokens carried its `client_id`) is given it here, the first time it is
 * read, as the boot step (`giveSystemClientsTheDeveloperAudience`,
 * `system-client-boot.ts`) gives it to every row that exists at boot. A row a
 * node of the previous release creates during a rolling upgrade, for a
 * realm's first sign-in, gets it the next time a node of this release reads
 * it; the token that node of the previous release minted from it is refused,
 * and its developer signs in again.
 *
 * When no row exists yet (a new deployment whose operator has not provisioned
 * it), this creates a placeholder that holds no secret and no keys, so it can
 * authenticate nowhere: `private_key_jwt` with no key set, no redirect URI and
 * no first-party profile, which only an operator path sets. Until #631 this
 * created a secret-based row with a random secret nobody held. The placeholder
 * carries {@link SYSTEM_CLIENT_AUDIENCE}, so the token `/auth/login` mints
 * from it carries the developer API's audience (#524).
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
      audience: [...SYSTEM_CLIENT_AUDIENCE],
      // The server provisions this placeholder itself, for its own first-party
      // login (ANT-2026-O8U3P920). It registers no redirect URI, so the marker
      // never sends an error response anywhere; it is set so that every
      // server-written client carries it consistently.
      provisionedByOperator: true,
    });
  } else if (!hasSystemClientAudience(client.audience)) {
    client = await fastify.repositories.oauthClients.update(realmId, client.id, {
      audience: [...SYSTEM_CLIENT_AUDIENCE],
    });
  }

  return client;
}
