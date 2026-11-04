import { and, asc, eq, isNotNull } from 'drizzle-orm';

import type {
  BackchannelLogoutClientForDelivery,
  BackchannelLogoutClientsRepository,
  Database,
} from '../../types';
import { oauthClients, realms } from '../schema/core';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Factory for the back-channel logout route's reads of `oauth_clients`
 * (OpenID Connect Back-Channel Logout 1.0, issue #624). Both run as the
 * delivery role's database user, so they read only the columns
 * `EVENT_DELIVERY_COLUMNS` grants it: the client's identity, state and
 * back-channel logout metadata, and its realm's name.
 *
 * @param db - The delivery role's database
 */
export function createBackchannelLogoutClientsRepository(
  db: Database
): BackchannelLogoutClientsRepository {
  return {
    async listDestinations() {
      return db
        .select({
          id: oauthClients.id,
          realmId: oauthClients.realmId,
          clientId: oauthClients.clientId,
        })
        .from(oauthClients)
        .where(
          and(
            isNotNull(oauthClients.backchannelLogoutUri),
            eq(oauthClients.enabled, true),
            eq(oauthClients.suspended, false)
          )
        )
        .orderBy(asc(oauthClients.id));
    },

    async findForDelivery(id): Promise<BackchannelLogoutClientForDelivery | undefined> {
      // Refuse an id that is not a UUID before it reaches Postgres (22P02).
      if (typeof id !== 'string' || !UUID_PATTERN.test(id)) return undefined;
      const [row] = await db
        .select({
          id: oauthClients.id,
          realmId: oauthClients.realmId,
          clientId: oauthClients.clientId,
          uri: oauthClients.backchannelLogoutUri,
          uriSource: oauthClients.backchannelLogoutUriSource,
          sessionRequired: oauthClients.backchannelLogoutSessionRequired,
          enabled: oauthClients.enabled,
          suspended: oauthClients.suspended,
          realmName: realms.name,
        })
        .from(oauthClients)
        .innerJoin(realms, eq(realms.id, oauthClients.realmId))
        .where(eq(oauthClients.id, id));
      if (row === undefined) return undefined;
      const { enabled, suspended, ...client } = row;
      return { ...client, active: enabled && !suspended };
    },
  };
}
