/**
 * The delivery role's view of the clients that registered a
 * `backchannel_logout_uri` (OpenID Connect Back-Channel Logout 1.0, issue
 * #624): the back-channel logout route of
 * `@qauth-labs/server-backchannel-logout` reads them through it.
 */

/** A client the route lists for the fan-out. */
export interface BackchannelLogoutClientDestination {
  /** `oauth_clients.id`. */
  readonly id: string;
  readonly realmId: string;
  /** The public `client_id` the events of the client's sessions name. */
  readonly clientId: string;
}

/** A client as one delivery attempt reads it. */
export interface BackchannelLogoutClientForDelivery extends BackchannelLogoutClientDestination {
  /** Its `backchannel_logout_uri` now; `null` once removed. */
  readonly uri: string | null;
  /** Who set the URI: the client at registration, or an admin. */
  readonly uriSource: 'client' | 'admin' | null;
  /** `backchannel_logout_session_required`. */
  readonly sessionRequired: boolean;
  /** It is enabled and not suspended. */
  readonly active: boolean;
  /** Its realm's name, which the egress allowlist's entries name. */
  readonly realmName: string;
}

/**
 * The reads of the back-channel logout route. They run as the delivery role's
 * database user, which `eventDeliveryGrantStatements` lets read only the
 * columns they name (`EVENT_DELIVERY_COLUMNS`).
 */
export interface BackchannelLogoutClientsRepository {
  /** The enabled, unsuspended clients with a `backchannel_logout_uri`, of every realm, by id. */
  listDestinations(): Promise<BackchannelLogoutClientDestination[]>;
  /** One client, whatever its state, or `undefined` when it does not exist. */
  findForDelivery(id: string): Promise<BackchannelLogoutClientForDelivery | undefined>;
}
