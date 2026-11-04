import { type EgressClient, type EgressLimits, isEgressError } from '@qauth-labs/server-egress';
import type {
  DeliveryOutcome,
  DeliveryRoute,
  RouteDestination,
} from '@qauth-labs/server-event-delivery';

import {
  BACKCHANNEL_LOGOUT_BACKFILL_MS,
  BACKCHANNEL_LOGOUT_DELIVERY_KIND,
  BACKCHANNEL_LOGOUT_EGRESS_PURPOSE,
  CLIENT_SESSION_ENDED_EVENT,
  LOGOUT_REQUEST_MEDIA_TYPE,
  LOGOUT_TOKEN_TYP,
} from './constants';
import { logoutRequestBody, logoutTokenClaims } from './logout-token';

/** A client the route lists for the fan-out. */
export interface BackchannelLogoutDestination {
  /** The client's row id (`oauth_clients.id`): the delivery's destination. */
  readonly id: string;
  readonly realmId: string;
  /** The client's public `client_id`: the events the fan-out matches name it. */
  readonly clientId: string;
}

/** A client as one delivery attempt reads it. */
export interface BackchannelLogoutClient {
  readonly id: string;
  readonly realmId: string;
  /** The `client_id`: the logout token's `aud`. */
  readonly clientId: string;
  /** Its `backchannel_logout_uri` now; `null` once it was removed. */
  readonly uri: string | null;
  /**
   * Who set the URI: the client at registration, or an admin. Only an admin's
   * URI may use the deployment's egress allowlist (ADR-019 Decision 8).
   */
  readonly uriSource: 'client' | 'admin' | null;
  /** `backchannel_logout_session_required`: the client needs `sid`. */
  readonly sessionRequired: boolean;
  /** It is enabled and not suspended. */
  readonly active: boolean;
  /** Its realm's name, which the egress allowlist's entries name. */
  readonly realmName: string;
}

/** Where the route reads its clients: the delivery role's view of `oauth_clients`. */
export interface BackchannelLogoutClientSource {
  /** The clients the route serves: enabled, not suspended, with a `backchannel_logout_uri`. */
  listDestinations(): Promise<readonly BackchannelLogoutDestination[]>;
  /** One client, whatever its state, or `undefined` when it no longer exists. */
  findForDelivery(id: string): Promise<BackchannelLogoutClient | undefined>;
}

/** Options of {@link createBackchannelLogoutRoute}. */
export interface BackchannelLogoutRouteOptions {
  readonly clients: BackchannelLogoutClientSource;
  /** The SSRF-safe egress client: every POST goes through it, and it checks the address again. */
  readonly egress: Pick<EgressClient, 'request'>;
  /** Caps of a POST, over the route's own (no redirect, a 64 KiB answer). */
  readonly limits?: Partial<EgressLimits>;
  /** Now, in epoch milliseconds; `Date.now` unless a test sets it. */
  readonly now?: () => number;
}

const DEFAULT_LIMITS: Partial<EgressLimits> = {
  maxRedirects: 0,
  maxResponseBytes: 64 * 1024,
};

/**
 * The statuses a receiver may stop answering without the request changing:
 * a timeout, a rate limit, and a server error (Back-Channel Logout 1.0 §2.5
 * lets the OP retransmit only for a temporary failure). Any other status is
 * the receiver's answer to this token, and a second one gets the same.
 */
function isRecoverableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/** A refusal no retry changes: the delivery ends `failed` at once. */
const dropped = (errorClass: string): DeliveryOutcome => ({
  ok: false,
  errorClass,
  retry: false,
});

/** A string member of the event's data, if it has one. */
function stringMember(data: Readonly<Record<string, unknown>>, name: string): string | undefined {
  const value = data[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/**
 * The OpenID Connect Back-Channel Logout 1.0 delivery route (issue #624),
 * run by the delivery role (ADR-019 Decision 8).
 *
 * - **What it sends.** A session revocation writes one
 *   `user.client_session_ended` event per client the session served that has
 *   a `backchannel_logout_uri`, in its own transaction. The route lists those
 *   clients, each taking only the events that name it (`typeRules.clientId`),
 *   so the fan-out writes one delivery per client and session. A realm the
 *   role fans out for the first time starts a day back
 *   ({@link BACKCHANNEL_LOGOUT_BACKFILL_MS}), so a notice committed before
 *   the role listed it is sent late rather than lost.
 * - **Checked again at send time.** A delivery may wait in the queue, retried
 *   for hours: before each attempt the route reads the client as it is now.
 *   A deleted client, a disabled or suspended one, a removed URI, or a client
 *   that now needs `sid` for an event without one ends the delivery at once.
 * - **The logout token.** `aud` is the client's `client_id`, `sub` the user
 *   and `sid` the session, the values its ID tokens carry; `iat` is the
 *   attempt's time and `exp` two minutes later; `jti` is the delivery's id,
 *   the same on every retry of it. The signer signs it with the key and
 *   algorithm of the realm's ID tokens (§2.4), `typ: logout+jwt`, and adds
 *   `iss`; the route holds no key.
 * - **The POST.** `logout_token` as an `application/x-www-form-urlencoded`
 *   body through the egress client, which checks the URI's addresses again at
 *   every attempt. A URI the client registered never uses the allowlist; one
 *   an admin set may. No redirect is followed.
 * - **Outcomes.** A `2xx` delivers. A `408`, a `429`, a `5xx`, a timeout or a
 *   network failure is retried on the delivery role's schedule; any other
 *   status is final, as Back-Channel Logout 1.0 §2.5 asks. An address the
 *   egress client refuses is retried, since a name may resolve elsewhere
 *   later; a URI whose form it refuses is not. Whatever the outcome, the
 *   session has already ended: delivery never undoes a sign-out.
 */
export function createBackchannelLogoutRoute(
  options: BackchannelLogoutRouteOptions
): DeliveryRoute {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;

  return {
    kind: BACKCHANNEL_LOGOUT_DELIVERY_KIND,
    // Every notice is written for a client with a URI: one committed before
    // the role first listed the realm is sent late, not lost.
    backfillMs: BACKCHANNEL_LOGOUT_BACKFILL_MS,

    async destinations(): Promise<RouteDestination[]> {
      const clients = await options.clients.listDestinations();
      return clients.map((client) => ({
        id: client.id,
        realmId: client.realmId,
        types: [CLIENT_SESSION_ENDED_EVENT],
        // Only the events that name this client: each event is one client's
        // notice, never another client's.
        typeRules: { [CLIENT_SESSION_ENDED_EVENT]: { clientId: client.clientId } },
      }));
    },

    async deliver(delivery, event, context): Promise<DeliveryOutcome> {
      const client = await options.clients.findForDelivery(delivery.destinationId);
      if (client === undefined) return dropped('client_deleted');
      if (client.realmId !== delivery.realmId || event.realm !== client.realmId) {
        return dropped('realm_mismatch');
      }
      // The fan-out wrote this row only for the event's own client; checked
      // again, so a row written under other rules never reaches another one.
      if (event.type !== CLIENT_SESSION_ENDED_EVENT || event.client?.id !== client.clientId) {
        return dropped('event_not_offered');
      }
      if (!client.active) return dropped('client_inactive');
      if (client.uri === null) return dropped('logout_uri_removed');

      const subject = event.subject?.type === 'user' ? event.subject.id : undefined;
      const sid = stringMember(event.data, 'sid');
      // Back-Channel Logout 1.0 §2.2: a client that registered
      // `backchannel_logout_session_required` gets no token without `sid`.
      if (client.sessionRequired && sid === undefined) return dropped('sid_unavailable');
      if (subject === undefined && sid === undefined) return dropped('event_not_offered');

      const token = await context.signer.signEventToken({
        realmId: client.realmId,
        typ: LOGOUT_TOKEN_TYP,
        claims: logoutTokenClaims({
          audience: client.clientId,
          ...(subject === undefined ? {} : { subject }),
          ...(sid === undefined ? {} : { sid }),
          jti: delivery.id,
          now: now(),
        }),
      });

      let status: number;
      try {
        const response = await options.egress.request({
          method: 'POST',
          url: client.uri,
          headers: { 'content-type': LOGOUT_REQUEST_MEDIA_TYPE },
          body: logoutRequestBody(token),
          purpose: BACKCHANNEL_LOGOUT_EGRESS_PURPOSE,
          // A URI the client registered never uses the allowlist (ADR-019
          // Decision 8); only one an admin set may, for the realm it names.
          source: client.uriSource === 'admin' ? 'admin' : 'client',
          realm: client.realmName,
          limits,
        });
        status = response.status;
      } catch (error) {
        if (!isEgressError(error)) throw error;
        if (error.outcome === 'blocked') {
          // An address may resolve elsewhere later; a URI's form never changes.
          return {
            ok: false,
            errorClass: 'destination_blocked',
            retry: error.reason === 'address',
          };
        }
        return { ok: false, errorClass: error.reason };
      }

      if (status >= 200 && status < 300) return { ok: true, statusCode: status };
      return {
        ok: false,
        statusCode: status,
        errorClass: 'http_status',
        retry: isRecoverableStatus(status),
      };
    },
  };
}
