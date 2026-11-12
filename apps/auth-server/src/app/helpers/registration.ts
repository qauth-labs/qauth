import { clientAllowsHostedFlow } from '@qauth-labs/shared-validation';

import { env } from '../../config/env';
import { isClientUsable } from './client-status';

/**
 * WHO MAY REGISTER (#640; ADR-017 Decisions 3 and 8). A registration needs
 * both the realm and the client: the realm's sign-up switch, and the
 * client's operator-set `hosted_flows` naming `register`. QAuth registers
 * accounts only through the Interaction API, so a deployment without it
 * (`INTERACTION_UI_ENABLED` off) offers no registration at all.
 *
 * The realm's switch is its `accounts.allowSignUp` policy (#639), seeded by
 * `ALLOW_SIGN_UP` and off by default: the one switch that also decides
 * whether an upstream identity creates an account, stored on the realm row
 * as ADR-020 keeps every login setting. ADR-017 names the older
 * `realms.registration_allowed` column, which nothing writes; it stays
 * unread.
 */

/** The realm's sign-up policy: its `accounts.allowSignUp` (`accountPoliciesOf`). */
export interface RealmSignUp {
  readonly allowSignUp: boolean;
}

/**
 * Whether the realm offers sign-up at all: its `accounts.allowSignUp`, served
 * by the Interaction API. Discovery lists `create` among the
 * `prompt_values_supported` only while this holds (OpenID Connect Prompt
 * Create 1.0 §4.2).
 */
export function realmOffersRegistration(realm: RealmSignUp): boolean {
  return realm.allowSignUp && env.INTERACTION_UI_ENABLED;
}

/**
 * Whether `client` may register accounts in `realm`: the realm offers sign-up
 * ({@link realmOffersRegistration}), and the client is usable (enabled and not
 * suspended, `isClientUsable`) and its `hosted_flows` name `register`.
 * Fail-closed: no client, a disabled or suspended one, or a flow list that is
 * not well formed allows nothing.
 */
export function registrationAllowed(
  realm: RealmSignUp,
  client: RegisteringClient | null | undefined
): boolean {
  if (!realmOffersRegistration(realm)) return false;
  if (client === null || client === undefined || !isClientUsable(client)) return false;
  return clientAllowsHostedFlow(client, 'register');
}

/**
 * Whether a sign-in of an authorization request may turn into a registration
 * within its interaction (#1079; ADR-017 Decision 8): the `register` path
 * marker beside the sign-in's first step. The realm and the client must
 * allow registration ({@link registrationAllowed}), and the request must ask
 * for no fresh sign-in: no `max_age` and no `prompt=login`, which a
 * registration never satisfies. These are the rules `prompt=create` meets
 * ({@link createPromptRefusal}) but for the `openid` scope, which only that
 * prompt needs (OpenID Connect Prompt Create 1.0 §4.1): a request without it
 * that registers ends in a code as any other does. The sign-in engine reads
 * the same gate again on every round.
 *
 * @param realm - reads the realm's sign-up policy; called only once the
 *   request and the client allow a registration, so a request that can never
 *   register reads no policy
 */
export function registrationSwitchAllowed(
  realm: () => RealmSignUp,
  client: RegisteringClient | null | undefined,
  query: { readonly prompt?: string; readonly max_age?: number }
): boolean {
  if (query.max_age !== undefined || query.prompt === 'login') return false;
  if (client === null || client === undefined || !clientAllowsHostedFlow(client, 'register')) {
    return false;
  }
  return registrationAllowed(realm(), client);
}

/** What the gate reads of a client: its status and its operator-set flows. */
export interface RegisteringClient {
  readonly hostedFlows?: unknown;
  readonly enabled: boolean;
  readonly suspended?: boolean | null;
}

/** Why `/oauth/authorize` refuses a `prompt=create` request, for the client and the event. */
export interface CreatePromptRefusal {
  readonly error: 'invalid_request' | 'unauthorized_client';
  /** The `authorization.failed` event's reason. */
  readonly reason:
    | 'create_without_openid'
    | 'registration_not_offered'
    | 'registration_not_allowed_for_client'
    | 'create_with_max_age';
  readonly description: string;
}

/** Whether a space-delimited scope string (RFC 6749 §3.3) holds `openid`. */
function requestsOpenId(scope: string | undefined): boolean {
  return scope !== undefined && scope.split(' ').includes('openid');
}

/**
 * Why a `prompt=create` request is refused, or `null` when it starts a
 * registration (#640; OpenID Connect Prompt Create 1.0; ADR-017 Decisions 3
 * and 8), in this order:
 *
 * 1. No `openid` scope: `invalid_request`. A registration ends in an ID
 *    token (Prompt Create 1.0 §4.1).
 * 2. The realm offers no sign-up (`realmOffersRegistration`): `invalid_request`,
 *    the answer to a `prompt` value the server does not support (§4.1), as
 *    discovery leaves `create` out of `prompt_values_supported`.
 * 3. The client's `hosted_flows` do not name `register`: `unauthorized_client`.
 * 4. `max_age`: `invalid_request`. It asks for a sign-in no older than it
 *    says, and a registration signs nobody in (ADR-017 Decision 8).
 */
export function createPromptRefusal(
  realm: RealmSignUp,
  client: RegisteringClient,
  query: { readonly scope?: string; readonly max_age?: number }
): CreatePromptRefusal | null {
  if (!requestsOpenId(query.scope)) {
    return {
      error: 'invalid_request',
      reason: 'create_without_openid',
      description: 'prompt=create requires the openid scope',
    };
  }
  if (!realmOffersRegistration(realm)) {
    return {
      error: 'invalid_request',
      reason: 'registration_not_offered',
      description: 'prompt=create is not supported',
    };
  }
  if (!registrationAllowed(realm, client)) {
    return {
      error: 'unauthorized_client',
      reason: 'registration_not_allowed_for_client',
      description: 'the client may not register accounts',
    };
  }
  if (query.max_age !== undefined) {
    return {
      error: 'invalid_request',
      reason: 'create_with_max_age',
      description: 'prompt=create cannot be combined with max_age',
    };
  }
  return null;
}
