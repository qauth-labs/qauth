import type { RoundContext } from '@qauth-labs/fastify-plugin-sign-in-engine';

/**
 * THE SET-UPS AN AUTHORIZATION REQUEST MAY ASK FOR (#1108; ADR-020 §1 and §3,
 * ADR-017 Decision 8, ADR-019 Decision 7): QAuth's `qauth_action` parameter.
 *
 * A passkey's relying-party ID is the realm host, so a console on another
 * host cannot create one itself (ADR-020 §1): it sends the person to the
 * authorization endpoint with `qauth_action=setup_passkey`, the
 * `setup_passkey` required action of #686. The request runs as the account
 * interaction of the hosted account page does (`account-interaction.ts`):
 *
 * - a fresh sign-in, whatever session the browser has, which no password
 *   reset stands in for and which holds the account's strongest bound factor
 *   (the engine's downgrade rule);
 * - then the engine's own passkey enrolment (`webauthn_create`,
 *   `RoundContext.enrol`), drawn by the ceremony app on the realm origin,
 *   with its own rules: an unclaimed account binds none, and the person may
 *   decline it;
 * - then the request goes on as any other: the consent if one is owed, and
 *   the code at the client's redirect URI.
 *
 * Nobody registers in such an interaction: it offers no switch to a
 * registration and no new account from an upstream identity.
 *
 * Kept free of imports beyond types, so the engines' round builders can read
 * it without loading the authorization endpoint's checks.
 */

/** The values of `qauth_action`: the set-ups a request may ask for. */
export const AUTHORIZATION_ACTIONS = ['setup_passkey'] as const;

export type AuthorizationAction = (typeof AUTHORIZATION_ACTIONS)[number];

/** A request, as far as these rules read it. */
export interface ActionRequest {
  readonly qauth_action?: AuthorizationAction;
  readonly prompt?: string;
  readonly qauth_link?: string;
}

/** Why a request's set-up is refused. */
export interface ActionRefusal {
  readonly error: 'invalid_request' | 'unauthorized_client';
  /** The `authorization.failed` event's reason. */
  readonly reason:
    | 'action_with_prompt_create'
    | 'action_with_link'
    | 'action_not_allowed_for_client'
    | 'action_not_offered';
  readonly description: string;
}

/**
 * Why the set-up `query` asks for is refused, or `null` when it may start
 * (or the request asks for none), in this order:
 *
 * 1. `prompt=create`: `invalid_request`. A registration binds no factor the
 *    person asked for: the account it creates is new.
 * 2. `qauth_link`: `invalid_request`. A link is a flow of its own (#670).
 * 3. A client whose `audience` does not list the account API's
 *    (`listsAccountAudience`): `unauthorized_client`. Only a client an
 *    operator set up to manage accounts, as the account console is, sends a
 *    person to change their sign-in methods.
 * 4. The interaction UI or passkey sign-in off (`offered`): `invalid_request`,
 *    the answer to a set-up the server does not support. Nothing would bind
 *    a passkey, and a code without one would read as a set-up done.
 *
 * `prompt=none` needs no rule here: a set-up always signs the person in, so
 * the request is decided as one without a session, `login_required`.
 */
export function actionRefusal(
  query: ActionRequest,
  client: { readonly listsAccountAudience: boolean },
  offered: boolean
): ActionRefusal | null {
  if (query.qauth_action === undefined) return null;
  if (query.prompt === 'create') {
    return {
      error: 'invalid_request',
      reason: 'action_with_prompt_create',
      description: 'qauth_action cannot be combined with prompt=create',
    };
  }
  if (query.qauth_link !== undefined) {
    return {
      error: 'invalid_request',
      reason: 'action_with_link',
      description: 'qauth_action cannot be combined with qauth_link',
    };
  }
  if (!client.listsAccountAudience) {
    return {
      error: 'unauthorized_client',
      reason: 'action_not_allowed_for_client',
      description: 'the client may not ask for qauth_action',
    };
  }
  if (!offered) {
    return {
      error: 'invalid_request',
      reason: 'action_not_offered',
      description: 'qauth_action=setup_passkey is not supported',
    };
  }
  return null;
}

/** Whether `request`, the interaction's authorization request, asks for a set-up. */
export function asksForSetUp(
  request: Pick<ActionRequest, 'qauth_action'> | undefined
): request is Pick<ActionRequest, 'qauth_action'> & { readonly qauth_action: AuthorizationAction } {
  return request?.qauth_action !== undefined;
}

/**
 * What every sign-in round of a request that asks for a set-up adds to the
 * context, as an account interaction's round adds it (`accountRoundOf`): a
 * fresh sign-in, and the factor it binds. Nothing for any other request.
 */
export function actionRoundOf(
  request: Pick<ActionRequest, 'qauth_action'> | undefined
): Pick<RoundContext, 'freshSignIn' | 'enrol'> {
  return request?.qauth_action === 'setup_passkey' ? { freshSignIn: true, enrol: 'passkey' } : {};
}
