import type { InteractionRequest } from './interaction-record';
import { buildRedirectUrl } from './oauth-redirect';
import { realmIssuer, type RealmUrlSource } from './realm-url';

/**
 * WHERE AN INTERACTION ENDS (#616, ADR-019 Decision 6): the final redirect of
 * the Interaction API, built from the interaction record (the authorization
 * request it holds, validated when the interaction was created) and the realm
 * row (its issuer), never from the request. No field of an answer or a cancel
 * reaches it.
 */

/** `state` as the authorization request carried it, when it carried one. */
function stateOf(request: InteractionRequest): { readonly state?: string } {
  return request.state === undefined ? {} : { state: request.state };
}

/**
 * The redirect of a cancelled interaction: the client's `redirect_uri` with
 * `error=access_denied`, its `state` and the realm's `iss` (RFC 6749
 * §4.1.2.1, RFC 9207).
 */
export function interactionCancelRedirect(
  realm: RealmUrlSource,
  request: InteractionRequest
): string {
  return buildRedirectUrl(request.redirect_uri, {
    error: 'access_denied',
    ...stateOf(request),
    iss: realmIssuer(realm),
  });
}

/**
 * The redirect of a finished interaction: the person signed in.
 *
 * Issuing the authorization code is the authorization endpoint's part, which
 * starts interactions in #628 and mints the code once the interaction
 * finishes (`mintAuthorizationCode`). Until then no interaction is created by
 * a production route, and a finished one answers the client with
 * `error=server_error`, its `state` and `iss`: never a code this route did
 * not check consent for. The browser keeps the session the sign-in created.
 */
export function interactionFinishRedirect(
  realm: RealmUrlSource,
  request: InteractionRequest
): string {
  return buildRedirectUrl(request.redirect_uri, {
    error: 'server_error',
    ...stateOf(request),
    iss: realmIssuer(realm),
  });
}
