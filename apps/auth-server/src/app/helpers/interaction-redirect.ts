import type { InteractionRequest } from './interaction-record';
import { buildRedirectUrl } from './oauth-redirect';
import { realmIssuer, type RealmUrlSource } from './realm-url';

/**
 * WHERE A CANCELLED INTERACTION ENDS (#616, ADR-019 Decision 6): the final
 * redirect of a cancel, built from the interaction record (the authorization
 * request it holds, validated when the interaction was created) and the realm
 * row (its issuer), never from the request. No field of a cancel reaches it.
 * A finished interaction goes on with its authorization request instead
 * (`helpers/authorization-interaction.ts`, #628).
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
