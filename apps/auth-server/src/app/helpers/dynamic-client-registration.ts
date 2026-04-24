import { BadRequestError } from '@qauth-labs/shared-errors';

import type { DynamicClientRegistrationRequest } from '../schemas/oauth';

/**
 * RFC 7591 error codes we return for client-metadata validation failures.
 * These follow RFC 7591 §3.2.2 ("invalid_client_metadata", "invalid_redirect_uri",
 * "invalid_software_statement" — the latter is n/a for us in MVP).
 *
 * We surface them as a `BadRequestError` whose message is the error code
 * (matching how the rest of the codebase encodes OAuth error codes into
 * `error` — see InvalidClientError, etc.). The `details` go in the log;
 * callers should not leak internal state to responders.
 */
export type DynamicRegistrationErrorCode = 'invalid_client_metadata' | 'invalid_redirect_uri';

export function rejectRegistration(code: DynamicRegistrationErrorCode, description: string): never {
  throw new BadRequestError(`${code}: ${description}`);
}

/**
 * OAuth 2.1 §10.3 / RFC 8252: `http://` redirect URIs are permitted only for
 * loopback (native app) flows. Anything else MUST be `https://` (or a
 * non-HTTP custom scheme for native clients — those we allow without
 * further restriction since we can't meaningfully validate them here).
 *
 * The `localhost` hostname SHOULD be avoided in native apps (RFC 8252 §7.3
 * recommends `127.0.0.1` / `[::1]`), but we accept it because many desktop
 * tools still use it — we just require the URL parse as loopback.
 */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', '::1', 'localhost']);

export function validateRedirectUri(uri: string): void {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    rejectRegistration('invalid_redirect_uri', `${uri} is not a valid URI`);
  }

  // Reject fragments per RFC 6749 §3.1.2
  if (parsed.hash && parsed.hash.length > 0) {
    rejectRegistration('invalid_redirect_uri', 'redirect_uri must not include a fragment');
  }

  if (parsed.protocol === 'http:') {
    const host = parsed.hostname.toLowerCase();
    if (!LOOPBACK_HOSTS.has(host)) {
      rejectRegistration(
        'invalid_redirect_uri',
        'http:// redirect_uri is only permitted for loopback addresses'
      );
    }
    return;
  }

  if (parsed.protocol === 'https:') {
    return;
  }

  // Non-http custom scheme (e.g. `com.example.app:/cb`) — allowed for native
  // clients per RFC 8252. We don't attempt structural validation here.
  if (/^[a-z][a-z0-9+\-.]*:$/i.test(parsed.protocol)) {
    return;
  }

  rejectRegistration('invalid_redirect_uri', `unsupported scheme: ${parsed.protocol}`);
}

/**
 * Policy defaults, applied when a dyn-reg request omits fields.
 * We pick conservative defaults: authorization_code + refresh_token,
 * `code` response type, public client (PKCE required).
 */
export const DYN_REG_DEFAULTS = {
  grantTypes: ['authorization_code', 'refresh_token'] as const,
  responseTypes: ['code'] as const,
  // RFC 7591 §2 default is `client_secret_basic`. OAuth 2.1 / MCP
  // expect most dyn-reg clients to be public, so we default to `none`
  // when no redirect URIs imply a user-involving flow AND when the
  // caller didn't declare a method. The route handler makes the call.
  tokenEndpointAuthMethod: 'none' as const,
} as const;

/**
 * Internal, normalized view of a DCR request after validation.
 * Callers get exactly the fields we persist, no optionals-on-optionals.
 */
export interface NormalizedRegistrationRequest {
  clientName: string | null;
  redirectUris: string[];
  grantTypes: ('authorization_code' | 'refresh_token' | 'client_credentials')[];
  responseTypes: 'code'[];
  tokenEndpointAuthMethod: 'none' | 'client_secret_basic' | 'client_secret_post';
  /** Parsed + capped-against-realm scope list. Empty array means no scopes. */
  scopes: string[];
  /** Unchanged string form, used for RFC 7591 echo-back. */
  scopeString: string | undefined;
  clientUri: string | null;
  logoUri: string | null;
  tosUri: string | null;
  policyUri: string | null;
  contacts: string[] | null;
  softwareId: string | null;
  softwareVersion: string | null;
  /** Whether this is a public client (token_endpoint_auth_method = none). */
  isPublic: boolean;
}

/**
 * Validate + normalize an incoming RFC 7591 request against realm policy.
 *
 * - Caps requested scopes to the realm's `dynamic_registration_allowed_scopes`.
 * - Enforces grant_type / response_type consistency (authorization_code
 *   requires the `code` response type).
 * - Requires redirect_uris for any user-involving grant.
 * - Validates every redirect_uri per OAuth 2.1 §10.3.
 * - Forces `token_endpoint_auth_method=none` for clients that only use
 *   authorization_code (public client posture) when not explicitly
 *   declared as confidential.
 *
 * Throws `BadRequestError` with an RFC 7591 error code in the message on
 * any policy violation. Returns a normalized shape ready to persist.
 */
export function validateAndNormalize(
  body: DynamicClientRegistrationRequest,
  realmAllowedScopes: string[]
): NormalizedRegistrationRequest {
  const grantTypes = (body.grant_types ?? [...DYN_REG_DEFAULTS.grantTypes]) as (
    | 'authorization_code'
    | 'refresh_token'
    | 'client_credentials'
  )[];
  const responseTypes = (body.response_types ?? [...DYN_REG_DEFAULTS.responseTypes]) as 'code'[];

  // RFC 7591 §2 / OIDC Reg §2: authorization_code grant pairs with `code`
  // response type. refresh_token / client_credentials have no response
  // type at the authorization endpoint (they're token-endpoint-only).
  if (grantTypes.includes('authorization_code') && !responseTypes.includes('code')) {
    rejectRegistration(
      'invalid_client_metadata',
      'authorization_code grant requires the "code" response type'
    );
  }
  if (!grantTypes.includes('authorization_code') && responseTypes.length > 0) {
    rejectRegistration(
      'invalid_client_metadata',
      'response_types without authorization_code grant is not supported'
    );
  }

  const userInvolving =
    grantTypes.includes('authorization_code') || grantTypes.includes('refresh_token');

  const redirectUris = body.redirect_uris ?? [];
  if (userInvolving && redirectUris.length === 0) {
    rejectRegistration(
      'invalid_redirect_uri',
      'redirect_uris is required for grants that involve a user-agent'
    );
  }
  for (const uri of redirectUris) {
    validateRedirectUri(uri);
  }

  // Scope cap: intersect with the realm's allowlist. An empty allowlist
  // means "no custom scopes allowed" and we reject any requested scope.
  let scopes: string[] = [];
  const scopeString = body.scope;
  if (scopeString && scopeString.trim().length > 0) {
    const requested = scopeString.split(/\s+/).filter((s) => s.length > 0);
    const disallowed = requested.filter((s) => !realmAllowedScopes.includes(s));
    if (disallowed.length > 0) {
      rejectRegistration(
        'invalid_client_metadata',
        `scope not permitted for dynamic registration: ${disallowed.join(' ')}`
      );
    }
    scopes = requested;
  }

  // Auth method gating.
  // - Explicit `none` → public client, no secret, PKCE required (caller).
  // - Explicit `client_secret_basic` or `client_secret_post` → confidential.
  // - Omitted → default to `none` (public client) per OAuth 2.1 / MCP
  //   expectation. This is intentionally tighter than RFC 7591's
  //   `client_secret_basic` default, because on-401-discover-and-register
  //   clients are public by construction.
  const tokenEndpointAuthMethod =
    body.token_endpoint_auth_method ?? DYN_REG_DEFAULTS.tokenEndpointAuthMethod;

  // client_credentials + `none` is a configuration error: a public client
  // cannot hold a secret, so it cannot authenticate to the token endpoint
  // for the client_credentials grant (RFC 6749 §4.4).
  if (tokenEndpointAuthMethod === 'none' && grantTypes.includes('client_credentials')) {
    rejectRegistration(
      'invalid_client_metadata',
      'client_credentials grant requires a confidential client (token_endpoint_auth_method must not be "none")'
    );
  }

  const isPublic = tokenEndpointAuthMethod === 'none';

  return {
    clientName: body.client_name ?? null,
    redirectUris,
    grantTypes,
    responseTypes,
    tokenEndpointAuthMethod,
    scopes,
    scopeString: scopes.length > 0 ? scopes.join(' ') : undefined,
    clientUri: body.client_uri ?? null,
    logoUri: body.logo_uri ?? null,
    tosUri: body.tos_uri ?? null,
    policyUri: body.policy_uri ?? null,
    contacts: body.contacts ?? null,
    softwareId: body.software_id ?? null,
    softwareVersion: body.software_version ?? null,
    isPublic,
  };
}
