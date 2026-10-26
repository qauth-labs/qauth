import { InvalidClientMetadataError, InvalidRedirectUriError } from '@qauth-labs/shared-errors';
import { isReservedQauthScope, reservedAudiencesIn } from '@qauth-labs/shared-validation';

import { hasOnlyUriCharacters } from '../schemas/common';
import type { DynamicClientRegistrationRequest } from '../schemas/oauth';
import { TOKEN_EXCHANGE_GRANT_TYPE } from '../schemas/oauth';
import { isAllowedRedirectUriScheme } from './oauth-redirect';

/**
 * The grant types a dynamic registration may carry — the DCR subset of the
 * `grant_type` pg enum, kept in step with
 * `dynamicClientRegistrationRequestSchema`'s own `grant_types` enum. Named
 * rather than repeated inline so the two cannot drift silently: this used to be
 * an inline cast that quietly LIED once the schema widened.
 */
export type DynRegGrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  | typeof TOKEN_EXCHANGE_GRANT_TYPE;

/**
 * RFC 7591 error codes we return for client-metadata validation failures.
 * These follow RFC 7591 §3.2.2 ("invalid_client_metadata", "invalid_redirect_uri",
 * "invalid_software_statement" — the latter is n/a for us in MVP).
 *
 * Each is its own error class, whose message is the bare code and whose
 * `errorDescription` is the text, so `/oauth/register` answers RFC 7591
 * §3.2.2's `{ error, error_description }` and the management API answers the
 * problem code of the same name (#513).
 */
export type DynamicRegistrationErrorCode = 'invalid_client_metadata' | 'invalid_redirect_uri';

export function rejectRegistration(code: DynamicRegistrationErrorCode, description: string): never {
  throw code === 'invalid_redirect_uri'
    ? new InvalidRedirectUriError(description)
    : new InvalidClientMetadataError(description);
}

/**
 * The `schemaErrorFormatter` of `POST /oauth/register` (RFC 7591 §3.2.2,
 * #513): a body the schema refuses is invalid client metadata, or an invalid
 * redirect URI when every failing field is under `redirect_uris`. Fastify
 * attaches the issues to the returned error as `validation`, so the log line
 * still carries them; the wire gets the code and the fields' messages.
 */
export function registrationSchemaError(
  issues: readonly { instancePath?: string; message?: string }[]
): InvalidClientMetadataError | InvalidRedirectUriError {
  const description = issues
    .slice(0, 5)
    .map(({ instancePath, message }) =>
      instancePath ? `${instancePath}: ${message ?? 'Invalid value'}` : (message ?? 'Invalid value')
    )
    .join('; ');
  const redirectUrisOnly =
    issues.length > 0 &&
    issues.every(({ instancePath }) => (instancePath ?? '').startsWith('/redirect_uris'));
  return redirectUrisOnly
    ? new InvalidRedirectUriError(description)
    : new InvalidClientMetadataError(description);
}

/**
 * OAuth 2.1 §10.3 / RFC 8252: `http://` redirect URIs are permitted only for
 * loopback (native app) flows. Anything else MUST be `https://`, an
 * RFC 8252 §7.1 private-use scheme for a native app (a reverse domain name,
 * e.g. `com.example.app:/callback`), or a scheme without a period that the
 * deployment lists in `REDIRECT_URI_CUSTOM_SCHEMES` (#774), passed in as
 * `customSchemes`. No other scheme is accepted: `javascript:`, `data:`,
 * `vbscript:`, `file:`, `blob:`, `about:` and every other scheme without a
 * period are refused (`isAllowedRedirectUriScheme`, shared with the
 * authorization-time gate).
 *
 * The `localhost` hostname SHOULD be avoided in native apps (RFC 8252 §7.3
 * recommends `127.0.0.1` / `[::1]`), but we accept it because many desktop
 * tools still use it — we just require the URL parse as loopback.
 */
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]', '::1', 'localhost']);

export function validateRedirectUri(uri: string, customSchemes: readonly string[]): void {
  // `new URL()` silently deletes an ASCII tab, LF or CR, so it would accept a
  // URI carrying one, and the value is stored as sent. The authorization
  // endpoint trims the requested redirect_uri and refuses one with such a
  // character inside it (`exactUrl` in schemas/common.ts), so a registered URI
  // that holds one could never match. Refuse it here instead.
  if (/[\t\n\r]/.test(uri)) {
    rejectRegistration('invalid_redirect_uri', 'redirect_uri must not contain a tab or line break');
  }
  // Checked before the parse: `new URL()` is quadratic in the distinct
  // non-ASCII characters of a host, and a registration may carry twenty URIs.
  // An RFC 3986 URI is ASCII; an IDN host is written in its `xn--` form.
  if (!hasOnlyUriCharacters(uri)) {
    rejectRegistration('invalid_redirect_uri', 'redirect_uri must be printable ASCII');
  }

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

  // A private-use scheme for a native app (RFC 8252 §7.1): a reverse domain
  // name such as `com.example.app:/cb`, or a bare scheme the deployment lists
  // (#774). Any other scheme is refused, whatever it would do in a browser
  // (found while fixing scan qauth-20261015-005).
  if (isAllowedRedirectUriScheme(uri, customSchemes)) {
    return;
  }

  rejectRegistration(
    'invalid_redirect_uri',
    `unsupported scheme: ${parsed.protocol} (use https, http to a loopback host, or a private-use scheme such as com.example.app: per RFC 8252 §7.1)`
  );
}

/**
 * The client metadata members a registration could name a token audience in.
 * Neither is registered metadata QAuth stores: the request schema drops both,
 * as RFC 7591 §2 lets a server ignore metadata it does not understand.
 */
const AUDIENCE_METADATA_MEMBERS = ['audience', 'resource'] as const;

/**
 * Refuse a registration whose `audience` or `resource` metadata names a
 * QAuth-defined audience (`urn:qauth:aud:`, #509), with
 * `invalid_client_metadata`. An API family audience is issued only to a client
 * an operator set up to list it (ADR-019 Decision 7), so a client that claims
 * one for itself is told so rather than registered as if it had not asked.
 *
 * Takes the body as it arrived, before the schema strips the two members; any
 * other value in them is still ignored. A Client ID Metadata Document is held
 * to the same rule (`toCimdClientInsert`).
 */
export function assertNoReservedAudienceMetadata(body: unknown): void {
  if (typeof body !== 'object' || body === null) return;
  for (const member of AUDIENCE_METADATA_MEMBERS) {
    const value: unknown = Reflect.get(body, member);
    if (reservedAudiencesIn(value).length > 0) {
      rejectRegistration(
        'invalid_client_metadata',
        `${member} values starting with "urn:qauth:aud:" are reserved for QAuth's own APIs and cannot be registered`
      );
    }
  }
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
  grantTypes: DynRegGrantType[];
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
  /**
   * Whether the client registered itself as an autonomous AI agent
   * (ADR-007 §2). Orthogonal to `isPublic`. Persisted to
   * `oauth_clients.is_agent`; defaults to false when the request omits it.
   */
  isAgent: boolean;
}

/**
 * Validate + normalize an incoming RFC 7591 request against realm policy.
 *
 * - Caps requested scopes to the realm's `dynamic_registration_allowed_scopes`,
 *   and always drops a scope in the reserved `qauth:` namespace (#507).
 * - Enforces grant_type / response_type consistency (authorization_code
 *   requires the `code` response type).
 * - Requires redirect_uris for any user-involving grant.
 * - Validates every redirect_uri per OAuth 2.1 §10.3.
 * - Forces `token_endpoint_auth_method=none` for clients that only use
 *   authorization_code (public client posture) when not explicitly
 *   declared as confidential.
 *
 * Throws `InvalidClientMetadataError` or `InvalidRedirectUriError` (the
 * RFC 7591 §3.2.2 code, via `rejectRegistration`) on any policy violation.
 * Returns a normalized shape ready to persist.
 */
export function validateAndNormalize(
  body: DynamicClientRegistrationRequest,
  realmAllowedScopes: string[],
  customRedirectSchemes: readonly string[]
): NormalizedRegistrationRequest {
  const grantTypes = (body.grant_types ?? [...DYN_REG_DEFAULTS.grantTypes]) as DynRegGrantType[];
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
    validateRedirectUri(uri, customRedirectSchemes);
  }

  // Scope cap: intersect requested scopes with the realm's allowlist. Per
  // RFC 7591 §2, the authorization server MAY register the client with a
  // narrower scope than requested rather than rejecting — and we do, so
  // discover-then-register MCP clients register cleanly. Such clients echo
  // back the protected resource's full advertised `scopes_supported`
  // (RFC 9728), which routinely includes privileged scopes a public dynamic
  // client can't hold; hard-rejecting the whole registration on those would
  // break every standards-compliant MCP client. We drop the disallowed
  // scopes and register the permitted subset (empty allowlist → no scopes).
  // De-dupe while preserving request order.
  //
  // A scope in QAuth's reserved `qauth:` namespace (#507, ADR-019 Decision 7),
  // such as an admin API scope, is dropped like any other scope outside the
  // allowlist: an MCP client that echoes `scopes_supported` still registers.
  // The allowlist cannot hold one (`realms_dynamic_registration_scopes_not_qauth`),
  // and the namespace is left out here too, so no list the realm resolves,
  // the environment's seed included, grants one through open registration.
  let scopes: string[] = [];
  const scopeString = body.scope;
  if (scopeString && scopeString.trim().length > 0) {
    const requested = scopeString.split(/\s+/).filter((s) => s.length > 0);
    scopes = [
      ...new Set(
        requested.filter((s) => realmAllowedScopes.includes(s) && !isReservedQauthScope(s))
      ),
    ];
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

  // Same rule, same reason, for RFC 8693 token exchange (#381). The token
  // endpoint authenticates the agent through the CONFIDENTIAL client-auth path
  // and rejects a public client with `invalid_client` before any exchange logic
  // runs. Registering the grant on a public client would therefore hand back a
  // capability the client can never reach — the precise failure the
  // `jwt-bearer` exclusion in `dynamicClientRegistrationRequestSchema` exists to
  // avoid. Fail at registration, where the operator can see it, rather than at
  // every exchange attempt.
  if (tokenEndpointAuthMethod === 'none' && grantTypes.includes(TOKEN_EXCHANGE_GRANT_TYPE)) {
    rejectRegistration(
      'invalid_client_metadata',
      'token-exchange grant requires a confidential client (token_endpoint_auth_method must not be "none")'
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
    isAgent: body.is_agent ?? false,
  };
}
