/**
 * The JSON member names an API family representation may use although they are
 * not `camelCase` (#506).
 *
 * The admin, account and developer APIs name their JSON members in
 * `camelCase`. A member that carries a registered OAuth or OpenID Connect
 * metadata value keeps its registered name instead, so a client representation
 * says `redirect_uris` and `token_endpoint_auth_method`, as RFC 7591 and every
 * OAuth library spell them. Only names that are not already `camelCase` need an
 * entry: `scope`, `issuer` and `sub` pass the naming rule as they are.
 *
 * Each group is one IANA registry, or the record that fixed a QAuth name. A
 * name is added here only when an API representation carries that registered
 * value; inventing a snake_case name does not qualify.
 */
const REGISTERED_NAME_GROUPS: Readonly<Record<string, readonly string[]>> = {
  // OAuth Dynamic Client Registration Metadata (RFC 7591 §2, RFC 7592,
  // OpenID Connect Dynamic Client Registration 1.0 §2, RFC 8705, RFC 9101,
  // RFC 9126, RFC 9449, OpenID Connect RP-Initiated, Front- and Back-Channel
  // Logout 1.0).
  'OAuth client metadata': [
    'redirect_uris',
    'token_endpoint_auth_method',
    'token_endpoint_auth_signing_alg',
    'grant_types',
    'response_types',
    'client_name',
    'client_uri',
    'logo_uri',
    'tos_uri',
    'policy_uri',
    'jwks_uri',
    'software_id',
    'software_version',
    'software_statement',
    'client_id',
    'client_secret',
    'client_id_issued_at',
    'client_secret_expires_at',
    'registration_access_token',
    'registration_client_uri',
    'application_type',
    'sector_identifier_uri',
    'subject_type',
    'id_token_signed_response_alg',
    'id_token_encrypted_response_alg',
    'id_token_encrypted_response_enc',
    'userinfo_signed_response_alg',
    'userinfo_encrypted_response_alg',
    'userinfo_encrypted_response_enc',
    'request_object_signing_alg',
    'request_object_encryption_alg',
    'request_object_encryption_enc',
    'default_max_age',
    'require_auth_time',
    'default_acr_values',
    'initiate_login_uri',
    'request_uris',
    'post_logout_redirect_uris',
    'frontchannel_logout_uri',
    'frontchannel_logout_session_required',
    'backchannel_logout_uri',
    'backchannel_logout_session_required',
    'tls_client_certificate_bound_access_tokens',
    'require_signed_request_object',
    'require_pushed_authorization_requests',
    'dpop_bound_access_tokens',
  ],
  // OAuth Authorization Server Metadata (RFC 8414 §2, OpenID Connect
  // Discovery 1.0 §3, RFC 8628, RFC 9126, RFC 9207, RFC 9449).
  'OAuth authorization server metadata': [
    'authorization_endpoint',
    'token_endpoint',
    'registration_endpoint',
    'userinfo_endpoint',
    'revocation_endpoint',
    'introspection_endpoint',
    'end_session_endpoint',
    'device_authorization_endpoint',
    'pushed_authorization_request_endpoint',
    'scopes_supported',
    'response_types_supported',
    'response_modes_supported',
    'grant_types_supported',
    'token_endpoint_auth_methods_supported',
    'token_endpoint_auth_signing_alg_values_supported',
    'revocation_endpoint_auth_methods_supported',
    'introspection_endpoint_auth_methods_supported',
    'code_challenge_methods_supported',
    'subject_types_supported',
    'id_token_signing_alg_values_supported',
    'claims_supported',
    'acr_values_supported',
    'dpop_signing_alg_values_supported',
    'service_documentation',
    'ui_locales_supported',
    'op_policy_uri',
    'op_tos_uri',
    'authorization_response_iss_parameter_supported',
  ],
  // OAuth Protected Resource Metadata (RFC 9728 §2).
  'OAuth protected resource metadata': [
    'authorization_servers',
    'bearer_methods_supported',
    'resource_signing_alg_values_supported',
    'resource_name',
    'resource_documentation',
    'resource_policy_uri',
    'resource_tos_uri',
  ],
  // JSON Web Token Claims (RFC 7519 §4, OpenID Connect Core 1.0 §2 and §5.1,
  // RFC 8693 §4, RFC 9068 §2.2).
  'JWT claims': [
    'auth_time',
    'may_act',
    'given_name',
    'family_name',
    'middle_name',
    'preferred_username',
    'email_verified',
    'phone_number',
    'phone_number_verified',
    'updated_at',
  ],
  // OAuth Parameters and OAuth Token Introspection Response (RFC 6749 §5.1,
  // RFC 7662 §2.2, RFC 8693 §2.2.1).
  'OAuth token response and introspection': [
    'access_token',
    'refresh_token',
    'id_token',
    'token_type',
    'expires_in',
    'issued_token_type',
  ],
  // ADR-019 Decision 7 fixed the name of the problem document's trace member.
  'ADR-019 Decision 7': ['trace_id'],
};

/** Every allowed non-camelCase name, mapped to the group it comes from. */
export const REGISTERED_NAMES: ReadonlyMap<string, string> = new Map(
  Object.entries(REGISTERED_NAME_GROUPS).flatMap(([group, names]) =>
    names.map((name) => [name, group] as const)
  )
);
