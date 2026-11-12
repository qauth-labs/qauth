// The generic upstream OpenID Connect client (#601): an AuthMethod (#599,
// EXPERIMENTAL) for one OpenID Provider per configured `oidc_<alias>` type,
// and the preset plugins built on it (#951), each with its own id, type and
// config. It makes no account decision; the upstream sign-in flow (#639) does.
export * from './lib/assertion-client';
export {
  UPSTREAM_STANDARD_ATTRIBUTES,
  type UpstreamClaimAttribute,
  upstreamClaimAttributes,
  upstreamClaimIsTrue,
} from './lib/attributes';
export * from './lib/config';
export * from './lib/errors';
export {
  ID_TOKEN_CLOCK_TOLERANCE_SECONDS,
  ID_TOKEN_MAX_AGE_SECONDS,
  type IdTokenExpectations,
  type IdTokenKeys,
  MAX_ID_TOKEN_LENGTH,
  validateIdToken,
} from './lib/id-token';
export {
  MAX_UPSTREAM_JWKS_KEYS,
  UPSTREAM_JWKS_REFRESH_INTERVAL_MS,
  UPSTREAM_JWKS_TTL_MS,
} from './lib/jwks';
export {
  fetchDiscoveryDocument,
  parseDiscoveryDocument,
  resolveProviderMetadata,
  type UpstreamProviderMetadata,
} from './lib/metadata';
export * from './lib/registration-check';
export * from './lib/stored-config';
export { CLIENT_ASSERTION_LIFETIME_SECONDS, JWT_BEARER_ASSERTION_TYPE } from './lib/token-request';
export {
  UPSTREAM_OIDC_CALL_CAPS,
  UPSTREAM_OIDC_PURPOSES,
  type UpstreamCallCaps,
} from './lib/upstream-call';
export {
  createUpstreamOidcMethod,
  MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH,
  UPSTREAM_DISCOVERY_FAILURE_TTL_MS,
  UPSTREAM_DISCOVERY_TTL_MS,
  UPSTREAM_OIDC_CALLBACK_PATH,
  UPSTREAM_OIDC_METHOD_ID,
  UPSTREAM_OIDC_TYPE_PATTERN,
  type UpstreamIdentityClaims,
  type UpstreamOidcMethodOptions,
  upstreamOidcRedirectUri,
  type UpstreamOidcTransaction,
  type UpstreamResponseMembers,
} from './lib/upstream-oidc-method';
export {
  createUpstreamOidcPresetMethod,
  MAX_UPSTREAM_OIDC_PRESET_ORIGINS,
  type UpstreamOidcPresetOptions,
} from './lib/upstream-oidc-preset';
