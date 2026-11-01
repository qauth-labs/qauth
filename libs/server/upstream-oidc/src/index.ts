// The generic upstream OpenID Connect client (#601): an AuthMethod (#599,
// EXPERIMENTAL) for one OpenID Provider per configured `oidc_<alias>` type.
// It makes no account decision; the upstream sign-in flow (#639) does.
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
export * from './lib/upstream-oidc-method';
