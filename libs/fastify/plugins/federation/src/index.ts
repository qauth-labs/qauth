export * from './lib/configured-providers';
export * from './lib/federation-plugin';
export type * from './types';

// Re-exported provider surface: app code (scope:app) may only depend on
// fastify plugins (scope:fastify), never on server libs directly — routes and
// bootstrap reach the ADR-003 provider API through here.
export type {
  AssuranceLevel,
  CredentialProvider,
  PasswordCredentialData,
  TrustRankedAttribute,
  UserAttribute,
  VerifiedIdentity,
} from '@qauth-labs/server-federation';
// Note the asymmetry with the password surface: `createWalletProvider` is
// deliberately NOT re-exported. `createConfiguredProviders` is the only
// sanctioned way for app code to put a wallet provider in the registry, so no
// bootstrap can register one while bypassing WALLET_FEDERATION_ENABLED (#232).
// The type/source constants ARE re-exported — #237/#238 route and claim code
// needs them.
export {
  buildPasswordCredentialData,
  createPasswordProvider,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  rankAttributeSource,
  selectTrustedAttribute,
  SELF_REPORTED_SOURCE,
  WALLET_PROVIDER_TYPE,
  WALLET_SOURCE,
} from '@qauth-labs/server-federation';

// OID4VP 1.0 transport surface (#233), re-exported for the same boundary reason
// as the provider API above: the `direct_post` response route lives in
// `apps/auth-server` (`scope:app`), which may not depend on `scope:server` libs
// directly.
//
// The `VerifierProfile` resolution surface comes with it — the route MUST resolve
// a profile per request and refuse when none is selected (#296 fail-closed), and
// it cannot import the resolver any other way.
export type {
  ClientIdPrefix,
  CredentialFormat,
  CredentialFormatAdapter,
  CredentialRequestSpec,
  DcqlClaimsQuery,
  DcqlCredentialQuery,
  DcqlQuery,
  Oid4vpAuthorizationRequest,
  Oid4vpDirectPostOutcome,
  Oid4vpRequestSecrets,
  PresentedCredential,
  RedeemedOid4vpRequestState,
  VerifierProfile,
  VerifierProfileId,
} from '@qauth-labs/server-federation';
export {
  assertNoRedirectUriParameter,
  assertProfileUnchanged,
  assertValidResponseUri,
  buildOid4vpAuthorizationRequest,
  buildRedirectUriClientId,
  DEFAULT_OID4VP_REQUEST_TTL_MS,
  DIRECT_POST_RESPONSE_MODE,
  encodeOid4vpRequestUri,
  generateOid4vpRequestSecrets,
  hashOid4vpState,
  MAX_VP_TOKEN_LENGTH,
  OID4VP_REJECTION_DESCRIPTION,
  OID4VP_RESPONSE_TYPE,
  Oid4vpTransportRejection,
  parseStoredDcqlQuery,
  parseVpToken,
  resolveOid4vpExpiry,
  resolveVerifierProfile,
  SD_JWT_VC_FORMAT,
} from '@qauth-labs/server-federation';
