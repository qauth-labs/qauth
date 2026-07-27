export * from './lib/configured-providers';
export * from './lib/federation-plugin';
// #234 + #236 composed for the app layer: validate a presentation, then decide
// whether its issuer is worth anything to this realm. The two halves are NOT
// re-exported individually — `validatePresentations` alone produces a
// plausible-looking `ValidatedCredential` from an untrusted issuer, which is
// precisely the object a caller in a hurry would use. See the module JSDoc.
export * from './lib/wallet-credential-verification';
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
// Re-exported for the bootstrap, which must run this check at startup and
// cannot import `scope:server` libs beyond `server-config` (#236). It is the
// only thing standing between an `OID4VP_TRUSTED_ISSUERS` entry the runtime
// cannot canonicalize and a realm that silently trusts nobody — see
// `assert-trusted-issuers.ts` for why that must fail the boot rather than
// surface as "every presentation is rejected".
export { assertTrustedIssuersUsable } from '@qauth-labs/server-federation';
export {
  buildPasswordCredentialData,
  buildWalletCredentialData,
  createPasswordProvider,
  EMAIL_ATTR_KEY,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  rankAttributeSource,
  readWalletBinding,
  selectTrustedAttribute,
  SELF_REPORTED_SOURCE,
  WALLET_PROVIDER_TYPE,
  WALLET_SOURCE,
  walletCredentialDataSchema,
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
  IssuerKeyResolver,
  Oid4vpAuthorizationRequest,
  Oid4vpDirectPostOutcome,
  Oid4vpRequestSecrets,
  PresentedCredential,
  RedeemedOid4vpRequestState,
  ValidatedCredential,
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

// Subject resolution (#300, ADR-009) — which ACCOUNT a validated presentation
// belongs to. Re-exported for the same boundary reason as everything above: the
// wallet-login seam (`app/helpers/wallet-presentation.ts`) and the account
// linking flow (#238) both live in `apps/auth-server`, which may not import
// `scope:server` libs directly.
//
// `SUBJECT_RESOLUTION_STRATEGY_IDS` comes with it for the cross-lib pin in
// `apps/auth-server/src/config/env.test.ts`, exactly as `VERIFIER_PROFILE_IDS`
// does — `server-config` spells the `OID4VP_SUBJECT_RESOLUTION` enum out as
// literals and the app is the only place both lists are visible at once.
export type {
  AssertedLookupConfig,
  IssuerScopedClaimConfig,
  SubjectAccountCandidate,
  SubjectAccountLookup,
  SubjectResolutionConfig,
  SubjectResolutionContext,
  SubjectResolutionOutcome,
  SubjectResolutionStrategy,
  SubjectResolutionStrategyId,
  WalletCredentialData,
  WalletLinkContext,
  WalletLinkOutcome,
} from '@qauth-labs/server-federation';
export {
  assertSubjectResolved,
  createSessionBindingStrategy,
  createSubjectResolutionStrategy,
  normalizeAssertedIdentifier,
  resolveSubjectResolution,
  SUBJECT_RESOLUTION_STRATEGY_IDS,
} from '@qauth-labs/server-federation';
// Account linking (#238, ADR-009 §5). `prepareWalletLink` produces a WRITE PLAN
// and touches no database — the app layer owns the transaction, because
// `scope:server` may not import `infra-db`.
export { prepareWalletLink } from '@qauth-labs/server-federation';

// Issuer trust (#236) for the realm-scoped registry the verification seam above
// consumes. `createStaticIssuerAllowlist` is deliberately NOT re-exported:
// `resolveTrustRegistry` is the only supported way to obtain a live registry,
// and it is fail-closed where the raw constructor throws on a bad entry.
export type { TrustRegistry, ValidatedIssuer } from '@qauth-labs/server-federation';
export { resolveTrustRegistry } from '@qauth-labs/server-federation';
