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
// Re-exported for the bootstrap, which must run this check at startup and
// cannot import `scope:server` libs beyond `server-config` (#236). It is the
// only thing standing between an `OID4VP_TRUSTED_ISSUERS` entry the runtime
// cannot canonicalize and a realm that silently trusts nobody — see
// `assert-trusted-issuers.ts` for why that must fail the boot rather than
// surface as "every presentation is rejected".
export { assertTrustedIssuersUsable } from '@qauth-labs/server-federation';
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

// VC claims normalization (#235). The wallet enrolment path in
// `apps/auth-server` writes both the `user_credentials` row and its
// `user_attributes` rows, so it needs the claim mapping and the ONE sanctioned
// constructor of the wallet `credential_data` shape — hand-rolling that object
// at the call site would pass every DB constraint and silently break the
// entitlement check on every returning user (see `wallet.provider.ts`).
//
// Note what is still NOT here: `createWalletProvider`, for the reason above.
export type {
  WalletAttributeSource,
  WalletCredentialData,
  WalletCredentialDataInput,
} from '@qauth-labs/server-federation';
export {
  buildWalletCredentialData,
  buildWalletVerifiedIdentity,
  extractWalletAttributes,
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
} from '@qauth-labs/server-federation';
export {
  assertSubjectResolved,
  createSessionBindingStrategy,
  createSubjectResolutionStrategy,
  deriveEnrolmentWalletBinding,
  normalizeAssertedIdentifier,
  resolveSubjectResolution,
  SUBJECT_RESOLUTION_STRATEGY_IDS,
} from '@qauth-labs/server-federation';

// Presentation validation (#234) and issuer trust (#236), re-exported for the
// wallet-login seam (#235). Both are PRECONDITIONS of subject resolution, in
// that order, and the seam that runs them lives in `apps/auth-server` — so the
// app needs the `ValidatedCredential` type to accept one and the trust gate to
// apply before it is acted on.
//
// `ValidatedIssuer` comes with them, and what it is NOT should be clear before
// anyone reads the export as a widening: the brand is a TYPE-CONFUSION defence
// inside the protocol layer — it stops a credential-asserted `iss` string from
// being mistaken for a resolved issuer identity — and it is not the trust
// decision. `assertIssuerTrusted` and the realm's allowlist are, and both still
// run over whatever is handed to them, so a hand-built instance grants nothing.
// `credential-format.mdoc-registration.test.ts` already constructs one through
// the same public factory.
export type { TrustRegistry, ValidatedCredential } from '@qauth-labs/server-federation';
export {
  assertIssuerTrusted,
  resolveTrustRegistry,
  ValidatedIssuer,
} from '@qauth-labs/server-federation';
