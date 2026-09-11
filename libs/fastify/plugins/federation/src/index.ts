export * from './lib/configured-providers';
// Credential revocation (#297/#378): turning OID4VP_STATUS_LIST_* into a wired
// `CredentialStatusChecker`, plus the boot-time refusal for a half-configured
// one. Same boundary reason as the issuer key resolver below — `scope:app` can
// reach neither the checker nor its anchor/allowlist factories directly.
export * from './lib/credential-status';
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

// Assurance → `acr` surface (#237). The auth-server needs all three halves and
// can reach none of them directly:
//
//  - `resolveAcrValue` / `AcrValueStyle` render a level into the deployment's
//    `acr` vocabulary at ID-token mint time (`helpers/acr-claims.ts`);
//  - `parseAssuranceLevel` narrows the level back out of an authorization-code
//    column or a Redis session payload, where it is an untrusted string;
//  - `resolveAssurancePolicy` / `resolveCredentialAssurance` derive the level
//    from a validated credential and its issuer — the call `resolveWalletPresentation`
//    makes once #234/#236/#300 give it a `ValidatedCredential` to work with.
//
// `createIssuerAssurancePolicy` is deliberately NOT re-exported: like the trust
// allowlist, a policy must be obtained through the realm-scoped resolver so no
// call site can assemble a deployment-wide one by hand.
export type {
  AcrValueStyle,
  AssuranceEvidence,
  AssurancePolicy,
  AssurancePolicyEnvLike,
  AssurancePolicyRealmLike,
  AssuredKeyStorage,
} from '@qauth-labs/server-federation';
export {
  ACR_VALUE_STYLES,
  DEFAULT_ACR_VALUE_STYLE,
  LOW_ONLY_ASSURANCE_POLICY,
  parseAcrValueStyle,
  parseAssuranceLevel,
  resolveAcrValue,
  resolveAssurancePolicy,
  resolveCredentialAssurance,
  supportedAcrValues,
} from '@qauth-labs/server-federation';

// Key-storage assurance (#308) joined to the assurance policy (#237) — the #379
// seam, and the reason this block exists at all. The app layer needs three
// things and can reach none of them directly:
//
//  - `keyStorageAssuranceGateFor` builds the GATE from the resolved profile, so
//    `wallet-verification.ts` can state a posture that survives a deployment
//    having provisioned no resolver. Never assemble the gate by object literal;
//    see `WalletCredentialVerificationOptions.keyStorageAssurance`.
//  - `translateKeyStorageAssurance` is the ONE D1 rule (ADR-010 §5) turning
//    #308's evidence into `AssuranceEvidence.keyStorage`. It is exported as a
//    function rather than inlined at the call site precisely so no consumer
//    re-derives "does this attestation mean eIDAS hardware".
//  - `DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL` is the floor an entry gets when it
//    states none, exported so a test or an operator-facing message can name it
//    rather than repeating the literal.
//
// The RESOLVER factories (`createKeyStorageAssuranceResolver`,
// `createStaticAttestingIssuers`) remain deliberately absent: like the trust
// allowlist and the status checker, a resolver must be obtained through a
// configuration-driven factory in this layer, not assembled at a call site.
// That factory now exists — `createConfiguredKeyStorageAssuranceResolver` in
// `lib/attesting-issuers.ts`, exported below with the provisioning predicate the
// bootstrap threads into `createConfiguredProviders`.
export {
  assertAttestingIssuersUsable,
  type ConfiguredAttestingIssuers,
  createConfiguredKeyStorageAssuranceResolver,
  keyStorageAssuranceProvisioningOf,
} from './lib/attesting-issuers';
export type {
  AttackPotentialResistance,
  KeyStorageAssuranceEvidence,
  KeyStorageAssuranceGate,
  KeyStorageAssuranceResolver,
  // Needed by `apps/auth-server`'s `app.ts`, which owns the single
  // `PROVISIONED_VERIFIER_MATERIAL` constant both the provider path and the
  // subject-resolution boot gate read (#233/#379).
  ProvisionedVerifierMaterial,
  TranslatedKeyStorage,
} from '@qauth-labs/server-federation';
export {
  // Re-exported for the cross-lib pin in `apps/auth-server`'s
  // `src/config/env.test.ts`: `server-config` DUPLICATES this §D.2 vocabulary
  // as a Zod enum rather than importing it (it is the lowest layer and carries
  // no dependency on `server-federation`), so something has to assert the two
  // still agree. The app is the lowest layer permitted to see both, and it can
  // only see this half through this barrel — without the export, the pin those
  // schemas' TSDoc promises cannot be written at all.
  ATTACK_POTENTIAL_RESISTANCE_ORDER,
  DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL,
  keyStorageAssuranceGateFor,
  translateKeyStorageAssurance,
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
  readWalletBinding,
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
  // Credential revocation (#297/#378). The bootstrap holds the checker as a
  // per-deployment singleton and writes its audit events to the server logger,
  // so it needs both the interface and the event shape; `scope:app` can reach
  // neither directly. The FACTORY is deliberately not re-exported — a checker
  // must be obtained through `createConfiguredCredentialStatusChecker`, which is
  // the only thing that passes a real breaker and refuses a half-configured
  // deployment.
  CredentialStatusAuditEvent,
  CredentialStatusChecker,
  CredentialStatusProvisioning,
  DcqlClaimsQuery,
  DcqlCredentialQuery,
  DcqlQuery,
  IssuerKeyResolver,
  Oid4vpAuthorizationRequest,
  Oid4vpDirectPostOutcome,
  Oid4vpRequestDelivery,
  Oid4vpRequestSecrets,
  PresentedCredential,
  RedeemedOid4vpRequestState,
  ValidatedCredential,
  VerifierProfile,
  VerifierProfileId,
  VerifierSigningMaterial,
} from '@qauth-labs/server-federation';
export {
  assertNoRedirectUriParameter,
  assertProfileUnchanged,
  assertResponseModeUnchanged,
  assertValidResponseUri,
  buildOid4vpAuthorizationRequest,
  buildRedirectUriClientId,
  buildX509HashClientId,
  createVerifierSigningMaterial,
  DEFAULT_OID4VP_REQUEST_TTL_MS,
  DEFAULT_REQUEST_OBJECT_LIFETIME_SECONDS,
  DIRECT_POST_JWT_RESPONSE_MODE,
  DIRECT_POST_RESPONSE_MODE,
  encodeOid4vpRequestUri,
  generateOid4vpRequestSecrets,
  hashOid4vpState,
  isSignedOid4vpRequest,
  MAX_VP_TOKEN_LENGTH,
  OID4VP_REJECTION_DESCRIPTION,
  OID4VP_REQUEST_OBJECT_MEDIA_TYPE,
  OID4VP_REQUEST_OBJECT_TYP,
  OID4VP_RESPONSE_TYPE,
  Oid4vpTransportRejection,
  parseStoredDcqlQuery,
  parseVpToken,
  resolveOid4vpExpiry,
  resolveVerifierProfile,
  SD_JWT_VC_FORMAT,
  selectOid4vpResponseMode,
  signOid4vpRequestObject,
  verifierMaterialProvisionedBy,
  X509_HASH_CLIENT_ID_PREFIX,
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
  WalletLinkContext,
  WalletLinkOutcome,
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

// Account linking (#238, ADR-009 §5). `prepareWalletLink` produces a WRITE PLAN
// and touches no database — the app layer owns the transaction, because
// `scope:server` may not import `infra-db`.
export { prepareWalletLink } from '@qauth-labs/server-federation';

// Presentation validation (#234) and issuer trust (#236), re-exported for the
// wallet seam (#235, #238). Both are PRECONDITIONS of subject resolution, in
// that order, and the seam that runs them lives in `apps/auth-server` — so the
// app needs the `ValidatedCredential` type to accept one and the trust gate to
// apply before it is acted on. `createStaticIssuerAllowlist` is deliberately NOT
// re-exported: `resolveTrustRegistry` is the only supported way to obtain a live
// registry, and it is fail-closed where the raw constructor throws on a bad
// entry.
//
// `ValidatedIssuer` comes with them, and what it is NOT should be clear before
// anyone reads the export as a widening: the brand is a TYPE-CONFUSION defence
// inside the protocol layer — it stops a credential-asserted `iss` string from
// being mistaken for a resolved issuer identity — and it is not the trust
// decision. `assertIssuerTrusted` and the realm's allowlist are, and both still
// run over whatever is handed to them, so a hand-built instance grants nothing.
// `credential-format.mdoc-registration.test.ts` already constructs one through
// the same public factory.
export type { TrustRegistry } from '@qauth-labs/server-federation';
export {
  assertIssuerTrusted,
  resolveTrustRegistry,
  ValidatedIssuer,
} from '@qauth-labs/server-federation';

// Encrypted Authorization Responses (#377 Phase C). The auth-server mints the
// per-request ECDH-ES pair, protects the private half for the row (plain by
// default, AES-256-GCM when `OID4VP_RESPONSE_KEY_SECRET` is set), and at the
// response endpoint reads the JWE `kid` BEFORE decrypting to find that row.
// None of that reaches `apps/auth-server` except through here.
export type {
  EncryptedAuthorizationResponse,
  EphemeralKeyProtectionOptions,
  Oid4vpEphemeralKeyProtection,
  ProtectedEphemeralKey,
} from '@qauth-labs/server-federation';
export {
  assertEncryptedResponseStateMatches,
  decryptOid4vpAuthorizationResponse,
  EPHEMERAL_KEY_PROTECTION_AES_256_GCM,
  EPHEMERAL_KEY_PROTECTION_PLAIN,
  EPHEMERAL_KEY_PROTECTION_SECRET_BYTES,
  MAX_ENCRYPTED_RESPONSE_LENGTH,
  MAX_ENCRYPTION_KID_LENGTH,
  OID4VP_ENCRYPTED_RESPONSE_ENC_VALUES,
  parseEphemeralKeyProtection,
  protectEphemeralKey,
  readEncryptedResponseKid,
  unprotectEphemeralKey,
} from '@qauth-labs/server-federation';
