# API report: `@qauth-labs/plugin-sdk`

Every name each entry point exports. `src/api-report.test.ts` compares this
list with the entry points and fails when they differ, so a change to the
plugin API always changes this file in the same pull request. A name marked
`(type)` exists only for TypeScript.

The package is the AuthMethod contract, `qauth-auth-method/1-rc.0`, and it is
experimental (ADR-018 §4). A breaking change to any name below, or to what it
means, raises `AUTH_METHOD_CONTRACT_VERSION`: the server refuses a plugin
written against another version, so a plugin built for the old one fails the
boot instead of running against a contract it does not know.

## `@qauth-labs/plugin-sdk`

What a plugin imports (`src/index.ts`): the `AuthMethod` interface and the
types it uses, the contract's constants, its errors and the static checks.

- `assertAuthMethod`
- `AssuranceLevel` (type)
- `AUTH_METHOD_ATTRIBUTE_KEY_PATTERN`
- `AUTH_METHOD_BINDING_PARAMETER_PATTERN`
- `AUTH_METHOD_BINDING_PATTERN`
- `AUTH_METHOD_CONTRACT_NAME`
- `AUTH_METHOD_CONTRACT_VERSION`
- `AUTH_METHOD_CONTRACT`
- `AUTH_METHOD_DISPLAY_NAME_PATTERN`
- `AUTH_METHOD_ICON_MEDIA_TYPES`
- `AUTH_METHOD_ID_PATTERN`
- `AUTH_METHOD_PLUGIN_EXPORT`
- `AUTH_METHOD_ROUTE_PATH_PATTERN`
- `AUTH_METHOD_ROUTE_ROOT`
- `AUTH_METHOD_STEP_URNS`
- `AUTH_METHOD_TYPE_PATTERN`
- `AuthMethod` (type)
- `AuthMethodBounce` (type)
- `AuthMethodBounceRoute` (type)
- `AuthMethodCallbackRequest` (type)
- `AuthMethodCallbackRoute` (type)
- `AuthMethodClientAssertionRequest` (type)
- `AuthMethodConfigError`
- `AuthMethodContext` (type)
- `AuthMethodContractError`
- `AuthMethodDisplay` (type)
- `AuthMethodEgress` (type)
- `AuthMethodEgressRequest` (type)
- `AuthMethodEgressResponse` (type)
- `AuthMethodFaultError`
- `AuthMethodIcon` (type)
- `AuthMethodLogger` (type)
- `AuthMethodParameters` (type)
- `authMethodProblems`
- `AuthMethodRoute` (type)
- `AuthMethodRouteBase` (type)
- `authMethodRoutePrefix`
- `AuthMethodRouteRequest` (type)
- `AuthMethodSigner` (type)
- `AuthMethodStepUrn` (type)
- `CredentialProvider` (type)
- `DEFAULT_AUTH_METHOD_BINDING_PARAMETER`
- `isAuthMethod`
- `MAX_AUTH_METHOD_ATTRIBUTE_VALUE_LENGTH`
- `MAX_AUTH_METHOD_DISPLAY_NAME_LENGTH`
- `MAX_AUTH_METHOD_EXTERNAL_SUB_LENGTH`
- `MAX_AUTH_METHOD_ICON_BYTES`
- `MAX_AUTH_METHOD_PARAMETER_LENGTH`
- `MAX_AUTH_METHOD_PARAMETER_VALUES`
- `MAX_AUTH_METHOD_PARAMETERS`
- `MAX_AUTH_METHOD_RAW_CLAIMS_BYTES`
- `MAX_UPSTREAM_REDIRECT_LENGTH`
- `MAX_UPSTREAM_TRANSACTION_BYTES`
- `PendingUpstreamTransaction` (type)
- `RESERVED_AUTH_METHOD_TYPES`
- `UPSTREAM_FAILURE_REASONS`
- `UPSTREAM_STEP_URN`
- `UpstreamCallbackOutcome` (type)
- `UpstreamFailureReason` (type)
- `UpstreamStart` (type)
- `UpstreamStartRequest` (type)
- `UserAttribute` (type)
- `VerifiedIdentity` (type)

The shape of an upstream OpenID Connect preset (#671), a plugin the server
builds on its own OpenID Connect client: its types, its constants, the helper
that defines one, the loader's static checks of it, and the generic client's
id and type namespace, which no plugin may take.

- `defineUpstreamOidcPreset`
- `isUpstreamOidcPreset`
- `MAX_UPSTREAM_ASSERTION_ISSUER_LENGTH`
- `MAX_UPSTREAM_OIDC_PRESET_ORIGINS`
- `MAX_UPSTREAM_RESPONSE_MEMBER_LENGTH`
- `MAX_UPSTREAM_RESPONSE_MEMBERS`
- `UPSTREAM_ASSERTION_ALGORITHMS`
- `UPSTREAM_ID_TOKEN_ALGORITHMS`
- `UPSTREAM_ID_TOKEN_ONLY_CLAIMS`
- `UPSTREAM_OIDC_METHOD_ID`
- `UPSTREAM_OIDC_PRESET_EXPORT`
- `UPSTREAM_OIDC_TYPE_PATTERN`
- `UPSTREAM_PRESET_CLIENT_AUTHENTICATION_METHODS`
- `UPSTREAM_RESPONSE_MEMBER_NAME_PATTERN`
- `UPSTREAM_RESPONSE_PARAMETERS`
- `UPSTREAM_SIGNED_CLIENT_SECRET`
- `UPSTREAM_STANDARD_ATTRIBUTES`
- `UPSTREAM_TENANT_PLACEHOLDER`
- `UPSTREAM_VERIFIED_CLAIM_PAIRS`
- `UpstreamAssertionAlgorithm` (type)
- `UpstreamClaimAttribute` (type)
- `upstreamClaimIsTrue`
- `UpstreamIdentityClaims` (type)
- `UpstreamIdTokenAlgorithm` (type)
- `UpstreamOidcClientAuthentication` (type)
- `UpstreamOidcEndpoints` (type)
- `UpstreamOidcPreset` (type)
- `UpstreamOidcPresetOptions` (type)
- `upstreamOidcPresetProblems`
- `UpstreamOidcProviderConfig` (type)
- `UpstreamOidcTenantIssuer` (type)
- `UpstreamResponseMembers` (type)

## `@qauth-labs/plugin-sdk/host`

The host's half (`src/host.ts`): what QAuth's server runs around a method,
and the test kit runs the same way. A plugin does not import it.

- `AUTH_METHOD_LOG_FIELDS_KEY`
- `AUTH_METHOD_LOG_REDACTED_FIELDS`
- `AuthMethodContextParts` (type)
- `AuthMethodHostEgress` (type)
- `AuthMethodHostSigner` (type)
- `authMethodParameters`
- `authMethodSnapshot`
- `authMethodTypeProblems`
- `completeUpstreamStep`
- `createAuthMethodContext`
- `declaresAuthMethodContract`
- `DEFAULT_UPSTREAM_MAX_ASSURANCE`
- `MAX_AUTH_METHOD_CLIENT_ASSERTION_LIFETIME_SECONDS`
- `parseAuthMethodConfig`
- `presentedUpstreamBinding`
- `routeProblems`
- `startUpstreamStep`
- `storableTransaction`
- `upstreamBindingMatches`
- `upstreamRedirectProblem`
- `UpstreamStepCompletion` (type)
- `UpstreamStepCompletionOptions` (type)
- `UpstreamStepFailureReason` (type)

## `@qauth-labs/plugin-sdk/testing`

The contract test kit (`src/testing/index.ts`), for a plugin's own tests.
It replaces the global `fetch` while it runs.

- `AuthMethodKitReport` (type)
- `AuthMethodKitRequest` (type)
- `AuthMethodKitScenario` (type)
- `checkAuthMethod`

The preset kit (#671), which checks an upstream OpenID Connect preset without
the server.

- `checkUpstreamOidcPreset`
- `UpstreamOidcPresetKitReport` (type)
- `UpstreamOidcPresetKitScenario` (type)
