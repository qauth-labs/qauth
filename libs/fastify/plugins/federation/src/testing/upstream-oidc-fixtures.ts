/**
 * TEST SUPPORT — the generic upstream OIDC client's fixtures, for an
 * auth-server suite (issue #639), which may not import the library itself:
 *
 * - `createFakeProvider`: a fake OpenID Provider with no network of its own,
 *   which a suite serves from a local HTTPS fixture (`startLocalHttpsFixture`
 *   of the egress plugin's fixtures) that only `createTestEgressClient`
 *   reaches;
 * - `sealUpstreamOidcConfig`: a provider's config as a realm's
 *   `realm_upstream_providers` row stores it, its client secret sealed with
 *   the server's signer, as the provider administration (#714) will write it;
 * - `examplePresetPackage`: a preset plugin on the generic client (#951), as
 *   a plugin package exports it, for the plugin runtime's suites, and
 *   `exampleTenantPresetPackage`, one whose issuer a tenant member shapes
 *   (#1031).
 */
export {
  sealUpstreamOidcConfig,
  type StoredUpstreamOidcConfig,
  type UpstreamOidcConfigInput,
} from '@qauth-labs/server-upstream-oidc';
export {
  EXAMPLE_PRESET_ID,
  EXAMPLE_PRESET_ISSUER,
  EXAMPLE_PRESET_PACKAGE,
  EXAMPLE_PRESET_SECRET_PATH,
  EXAMPLE_PRESET_TYPE,
  EXAMPLE_TENANT_PRESET_ID,
  EXAMPLE_TENANT_PRESET_PACKAGE,
  EXAMPLE_TENANT_PRESET_SECRET_PATH,
  EXAMPLE_TENANT_PRESET_TYPE,
  examplePresetPackage,
  exampleTenantIssuer,
  exampleTenantPresetPackage,
} from '@qauth-labs/server-upstream-oidc/src/testing/example-preset';
export {
  createFakeProvider,
  type FakeAnswer,
  type FakeClient,
  type FakeClientAuthentication,
  type FakeProvider,
  type FakeProviderOptions,
  type FakeRequest,
  type FakeSignIn,
} from '@qauth-labs/server-upstream-oidc/src/testing/fake-provider';
