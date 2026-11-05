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
 *   the server's signer, as the provider administration (#714) will write it.
 */
export {
  sealUpstreamOidcConfig,
  type StoredUpstreamOidcConfig,
  type UpstreamOidcConfigInput,
} from '@qauth-labs/server-upstream-oidc';
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
