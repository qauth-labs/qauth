# @qauth-labs/server-upstream-oidc

The generic upstream OpenID Connect client (#601): the relying-party side QAuth uses toward an
upstream OpenID Provider. It is an **AuthMethod** (the experimental plugin contract of #599,
`@qauth-labs/plugin-sdk`), one per configured provider, and it makes no account
decision: the upstream sign-in flow (#639) looks the identity up and decides.

> **Experimental**, like the AuthMethod contract it implements. Nothing registers it in a running
> server yet: the plugin runtime is #600, provider administration #714, the sign-in flow #639.

## What it does

```ts
import { createUpstreamOidcMethod } from '@qauth-labs/server-upstream-oidc';

const method = createUpstreamOidcMethod({ type: 'oidc_corp', display: { name: 'Example Corp' } });
```

- **Type and callback.** A provider's `type` is `oidc_` and a lower-case alias. Its routes mount
  under `/upstream/<type>`, so each provider has its own callback, `/upstream/<type>/callback` on
  the realm host (`upstreamOidcRedirectUri(origin, type)` builds the URL to register at the
  provider): a response for one provider cannot be replayed at another.
- **Discovery** (`<issuer>/.well-known/openid-configuration`, through the egress client). The
  document's `issuer` must equal the configured one byte for byte. Every URL it names goes out as
  a `remote_document` destination, which the deployment's egress allowlist never opens, so a
  discovered endpoint never reaches a private or loopback address. The document is kept five
  minutes per realm and issuer, and checked against the config at every use. Concurrent starts
  share one read, and a failed read is kept 30 seconds (`UPSTREAM_DISCOVERY_FAILURE_TTL_MS`), so a
  provider that is down costs one outbound call per 30 seconds, not one per visitor.
- **Endpoints by hand** (`endpoints`), for a provider on a private address: no discovery document
  is read, and the endpoints are `admin` destinations, which an allowlist entry naming the realm may
  open.
- **Authorization request**: `response_type=code`, the provider's own `redirect_uri`, the scopes, a
  fresh `state` (also the binding the host checks), a fresh `nonce` and PKCE with S256, and
  `response_mode=form_post` when configured.
- **Callback**: `GET /callback`, and `POST /callback` for `form_post`, which bounces the browser to
  the `GET` callback on the same origin so it brings the `SameSite=Lax` flow cookie. The handler
  checks the transaction is this provider's, checks `iss` (RFC 9207; required when the provider
  says it sends it), ends as `declined` on `access_denied`, then redeems the code.
- **Code exchange** with `client_secret_basic`, `client_secret_post` or `private_key_jwt`. For
  `private_key_jwt` the signer role signs the assertion with the realm's
  `upstream_client_assertion` key for the provider (ADR-019 Decision 9); the library never sees the
  key.
- **ID token**: the signature against the provider's key set (fetched through the egress client and
  kept at most five minutes, fetched again for an unknown `kid` at most once a minute), an
  allowlist of asymmetric algorithms (never `none`, never `HS*`), `iss`, `aud`, `azp`, `exp`,
  `iat` and `nonce`.
- **Userinfo** when `fetchUserinfo` is set; its `sub` must equal the ID token's. The identity's
  `rawClaims` are the ID token's claims over the userinfo claims, `iss` among them. The protocol
  claims (`iss`, `aud`, `azp`, `exp`, `iat`, `nbf`, `jti`, `nonce`, `at_hash`, `c_hash`, `s_hash`,
  `acr`, `amr`, `auth_time`, `sid`, `cnf`) come from the signed ID token alone: userinfo's are
  dropped, so it never adds an `acr` or `auth_time` the ID token lacks.
- **Caps on every call**: no redirect is followed (`redirect: 'error'`), and each call has its own
  deadline and response size cap (`UPSTREAM_OIDC_CALL_CAPS`). These two only stop the method
  waiting and reading; the host egress client's own limits bound the underlying call (see "Caps"
  below).

## Stored config

`sealUpstreamOidcConfig` encrypts the client secret with the realm's data-at-rest key through the
signer role (`Signer.encrypt`, context
`upstream-oidc:client-secret:<realm id>:<type>:<destination>`); `openUpstreamOidcConfig` decrypts
it for the method's context; `describeUpstreamOidcConfig` is the view an API or event may carry,
with neither the secret nor its ciphertext.

**The secret is bound to where it is sent.** `<destination>` is the SHA-256 (hex) of the issuer
and, when the endpoints are set by hand, the token endpoint (`upstreamClientSecretDestination`).
The stored form records it as `clientSecretDestination`. An admin who cannot read the write-only
secret therefore cannot send it to a host they control by changing `issuer` or `endpoints.token`:
`openUpstreamOidcConfig` refuses such a config with `UpstreamClientSecretDestinationChangedError`
and decrypts nothing, and a row whose recorded destination was edited to match still does not
decrypt, since the context names the destination. Switching between discovery and endpoints set by
hand changes it too. The provider administration (#714) must ask for the client secret again
whenever the issuer or the token endpoint set by hand changes, and seal it with the new config.

The context's prefix is `UPSTREAM_CLIENT_SECRET_CONTEXT_PREFIX` of `@qauth-labs/server-keys`. The
signer's policy lets the `api` role decrypt a context under it (besides a realm's mail secret), so
the host opens a stored config as `api`, or as `local` in a single deployment. The `web` and
`delivery` roles cannot decrypt it.

## Preset plugins

`createUpstreamOidcPresetMethod` builds a **preset plugin's** method (#951, #671): an AuthMethod
for one named provider that runs this client's code under its own `id`, `type` and config. A
preset lives in its own repository and depends only on the plugin SDK: its package exports an
`upstreamOidcPreset` (`defineUpstreamOidcPreset` of `@qauth-labs/plugin-sdk`), and the plugin
loader (#600) builds its method with this function, so the plugin runtime loads it as any plugin,
only while `PLUGIN_API_ENABLED` is on. The preset's shape, its options type, limits and claim
lists are the SDK's, which this library re-exports; `src/lib/config-shape.test.ts` holds the SDK's
provider config and this library's schema to one shape. The generic client's `id` `oidc` and its
`oidc_<alias>` types stay reserved for the realm's provider rows.

```ts
// What the loader does with a package's upstreamOidcPreset; a server test may call it on options.
const method = createUpstreamOidcPresetMethod({
  id: 'example-idp',
  type: 'example_idp',
  display: { name: 'Example IdP' },
  origins: ['https://idp.example.com'],
  configSchema: z.strictObject({
    clientId: z.string().min(1).max(255),
    clientSecret: z.string().min(1).max(1024).meta({ writeOnly: true }),
  }),
  upstreamConfig: (config) => ({
    issuer: 'https://idp.example.com',
    clientId: config.clientId,
    clientAuthentication: { method: 'client_secret_basic', clientSecret: config.clientSecret },
  }),
});
```

- `upstreamConfig` turns the preset's parsed config into this client's config at every use. It
  must pass the client secret on as the preset's `writeOnly` member holds it: a config whose
  client secret is not the value of such a member is refused, since the runtime would store it in
  the clear.
- `origins` binds the secret to its provider. The runtime seals a plugin's secret under the
  plugin's own context (`auth-method-plugin:<id>:<package>:<type>:<path>`), not under the issuer and token endpoint
  as the stored config above does, so a preset names the `https` origins its provider answers on,
  every host its endpoints are on included. A config whose issuer or any endpoint set by hand is on
  none of them is refused where the host parses it, at the admin API's configure and at every use,
  and a discovery document that names an endpoint off them is refused before any call to it: no
  config sends the secret to another host.
- `secretDestination` names where the secret goes within the origins (#1031). The preset
  implements this optional AuthMethod member with the issuer and the token endpoint set by hand
  that `upstreamConfig` makes for a config, as the digest `upstreamClientSecretDestination` gives
  the stored config above. The admin API compares it for the stored config and the new one at
  each configure, on top of its own URL-origin rule, so a configure that changes either (a member
  that shapes the issuer's path, such as a tenant, or a token endpoint's path) and keeps the
  stored secret is refused: the secret is sealed again, as the generic client asks for it again.
  Unlike the stored config above, the plugin secret's context does not name the destination.
- A config whose provider config carries a secret member's value anywhere but in the client
  secret (the client id, a scope, a URL) is refused: it would go out, and be logged, in the clear.
- Every call goes out as a `remote_document` destination unless the preset's own config names its
  origin, so a preset never reaches a private address through the egress allowlist.
- `src/testing/example-preset.ts` is a preset on the fake provider, its client secret inside a
  discriminated union of client authentication methods; it passes the contract test kit.

What a named provider needs beyond the generic client, a preset sets in its options (#671), never
a realm's admin, whose config for the generic client has none of it. This library names no
provider:

- **A signed client secret** (`clientAuthentication: { method: 'signed_client_secret' }`, ES256
  unless it names another algorithm): the signer role signs a JWT with the realm's
  `upstream_client_assertion` key for the plugin's type, with the claims and the 60-second
  lifetime of a client assertion, and the client sends it as the `client_secret` of a
  `client_secret_post` request, for a provider that takes no static secret. Its `iss` is the
  signer's configuration of the provider: the client id, or the assertion issuer it names.
- **An issuer template** (`tenantIssuer: { template, tenantClaim }`) for a multi-tenant provider
  whose shared endpoint serves many tenants: the discovery document names the template (e.g.
  `https://idp.example.com/{tenantid}/v2.0`), and an ID token is accepted only when its
  `iss` is the template with the token's own tenant claim in place. The tenant id is letters,
  digits and `-` (`UPSTREAM_TENANT_ID_PATTERN`), so it never reaches past its path segment, and
  the template's origin must be among the preset's origins.
- **Response members** (`responseMembers`): members of the authorization response besides the
  protocol's own that the callback reads, such as a member that carries the person's name, each
  mapped to the value the `form_post` bounce carries on in the callback's URL (at most 1024
  characters). The map must give its own output back unchanged, since the callback maps the
  carried value again. The browser chooses that value: whatever is made of it is an unverified
  claim. The auth server censors each loaded preset's members in its request log.
- **Identity claims** (`identityClaims`): claims set over the provider's from the response members
  and the preset's config. `sub` and the claims only the ID token may carry stay the validated
  ones; a claim set to `undefined` is removed. A claim the provider vouches for (`email`,
  `phone_number`) and its `*_verified` flag may be removed, never set, so a value the preset makes
  up is never taken as verified.
- **Attribute rules** (`attributes`, `UpstreamClaimAttribute`): the claims the identity maps to
  as attributes and the claim that marks each verified, in place of the standard rules
  (`UPSTREAM_STANDARD_ATTRIBUTES`).

## Registration check

`checkUpstreamOidcProvider(egressClient, realmName, config)` runs discovery and the egress
client's address checks on every endpoint without calling it, and reports one finding:
`invalid_config`, `discovery_unavailable`, `invalid_document` or `destination_refused`.

## Rules for the code that uses it

- **Tie the subject to the issuer.** `externalSub` is the provider's bare `sub`, and the provider
  type (`oidc_<alias>`) does not name the issuer, while only `iss` and `sub` together identify a
  person (OpenID Connect Core 1.0 §5.7). `rawClaims.iss` is always the checked issuer (the ID
  token's claims win over userinfo's). The sign-in flow (#639) must store that issuer with the
  credential and refuse a mismatch, or the provider administration (#714) must refuse an issuer
  change while credentials exist: otherwise re-pointing `oidc_corp` at another provider lets
  that provider's user with an equal `sub` sign in as an existing one.
- **Open the stored config before building the context.** The method's `configSchema` takes the
  plaintext `clientSecret`; the stored form holds `clientSecretSealed`. A host calls
  `openUpstreamOidcConfig` and hands the result to `createAuthMethodContext`, both as the signer
  caller `api`, or `local` in a single deployment: `api` may decrypt the client secret and sign
  the `private_key_jwt` assertion. The callback routes are browser routes, but the `web` role can
  do neither.
- **One client id.** For `private_key_jwt` the form's `client_id` is the config's `clientId`, and
  the assertion's `iss` and `sub` are the client id the signer's upstream-provider record names;
  the two must agree.
- **Caps.** The per-call deadline and size cap only stop the method waiting and reading: past
  its deadline the method gives up on the call, and an answer over its cap is refused after the
  egress client has read it. Neither aborts the call or limits what the egress client fetches.
  The host egress client's own limits, `totalTimeoutMs` and `maxResponseBytes`, bound the
  underlying call, so they are what holds a slow or oversized provider in check.
- **Discovery is lenient where the document is silent.** A document that omits
  `token_endpoint_auth_methods_supported`, `response_modes_supported`,
  `response_types_supported` or (for `private_key_jwt`)
  `token_endpoint_auth_signing_alg_values_supported` is taken at its word for the configured
  method, mode and assertion algorithm; one that lists them must list what the config uses.
- **The assertion's `aud`** is the issuer identifier alone (draft-ietf-oauth-rfc7523bis). A
  provider that wants its token endpoint there is not served yet.

## Tests

```sh
pnpm exec nx test server-upstream-oidc
```

`src/testing/fake-provider.ts` is a fake OpenID Provider with no network of its own, used here and
by the flow tests in `libs/fastify/plugins/federation`, which run it behind a local HTTPS server and
the real egress client.
