# @qauth-labs/server-upstream-oidc

The generic upstream OpenID Connect client (#601): the relying-party side QAuth uses toward an
upstream OpenID Provider. It is an **AuthMethod** (the experimental plugin contract of #599,
`libs/server/federation/src/auth-method/`), one per configured provider, and it makes no account
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
  minutes per realm and issuer, and checked against the config at every use.
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
  `rawClaims` are the ID token's claims over the userinfo claims, `iss` among them.
- **Caps on every call**: no redirect is followed (`redirect: 'error'`), and each call has its own
  deadline and response size cap (`UPSTREAM_OIDC_CALL_CAPS`), under the egress client's.

## Stored config

`sealUpstreamOidcConfig` encrypts the client secret with the realm's data-at-rest key through the
signer role (`Signer.encrypt`, context `upstream-oidc:client-secret:<realm id>:<type>`);
`openUpstreamOidcConfig` decrypts it for the method's context; `describeUpstreamOidcConfig` is
the view an API or event may carry, with neither the secret nor its ciphertext.

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
  `openUpstreamOidcConfig` and hands the result to `createAuthMethodContext`, with a signer caller
  role that may `decrypt` (and `signClientAssertion`, for `private_key_jwt`): `api` or `local`
  today, not `web`.
- **One client id.** For `private_key_jwt` the form's `client_id` is the config's `clientId`, and
  the assertion's `iss` and `sub` are the client id the signer's upstream-provider record names;
  the two must agree.
- **Caps.** Each call's deadline and size cap apply on top of the egress client's own: a call
  past its deadline is abandoned (the egress client still bounds it), and an answer over its
  cap is refused after the egress client has read it, within its own cap.
- **Discovery is lenient where the document is silent.** A document that omits
  `token_endpoint_auth_methods_supported`, `response_modes_supported` or
  `response_types_supported` is taken at its word for the configured method and mode; one that
  lists them must list what the config uses.
- **The assertion's `aud`** is the issuer identifier alone (draft-ietf-oauth-rfc7523bis). A
  provider that wants its token endpoint there is not served yet.

## Tests

```sh
pnpm exec nx test server-upstream-oidc
```

`src/testing/fake-provider.ts` is a fake OpenID Provider with no network of its own, used here and
by the flow tests in `libs/fastify/plugins/federation`, which run it behind a local HTTPS server and
the real egress client.
