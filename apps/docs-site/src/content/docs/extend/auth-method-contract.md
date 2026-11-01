---
title: The AuthMethod contract
description: The experimental plugin API for sign-in methods — what an AuthMethod adds to CredentialProvider, the upstream step it serves, what a method is handed, where its routes mount, and the test kit that checks a method against the contract.
sidebar:
  order: 6
lastVerified: '2026-11-01'
experimental: true
---

> **Experimental.** The AuthMethod contract is QAuth's plugin API, the experimental item
> [`plugin-api`](/reference/experimental-features/#plugin-api). It is public and documented, so
> others can write methods against it, but it is outside the 1.0 stability promise: it may change
> in a minor release without a deprecation window. It becomes stable in 1.x, once QAuth's own
> plugins have matured on it ([ADR-018](/reference/records/adr/018-1-0-scope-and-stability/) §4).

An **AuthMethod** is a sign-in method that plugs into QAuth's engine, such as an upstream OpenID
Connect provider. It extends the [`CredentialProvider`](/extend/adding-a-credential-provider/)
interface of [ADR-003](/reference/records/adr/003-credential-provider-interface/):
`CredentialProvider` stays the verification half, and AuthMethod adds what a method needs beyond
verification. The contract lives in `libs/server/federation/src/auth-method/`.

## What exists today

The contract, the registry entries, the route mount, the test kit, and the first method on it:
the generic OpenID Connect upstream client (#601, [below](#the-generic-openid-connect-client)).
Nothing registers an AuthMethod in a running server yet: the plugin runtime that loads installed
methods is #600, provider administration is #714, and the upstream sign-in flow that offers the
step and acts on its outcome is #639. `WalletProvider` is not an AuthMethod and stays a plain
provider whose `verify()` rejects; wallet sign-in keeps its own seam.

## The contract

`libs/server/federation/src/auth-method/auth-method.interface.ts` (`AuthMethod`):

| Member                | What it is                                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`                | From `CredentialProvider`: the registry key, the `user_credentials.provider_type` value, the `source` of every attribute, and a segment of the route prefix.                 |
| `verify()`            | From `CredentialProvider`: turns the result the method's own callback returned into a `VerifiedIdentity`, and rejects anything else.                                         |
| `extractAttributes()` | From `CredentialProvider`: the attributes of a verified identity.                                                                                                            |
| `contract`            | The contract version the method is written against: `qauth-auth-method/1-rc.0`. Its presence is what makes a registered provider an AuthMethod.                              |
| `id`                  | The stable name of the method's implementation. Instances of one implementation, one per configured provider, share it; `type` tells them apart.                             |
| `display`             | Default display data: `name` (at most 64 characters, under the Interaction API's display rule) and an optional `icon` (a PNG of at most 16 KiB). An admin may override both. |
| `configSchema`        | A Zod object schema of the method's config for one realm. A secret member is marked `.meta({ writeOnly: true })`.                                                            |
| `steps`               | The Interaction API steps the method contributes, by versioned URN. Today only the upstream step, `urn:qauth:ia:upstream:v1-rc.0`.                                           |
| `routes`              | The routes the method mounts below its prefix.                                                                                                                               |
| `start()`             | Starts an upstream transaction: where the browser goes, the transaction the method needs back, and the binding the provider carries back.                                    |

The type rules are strict because `type` lands in four places: lower-case ASCII letters, digits
and `_`, starting with a letter, at most 63 characters. A type with `:` or `/` (an ID-JAG issuer
type, `oidc_<issuer URL>`) never matches, and the types QAuth writes itself (`password`, `wallet`,
`webauthn`, `self_reported`, `totp`, `recovery_code`, `email_code`) are reserved.

## The upstream step

```text
engine offers the upstream step ──► person picks the method
        │
        ▼
start(context, { uiLocales })  ──► { redirectTo, transaction, binding }
        │  the engine keeps the transaction and its binding server-side,
        │  bound to the interaction and its flow cookie, and sends the
        │  browser on
        ▼
provider ──► GET /upstream/<type>/callback?code=…&state=<binding>
        │  the host compares the binding with the pending transaction's
        │  (constant time) BEFORE it takes the transaction; with none, or
        │  a binding that does not match, it answers transaction_mismatch,
        │  the transaction stays pending and the method never runs.
        │  Otherwise it takes the transaction (once) and hands the
        │  callback the query and the transaction; no header, no cookie
        ▼
callback ──► result | declined | failed (reason)   (a throw: a fault)
        │
        ▼
engine: verify(result) ──► VerifiedIdentity, checked, assurance capped
        extractAttributes() ──► attributes, each with source = type
```

1. **Start.** The engine calls `start()`. The method answers where the browser goes, the
   transaction it needs back (a fresh `state`, a `nonce`, a PKCE verifier) and the **binding**: a
   fresh random value the authorization request carries to the provider and the provider carries
   back, usually the `state` itself. The engine checks the answer (`startUpstreamStep`): the
   redirect is an absolute `https` URL with no credentials and no fragment, the transaction is an
   object of JSON data of at most 4096 bytes, and the binding is 22 to 512 base64url characters
   (22 is the length of 128 random bits; the check is of length and alphabet, the method makes it
   random). The host keeps the transaction with its binding (`PendingUpstreamTransaction`).
2. **Callback.** The provider sends the browser back to one of the method's callback routes. The
   host reads the pending transaction the flow cookie names without taking it, and compares the
   binding the callback carries with its binding, in constant time (`upstreamBindingMatches`). The
   callback carries it in the route's `bindingParameter`, `state` unless the route names another:
   a query parameter of a `GET` route, a form member of a `POST` one, exactly once. With no pending
   transaction (no flow cookie, another interaction, a replay) or a binding that is missing,
   empty, repeated or another start's, the host answers `transaction_mismatch` itself: the method
   never runs, so it never spends the code, and the transaction stays pending, so a request from
   another site cannot cancel the sign-in. Otherwise the host takes the transaction, once, checks
   the binding of what it took again, and hands the transaction to the route's handler, which
   checks the provider's answer and answers one of three outcomes: `result`, `declined` (the
   person cancelled at the provider, `access_denied`), or `failed` with a reason from a closed set
   (`transaction_mismatch`, `provider_error`, `invalid_response`, `upstream_unavailable`). A
   handler may compare `state` with its transaction again; it costs nothing. A handler that
   throws, or a context the host cannot build (an `AuthMethodConfigError`), is a fault: the mount
   hands the engine an `AuthMethodFaultError` with the error as its cause, through the same
   completion as every other outcome, never a raw 500.
3. **Identity.** The engine (`completeUpstreamStep`) passes a `result` to `verify()`, checks the
   identity it resolves (an `externalSub` of 1 to 255 characters of well-formed text with no
   control character, an assurance level, raw claims of JSON data within 64 KiB, which it copies
   and freezes; a claim that is `undefined` or a `Date` is not JSON data and makes the answer a
   fault), then takes the attributes. The assurance level is capped: `completeUpstreamStep` takes
   `{ maxAssurance }` and lowers the method's level to it, `low` when the caller names none, since
   an upstream sign-in ranks with a password until an operator raises the ceiling for a provider
   it trusts more. Every attribute's `source` must equal the method's `type`: a method cannot
   write attributes under another source, such as `wallet`, which outranks every other in claim
   resolution. An attribute value is well-formed text too (Postgres stores a lone surrogate as
   U+FFFD, which would make two values one), and the engine builds the checked list and copies
   each `expiresAt` itself. A `verify()` rejection ends the step as `verification_refused`; any
   other broken answer is an `AuthMethodFaultError`, and the engine acts on none of it.

The graph of this step is `graphs/flows/federation/upstream-step/flow.yaml`.

## What a method is handed

Plugin code is trusted code that runs in-process
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/) Decision 12), and
the contract hands it only what it needs. `createAuthMethodContext`
(`libs/server/federation/src/auth-method/context.ts`) builds the context, with five members:

- `config`: the realm's config of the method, parsed by `configSchema`, copied and deep-frozen.
  It must be plain data (objects, arrays and primitives): a parsed config that holds a `Map`,
  `Set`, `Date` or other class instance is refused with an `AuthMethodConfigError` naming the
  member, since none of them freezes;
- `egress`: `request()` over the egress client, so every outbound call is checked (ADR-019
  Decision 8). It passes on only `method` (`GET` or `POST`), `url`, `headers`, `body`, `purpose`
  and `source` (`operator`, `admin` or `remote_document`, never a destination a client or an end
  user chose), and adds the realm's name itself: a method cannot pick another realm's allowlist
  entries or lift the client's caps. `operator` and `admin` are the labels the realm's allowlist
  applies to, for non-public addresses, so the adapter keeps them only for a URL whose origin is
  the origin of a URL in the method's parsed config; any other call goes as `remote_document`.
  `redirect: 'error'` makes a redirect answer reject the call before anything goes to its target
  (the host client's `maxRedirects: 0`, the one cap a method may set, since it can only tighten);
  a call that carries a credential in its body uses it, or a `307` would send that body on.
  `follow`, the default, follows each redirect after the same checks as the first URL;
- `signer`: `signClientAssertion()` and `getUpstreamJwks()` over the signer role, with the realm,
  the provider and the caller role fixed by the host. Signatures, never a key (ADR-019 Decision 9).
  An assertion gets `iat` when its claims carry none (a future one is refused), and its `exp` is
  lowered to at most five minutes from now;
- `log`: a logger's four levels, with a fields object and a message. The fields are nested under
  `authMethod`, so a method cannot overwrite the line's `reqId` or `realm`, as a copy in which
  `code`, `code_verifier`, `client_secret`, `client_assertion`, `refresh_token`, `access_token`,
  `id_token`, `nonce` and `password` are redacted at any depth;
- `routeUrl(path)`: the absolute URL of one of the method's own routes on the realm host, for a
  `redirect_uri`. Only a path the method's `routes` declare.

Each member is an adapter the builder writes, not a bound copy of the host's function, so the host
can hand over its whole egress client, signer and logger and the method still reaches nothing
more. No database or cache handle, no private key, no Fastify instance, no request header and no
cookie.

## Routes

A method declares its routes as data and never touches Fastify. `authMethodRoutesPlugin`
(`libs/fastify/plugins/federation/src/lib/auth-method-routes.ts`) mounts each registered method's
routes under its own prefix, `/upstream/<type>`, as `browser` routes: they answer on the realm's
primary host only, where the flow cookie lives. A route path is one to four lower-case segments,
such as `/callback`; no dot segment, encoded character, parameter or wildcard can match, so a
route cannot leave its prefix, and the mount checks the joined path again. Each provider gets its
own callback URL, so a response meant for one provider cannot be replayed at another.

There are two kinds of route:

- a **callback** route gets the query, the form and the taken transaction, once its binding
  matched, and answers an outcome that goes to the engine. It may name the parameter that
  carries the binding back (`bindingParameter`, `state` by default);
- a **bounce** route gets no transaction and no context, and may only send the browser to one of
  the method's own `GET` callback routes on the same origin, with a query that is a plain object
  of strings. It is for a provider's `form_post`, which arrives cross-site without the
  `SameSite=Lax` flow cookie. Anyone can send that POST, so the code it runs holds no egress
  client, no signer and no config. A bounce that throws or goes elsewhere is a fault, handed to
  the engine like a callback's.

A route has no `HEAD` twin, a `POST` route reads only a urlencoded form (a JSON body reaches the
method as an empty form), and a method sees at most 64 parameters, each at most 8192 characters,
a repeated one as a list of at most 16, in a frozen object with no prototype
(`authMethodParameters`; the test kit hands a method the same objects). The request log censors
the value of a `code`, `id_token` or `access_token` parameter in the logged URL: an upstream
authorization code rides there, and a bounce may carry a provider's tokens on.

The path carries no version: the callback URL is registered at the provider, and a path that
changed at 1.0 would break every registration.

## Registration

The provider registry holds AuthMethods beside plain providers, in one `type` space
(`libs/server/federation/src/providers/provider-registry.ts`). `resolveAuthMethod(type)` finds
only an AuthMethod, `findAuthMethod(type)` answers `undefined` for a type that came from a
request and names none, and `authMethods()` lists them for the mount. `resolve(type)` answers a
plain provider as registered, and for an AuthMethod's type a fail-closed stand-in whose
`verify()` rejects and `extractAttributes()` throws: an AuthMethod's `verify()` resolves for its
own callback's results, so it is handed out only to the engine's upstream step.
The registry keeps a frozen snapshot of each method, read once and validated as kept: the `type`
it checked, the routes it mounts and the members the engine calls cannot change afterwards. A
provider that carries a `contract` member is held to the whole contract at registration, so a
method written against another contract version, with a route that could leave its prefix, or
under a reserved type, fails the boot, and so does a duplicate `type`.
`createConfiguredProviders` takes the methods to register (`authMethods`), holds every entry to the
whole contract (one with no `contract` member too, which the registry alone would take for a plain
provider) and appends them after the built-in providers; leaving them out registers none.

## The generic OpenID Connect client

`libs/server/upstream-oidc` (`@qauth-labs/server-upstream-oidc`) is the relying-party client QAuth
uses toward an upstream OpenID Provider: `createUpstreamOidcMethod({ type, display })` builds one
AuthMethod per configured provider, with the `id` `oidc`. It makes no account decision; the
upstream sign-in flow (#639) looks the identity up by `(realm, type, externalSub)` and decides.

**Callback path.** A provider's `type` is `oidc_` and a lower-case alias (`oidc_corp`), so its
callback is `/upstream/oidc_<alias>/callback` on the realm host, one per provider, and the
`redirect_uri` an operator registers at the provider is
`https://<realm host>/upstream/oidc_<alias>/callback` (`upstreamOidcRedirectUri`). The same path
answers `GET` (a `query` response) and `POST` (a `form_post` response, which the bounce sends on to
the `GET` callback on the same origin, so the browser brings the `SameSite=Lax` flow cookie).

**Config** (`upstreamOidcConfigSchema`): `issuer`, `clientId`, `clientAuthentication`
(`client_secret_basic` or `client_secret_post` with a `writeOnly` `clientSecret`, or
`private_key_jwt` with the key's `signingAlgorithm`), `scopes` (with `openid`; `openid email
profile` by default), `responseMode` (`query` or `form_post`), `idTokenSigningAlgorithms`
(asymmetric only, never `none` or `HS*`), `fetchUserinfo`, and optional `endpoints`.

What it does:

- **Discovery** reads `<issuer>/.well-known/openid-configuration` through the egress client, as an
  `admin` destination. The document's `issuer` must equal the configured one byte for byte, every
  URL it names is an `https` URL with no credentials or fragment, and each goes out as a
  `remote_document` destination, which the egress allowlist never opens: a discovered endpoint
  never reaches a private or loopback address, whatever the allowlist says. A provider on a
  private address sets `endpoints` by hand instead (authorization, token, JWKS, optional userinfo,
  and whether it sends `iss`); those are `admin` destinations, which an allowlist entry naming the
  realm may open, and no discovery document is read.
- **The authorization request** carries `response_type=code`, the client id, the provider's own
  `redirect_uri`, the scopes, a fresh `state` (the binding), a fresh `nonce` and PKCE with S256.
- **The callback** checks the transaction is this provider's (its type, issuer and
  `redirect_uri`), checks `iss` (RFC 9207: a response naming another issuer is refused, and so is
  one without `iss` from a provider that says it sends it), ends as `declined` on
  `access_denied`, and redeems the code with the verifier.
- **Client authentication** at the token endpoint is `client_secret_basic` (each part
  form-urlencoded first, RFC 6749 §2.3.1), `client_secret_post`, or `private_key_jwt`: the signer
  role signs the assertion with the realm's `upstream_client_assertion` key for the provider
  (`iss` and `sub` are the client id the signer's upstream configuration names, `aud` the issuer,
  with a fresh `jti` and a 60-second `exp`). The method sends the string it gets back and never
  sees a key.
- **The ID token** is checked against the provider's key set (fetched through the egress client,
  kept at most five minutes, fetched again for an unknown `kid` at most once a minute) with an
  allowlist of algorithms, then `iss`, `aud`, `azp` (required when there are several audiences),
  `exp`, `iat` (at most ten minutes old) and `nonce`, with 30 seconds of clock tolerance.
- **Userinfo**, when `fetchUserinfo` is set, must carry the ID token's `sub`. The identity's
  `externalSub` is the provider's `sub`, and its `rawClaims` are the ID token's claims over the
  userinfo claims, `iss` among them. `extractAttributes()` takes the standard profile claims that
  are plain text; `email` and `phone_number` are verified only when the provider's own
  `*_verified` claim is `true`.
- **Every call** asks for `redirect: 'error'` (no redirect is followed) and has its own deadline
  and response cap under the egress client's: 5 seconds and 64 KiB for discovery, the key set and
  userinfo, 10 seconds and 64 KiB for the token request.

**The stored client secret.** `sealUpstreamOidcConfig` encrypts it with the realm's
`data_at_rest` key through the signer role, under the context
`upstream-oidc:client-secret:<realm id>:<type>:<destination>`, where `<destination>` is the
SHA-256 of the issuer and, for endpoints set by hand, the token endpoint. So a ciphertext moved to
another provider or realm does not decrypt, and neither does one whose config was pointed at
another host: an admin who cannot read the write-only secret cannot send it elsewhere by changing
`issuer` or `endpoints.token`. `openUpstreamOidcConfig` refuses such a config with
`UpstreamClientSecretDestinationChangedError`, and provider administration (#714) asks for the
secret again whenever either value changes. The signer lets the `api` role decrypt a context under
`upstream-oidc:client-secret:`, and neither `web` nor `delivery`. `openUpstreamOidcConfig` decrypts
the secret for the method's context, and `describeUpstreamOidcConfig` is the view an API or event
may carry, with neither the secret nor its ciphertext. Where the stored form lives is #714's and
#600's.

**What the sign-in flow must add.** `externalSub` is the provider's bare `sub`, and the type
`oidc_<alias>` does not name the issuer, while only `iss` and `sub` together identify a person
(OpenID Connect Core 1.0 §5.7). `rawClaims.iss` is always the checked issuer, so the upstream
sign-in flow (#639) stores it with the credential and refuses a mismatch, or provider
administration (#714) refuses an issuer change while credentials exist. The host opens the stored
config and builds the method's context as the signer caller `api`, or `local` in a single
deployment: `api` may decrypt the client secret and sign client assertions, and `web` may do
neither.

**At registration.** `checkUpstreamOidcProvider(egressClient, realmName, config)` runs discovery
and the egress client's address checks on every endpoint without calling it, and answers one
finding: `invalid_config`, `discovery_unavailable`, `invalid_document` or `destination_refused`.
Each use checks again, since every call goes through the egress client.

## Checking a method: the contract test kit

`checkAuthMethod(method, scenario)` is the one function a method's author calls, in any test
runner. The author plays the provider: the scenario gives a config, answers the method's
outbound calls, and says what the browser comes back with. It is test support: it comes from the
`testing` entry point, never the main one, and it refuses to run with `NODE_ENV=production`,
because it replaces the global `fetch` while it runs. Today the contract and the kit are exported
from the workspace package `@qauth-labs/server-federation`, which is not published to npm.

```ts
import { checkAuthMethod } from '@qauth-labs/server-federation/testing';

it('meets the AuthMethod contract', async () => {
  await checkAuthMethod(myMethod, {
    config: { clientId: 'kit-client', clientSecret: 'kit-secret' },
    egress: (request) => fakeProvider.answer(request),
    callback: (authorizationRequest) => fakeProvider.signIn(authorizationRequest),
    declined: (authorizationRequest) => fakeProvider.decline(authorizationRequest),
  });
});
```

It resolves with the checks it ran and rejects with an `AuthMethodContractError` that lists every
check the method failed:

- the static checks the registry runs, and a config schema that renders as JSON Schema;
- `start()` answers a valid redirect, transaction and binding, and two starts answer different
  transactions;
- two starts answer different bindings, and each sends its binding to the provider, in the
  redirect or in a body the method posted (as a pushed authorization request does);
- the provider's callback carries the binding back in the route's `bindingParameter`: the kit
  compares it as the host does, and calls the handler only when it matches. The callback ends in
  an identity whose attributes carry the method's `type`, and a second sign-in of the same person
  resolves the same `externalSub`;
- PKCE with S256: an authorization request that asks for a code (`response_type=code`) carries
  `code_challenge_method=S256` and a `code_challenge`, and every token request the callback makes
  (`grant_type=authorization_code`) carries the `code_verifier` whose S256 is that challenge;
- `verify()` rejects inputs no callback produced: a well-formed identity, a copy of a real result,
  and a result it has already verified;
- a declined callback ends as `declined`, when the scenario gives one;
- the method never calls the global `fetch` while the kit runs it (the kit cannot see
  `node:https`, `undici` or a `fetch` kept from before; the lint rule `qauth/no-direct-network`
  refuses those in QAuth's own code);
- no log line carries the value of a `writeOnly` config member: any string inside such a member,
  found through `properties`, `items`, `additionalProperties`, `anyOf`, `oneOf`, `allOf` and local
  `$ref`s, as it is, in base64 or base64url, percent-encoded, or as HTTP Basic credentials with
  another string of the config, in a field, a message, or an error's message, stack, cause or own
  fields. Every secret is looked for, however short, so give the scenario's secrets a realistic
  length: a short one can match text that is no leak. It is a check for common leaks, not a proof
  that none exists.

`libs/server/federation/testing/sample-auth-method.fixture.ts` is a sample method that passes,
written the way a plugin would be; `libs/server/federation/src/testing/contract-kit.test.ts`
shows the broken methods the kit refuses, each with the problems it reports.
