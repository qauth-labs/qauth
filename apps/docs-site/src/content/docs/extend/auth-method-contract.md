---
title: The AuthMethod contract
description: The experimental plugin API for sign-in methods — what an AuthMethod adds to CredentialProvider, the upstream step it serves, what a method is handed, where its routes mount, and the test kit that checks a method against the contract.
sidebar:
  order: 6
lastVerified: '2026-10-31'
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

The contract, the registry entries, the route mount and the test kit. Nothing registers an
AuthMethod in a running server yet: the plugin runtime that loads installed methods is #600, the
generic OpenID Connect upstream client is #601, and the upstream sign-in flow that offers the
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
| `start()`             | Starts an upstream transaction.                                                                                                                                              |

The type rules are strict because `type` lands in four places: lower-case ASCII letters, digits
and `_`, starting with a letter, at most 63 characters. A type with `:` or `/` (an ID-JAG issuer
type, `oidc_<issuer URL>`) never matches, and the types QAuth writes itself (`password`, `wallet`,
`webauthn`, `self_reported`, `totp`, `recovery_code`, `email_code`) are reserved.

## The upstream step

```text
engine offers the upstream step ──► person picks the method
        │
        ▼
start(context, { uiLocales })  ──► { redirectTo, transaction }
        │  the engine keeps the transaction server-side, bound to the
        │  interaction and its flow cookie, and sends the browser on
        ▼
provider ──► GET /upstream/<type>/callback?code=…&state=…
        │  the host takes the pending transaction (once); with none it
        │  answers transaction_mismatch and the method never runs.
        │  Otherwise it hands the callback the query and the
        │  transaction; no header, no cookie
        ▼
callback ──► result | declined | failed (reason)
        │
        ▼
engine: verify(result) ──► VerifiedIdentity, checked
        extractAttributes() ──► attributes, each with source = type
```

1. **Start.** The engine calls `start()`. The method answers where the browser goes and the
   transaction it needs back: a fresh `state`, a `nonce`, a PKCE verifier. The engine checks the
   answer (`startUpstreamStep`): the redirect is an absolute `https` URL with no credentials and no
   fragment, and the transaction is JSON data of at most 4096 bytes.
2. **Callback.** The provider sends the browser back to one of the method's callback routes. The
   host takes the transaction the flow cookie names, once. A request with none (no flow cookie,
   another interaction, a replay) ends as `transaction_mismatch` in the host: the method never
   runs for it, so it never spends the code. Otherwise the host hands the transaction to the
   route's handler, which checks `state` against it before it does anything else (a `state` that
   is missing, empty, repeated or another start's is a `transaction_mismatch` too), and answers
   one of three outcomes: `result`, `declined` (the person cancelled at the provider, `access_denied`), or
   `failed` with a reason from a closed set (`transaction_mismatch`, `provider_error`,
   `invalid_response`, `upstream_unavailable`).
3. **Identity.** The engine (`completeUpstreamStep`) passes a `result` to `verify()`, checks the
   identity it resolves (an `externalSub` of 1 to 255 characters with no control character, an
   assurance level, raw claims of JSON data within 64 KiB, which it copies and freezes), then
   takes the attributes. Every attribute's `source` must equal
   the method's `type`: a method cannot write attributes under another source, such as `wallet`,
   which outranks every other in claim resolution. A `verify()` rejection ends the step as
   `verification_refused`; any other broken answer is an `AuthMethodFaultError`, and the engine
   acts on none of it.

The graph of this step is `graphs/flows/federation/upstream-step/flow.yaml`.

## What a method is handed

Plugin code is trusted code that runs in-process
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/) Decision 12), and
the contract hands it only what it needs. `createAuthMethodContext`
(`libs/server/federation/src/auth-method/context.ts`) builds the context, with five members:

- `config`: the realm's config of the method, parsed by `configSchema`, copied and frozen;
- `egress`: `request()` over the egress client, so every outbound call is checked (ADR-019
  Decision 8). It passes on only `method` (`GET` or `POST`), `url`, `headers`, `body`, `purpose`
  and `source` (`operator`, `admin` or `remote_document`, never a destination a client or an end
  user chose), and adds the realm's name itself: a method cannot pick another realm's allowlist
  entries or lift the client's caps;
- `signer`: `signClientAssertion()` and `getUpstreamJwks()` over the signer role, with the realm,
  the provider and the caller role fixed by the host. Signatures, never a key (ADR-019 Decision 9);
- `log`: a logger's four levels, with a fields object and a message;
- `routeUrl(path)`: the absolute URL of one of the method's own routes on the realm host, for a
  `redirect_uri`.

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

- a **callback** route gets the query, the form and the taken transaction, and answers an outcome
  that goes to the engine;
- a **bounce** route gets no transaction and may only send the browser to one of the method's own
  `GET` callback routes on the same origin. It is for a provider's `form_post`, which arrives
  cross-site without the `SameSite=Lax` flow cookie.

A route has no `HEAD` twin, a `POST` route reads only a urlencoded form (a JSON body reaches the
method as an empty form), and a method sees at most 64 parameters, each at most 8192 characters.
The request log censors the value of a `code` parameter in the logged URL, since an upstream
authorization code rides there.

The path carries no version: the callback URL is registered at the provider, and a path that
changed at 1.0 would break every registration.

## Registration

The provider registry holds AuthMethods beside plain providers, in one `type` space
(`libs/server/federation/src/providers/provider-registry.ts`). `resolve(type)` finds either kind,
`resolveAuthMethod(type)` finds only an AuthMethod, `findAuthMethod(type)` answers `undefined`
for a type that came from a request and names none, and `authMethods()` lists them for the
mount.
A provider that carries a `contract` member is held to the whole contract at registration, so a
method written against another contract version, with a route that could leave its prefix, or
under a reserved type, fails the boot, and so does a duplicate `type`.
`createConfiguredProviders` takes the methods to register (`authMethods`) and appends them after
the built-in providers; leaving them out registers none.

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
- `start()` answers a valid redirect and transaction, and two starts answer different
  transactions;
- the callback, with its transaction, ends in an identity whose attributes carry the method's
  `type`, and a second sign-in of the same person resolves the same `externalSub`;
- the callback carries a value of the authorization request (`state`) that binds it to its
  transaction; without it, with it empty or repeated, and with another start's transaction, the
  callback never gives a result and never calls the provider;
- `verify()` rejects inputs no callback produced: a well-formed identity, a copy of a real result,
  and a result it has already verified;
- a declined callback ends as `declined`, when the scenario gives one;
- the method never calls the global `fetch` while the kit runs it (the kit cannot see
  `node:https`, `undici` or a `fetch` kept from before; the lint rule `qauth/no-direct-network`
  refuses those in QAuth's own code);
- no log line carries the value of a `writeOnly` config member, in a field, a message or an
  error, wherever the member sits in the config schema.

`libs/server/federation/testing/sample-auth-method.fixture.ts` is a sample method that passes,
written the way a plugin would be; `libs/server/federation/src/testing/contract-kit.test.ts`
shows the broken methods the kit refuses, each with the problems it reports.
