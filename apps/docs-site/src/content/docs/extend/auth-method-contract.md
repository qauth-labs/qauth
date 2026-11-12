---
title: The AuthMethod contract
description: The experimental plugin API for sign-in methods — what an AuthMethod adds to CredentialProvider, the upstream step it serves, what a method is handed, where its routes mount, the test kit that checks a method against the contract, and how to write a plugin in its own repository with @qauth-labs/plugin-sdk.
sidebar:
  order: 6
lastVerified: '2026-11-09'
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
verification. The contract is the npm package `@qauth-labs/plugin-sdk` (`libs/sdk/plugin-sdk/`):
a plugin is written against it in its own repository
([below](#write-a-plugin-in-your-own-repository)), and the server imports it from there.

## What exists today

The contract and its test kit, in the package `@qauth-labs/plugin-sdk`, the registry entries, the
route mount, the plugin runtime and the first method on the contract. With the plugin runtime, a deployment installs plugin packages, the
server loads them at boot, and an admin enables, configures and disables each one per realm
([below](#installing-and-enabling-a-plugin)). The first method is the generic OpenID Connect
upstream client (#601, [below](#the-generic-openid-connect-client)): a library that builds one
method per configured provider, not a plugin package, so nothing registers it in a running server
until provider administration (#714). The upstream sign-in flow (#639) offers the step and acts
on its outcome: each plugin a realm has enabled is one of the realm's upstream providers, and an
account a plugin creates counts as verified. `WalletProvider` is not an
AuthMethod and stays a plain provider whose `verify()` rejects; wallet sign-in keeps its own seam.

## The contract

`libs/sdk/plugin-sdk/src/lib/auth-method.ts` (`AuthMethod`):

| Member                | What it is                                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `type`                | From `CredentialProvider`: the registry key, the `user_credentials.provider_type` value, the `source` of every attribute, and a segment of the route prefix.                                           |
| `verify()`            | From `CredentialProvider`: turns the result the method's own callback returned into a `VerifiedIdentity`, and rejects anything else.                                                                   |
| `extractAttributes()` | From `CredentialProvider`: the attributes of a verified identity.                                                                                                                                      |
| `contract`            | The contract version the method is written against: `qauth-auth-method/1-rc.0`. Its presence is what makes a registered provider an AuthMethod.                                                        |
| `id`                  | The stable name of the method's implementation. Instances of one implementation, one per configured provider, share it; `type` tells them apart.                                                       |
| `display`             | Default display data: `name` (at most 64 characters, under the Interaction API's display rule) and an optional `icon` (a PNG of at most 16 KiB). An admin may override both.                           |
| `configSchema`        | A Zod object schema of the method's config for one realm. A secret member is marked `.meta({ writeOnly: true })`.                                                                                      |
| `steps`               | The Interaction API steps the method contributes, by versioned URN. Today only the upstream step, `urn:qauth:ia:upstream:v1-rc.0`.                                                                     |
| `routes`              | The routes the method mounts below its prefix.                                                                                                                                                         |
| `start()`             | Starts an upstream transaction: where the browser goes, the transaction the method needs back, and the binding the provider carries back.                                                              |
| `secretDestination()` | Optional. Where the config's secret members are sent, as a stable string for a parsed config. The admin API asks for a kept secret again when it changes ([below](#installing-and-enabling-a-plugin)). |

The type rules are strict because `type` lands in four places: lower-case ASCII letters, digits
and `_`, starting with a letter, at most 63 characters. A type with `:` or `/` (an ID-JAG issuer
type, `oidc_<issuer URL>`) never matches, and the types QAuth writes itself (`password`, `wallet`,
`webauthn`, `self_reported`, `totp`, `recovery_code`, `email_code`) are reserved.

## The upstream step

```text
engine offers the upstream step ──► person picks the method
        │
        ▼
start({ uiLocales }, context)  ──► { redirectTo, transaction, binding }
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
   fault), then takes the attributes. The raw claims name the issuer that assigned
   `externalSub`, as `rawClaims.iss`: a subject is unique only within its issuer (OpenID Connect
   Core 1.0 §5.7), so the upstream sign-in flow (#639) stores the issuer with the credential,
   refuses a later sign-in under another one, and refuses an identity that names none. The assurance level is capped: `completeUpstreamStep` takes
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
(`libs/sdk/plugin-sdk/src/lib/context.ts`) builds the context, with five members:

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
  the origin of a URL among the plain members of the method's parsed config, never a secret
  member; any other call goes as `remote_document`.
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
  `id_token`, `nonce` and `password` are redacted at any depth, matched without regard to case,
  `_` or `-` (`clientSecret` matches `client_secret`). The last segment of each of the method's
  secret paths is redacted the same way, and each secret's value is cut out of every string and
  of the message;
- `routeUrl(path)`: the absolute URL of one of the method's own routes on the realm host, for a
  `redirect_uri`. Only a path the method's `routes` declare.

Each member is an adapter the builder writes, not a bound copy of the host's function, so the host
can hand over its whole egress client, signer and logger and the method still reaches nothing
more. No database or cache handle, no private key, no Fastify instance, no request header and no
cookie.

The plugin runtime builds the context for the request's realm
(`apps/auth-server/src/app/helpers/auth-method-plugins.ts`): the realm's stored config with its
secret members decrypted back into place, the method's `type` as the signer's provider, and the
request's logger with the plugin's name. The context signs and decrypts as `api`: its grant holds
`signClientAssertion`, and among the stored secrets it may decrypt are a plugin secret's
`auth-method-plugin:<plugin>:<package>:<type>:<path>` contexts, beside a realm's mail secrets and
an upstream OpenID Connect client's secret. `web`, which serves a plugin's routes, may neither decrypt nor sign
a client assertion, and `local` would open every stored secret. The admin API seals a value for a
configure (`secrets.seal`) and opens it as `admin`, whose grant encrypts and decrypts only
`admin-sealed-value:` contexts; it stores a plugin secret sealed again as `local`, as the realm
secret store does, and opens a stored one as `api`. In a single deployment every role shares the
signer's process. A deployment that runs the signer apart (#497) still needs a grant for the admin
API's storing, since the signer service takes the role from the caller's certificate and never
accepts `local` from a peer; until then a process without the signer refuses the call.

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
provider) and appends them after the built-in providers; leaving them out registers none. The
auth server passes the methods of the plugins it loaded at boot.

## Packaging a plugin

A plugin is an npm package that exports its method as `authMethod`
(`AUTH_METHOD_PLUGIN_EXPORT`; a CommonJS package may put it under `default`):

```ts
// index.ts of @example/qauth-plugin-corp-sso
import { AUTH_METHOD_CONTRACT, type AuthMethod } from '@qauth-labs/plugin-sdk';

export const authMethod: AuthMethod<CorpSsoConfig, CorpSsoTransaction> = {
  contract: AUTH_METHOD_CONTRACT, // 'qauth-auth-method/1-rc.0'
  type: 'corp_sso',
  id: 'corp-sso',
  // display, configSchema, steps, routes, start, verify, extractAttributes
};
```

A package for an OpenID Connect provider may export an `upstreamOidcPreset` instead, whose method
the server builds on its own client ([Preset plugins](#preset-plugins-on-the-generic-client)). It
exports one of the two, never both: the loader refuses a package with both, or with neither.

One package holds one method. Its `id` is the name the admin API gives the plugin, and stays the
same across versions of the package; its `type` is the segment of its routes,
`/upstream/<type>/…`, and the value written to `user_credentials.provider_type`. A realm's state
of the plugin belongs to the package and the type that wrote it: keep both across versions, or
every realm has to configure the plugin again
([The plugin that wrote the state](#the-plugin-that-wrote-the-state)).

**Taken names.** A plugin's `type` may not be a type QAuth writes itself
(`RESERVED_AUTH_METHOD_TYPES`), which the registry and the kit refuse. Nor may it start with
`oidc_`, and its `id` may not be `oidc`: the namespace belongs to the
[generic OpenID Connect client](#the-generic-openid-connect-client). The kit lets these two pass,
since it checks that client's methods too; the plugin loader refuses them, and the boot fails.

**Secret members.** A member of the config schema marked `.meta({ writeOnly: true })` is a secret,
such as a client secret. The runtime reads the marks from the schema's JSON Schema, from its input
side and from its output side. A secret is a string, or a nullable one, at any depth of nested
objects, marked on the input side or on the output side of a pipe that keeps its path and its
string. It may sit inside a union whose branches are all objects, such as a discriminated union of
client authentication methods, when every branch with a member at its path marks it there, on the
same side of the schema: a branch without the member (`private_key_jwt` beside
`client_secret_basic`) takes no secret. The
runtime puts a stored secret back at its path whatever branch the plain config takes, so a
configure that switches to a branch without the member clears the secret in the same request
(`"secrets": { "<path>": null }`), or a plugin whose branches are strict objects refuses the
config. A schema that is not an object, that holds a part JSON Schema cannot describe (a `Set`, a
`Map`, a date, a custom check), or that marks a member inside a list, a record, a recursive part
or a union with a branch that is not an object (a nullable object among them), in one branch of a
union and as a plain member of another, behind a pipe that reshapes or renames it, or one that is
not a string, is refused at boot: the runtime could not keep it write-only. So is a schema built with a Zod copy that keeps
a metadata registry of its own (Zod 4.6 shares one between copies): build a plugin against the
server's Zod, as a peer dependency.

## Installing and enabling a plugin

**Installing.** The operator installs the package with the deployment, as any other dependency
of the auth server ([into the published image](/operate/images/#add-a-plugin-to-the-image)), and
lists it in `AUTH_METHOD_PLUGINS` by package name, comma-separated. A
path, a URL or a `file:` or `git+` specifier is refused: the server never fetches code, and the
admin console never uploads or edits it.

```sh
AUTH_METHOD_PLUGINS=@example/qauth-plugin-corp-sso
PLUGIN_API_ENABLED=true
```

**At boot**, a process that serves the sign-in pages or the admin API imports each listed package,
checks the contract version its method declares first (a plugin built for another version says
so, whatever else it breaks), holds the method to the whole contract, reads its secret members and
registers it after the built-in providers. A package that is not installed, throws as it is
imported, exports no `authMethod`, is written against another contract version, or repeats another
plugin's `id` or `type` stops the boot. The boot logs one line per plugin it loads.

**The switch.** A plugin outside QAuth's first-party list loads only while
`PLUGIN_API_ENABLED=true`, and then the server logs the experimental warning of `plugin-api` at
every boot; a process that loads plugins and holds the `signer` role, as a single deployment
does, logs one more line saying that plugin code runs beside the signing keys and the KEK. With it
off, such a package is never imported, and the boot logs a warning saying why.
A plugin on QAuth's first-party list loads whatever the switch says. The list is fixed in the
server's code (`FIRST_PARTY_AUTH_METHOD_PLUGINS`), never a setting, and it is empty: a first-party
plugin released from its own repository, such as the GitHub one, loads like any other package until
it joins the list ([ADR-018](/reference/records/adr/018-1-0-scope-and-stability/) §3). Discovery
has no member for plugins, and their routes
are left out of the OpenAPI documents.

**Per realm**, every plugin starts off. The admin API's plugin operations, under
`/admin/v1-rc.0/realms/{realmId}/plugins`, list the installed plugins with the realm's state of
each (`plugins.list`, `plugins.get`), replace a
plugin's config (`plugins.update`, `POST …/plugins/{plugin}/config`) and turn it on and off
(`plugins.enable`, `plugins.disable`). `{plugin}` is the plugin's `id`. The three writes change
which upstream credentials sign users in, so each is a
[security operation](/reference/security-operations/) with the effect `credential-path`: it needs
`qauth:admin:security` (the permission `plugins.security`) and an approval, and
`qauth:admin:write` reaches none of them. Each of the three names in its body the `version` of
the state it acts on, as its read gave it (`{ "version": 1 }` for an enable or a disable), so the
approval binds it and the approver sees it, and a state that moved since answers 412: two approved
configures never overwrite each other unseen, and an approved enable never turns on a config its
approver never saw. Each may carry `If-Match` too.

**Secrets.** A plugin's secret members follow the rule of every security operation: the operation
takes a secret only sealed ([API conventions](/reference/api-conventions/#approvals)). A secret's
value reaches the server in one request only: `secrets.seal`
(`POST /admin/v1-rc.0/realms/{realmId}/secrets/seal`), for the operation `plugins.update`, the
member `/secrets/<path>` (the path written as a JSON Pointer token: `~` as `~0`, `/` as `~1`) and
the params `{ "plugin": "<id>" }`, which encrypts it with the realm's `data_at_rest` key, bound to
that operation, member, plugin, the package and type installed under it, and the realm, and
answers the ciphertext. It changes nothing, so it is a write under `secrets.seal`. A configure request then sends the plain members
under `config` and names each secret member under `secrets`, by path: `{ sealed }` sets one to the
sealed value, `null` clears it, and one it does not name keeps its value, unless the configure
sends the plugin somewhere new: a configure that keeps a stored secret while a member whose value
is an http(s) URL is added or changes origin is refused with `400`, naming the secrets to seal
again, so a kept secret never follows a destination it was not set for (as the upstream OpenID
Connect client refuses a changed issuer or token endpoint). So the request an
approval stores until it is used, and the digest it is bound by, hold a ciphertext, never the
value. The handler opens each sealed value for `plugins.update`, its member, the plugin of the path with
the package and type installed under it, and this realm (a value sealed for another operation,
member, plugin, package, type or realm is refused with `400`, so a secret sealed while one package
was installed is never handed to another), and stores it sealed
again under the plugin's own context, bound to the plugin, its package and type, and the member:
what the approval bound is never what is stored. The whole config, secrets included, must pass the
plugin's own schema; a plugin is
enabled only with a config that does. A secret member sent under `config`, however it is spelled,
is refused. No response, audit row, event or log line holds a value: the representation says only
which secret members hold one, and the audit row of a configure names the secrets it set or
cleared. A member that a newer version of a plugin marks secret is never shown or handed to the
plugin from the plain config an older version stored, and leaves it at the next write.

**A plugin's own destination** (#1031). The URL rule above holds every plugin, and reads only the
URLs among the plain members, and only their origins. A plugin whose destination depends on
another member, such as a tenant that shapes an issuer's path, or on a URL's path, names it with
`secretDestination(config)`, and is held to that too: once the new config passes the plugin's
schema, the handler calls it for the stored config, parsed with the secrets it was stored with,
and for the new one, parsed with those the realm will hold, and a configure that keeps a stored
secret while the two differ is refused with the same `400`. So a secret member the plugin routes
by, replaced while another is kept, moves the kept one too; a stored value the configure replaces
or clears is opened for this comparison alone. A configure for which either destination cannot
be told is refused as well: a stored value that does not open, a stored config the plugin's
schema no longer takes, or a hook that throws or answers no string. The hook only
adds a refusal; it never lifts the URL rule. Its result is compared, never logged, stored or
answered. It is a check made at each configure: the stored secret's context does not name the
destination, as the upstream OpenID Connect client's does, so a new version of a plugin that maps
the same config elsewhere sends the stored secret there without asking for it again.

```http
POST /admin/v1-rc.0/realms/{realmId}/secrets/seal
{ "operation": "plugins.update", "member": "/secrets/clientSecret",
  "params": { "plugin": "corp-sso" }, "value": "…" }
→ 200 { "operation": "plugins.update", "member": "/secrets/clientSecret", "sealed": "v1.…" }

POST /admin/v1-rc.0/realms/{realmId}/plugins/corp-sso/config
QAuth-Approval: {approvalId}
{ "version": 0,
  "config": { "issuer": "https://idp.example", "clientId": "qauth" },
  "secrets": { "clientSecret": { "sealed": "v1.…" } } }
```

**A disabled plugin's routes** answer `404` with the `not_found` document of a path no route
serves, before the request's body is read and without the rate limit's headers; disabling keeps
the config. They are checked after the rate limit, so a flood past it answers 429 where an unknown
path answers 404: that tells a plugin of that type is installed, never which realms have it on.

### The plugin that wrote the state

A realm's state of a plugin is keyed by the plugin's `id`, and it records the npm package and the
`type` of the plugin that wrote it. A secret is sealed under a context that names both
(`auth-method-plugin:<id>:<package>:<type>:<path>`). So when the deployment puts another package
behind the same `id`, or a version of the package changes its `type`, the new plugin inherits
nothing from the realm: neither the switch, the config nor the secrets. Until the realm configures
it again:

- its routes answer `404`, as for a disabled plugin, and the sign-in page offers no button for it;
- its stored secrets do not open, and count as unset;
- `plugins.get` and `plugins.list` show it as off, with `configuredBy`, the package and type that
  wrote the state, and `mismatch`, why the state is not this plugin's: `package_changed`,
  `type_changed`, or `package_unrecorded` for a state written before QAuth recorded the package;
- `plugins.enable` is refused with `400`.

A configure (`plugins.update`) under the installed plugin writes the state again for it, off, with
each secret sealed again for it: a secret it does not send again is not kept. An approved enable
then turns it on. `plugins.disable` turns the stored switch off and keeps the rest, so the state
stays off if the other package comes back.

A new version of the same package, with the same `id` and `type`, keeps the realm's state as it is:
it stays on, and its secrets open.

A realm state written by QAuth 0.2, which recorded no package, reads as `package_unrecorded` after
the upgrade: configure and enable each plugin again in each realm that used it. During a rolling
upgrade, such a plugin stays on at the nodes of 0.2 and is off at the new ones; configure no plugin
until every node runs the new release, since a node of 0.2 neither records the package nor seals
under the new context, and opens no secret the new nodes sealed.

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
  userinfo claims, `iss` among them. The protocol claims (`acr`, `amr`, `auth_time`, `sid`, `nonce`,
  the validity claims and the hashes) come from the signed ID token alone; userinfo's are dropped. `extractAttributes()` takes the standard profile claims that
  are plain text; `email` and `phone_number` are verified only when the provider's own
  `*_verified` claim is `true`.
- **Every call** asks for `redirect: 'error'` (no redirect is followed) and has its own deadline
  and response cap: 5 seconds and 64 KiB for discovery, the key set and userinfo, 10 seconds and
  64 KiB for the token request. These only stop the method waiting and reading: they abort no
  call and limit nothing the egress client fetches. The host egress client's own limits,
  `totalTimeoutMs` and `maxResponseBytes`, bound the underlying call.

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
may carry, with neither the secret nor its ciphertext. Where the stored form lives is provider
administration's (#714): the client is not a plugin package, so the plugin runtime's
`realm_auth_method_plugins` (#600), which seals a plugin's secrets under contexts of its own, does
not hold it.

**How the sign-in flow ties the subject to its issuer.** `externalSub` is the provider's bare
`sub`, and the type `oidc_<alias>` does not name the issuer, while only `iss` and `sub` together
identify a person (OpenID Connect Core 1.0 §5.7). `rawClaims.iss` is always the checked issuer,
and the upstream sign-in flow (#639) stores it with the credential and refuses a later sign-in
under another issuer, so a provider re-pointed at another issuer never hands its subjects the
old accounts. The host opens the stored
config and builds the method's context as a signer caller that may decrypt the client secret and
sign client assertions: `api` may do both, and `web`, which serves the sign-in pages where a
method's routes mount, may do neither. So in a single deployment the host calls as `local`, as the
plugin runtime does ([above](#what-a-method-is-handed)); which role calls once the signer runs
apart is #497's.

**At registration.** `checkUpstreamOidcProvider(egressClient, realmName, config)` runs discovery
and the egress client's address checks on every endpoint without calling it, and answers one
finding: `invalid_config`, `discovery_unavailable`, `invalid_document` or `destination_refused`.
Each use checks again, since every call goes through the egress client.

## Preset plugins on the generic client

A preset is a plugin for one named provider that runs the generic client's code under its own id,
type and config (#951). It lives in its own repository and depends only on the SDK (#671): its
package exports the preset as `upstreamOidcPreset`, made with `defineUpstreamOidcPreset`, and the
plugin loader builds its AuthMethod on the server's client (`createUpstreamOidcPresetMethod`). The
protocol code is the server's, so the plugin carries none of it.
[Write a preset plugin](/extend/preset-plugins/) is the guide:

```ts
import { defineUpstreamOidcPreset } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

export const upstreamOidcPreset = defineUpstreamOidcPreset({
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

- **Its own names.** Its `id` is never `oidc` and its `type` never starts with `oidc_`, so the plugin
  loader takes it as any plugin: it loads only while `PLUGIN_API_ENABLED` is on, as no provider
  plugin is on the server's first-party list. Its callback is `/upstream/<type>/callback` on the
  realm host: the `redirect_uri` to register at the provider.
- **Its own config.** An admin configures it with the plugin operations
  ([above](#installing-and-enabling-a-plugin)). `upstreamConfig` turns the parsed config into the
  generic client's config at every use; discovery, PKCE with S256, the callback, the ID token
  checks, `verify()` and the attributes are the generic client's, under the preset's type.
- **Its client secret stays write-only.** It is a member the preset's schema marks `writeOnly`,
  inside a discriminated union of client authentication methods if the preset offers several, so
  the runtime seals it under the plugin's own context and no response, event or log line shows it.
  A config whose client secret is not the value of such a member is refused: it would be stored in
  the clear.
- **Its secret is bound to its provider.** The generic client binds a stored secret to the issuer
  and token endpoint it was entered for; a plugin's secret is bound to the plugin. So a preset
  names the `https` origins its provider answers on (`origins`), every host its endpoints are on
  included, and the client calls no endpoint off them. A config whose issuer, or any endpoint set
  by hand, is on none of them is refused where the host parses it: at the configure (400, naming
  no value) and at every use. A discovery document that names an endpoint off them is refused at
  the sign-in, before any call to it. Whatever a realm's admin sets, the secret goes to that
  provider's origins and to no other host. A provider whose host the admin chooses is a generic
  provider, not a preset.
- **A configure that moves its secret asks for it again.** Within those origins, the preset's
  `secretDestination` names the issuer and the token endpoint set by hand that `upstreamConfig`
  makes for a config, as the digest the generic client binds its stored secret to
  (`upstreamClientSecretDestination`). A configure that changes either and keeps the stored secret,
  through a member that shapes the issuer's path such as a tenant, or through a token endpoint's
  path, is refused with `400` ([above](#installing-and-enabling-a-plugin)): the secret is sealed
  again, as the generic client asks for it again. A discovered token endpoint is not part of it,
  since discovery reads the issuer's own document. The URL rule still holds the preset too, so a
  URL member that moves to another of its origins asks for the secret again as well.
- **No secret elsewhere.** A config whose provider config carries a secret member's value anywhere
  but in the client secret (the client id, a scope, a URL) is refused: it would go out, and be
  logged, in the clear.
- **No allowlisted address.** Every call goes out as a `remote_document` destination unless the
  preset's own config names its origin (the context's rule, [above](#what-a-method-is-handed)), so
  a preset whose config names no URL never reaches a private address the egress allowlist opens.

- **What only a preset sets.** A client secret the signer signs (`signed_client_secret`), a
  multi-tenant issuer template (`tenantIssuer`), response members its `form_post` bounce carries,
  identity claims and attribute rules ([Write a preset plugin](/extend/preset-plugins/)). A realm's
  admin, who writes the generic client's config, sets none of them.
- **Its attributes rank with `oidc_*`.** Claim resolution ranks the attributes of a method the
  loader built from a preset with an `oidc_*` provider's, since the server's client checked the ID
  token. A plugin that exports its own `authMethod` keeps an unknown rank, whatever its type.

A preset's method passes the contract test kit as the generic client does, and
`checkUpstreamOidcPreset` of the SDK's `/testing` entry point checks the preset itself
([Write a preset plugin](/extend/preset-plugins/#check-it-with-the-preset-kit)).

## Checking a method: the contract test kit

`checkAuthMethod(method, scenario)` is the one function a method's author calls, in any test
runner. The author plays the provider: the scenario gives a config, answers the method's
outbound calls, and says what the browser comes back with. It is test support: it comes from the
SDK's `/testing` entry point, never the main one, and it refuses to run with
`NODE_ENV=production`, because it replaces the global `fetch` while it runs.

```ts
import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';

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
  an identity whose `rawClaims.iss` names its issuer and whose attributes carry the method's
  `type`, and a second sign-in of the same person resolves the same `externalSub`;
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

`libs/sdk/plugin-sdk/testing/sample-auth-method.fixture.ts` is a sample method that passes;
`libs/sdk/plugin-sdk/src/testing/contract-kit.test.ts` shows the broken methods the kit refuses,
each with the problems it reports.

## Write a plugin in your own repository

A plugin needs nothing of QAuth's own repository. The contract, its errors and static checks, and
the test kit are the npm package `@qauth-labs/plugin-sdk`, which depends on no other QAuth package.
It is experimental, like the contract it carries. Its README and its `api-report.md` list what
each entry point exports. `libs/sdk/plugin-sdk/examples/minimal-plugin` is a complete plugin for an
OAuth 2.0 provider with PKCE: QAuth's release dry run installs the packed SDK into an empty
project on every pull request, and builds and tests the example there.

For example, QAuth's GitHub plugin is the example of a plugin in its own repository:
`@qauth-labs/plugin-github`, from the example repository [qauth-labs/plugin-github](https://github.com/qauth-labs/plugin-github).
It depends only on the published SDK, runs the kit in its CI, and runs an end-to-end suite against
the released server image with the plugin added on top, as an operator adds it. QAuth makes and
releases it, yet it is not on the server's first-party list: like any other package, it loads only
while `PLUGIN_API_ENABLED` is on.

**Install the SDK.** The package carries QAuth's own version: install the version of the QAuth
release the plugin is for. A release is on npm's `latest` dist-tag, the first being `0.2.0`,
and a release candidate is on `next`. Zod is a peer dependency, so install it beside the SDK:

```sh
npm install @qauth-labs/plugin-sdk@0.2.3 zod
```

**Export the method.** The package's entry point exports its method as `authMethod`
([above](#packaging-a-plugin)):

```ts
import { AUTH_METHOD_CONTRACT, type AuthMethod, UPSTREAM_STEP_URN } from '@qauth-labs/plugin-sdk';
import { z } from 'zod';

const configSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1).meta({ writeOnly: true }),
});

export const authMethod: AuthMethod<z.output<typeof configSchema>, CorpSsoTransaction> = {
  contract: AUTH_METHOD_CONTRACT,
  type: 'corp_sso',
  id: 'corp-sso',
  display: { name: 'Corp SSO' },
  configSchema,
  steps: [UPSTREAM_STEP_URN],
  // routes, start, verify, extractAttributes
};
```

`AUTH_METHOD_CONTRACT` is the contract version of the SDK release you install. A server refuses a
plugin written against another version, so pin the SDK to the QAuth release you build for.

**Run the kit.** `checkAuthMethod` comes from `@qauth-labs/plugin-sdk/testing` and works in any
test runner ([above](#checking-a-method-the-contract-test-kit)). Under Node's own:

```ts
import { test } from 'node:test';

import { checkAuthMethod } from '@qauth-labs/plugin-sdk/testing';

import { authMethod } from './index.js';

test('meets the AuthMethod contract', async () => {
  await checkAuthMethod(authMethod, scenario);
});
```

**Publish.** Publish the compiled JavaScript and its declarations: Node does not strip TypeScript
types under `node_modules`. List `@qauth-labs/plugin-sdk` under `dependencies`, because the
contract's constants are part of the method at run time. List `zod` under `peerDependencies`, so
the method's schema is built with the server's Zod ([secret members](#packaging-a-plugin)):

```json
{
  "name": "@example/qauth-plugin-corp-sso",
  "type": "module",
  "exports": { ".": { "types": "./dist/index.d.ts", "import": "./dist/index.js" } },
  "files": ["dist"],
  "dependencies": { "@qauth-labs/plugin-sdk": "0.2.3" },
  "peerDependencies": { "zod": "^4.6.7" }
}
```

**What the operator does** ([above](#installing-and-enabling-a-plugin)):

1. installs the package with the deployment, as any other dependency of the auth server: on top
   of the published image, as [Published images](/operate/images/#add-a-plugin-to-the-image) shows;
2. lists it by package name in `AUTH_METHOD_PLUGINS`;
3. turns on `PLUGIN_API_ENABLED=true`. A plugin outside QAuth's first-party list loads only while
   the switch is on. With the switch off, the boot logs a warning that names the package and says
   why it was not loaded;
4. enables and configures it per realm through the admin API's plugin operations.

```sh
AUTH_METHOD_PLUGINS=@example/qauth-plugin-corp-sso
PLUGIN_API_ENABLED=true
```

A plugin is trusted code that runs in the server's process, beside its keys in a single
deployment. Install only a package you trust as you trust the server.
