---
title: Write a preset plugin
description: How a provider plugin in its own repository builds on QAuth's generic OpenID Connect client through @qauth-labs/plugin-sdk alone — the preset's shape, a minimal example, what a preset may set beyond a realm's provider, the preset test kit, and how a deployment loads it.
sidebar:
  order: 7
lastVerified: '2026-11-09'
experimental: true
---

> **Experimental.** A preset is a plugin on the AuthMethod contract, QAuth's plugin API, the
> experimental item [`plugin-api`](/reference/experimental-features/#plugin-api). It may change in
> a minor release without a deprecation window
> ([ADR-018](/reference/records/adr/018-1-0-scope-and-stability/) §4).

A **preset** is a plugin for one named OpenID Connect provider. It holds the provider's facts (its
issuer, its origins, how QAuth authenticates to it) and its claim rules, and nothing of the
protocol. The server builds its sign-in method on its own
[generic OpenID Connect client](/extend/auth-method-contract/#the-generic-openid-connect-client):
discovery, PKCE with S256, `state` and `nonce`, the ID token and key set checks, the token request
and the signer call are the server's. A fix to that code reaches every preset with a server
release, and no plugin carries its own copy.

Every provider plugin lives in its own repository, depends only on the published plugin SDK,
`@qauth-labs/plugin-sdk`, and has its own version line
([ADR-018](/reference/records/adr/018-1-0-scope-and-stability/) §3). The server's code names no
provider.

## A minimal preset

The package's entry point exports the preset as `upstreamOidcPreset`, made with
`defineUpstreamOidcPreset`:

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

`defineUpstreamOidcPreset` runs the checks the server's loader runs, throws an
`AuthMethodContractError` that lists every problem, and returns the preset frozen, with the
contract version of the SDK release (`AUTH_METHOD_CONTRACT`). A server refuses a preset written
against another version, so pin the SDK to the QAuth release you build for.

## The preset's members

The SDK's type is `UpstreamOidcPresetOptions<TConfig>`; `UpstreamOidcPreset` is the same with its
`contract`.

| Member            | What it is                                                                                                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`              | Its AuthMethod id, the admin API's name for it. Never `oidc`, which the generic client holds.                                                                                                            |
| `type`            | Its AuthMethod type: the attributes' source, and the route segment of `/upstream/<type>/callback`, the `redirect_uri` to register at the provider. Never `oidc_<alias>`, the generic client's namespace. |
| `display`         | Its name, and optionally its icon, on the sign-in pages.                                                                                                                                                 |
| `origins`         | The `https` origins the provider answers on, one to eight. The issuer and every endpoint, set by hand or discovered, must be on one of them, so the client secret reaches no other host.                 |
| `configSchema`    | A Zod schema of what an admin sets for a realm. Its client secret is a member marked `.meta({ writeOnly: true })`, which the server stores encrypted and never shows.                                    |
| `upstreamConfig`  | A function of the parsed config that makes the client's config, `UpstreamOidcProviderConfig`, at every use.                                                                                              |
| `responseMembers` | Optional. Members of the authorization response the callback reads, beside the protocol's own.                                                                                                           |
| `identityClaims`  | Optional. Claims the identity gets besides the provider's, from those members and the config.                                                                                                            |
| `attributes`      | Optional. The attributes the claims map to; `UPSTREAM_STANDARD_ATTRIBUTES` unless set.                                                                                                                   |

`UpstreamOidcProviderConfig` is the generic client's config: `issuer`, `clientId`,
`clientAuthentication`, and optionally `scopes`, `endpoints` set by hand, `responseMode`
(`query` or `form_post`), `idTokenSigningAlgorithms`, `fetchUserinfo` and `tenantIssuer`. The
server parses it with its own schema at every use; a config whose URLs are off the preset's
origins is refused at the admin's configure, naming no value.

## What a preset may set beyond a realm's provider

A realm's admin configures a generic provider with an issuer and a client. A preset may also set
these, which no admin can:

- **A client secret the signer signs** (`clientAuthentication: { method: 'signed_client_secret' }`):
  for a provider that takes no static secret but a JWT in the `client_secret` form member. The
  signer role signs it for each token request with the realm's `upstream_client_assertion` key for
  the preset's type: `iss` is the issuer the provider's client record names (`assertionIssuer`),
  `sub` the client id, and it lives sixty seconds. No secret is stored and the plugin holds no key.
- **A multi-tenant issuer** (`tenantIssuer: { template, tenantClaim }`): for a provider whose shared
  endpoints serve many tenants. The template holds `{tenantid}` once, in its path
  (`https://idp.example.com/{tenantid}/v2.0`), and a token is accepted only when its `iss` is the
  template with its own `tenantClaim` value in place. A token of another tenant than the configured
  one is refused.
- **Response members** (`responseMembers`): at most four members the provider sends beside the
  protocol's parameters, each with a map. A provider that answers by `form_post` posts the response
  cross-site; the client bounces it to the `GET` callback, and each member rides on in the URL as
  its map makes it, at most 1024 characters, or is dropped. The callback maps the carried value
  again, so a map must give its own output back unchanged. The request log censors each loaded
  preset's members. A member is the browser's to choose, never signed by the provider.
- **Identity claims** (`identityClaims({ claims, response, config })`): claims set over the
  provider's, such as a name from a response member. A preset never sets `sub` or a claim only the
  ID token carries (`UPSTREAM_ID_TOKEN_ONLY_CLAIMS`), and it may remove a claim the provider vouches
  for (`email`, `phone_number` and their `*_verified` flags, `UPSTREAM_VERIFIED_CLAIM_PAIRS`) but
  never set one: a value it makes up is never taken as verified.
- **Attribute rules** (`attributes`): which claims become the account's attributes, under which
  key, and when one is verified (`verified: (claims) => upstreamClaimIsTrue(claims, 'email_verified')`).
  Without `verified`, an attribute is never verified.

## Check it with the preset kit

`checkUpstreamOidcPreset(preset, scenario)` of `@qauth-labs/plugin-sdk/testing` checks what it can
without the server, in any test runner, and throws an `AuthMethodContractError` that names each
problem:

- the static checks `defineUpstreamOidcPreset` runs;
- every scenario config passes the schema, and `upstreamConfig` makes a provider config for it whose
  URLs are `https` and on the preset's origins, with a tenant template whose `{tenantid}` is in its
  path;
- the client secret is the value of a `writeOnly` member, and no such member's value is anywhere
  else in the provider config;
- each response member's map keeps its output within 1024 characters and gives it back unchanged;
- `identityClaims` sets neither `sub`, a claim only the ID token carries, nor a claim the provider
  vouches for.

```ts
import { checkUpstreamOidcPreset } from '@qauth-labs/plugin-sdk/testing';

import { upstreamOidcPreset } from './index.js';

it('is a preset the server can build', () => {
  checkUpstreamOidcPreset(upstreamOidcPreset, {
    configs: [{ clientId: 'kit-client', clientSecret: 'kit-secret-value-0123' }],
  });
});
```

The full sign-in is the plugin's own end-to-end test against the released server image, with the
plugin added on top, as an operator adds it.

## Package, load and enable it

Publish it as any plugin
([Write a plugin in your own repository](/extend/auth-method-contract/#write-a-plugin-in-your-own-repository)):
the compiled JavaScript, `@qauth-labs/plugin-sdk` under `dependencies` and `zod` under
`peerDependencies`. A package exports an `upstreamOidcPreset` or an `authMethod`, never both.

A deployment loads it only when `AUTH_METHOD_PLUGINS` names it and `PLUGIN_API_ENABLED` is on; no
provider plugin is on the server's first-party list. The boot logs each plugin it loads with how
its method was built (`kind: "upstream-oidc-preset"`), and says why it skipped one. Each realm then
has it off until an admin configures and enables it with the
[plugin operations](/extend/auth-method-contract/#installing-and-enabling-a-plugin).

## How its attributes rank

Claim resolution asserts the highest-ranked verified attribute: `wallet`, then the `oidc_*`
providers, then `self_reported`. A method the loader built from a preset ranks with `oidc_*`,
because the server's own client checked the provider's ID token. A plugin that exports its own
`authMethod` keeps an unknown rank, below `self_reported`, whatever its type.

## Examples

QAuth's own presets are written this way, each in its own repository: `qauth-labs/plugin-google`
(#1074), `qauth-labs/plugin-microsoft` (#1075), a multi-tenant provider with an issuer template,
and `qauth-labs/plugin-apple` (#1076), with a signed client secret and a `form_post` response
member. Sign in with Apple also needs the signer to hold the key Apple issues and to read the
client's Team ID and Services ID (#1073).
